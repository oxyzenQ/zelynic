// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The --during userspace half (night-during, schema v23): the
//! wall-to-monotonic translation the apply path writes, the window
//! map plumbing, and the offset bridge stamps. The grammar lives
//! in the during_parse sibling (the parse.rs discipline one feature
//! over); the pure verdict arithmetic lives in ebpf/src/during.rs
//! (the kernel object's own file); this module owns everything a
//! CLI visit does AROUND the two.
//!
//! The translation (during_to_window): SPAN rows carry wall
//! instants PRE-TRANSLATED into the monotonic clock (wall minus
//! the apply-instant offset), so `bpf_ktime_get_ns` decides the
//! verdict with zero drift — NTP slew and a manual `date -s`
//! cannot move it (the stated residue: monotonic does not count
//! suspend, so a sleeping host's span outlives its wall-calendar
//! promise by the slept time). DAILY rows need no translation.
//!
//! The twin (window_active_user): the userspace-side verdict for
//! the probe gate and the status surface — the SAME margin law the
//! kernel comparator applies, evaluated with the true wall the CLI
//! holds (no bridge uncertainty). Pinned against the kernel core
//! by the during_user_tests grid: for any (wall, mono) pair the
//! twin answers exactly what the kernel would with a freshly
//! stamped bridge — the drift-freedom the twin exists to prove.

use anyhow::{anyhow, Context, Result};
use aya::maps::HashMap as BpfHashMap;

use super::during_parse::{civil_from_days, DuringSpec, NS_PER_DAY, NS_PER_SEC};
use super::format::monotonic_ns;
use super::lanes;
use super::types::{PolicyWindowRaw, WINDOW_KIND_DAILY, WINDOW_KIND_SPAN};
use crate::ebpf::pin::{PIN_MAP_POLICY_WINDOW, PIN_MAP_WALL_CLOCK_OFFSET};

// ━━ The clocks and the translation ━━

/// The wall clock as ns since the Unix epoch (the CLI's own clock
/// read; every translation and stamp flows through here so tests
/// can inject theirs).
pub fn wall_now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// The bridge value: wall minus monotonic, the offset the kernel
/// comparator adds to `bpf_ktime_get_ns` (saturating — the wall is
/// ~1.78e18 ns against a boot-fresh mono near zero on any real
/// host; a backwards wall saturates to 0, the under-enforcement
/// direction).
pub fn wall_minus_mono(wall_ns: u64, mono_ns: u64) -> u64 {
    wall_ns.saturating_sub(mono_ns)
}

/// Translate one spec into the side-map row, at the apply instant.
/// SPAN/DURATION: `start_mono = mono - (wall - start_wall)`
/// (saturating — a start before the host booted clamps to "since
/// boot", the span simply already running) and
/// `end_mono = mono + (end_wall - wall)` (never negative: the parse
/// family refuses past ends). DURATION: start is the mono now.
/// DAILY: fields verbatim, no clock.
pub fn during_to_window(spec: &DuringSpec, wall_now_ns: u64, mono_now_ns: u64) -> PolicyWindowRaw {
    let mut row = PolicyWindowRaw::default();
    match spec {
        DuringSpec::Daily { start_s, end_s } => {
            row.kind = WINDOW_KIND_DAILY;
            row.start_s = *start_s;
            row.end_s = *end_s;
        }
        DuringSpec::Span {
            start_wall_ns,
            end_wall_ns,
        } => {
            row.kind = WINDOW_KIND_SPAN;
            row.start_mono_ns =
                mono_now_ns.saturating_sub(wall_now_ns.saturating_sub(*start_wall_ns));
            row.end_mono_ns = mono_now_ns.saturating_add(end_wall_ns.saturating_sub(wall_now_ns));
        }
        DuringSpec::Duration { ns } => {
            row.kind = WINDOW_KIND_SPAN;
            row.start_mono_ns = mono_now_ns;
            row.end_mono_ns = mono_now_ns.saturating_add(*ns);
        }
    }
    row
}

// ━━ The userspace twin (the probe gate / status verdict) ━━

/// The daily comparator's twin: the position-relative formulation
/// with the margin erosion, byte-for-byte the kernel core's law
/// (ebpf/src/during.rs daily_active) — pinned equal by the
/// during_user_tests grid. Private here because the kernel file
/// owns the law's text; this copy exists only because src/ never
/// compiles the ebpf tree (the mirror-types discipline).
fn daily_active_twin(secs: u64, start_s: u32, end_s: u32, margin_ns: u64) -> bool {
    let start = u64::from(start_s).saturating_mul(NS_PER_SEC);
    let end = u64::from(end_s).saturating_mul(NS_PER_SEC);
    let len = end.wrapping_sub(start) % NS_PER_DAY;
    if len == 0 {
        return false;
    }
    let rel = secs.wrapping_sub(start) % NS_PER_DAY;
    rel < len && rel >= margin_ns && len - rel > margin_ns
}

/// The twin of the kernel verdict, evaluated the way the kernel
/// does: the wall is `mono + (wall - mono)` — the same SATURATING
/// offset arithmetic the bridge stamp uses, so the twin answers
/// exactly what the datapath would with a freshly stamped bridge
/// for EVERY (wall, mono) pair, saturation domain included (on any
/// real host wall >> mono and the effective wall IS the true wall;
/// the saturation only bites in synthetic tests, and the grid pin
/// owns the whole domain). The margin is the kernel core's
/// FIRE_EARLY (2s): both edges erode toward less enforcement, so a
/// caller standing down (the probe) or claiming "active" (status)
/// stays on the conservative side of every boundary.
pub fn window_active_user(win: &PolicyWindowRaw, wall_now_ns: u64, mono_now_ns: u64) -> bool {
    match win.kind {
        WINDOW_KIND_DAILY => {
            let effective_wall =
                mono_now_ns.saturating_add(wall_minus_mono(wall_now_ns, mono_now_ns));
            let secs = effective_wall % NS_PER_DAY;
            daily_active_twin(secs, win.start_s, win.end_s, 2 * NS_PER_SEC)
        }
        // SPAN and unknown kinds: the span compare is exact (the
        // monotonic domain holds no drift); unknown kinds enforce,
        // the kernel core's absent-entry verdict.
        _ => mono_now_ns >= win.start_mono_ns && mono_now_ns < win.end_mono_ns,
    }
}

/// Why a window is NOT policing right now (the probe's stand-down
/// note and the status row's lifetime line share it): a dormant
/// future span names its wake instant (translated back to wall
/// through the same offset pair), an ended span names expiry, a
/// daily window names its hours. `None` = active now.
pub fn dormancy_note(win: &PolicyWindowRaw, wall_now_ns: u64, mono_now_ns: u64) -> Option<String> {
    match win.kind {
        WINDOW_KIND_DAILY => {
            if window_active_user(win, wall_now_ns, mono_now_ns) {
                return None;
            }
            Some(format!(
                "outside the daily window {:02}:{:02}-{:02}:{:02} UTC — the row is \
                 not policing this minute",
                win.start_s / 3600,
                (win.start_s / 60) % 60,
                win.end_s / 3600,
                (win.end_s / 60) % 60
            ))
        }
        WINDOW_KIND_SPAN => {
            if mono_now_ns < win.start_mono_ns {
                let wake_wall = win
                    .start_mono_ns
                    .saturating_add(wall_minus_mono(wall_now_ns, mono_now_ns));
                Some(format!(
                    "the window sleeps until {} — the row is not policing yet",
                    format_wall_utc(wake_wall)
                ))
            } else if mono_now_ns >= win.end_mono_ns {
                Some(format!(
                    "the window expired at {} — the row is no longer policing \
                     (awaiting sweep)",
                    format_wall_utc(
                        win.end_mono_ns
                            .saturating_add(wall_minus_mono(wall_now_ns, mono_now_ns))
                    )
                ))
            } else {
                None
            }
        }
        // Unknown kinds enforce (the absent-entry verdict) — no
        // dormancy to name.
        _ => None,
    }
}

/// Wall instant as "YYYY-MM-DD HH:MM:SS UTC" (the CLI's own
/// calendar renderer — no chrono dependency, the Hinnant pair
/// above; pinned on known instants).
pub fn format_wall_utc(wall_ns: u64) -> String {
    let secs = wall_ns / NS_PER_SEC;
    let days = (secs / 86_400) as i64;
    let sod = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        sod / 3600,
        (sod / 60) % 60,
        sod % 60
    )
}

// ━━ The map plumbing (the Limiter side) ━━

/// One window mutation this invocation made, carrying the row's
/// PRE-APPLY state so the atomic rollback can restore it exactly
/// (the PolicyMutation contract, one level up from legs).
#[derive(Debug, Clone)]
pub(super) struct WindowMutation {
    pub(super) cgroup_id: u32,
    /// The window row the map held before this invocation touched
    /// it: `Some(raw)` restores it verbatim; `None` means absent
    /// (a fresh window), so the rollback removes what the apply
    /// wrote.
    pub(super) previous: Option<PolicyWindowRaw>,
}

impl super::Limiter {
    /// Read one row's window (the probe gate and the status surface
    /// read; absent = no window, today's behavior). Read-only
    /// `&self`, the stats.rs reader pattern (the pinned-map lane,
    /// not the mutable with_u32_map acquisition the apply family
    /// owns) — a probe or a display must never need a mutable
    /// handle for a read.
    pub fn read_policy_window(&self, cgroup_id: u32) -> Result<Option<PolicyWindowRaw>> {
        let pinned;
        let map_ref: &aya::maps::Map = match self.bpf.as_ref() {
            Some(bpf) => bpf
                .map("policy_window")
                .context("policy_window map not found")?,
            None => {
                pinned = crate::ebpf::pin::open_pinned_hash_map(PIN_MAP_POLICY_WINDOW)?;
                &pinned
            }
        };
        let map: BpfHashMap<_, u32, PolicyWindowRaw> =
            BpfHashMap::try_from(map_ref).context("Failed to access policy_window")?;
        match map.get(&cgroup_id, 0) {
            Ok(raw) => Ok(Some(raw)),
            Err(e) if lanes::map_remove_means_absent(&e) => Ok(None),
            Err(e) => Err(anyhow!("failed to read cg:{cgroup_id} policy window: {e}")),
        }
    }

    /// Write one row's window (the apply path; the mutation ledger
    /// capture happens in policy.rs, beside the leg mutations).
    pub(super) fn write_policy_window(
        &mut self,
        cgroup_id: u32,
        raw: PolicyWindowRaw,
    ) -> Result<()> {
        self.with_u32_map::<PolicyWindowRaw, ()>("policy_window", PIN_MAP_POLICY_WINDOW, |map| {
            map.insert(cgroup_id, raw, 0)
                .map_err(|e| anyhow!("failed to write cg:{cgroup_id} policy window: {e}"))
        })
    }

    /// Remove one row's window. `Ok(true)` removed, `Ok(false)`
    /// ENOENT-absent (the improve-29-twin: an apply WITHOUT
    /// --during removes any stale window; an unstrict/reclaim
    /// removes it with the legs).
    pub(super) fn remove_policy_window(&mut self, cgroup_id: u32) -> Result<bool> {
        self.remove_map_entry::<PolicyWindowRaw>("policy_window", PIN_MAP_POLICY_WINDOW, cgroup_id)
    }

    /// The atomic rollback's window half: restore each mutation's
    /// pre-apply row verbatim, remove what a fresh window wrote.
    /// Mirrors rollback_mutations' contract — a failed restore
    /// names the survivor, never hides it.
    pub(super) fn rollback_window_mutations(
        &mut self,
        mutations: &[WindowMutation],
    ) -> Vec<String> {
        let mut survivors: Vec<String> = Vec::new();
        for mutation in mutations {
            match mutation.previous {
                Some(raw) => {
                    if let Err(e) = self.write_policy_window(mutation.cgroup_id, raw) {
                        eprintln_safe!(
                            "[limiter] window rollback failed: cg:{}: {e}",
                            mutation.cgroup_id
                        );
                        survivors.push(format!("cg:{} window", mutation.cgroup_id));
                    }
                }
                None => {
                    if let Err(e) = self.remove_policy_window(mutation.cgroup_id) {
                        eprintln_safe!(
                            "[limiter] window rollback failed: cg:{}: {e}",
                            mutation.cgroup_id
                        );
                        survivors.push(format!("cg:{} window", mutation.cgroup_id));
                    }
                }
            }
        }
        survivors
    }

    /// Stamp the offset bridge (every apply-family mutation — the
    /// CLI visit IS the refresh channel). The value is
    /// wall-minus-mono read THIS instant; the write rides the
    /// Array lane (the one acquisition path contract).
    pub(super) fn stamp_wall_clock_offset(&mut self) -> Result<()> {
        let offset = wall_minus_mono(wall_now_ns(), monotonic_ns());
        self.with_array_u64_map("wall_clock_offset", PIN_MAP_WALL_CLOCK_OFFSET, |map| {
            map.set(0, offset, 0)
                .map_err(|e| anyhow!("failed to stamp wall_clock_offset: {e}"))
        })
    }
}

/// The attach-path stamp on the REUSE lane (pins already healthy,
/// the early return before any object exists): open the pinned
/// Array directly through the pin.rs open helper (a read-handle
/// open, never a mutable object acquisition), so the architecture
/// pin's one-acquisition-path contract holds. THE two stamp points that matter: this one (every
/// enforcement command's attach-reuse refreshes the bridge for the
/// daily windows that live in the pinned maps) and the
/// apply-family lane stamp above (before every window write, the
/// authoritative one). A fresh LOAD stamps nothing on purpose: a
/// reload unpins every map first (the one-time re-apply contract),
/// so no window row exists to read the bridge until the next
/// apply — which stamps through the lane before it writes.
/// Best-effort by design: the visit must not fail because a
/// read-only visit could not refresh a counter.
pub(super) fn stamp_offset_on_pinned(verbose: bool) {
    use aya::maps::Array as BpfArray;
    let offset = wall_minus_mono(wall_now_ns(), monotonic_ns());
    let stamp = crate::ebpf::pin::open_pinned_array_map(PIN_MAP_WALL_CLOCK_OFFSET)
        .map_err(|e| anyhow!("pinned map {PIN_MAP_WALL_CLOCK_OFFSET}: {e}"))
        .and_then(|mut obj| {
            BpfArray::<&mut aya::maps::MapData, u64>::try_from(&mut obj)
                .map_err(|e| anyhow!("failed to open: {e}"))
                .and_then(|mut map| {
                    map.set(0, offset, 0)
                        .map_err(|e| anyhow!("failed to stamp: {e}"))
                })
        });
    if let Err(e) = stamp {
        if verbose {
            eprintln_safe!("[limiter] wall_clock_offset refresh skipped: {e}");
        }
    }
}

// NIGHT-hunt-17: pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the policy pins.
#[cfg(test)]
#[path = "../../../test/ebpf/limiter/during_user_tests.rs"]
mod during_user_tests;
