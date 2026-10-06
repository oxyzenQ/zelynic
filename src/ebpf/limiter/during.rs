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
use super::types::{PolicyWindowRaw, Target, WINDOW_KIND_DAILY, WINDOW_KIND_SPAN};
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

// ━━ The status classifier + the persistence form ━━

/// The window's current state, the one vocabulary the human table,
/// the JSON document, and the pins share: "active" (policing now),
/// "dormant" (a future span sleeping), "outside" (a daily window
/// between its hours), "expired" (an ended span awaiting the
/// sweep). Unknown kinds are "active" (the absent-entry verdict).
pub fn window_state(win: &PolicyWindowRaw, wall_now_ns: u64, mono_now_ns: u64) -> &'static str {
    match win.kind {
        WINDOW_KIND_SPAN => {
            if mono_now_ns < win.start_mono_ns {
                "dormant"
            } else if mono_now_ns >= win.end_mono_ns {
                "expired"
            } else {
                "active"
            }
        }
        WINDOW_KIND_DAILY => {
            if window_active_user(win, wall_now_ns, mono_now_ns) {
                "active"
            } else {
                "outside"
            }
        }
        _ => "active",
    }
}

/// The WALL-clock persistence form of one window row (the snapshot
/// document's `during` field): a span's monotonic deadlines are
/// meaningless across a reboot (mono resets), so the census
/// serializes the WALL instants (reconstructed through the same
/// offset pair the twin uses) and the daily pair verbatim; the
/// restore re-translates through a fresh bridge. A restored row
/// must never convert "auto-expires" into "forever" — the design
/// brief's safety direction.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct WindowPersist {
    /// "span" or "daily" (the WINDOW_KIND_* twins by name).
    pub kind: String,
    /// SPAN: inclusive start, wall ns since epoch. DAILY: 0.
    pub start_wall_ns: u64,
    /// SPAN: exclusive end, wall ns since epoch. DAILY: 0.
    pub end_wall_ns: u64,
    /// DAILY: window start, seconds-of-day UTC. SPAN: 0.
    pub start_s: u32,
    /// DAILY: window end, seconds-of-day UTC. SPAN: 0.
    pub end_s: u32,
}

/// One row's persistence form (pure): the span's wall instants
/// reconstructed as `mono + (wall - mono)` — the exact inverse of
/// the apply-time translation, the twin's own arithmetic.
pub fn window_persist_form(
    win: &PolicyWindowRaw,
    wall_now_ns: u64,
    mono_now_ns: u64,
) -> WindowPersist {
    let offset = wall_minus_mono(wall_now_ns, mono_now_ns);
    match win.kind {
        WINDOW_KIND_DAILY => WindowPersist {
            kind: "daily".to_string(),
            start_wall_ns: 0,
            end_wall_ns: 0,
            start_s: win.start_s,
            end_s: win.end_s,
        },
        _ => WindowPersist {
            kind: "span".to_string(),
            start_wall_ns: win.start_mono_ns.saturating_add(offset),
            end_wall_ns: win.end_mono_ns.saturating_add(offset),
            start_s: 0,
            end_s: 0,
        },
    }
}

/// The restore half (pure): the persistence form back into the
/// spec the apply family takes — a fresh bridge re-translates the
/// span at the restore instant. A file whose kind is neither name
/// refuses (the state-schema honesty: never a best-guess parse).
pub fn window_persist_to_spec(form: &WindowPersist) -> Option<DuringSpec> {
    match form.kind.as_str() {
        "daily" => Some(DuringSpec::Daily {
            start_s: form.start_s,
            end_s: form.end_s,
        }),
        "span" => Some(DuringSpec::Span {
            start_wall_ns: form.start_wall_ns,
            end_wall_ns: form.end_wall_ns,
        }),
        _ => None,
    }
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
            Err(e) if lanes::map_error_means_absent(&e) => Ok(None),
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

    /// Read every window row (the status join and the sweep's scan).
    /// The same read-only pinned-map lane the census readers own.
    pub fn read_policy_windows_all(&self) -> Result<Vec<(u32, PolicyWindowRaw)>> {
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
        Ok(map.iter().flatten().collect())
    }

    /// The lazy SWEEP (night-during, schema v23 — "the CLI is the
    /// daemon"): every apply-family invocation drives ENDED spans
    /// through the unstrict machinery (the whole reclaim the named
    /// removal owns). Dormant spans and daily windows are never
    /// swept (span_ended is the only removal predicate); an ended
    /// row has been answering ALLOW since its instant, so the sweep
    /// is pure reclamation. Best-effort: a sweep failure warns and
    /// never fails the apply that triggered it.
    pub fn sweep_expired_windows(&mut self) -> Result<usize> {
        let mono = monotonic_ns();
        let ended: Vec<u32> = self
            .read_policy_windows_all()?
            .into_iter()
            .filter(|(_, w)| w.kind == WINDOW_KIND_SPAN && mono >= w.end_mono_ns)
            .map(|(id, _)| id)
            .collect();
        if ended.is_empty() {
            return Ok(0);
        }
        let mut swept = 0usize;
        for cgroup_id in ended {
            if self.verbose {
                eprintln_safe!(
                    "[limiter] window sweep: cg:{cgroup_id} span ended — removing the row"
                );
            }
            // The unstrict path is the removal the repo already
            // owns: both legs, the state reclaim, the window row at
            // row death (the stats gate), the group supersession.
            match self.unstrict(&Target::CgroupId(cgroup_id)) {
                Ok(_) => swept += 1,
                Err(e) => {
                    eprintln_safe!(
                        "[limiter] window sweep failed for cg:{cgroup_id}: {e} — \
                         the row stays (expired, awaiting the next sweep)"
                    );
                }
            }
        }
        Ok(swept)
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

/// The attach-path stamp on the REUSE lane (pins healthy, the early
/// return before any object exists): the pin.rs open helper directly (a
/// read-handle open, never a mutable acquisition), so the architecture
/// pin one-path contract holds. The two stamp points that matter: this
/// one (every enforcement command's attach-reuse) and the apply-family
/// lane stamp above (the authoritative one, before every window write).
/// A fresh LOAD stamps nothing on purpose — a reload unpins every map
/// first, so no window row exists until the next apply stamps through
/// the lane. Best-effort: a visit never fails on a refresh.
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
