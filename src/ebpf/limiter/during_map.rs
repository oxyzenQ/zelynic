// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The --during map plumbing (night-during, schema v23): the
//! side-map half of the time-window feature — the window row
//! read/write/remove lanes on Limiter, the atomic rollback's window
//! ledger, the lazy expired-span sweep, and the two offset-bridge
//! stamps. The grammar lives in the during_parse sibling, the pure
//! verdict arithmetic in ebpf/src/during.rs, and the translation /
//! twin / persistence family in the during sibling; this module
//! owns everything that touches a MAP. Split out of the during
//! sibling by night-audit-1 task 17 (the dormancy fix pushed the
//! file past the 500-LOC cap; the pure-logic/plumbing seam is the
//! boundary the file already wore — the bpf_syscall precedent).

use anyhow::{anyhow, Context, Result};
use aya::maps::HashMap as BpfHashMap;

use super::during::{during_to_window, wall_minus_mono, wall_now_ns};
use super::during_parse::DuringSpec;
use super::format::monotonic_ns;
use super::lanes;
use super::types::{PolicyWindowRaw, Target, WINDOW_KIND_SPAN};
use crate::ebpf::pin::{PIN_MAP_POLICY_WINDOW, PIN_MAP_WALL_CLOCK_OFFSET};

// ━━ The mutation ledger ━━

/// Translate one spec at the apply instant, the monotonic clock
/// read fresh: the one-shot form every apply-family caller shares
/// (policy.rs apply_single/apply_group, atomic.rs apply_multi) —
/// one place owns the read, so every caller sees the same
/// discipline. The duration-only grammar needs no wall read
/// here anymore (the span/daily translations that did are retired
/// with the restore lane — NIGHT-improve-55); the wall clock
/// still rides the offset-bridge stamps below.
pub(super) fn translate_now(spec: &DuringSpec) -> PolicyWindowRaw {
    during_to_window(spec, monotonic_ns())
}

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

// ━━ The Limiter window lanes ━━

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
