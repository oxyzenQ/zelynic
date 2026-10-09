// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The zombie-policy sweep (NIGHT-hunt-43) — the reclamation
//! family's third collector, named for the residue the census
//! sweep's own law cannot reach: a policy row whose CGROUP died.
//!
//! The gap (the owner's find, one class above hunt-34's orphan
//! rings): every existing collector gates on the policy census.
//! [`sweep_census_orphans`](super::reclaim::Limiter::sweep_census_orphans)
//! collects state no policy names; the removal paths collect what a
//! live hand asks them to; `recover` walks orphan POLICIES — but
//! only when its human runs it. A cgroup that dies with its policy
//! standing (the per-job systemd scope, the container that exited,
//! the session that closed — every one of them limited while it
//! lived) leaves the policy row naming state the census sweep must
//! keep: to that sweep the row is LIVE, because the proof it gates
//! on is "a policy names it", and one does. Nothing automatic ever
//! contradicts that proof — the residue renders a permanent ghost
//! `steady 0 B/s` verdict on the eagle-eyes baseline panel (the
//! lane folds every key the ring read carries, identity or not),
//! holds its census slots for the life of the pin epoch (the
//! 1024-entry budget the family keeps proportional to LIVE
//! policies), and reads as an ACTIVE limit on `status` — a dead
//! cgroup's row counted as enforcement. Until this sweep, the only
//! collector was `sudo zelynic recover` — the manual visit the
//! owner got tired of running.
//!
//! ── The two-signal liveness test ─────────────────────────────────
//!
//! A root is a zombie only when BOTH life signals are absent, the
//! session board's own retire_dead predicate (one law, both homes —
//! the board's "no identity entry AND no window traffic"):
//!
//! 1. **No identity entry.** The identity walk resolves every live
//!    process's cgroup; a root with no entry has no process left
//!    in it. The walk's own failure modes stand the sweep down
//!    (the signal guard below) — an empty identity map is a failed
//!    walk, never proof of universal death.
//!
//! 2. **No ring traffic for the horizon.** The ring stamps a slot
//!    only when the kernel DELIVERS a packet under the policy, so
//!    `ring_series(...).live == 0` proves the root moved nothing
//!    for the full 8s window set — the grace window rides the
//!    ring's own rotation (windows age out by time, not by
//!    packets), so a root that died mid-traffic is skipped until
//!    its last delivered second rotates out. The belt is load
//!    bearing: an alive-but-unresolvable root (a process that
//!    entered a cgroup namespace after its policy was applied —
//!    the one shape where signal 1 lies) still stamps its ring,
//!    and traffic vetoes retirement. Enforcement is never lost to
//!    a resolution blind spot the ring can see through.
//!
//! Fail-closed for reclamation, the posture every sweep in the
//! family owns: silence must be PROVEN, never assumed. A direction
//! whose lens cannot be read (the absent-lens contract — a stale
//! pin epoch) or a root with no ring row at all (a ring whose
//! creation failed on a full map) leaves silence unproven, and the
//! root waits — the manual `recover` scan (identity-only, reported
//! before it cleans) remains the tool for those corners.
//!
//! ── Placement — the visit law, one more collector ────────────────
//!
//! The sweep rides exactly the sites the window and census sweeps
//! ride (hunt-30's "CLI is the daemon" law: the mutation-capable
//! visits collect what reality says is dead), ordered BETWEEN them
//! — windows first (an expired `--during` row dies by its own
//! clock), then zombies (the biggest collector: whole roots,
//! policies and state together), then the census sweep (which then
//! also mops up any state a FAILED zombie reclaim just orphaned —
//! the belt and braces order themselves). Not placed in `recover`:
//! that command's own orphan scan IS this operation with the
//! diagnostic report in front of it, and a silent sweep running
//! first would empty the very report its human came for.

use std::collections::HashSet;

use super::rate_ring::{ring_series, RateRingRaw};
use super::types::Direction;
use super::Limiter;

/// What the ring lens proved about one candidate root, one
/// direction (NIGHT-hunt-43, pure so the decision core below is
/// unit-pinned): the belt's own three-state verdict.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum RingProof {
    /// The direction's read succeeded and the root's ring carries
    /// at least one live window stamp — kernel-side delivery inside
    /// the horizon. Life, against the retirement.
    Traffic,
    /// The read succeeded, the row exists, and no slot is live:
    /// the full horizon delivered nothing. Silence, proven.
    Silent,
    /// Neither could be proven — the direction's lens is absent
    /// (stale pin epoch) or the root holds no ring row (a ring
    /// whose creation failed on a full map). Silence is unproven;
    /// retirement is vetoed (fail-closed for reclamation).
    Unknown,
}

/// The zombie decision core (NIGHT-hunt-43, pure so it is
/// unit-pinned): from one policy root's evidence — the identity
/// verdict and the ring proof per direction it holds a policy in —
/// the retirement verdict. `None` per direction means the root
/// holds no policy leg there, so the lens has nothing to prove
/// about it (a stray row in that direction is census residue, the
/// census sweep's own subject, not this root's life signal). A
/// root retires only when no identity entry stands AND every
/// policed direction proved SILENT — the session board's
/// retire_dead predicate, the two-signal law in the module header.
fn zombie(identity_hit: bool, dl: Option<RingProof>, ul: Option<RingProof>) -> bool {
    if identity_hit {
        return false;
    }
    match (dl, ul) {
        // A root no direction polices is not this sweep's subject
        // at all (the walk only names roots the policy maps carry;
        // the core stays defensive — no leg, no retirement).
        (None, None) => false,
        _ => [dl, ul]
            .into_iter()
            .flatten()
            .all(|p| p == RingProof::Silent),
    }
}

/// Verbose trace line for the zombie sweep (NIGHT-hunt-43): pure
/// formatting so the wording is unit-pinned beside its siblings.
fn zombie_sweep_trace_line(retired: usize, state_reclaimed: usize) -> String {
    format!(
        "[limiter] zombie sweep: retired {retired} dead-cgroup polic{} — \
         no identity entry, no ring traffic for the horizon; {state_reclaimed} state {} \
         returned to the census budget",
        if retired == 1 { "y" } else { "ies" },
        if state_reclaimed == 1 {
            "entry"
        } else {
            "entries"
        },
    )
}

/// The per-direction ring census a sweep needs: the roots whose
/// rows carry a live stamp (traffic) and every root that holds a
/// row at all (presence — the row's absence is `Unknown`, never
/// silence). `None` in, `None` out: an absent lens proves nothing
/// about any root in that direction.
fn ring_census(
    rows: Option<&[(u32, RateRingRaw)]>,
    now: u64,
) -> Option<(HashSet<u32>, HashSet<u32>)> {
    let rows = rows?;
    let mut traffic = HashSet::new();
    let mut present = HashSet::new();
    for (root, raw) in rows {
        present.insert(*root);
        if ring_series(raw, now).live > 0 {
            traffic.insert(*root);
        }
    }
    Some((traffic, present))
}

/// One root's proof from a direction's census (the three-state
/// verdict above; a `None` census is the absent lens).
fn ring_proof(census: Option<&(HashSet<u32>, HashSet<u32>)>, root: u32) -> RingProof {
    match census {
        None => RingProof::Unknown,
        Some((traffic, present)) => {
            if traffic.contains(&root) {
                RingProof::Traffic
            } else if present.contains(&root) {
                RingProof::Silent
            } else {
                RingProof::Unknown
            }
        }
    }
}

impl Limiter {
    /// Sweep the ZOMBIE policies — roots whose cgroup died with
    /// their policy standing (NIGHT-hunt-43, the owner's residual:
    /// the class `sweep_census_orphans` cannot name, because a
    /// zombie's policy row is exactly the proof that sweep gates
    /// on). One visit, three reads (both policy maps, both ring
    /// maps, the identity map — loaded lazily when the caller's
    /// visit never did, the Limiter's own lazy-identity law), then
    /// the two-signal walk: a root retires only when no identity
    /// entry stands and every direction it holds a policy in PROVED
    /// ring silence for the full horizon (the module header's belt —
    /// traffic vetoes retirement even when identity cannot see the
    /// root, so an alive-but-unresolvable cgroup keeps its
    /// enforcement).
    ///
    /// Fail-closed on proof, best-effort on collection, the
    /// family's own ladder: an unreadable policy map or an EMPTY
    /// identity map (a failed walk, the signal guard) stands the
    /// whole sweep down; an absent ring lens only widens `Unknown`
    /// to every root in that direction (nothing retires on an
    /// unprovable silence); a failed delete warns and the root
    /// waits for the next visit. Retirement is the full recover
    /// shape per root: group ids captured read-before-delete, both
    /// policy legs deleted (an uncertain leg keeps the state,
    /// conservative like every removal here), the state reclaimed
    /// once both legs are confirmed gone, and the captured groups
    /// swept for dead shared buckets at the end. Returns the
    /// number of POLICY rows actually removed.
    pub fn sweep_zombie_policies(&mut self) -> usize {
        // The policy census itself: an unreadable direction proves
        // nothing dead — keep every root (the fail-closed posture
        // the census and dead-group sweeps both own).
        let dl = self.read_policies_public(Direction::Download);
        let ul = self.read_policies_public(Direction::Upload);
        let (Ok(dl), Ok(ul)) = (dl, ul) else {
            return 0;
        };

        // The walk needs no identity lens when there is nothing to
        // walk: the no-policies host (the common case) pays neither
        // the map iterations above's follow-on work nor the /proc
        // walk below.
        if dl.is_empty() && ul.is_empty() {
            return 0;
        }

        // The identity map is lazy by the Limiter's own law (write
        // operations never load it — `strict` and friends resolve
        // their targets one layer up). This sweep cannot run
        // without it, so it triggers the load the same way status
        // and recover do: one /proc walk, paid once per
        // mutation-capable visit, only when there are policy rows
        // to judge.
        if self.identity().is_empty() {
            self.refresh_identity();
        }

        // The signal guard: an empty identity map AFTER a refresh
        // attempt is a failed walk (procfs unreadable), never proof
        // that every policy's cgroup died. The sweep stands down
        // entirely — the same direction the session board's
        // retire_dead takes.
        if self.identity().is_empty() {
            return 0;
        }

        // The ring lens census, both directions, one clock: the
        // same monotonic nanoseconds the stamp protocol rides.
        let reads = self.read_rate_rings();
        let now = super::monotonic_ns();
        let dl_census = ring_census(reads.dl.as_deref(), now);
        let ul_census = ring_census(reads.ul.as_deref(), now);

        // The walk: every root either direction names, sorted for
        // deterministic traces (HashMap iteration order is random;
        // the verbose log and the pinned pins both deserve one
        // order).
        let mut roots: Vec<u32> = dl
            .iter()
            .chain(ul.iter())
            .map(|(id, _)| *id)
            .collect::<HashSet<u32>>()
            .into_iter()
            .collect();
        roots.sort_unstable();

        let mut retired = 0usize;
        let mut state_reclaimed = 0usize;
        let mut captured_groups: Vec<u32> = Vec::new();
        for id in roots {
            let has_dl = dl.iter().any(|(k, _)| *k == id);
            let has_ul = ul.iter().any(|(k, _)| *k == id);
            let dl_proof = has_dl.then(|| ring_proof(dl_census.as_ref(), id));
            let ul_proof = has_ul.then(|| ring_proof(ul_census.as_ref(), id));
            if !zombie(self.identity().get(id).is_some(), dl_proof, ul_proof) {
                continue;
            }
            // The retirement, recover's own shape per root: capture
            // the group ids read-before-delete, delete both legs,
            // reclaim the state once both are confirmed gone.
            let mut dl_gone = false;
            let mut ul_gone = false;
            for direction in [Direction::Download, Direction::Upload] {
                let is_dl = matches!(direction, Direction::Download);
                // Capture read-before-delete: an Err keeps the
                // bucket (a leaked slot never bricks enforcement).
                if let Ok(Some(group)) = self.read_policy_group(id, direction) {
                    captured_groups.push(group);
                }
                match self.delete_policy(id, direction) {
                    Ok(true) => {
                        retired += 1;
                        if is_dl {
                            dl_gone = true;
                        } else {
                            ul_gone = true;
                        }
                    }
                    Ok(false) => {
                        // ENOENT: the leg was already gone — the
                        // state reclaim may proceed for it.
                        if is_dl {
                            dl_gone = true;
                        } else {
                            ul_gone = true;
                        }
                    }
                    Err(e) => {
                        eprintln_safe!(
                            "[limiter] zombie sweep: cg:{id} {} policy delete failed: {e}",
                            direction.label()
                        );
                    }
                }
            }
            if dl_gone && ul_gone {
                state_reclaimed += self.reclaim_cgroup_state(id, true, true, true);
            }
        }

        // The dead-group sweep, recover's own tail: a captured
        // group no live policy references returns its shared-bucket
        // slots.
        self.reclaim_dead_groups(&captured_groups);

        if self.verbose && retired > 0 {
            eprintln_safe!("{}", zombie_sweep_trace_line(retired, state_reclaimed));
        }
        retired
    }
}

// NIGHT-hunt-43: the pins live under the single test/ tree
// (cosmostrix Pattern C), #[path]-wired exactly like the reclaim
// and census siblings.
#[cfg(test)]
#[path = "../../../test/ebpf/limiter/zombie_tests.rs"]
mod zombie_tests;
