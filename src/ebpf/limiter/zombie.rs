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
//!    a direction with no live stamp proves the root moved nothing
//!    for the full 8s window set — the grace window rides the
//!    ring's own rotation (windows age out by time, not by
//!    packets), so a root that died mid-traffic is skipped until
//!    its last delivered second rotates out. A direction with NO
//!    ring row at all is the same verdict, not a weaker one: the
//!    ring is created lazily, at the first ALLOWED packet
//!    (enforce_helpers' get_ring_ptr), so an absent row is the
//!    never-delivered verdict — the block lane's rate-0 direction
//!    books nothing by contract, a one-way stream books nothing on
//!    its quiet leg, and those zombies retire like any other. The
//!    belt is load bearing either way: an alive-but-unresolvable
//!    root (a process that entered a cgroup namespace after its
//!    policy was applied — the one shape where signal 1 lies)
//!    still stamps its ring while it delivers, and traffic vetoes
//!    retirement. Enforcement is never lost to a resolution blind
//!    spot the ring can see through.
//!
//! Fail-closed for reclamation, the posture every sweep in the
//! family owns: silence must be PROVEN, never assumed — and a
//! direction whose lens cannot be READ (the absent-lens contract,
//! a stale pin epoch) proves nothing. Every root in that
//! direction waits — UNLESS the cgroupfs census can prove the
//! stronger verdict: the root's directory is GONE from a complete
//! walk of the mount (the owner-approved absent-lens residual,
//! see [`crate::ebpf::identity::pathwalk::cgroupfs_id_census`]).
//! Death is a stronger proof than silence — the kernel destroys a
//! cgroup only after its last process left, so nothing can ever
//! deliver from it again — and a zombie that dies on a stale pin
//! epoch now retires at the next visit instead of waiting for the
//! manual `recover` scan (which remains the tool for the shapes
//! the census cannot conclude: an inconclusive walk, a tree past
//! the bounds, a cgroup-namespace view that cannot see the root's
//! branch of the host hierarchy).
//!
//! ── The cgroupfs belt (night-audit-8) ────────────────────────────
//!
//! The two-signal law's named residual, closed: an alive root
//! whose processes all entered a cgroup namespace after its apply
//! is observationally identical to a dead one on both signals
//! (the namespaced /proc view hides its members; a quiet app hides
//! its traffic) — and used to retire with the dead, taking its
//! standing policy with it. The belt closes the class by making
//! the DEATH PROOF the one retirement law: a root retires only
//! when a complete census walk proves its directory GONE — the
//! cgroup object itself destroyed, nothing can ever join it or
//! deliver from it again. A STANDING directory keeps the policy
//! whatever its state — the alive-unresolvable root (its
//! processes live, namespaced out of the walk's view), the
//! pre-provisioned bed (a limit armed before its service spawns —
//! the supermassive fleet's own shape), the kept scope directory:
//! enforcement is preserved over bookkeeping, the estate's
//! fail-open posture completed. The first cut of this belt
//! (075551e) also retired memberless standing directories on a
//! cgroup.events read — the second cut retracts that lane: an
//! empty-but-kept cgroup is a policy the owner armed on purpose,
//! and the kernel destroying the directory (systemd's scope
//! cleanup, the container exit) is the only death the sweep can
//! prove. Fail-closed unchanged: a census that cannot conclude
//! holds every candidate for the next visit (the manual `recover`
//! scan keeps its lane).
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

use super::Limiter;
use super::rate_ring::{RateRingRaw, ring_series};
use super::types::Direction;

/// What the ring lens proved about one candidate root, one
/// direction (NIGHT-hunt-43, pure so the decision core below is
/// unit-pinned): the belt's own three-state verdict.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum RingProof {
    /// The direction's read succeeded and the root's ring carries
    /// at least one live window stamp — kernel-side delivery inside
    /// the horizon. Life, against the retirement.
    Traffic,
    /// The direction proved quiet: either the row exists with no
    /// live stamp (the full horizon delivered nothing) or NO row
    /// exists at all — and the ring is created lazily, at the
    /// first ALLOWED packet (enforce_helpers' get_ring_ptr), so an
    /// absent row is the never-delivered verdict, not an unknown:
    /// a block lane's rate-0 direction books nothing by contract,
    /// a one-way stream books nothing on its quiet leg, and a
    /// root that never talked books nothing at all. Silence,
    /// proven either way.
    Silent,
    /// The direction's lens is absent (a stale pin epoch — the
    /// map could not be read at all): silence is unproven, and
    /// retirement is vetoed (fail-closed for reclamation, the
    /// posture every sweep in the family owns) — UNLESS the
    /// cgroupfs census proves the root's directory itself is
    /// gone, the one verdict stronger than silence (death needs
    /// no silence read; see the decision core's `fs_gone` leg,
    /// night-audit-8's one retirement law).
    Unknown,
}

/// The zombie decision core (NIGHT-hunt-43, pure so it is
/// unit-pinned; the belt re-cut by night-audit-8): from one policy
/// root's evidence — the identity verdict, the ring proof per
/// direction it holds a policy in, and the cgroupfs death proof —
/// the retirement verdict. `None` per direction means the root
/// holds no policy leg there, so the lens has nothing to prove
/// about it (a stray row in that direction is census residue, the
/// census sweep's own subject, not this root's life signal).
///
/// A root retires only when no identity entry stands AND the
/// cgroupfs census PROVED the root's directory gone from a
/// complete walk — the one retirement law (night-audit-8's belt):
/// a standing directory keeps the policy whatever its state, so
/// the alive-unresolvable root and the pre-provisioned bed keep
/// their enforcement, and death subsumes the silence question
/// (nothing can deliver from a destroyed cgroup — Silent legs and
/// the absent lens's Unknown legs alike pass under it). Traffic
/// vetoes unconditionally — pre-death residue at worst, the root
/// waits a visit even when its directory is already gone.
fn zombie(identity_hit: bool, dl: Option<RingProof>, ul: Option<RingProof>, fs_gone: bool) -> bool {
    if identity_hit {
        return false;
    }
    // The belt (night-audit-8): the death proof is the one
    // retirement law. No census, an inconclusive walk, or a
    // standing directory — the policy stands (fail-closed for
    // reclamation, enforcement preserved over bookkeeping).
    if !fs_gone {
        return false;
    }
    match (dl, ul) {
        // A root no direction polices is not this sweep's subject
        // at all (the walk only names roots the policy maps carry;
        // the core stays defensive — no leg, no retirement).
        (None, None) => false,
        // Death subsumes the silence read: a Silent leg proved the
        // quiet, an Unknown leg could not — but nothing can ever
        // deliver from a destroyed cgroup either way. Only Traffic
        // (pre-death residue) keeps the root waiting a visit.
        _ => [dl, ul]
            .into_iter()
            .flatten()
            .all(|p| p != RingProof::Traffic),
    }
}

/// Verbose trace line for the zombie sweep (NIGHT-hunt-43): pure
/// formatting so the wording is unit-pinned beside its siblings.
/// The evidence clause names which proof retired the rows — under
/// night-audit-8's belt every retirement carries the cgroupfs
/// death proof, and the clause separates the rows whose lenses
/// also READ their silence from the rows only the death proof
/// could reach (the absent lens's own lane — the honest surface:
/// a retirement never reads as a silence the visit never
/// collected).
fn zombie_sweep_trace_line(retired: usize, state_reclaimed: usize, fs_proven: usize) -> String {
    let silence_read = retired.saturating_sub(fs_proven);
    let evidence = match (silence_read, fs_proven) {
        (_, 0) => "no ring traffic for the horizon and the cgroupfs death proof",
        (0, _) => {
            "the cgroupfs death proof alone — the directory gone from a \
             complete walk (the absent lens's own lane)"
        }
        _ => {
            "no ring traffic for the horizon and the cgroupfs death proof \
             (the directory gone from a complete walk)"
        }
    };
    format!(
        "[limiter] zombie sweep: retired {retired} dead-cgroup polic{} — \
         no identity entry, {evidence}; {state_reclaimed} state {} \
         returned to the census budget",
        if retired == 1 { "y" } else { "ies" },
        if state_reclaimed == 1 {
            "entry"
        } else {
            "entries"
        },
    )
}

/// The belt's hold line (night-audit-8, verbose only): a root the
/// two-signal walk named but the death proof kept — the diagnosis
/// the hunt-43 audit promised would be "one grep away" the day a
/// report arrived, printed by the very visit that held it.
fn zombie_sweep_held_line(held: usize) -> String {
    format!(
        "[limiter] zombie sweep: {held} candidate{} held — the cgroup's directory \
         still stands, or the census could not conclude (fail-closed; \
         the policy stands)",
        if held == 1 { "" } else { "s" },
    )
}

/// The per-direction ring census a sweep needs: the roots whose
/// rows carry a live stamp (traffic). `None` in, `None` out: an
/// absent lens proves nothing about any root in that direction.
fn ring_census(rows: Option<&[(u32, RateRingRaw)]>, now: u64) -> Option<HashSet<u32>> {
    let rows = rows?;
    let mut traffic = HashSet::new();
    for (root, raw) in rows {
        if ring_series(raw, now).live > 0 {
            traffic.insert(*root);
        }
    }
    Some(traffic)
}

/// One root's proof from a direction's census (the three-state
/// verdict above; a `None` census is the absent lens — the only
/// `Unknown` left, since an absent ROW is the lazy-creation law's
/// own never-delivered verdict).
fn ring_proof(census: Option<&HashSet<u32>>, root: u32) -> RingProof {
    match census {
        None => RingProof::Unknown,
        Some(traffic) => {
            if traffic.contains(&root) {
                RingProof::Traffic
            } else {
                RingProof::Silent
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
    /// whole sweep down; an absent ring lens vetoes every root in
    /// that direction unless the cgroupfs census proves the root's
    /// directory gone (the death proof, the module header's rescue
    /// — death is a stronger verdict than the silence the lens
    /// could not read); a failed delete warns and the root waits
    /// for the next visit. Retirement is the full recover shape
    /// per root: group ids captured read-before-delete, both
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

        // Evidence pass (night-audit-8): per root the identity and
        // ring proofs, collected BEFORE any cgroupfs walk — the
        // census below is built only when a root could reach
        // retirement (its legs carry no traffic veto and identity
        // misses), so the healthy host pays nothing and the
        // retiring visit pays one bounded walk, the same cost law
        // the lazy identity load above owns. Sorted for
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
        let proofs: Vec<(u32, bool, Option<RingProof>, Option<RingProof>)> = roots
            .iter()
            .map(|&id| {
                let has_dl = dl.iter().any(|(k, _)| *k == id);
                let has_ul = ul.iter().any(|(k, _)| *k == id);
                (
                    id,
                    self.identity().get(id).is_some(),
                    has_dl.then(|| ring_proof(dl_census.as_ref(), id)),
                    has_ul.then(|| ring_proof(ul_census.as_ref(), id)),
                )
            })
            .collect();

        // The census need (night-audit-8): a root whose retirement
        // the belt must prove (it passed the identity miss and
        // carries no Traffic leg — the death proof is the one
        // retirement law, and every such candidate asks for the
        // walk). A root carrying Traffic in any policed direction
        // can never retire — it never asks for the walk; the
        // healthy host with no candidates pays nothing.
        let needs_census = proofs.iter().any(|(_, hit, dl, ul)| {
            if *hit {
                return false;
            }
            let mut any_leg = false;
            for p in [*dl, *ul].into_iter().flatten() {
                any_leg = true;
                if p == RingProof::Traffic {
                    return false;
                }
            }
            any_leg
        });
        // The cgroupfs census, the belt's one evidence: built ONLY
        // when a candidate asks for it, complete-or-nothing. A
        // census that could not conclude reads as None, every
        // root's death proof stays false, and the veto stands —
        // fail-closed, the walk's own contract.
        let fs_census = if needs_census {
            crate::ebpf::identity::pathwalk::cgroupfs_id_census()
        } else {
            None
        };

        let mut retired = 0usize;
        let mut state_reclaimed = 0usize;
        let mut fs_proven = 0usize;
        let mut belt_held = 0usize;
        let mut captured_groups: Vec<u32> = Vec::new();
        for (id, identity_hit, dl_proof, ul_proof) in proofs {
            // The death-proof bit: true only when the census
            // COMPLETED and the root's directory is absent from it
            // — kernel-proven gone. A root the census still names
            // (alive, memberless, or an id a recycled directory
            // inherited), or a census that could not conclude,
            // keeps the bit false and the policy stands.
            let fs_gone = fs_census.as_ref().is_some_and(|set| !set.contains(&id));
            if !zombie(identity_hit, dl_proof, ul_proof, fs_gone) {
                // The belt's own hold (verbose-diagnosable): a root
                // the ring-and-identity legs passed but the death
                // proof kept — the counterfactual pins the leg that
                // held it (an Unknown RING leg is the absent
                // lens's wait, not the belt's; a Traffic leg was
                // never a candidate).
                if zombie(identity_hit, dl_proof, ul_proof, true) {
                    belt_held += 1;
                }
                continue;
            }
            // A retirement with an absent-lens leg rode the death
            // proof ALONE to its verdict — the trace's evidence
            // clause must never call it a silence the lens never
            // read.
            if [dl_proof, ul_proof]
                .into_iter()
                .flatten()
                .any(|p| p == RingProof::Unknown)
            {
                fs_proven += 1;
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
            eprintln_safe!(
                "{}",
                zombie_sweep_trace_line(retired, state_reclaimed, fs_proven)
            );
        }
        if self.verbose && belt_held > 0 {
            eprintln_safe!("{}", zombie_sweep_held_line(belt_held));
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
