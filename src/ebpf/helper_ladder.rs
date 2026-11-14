// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The per-helper capability ladder (night-frontier-Z5) — the eBPF
//! facts the two embedded objects consume, one rung each, with the
//! kernel release that introduced it.
//!
//! The floor law (kernel_floor.rs) is a single gate: at or above
//! 5.15.0 the attach proceeds, below it everything is refused. The
//! ladder is the accounting BENEATH that gate: every helper the
//! objects call, and every ISA/syscall shape they are built against,
//! sits on a rung at (or below) the floor — so the floor's guarantee
//! is not folklore but an itemized list a doctor can render and a
//! release can attest. On any kernel the floor admits, every rung
//! here is met BY CONSTRUCTION; the day a future helper is adopted
//! whose rung sits ABOVE the floor, its row carries the graceful
//! degradation plan and the gate test below refuses to let it land
//! without one — per-feature degradation, named at adoption time,
//! never a whole-attach cliff discovered in the field.
//!
//! Versions are the canonical introduction releases (the iovisor BCC
//! kernel-versions table, each row backed by the introducing commit;
//! bpf_link via kernelnewbies' 5.7 notes, BPF_ATOMIC via the
//! "Atomics for eBPF" 5.12 series). The rows are ordered
//! since-ascending — the ladder climbs from 4.1 to 5.12, and the
//! 5.15 floor stands one rung above the top.
//!
//! This module is deliberately NOT gated behind the `ebpf` feature,
//! exactly like kernel_floor.rs: the half-life doctor rides the same
//! pure table (no syscall, no privilege — a version-string parse is
//! the whole probe), so one law renders in every build shape.

use crate::ebpf::kernel_floor::parse_kernel_release;

/// A rung's class: a BPF helper function the objects call, or a
/// shape fact — an ISA or syscall surface the objects are BUILT
/// against (not a call, but its absence fails the load all the same).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RungKind {
    /// A BPF helper function call (bpf_ktime_get_ns and friends).
    Helper,
    /// An ISA or syscall surface (the BPF_ATOMIC instruction class,
    /// the BPF_LINK_CREATE command).
    Shape,
}

/// One rung of the ladder: the capability's exact name, the kernel
/// release that introduced it, what rides it, and — only for a
/// future rung ABOVE the floor — the named graceful degradation the
/// engine takes when the kernel misses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperRung {
    /// The exact identifier as the tree speaks it: the helper's
    /// kernel name for [`RungKind::Helper`] rows, the tree's own
    /// shape-fact spelling (bpf_link, bpf_atomic_64) for
    /// [`RungKind::Shape`] rows.
    pub name: &'static str,
    /// The (major, minor) release that introduced the capability.
    pub since: (u32, u32),
    /// Helper call, or built-against shape.
    pub kind: RungKind,
    /// Which lanes consume the rung (the review prose, one line).
    pub riders: &'static str,
    /// The graceful degradation plan for a rung above the floor.
    /// Every current row sits at or below the 5.15.0 floor (the
    /// floor GUARANTEES it), so every current row is None; the gate
    /// test below holds the law: a row above the floor cannot land
    /// without naming its degradation here.
    pub above_floor_plan: Option<&'static str>,
}

/// The ladder itself (night-frontier-Z5): every eBPF capability the
/// two embedded objects consume, since-ascending. Ten rungs — eight
/// helper calls and two shape facts — and the top rung (the
/// BPF_ATOMIC ISA, 5.12) sits below the 5.15.0 floor, which is the
/// whole guarantee: the floor law refuses every kernel that could
/// miss any rung here.
pub const LADDER: &[HelperRung] = &[
    HelperRung {
        name: "bpf_ktime_get_ns",
        since: (4, 1),
        kind: RungKind::Helper,
        riders: "the enforcement core's deadline math, the rate ring's pacing windows, \
                 the limiter's clock",
        above_floor_plan: None,
    },
    HelperRung {
        name: "bpf_skb_load_bytes",
        since: (4, 5),
        kind: RungKind::Helper,
        riders: "the QUIC flow's header reads",
        above_floor_plan: None,
    },
    HelperRung {
        name: "bpf_get_socket_cookie",
        since: (4, 12),
        kind: RungKind::Helper,
        riders: "the per-socket attribution keys the RECWN and QUIC hint lanes key by",
        above_floor_plan: None,
    },
    HelperRung {
        name: "bpf_setsockopt",
        since: (4, 13),
        kind: RungKind::Helper,
        riders: "the shaping lanes' pacing and congestion writes (sock_ops)",
        above_floor_plan: None,
    },
    HelperRung {
        name: "bpf_skb_cgroup_id",
        since: (4, 18),
        kind: RungKind::Helper,
        riders: "the observer's cgroup attribution",
        above_floor_plan: None,
    },
    HelperRung {
        name: "bpf_skb_ancestor_cgroup_id",
        since: (4, 19),
        kind: RungKind::Helper,
        riders: "the MMSPA ancestor walk",
        above_floor_plan: None,
    },
    HelperRung {
        name: "bpf_skb_ecn_set_ce",
        since: (5, 1),
        kind: RungKind::Helper,
        riders: "the ECN-first lane's CE marking",
        above_floor_plan: None,
    },
    HelperRung {
        name: "bpf_sk_storage_get",
        since: (5, 2),
        kind: RungKind::Helper,
        riders: "the RECWN and pace lanes' per-socket state",
        above_floor_plan: None,
    },
    HelperRung {
        name: "bpf_link",
        since: (5, 7),
        kind: RungKind::Shape,
        riders: "the observer's and limiter's cgroup attach (BPF_LINK_CREATE)",
        above_floor_plan: None,
    },
    HelperRung {
        name: "bpf_atomic_64",
        since: (5, 12),
        kind: RungKind::Shape,
        riders: "the enforcement core's debt and bucket math (the BPF_ATOMIC ISA)",
        above_floor_plan: None,
    },
];

/// One rung's verdict against a parsed release (the pure probe —
/// no syscall, the same honesty class as the shape facts it feeds):
/// the kernel offers it, the kernel predates it, or the release
/// cannot be parsed and the probe refuses to guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RungVerdict {
    /// The running kernel meets the rung.
    Met,
    /// The kernel predates the rung's introduction. On today's table
    /// this can only happen BELOW the floor (where the attach is
    /// refused wholesale); a future above-floor rung carries its
    /// [`HelperRung::above_floor_plan`] for exactly this verdict.
    Missed,
    /// The release string cannot be parsed — the probe cannot
    /// verify, so it does not (the floor law's own honesty).
    Unprobeable,
}

/// Walk the ladder against one release string, in table order
/// (since-ascending — the doctor's render order is the ladder's own
/// order, never a map iteration). Pure: a parse and a compare per
/// rung, no syscall, no privilege.
#[must_use]
pub fn rung_verdicts(release: &str) -> Vec<(&'static str, RungVerdict)> {
    let version = parse_kernel_release(release);
    LADDER
        .iter()
        .map(|rung| {
            let verdict = match version {
                Some(v) if v >= rung.since => RungVerdict::Met,
                Some(_) => RungVerdict::Missed,
                None => RungVerdict::Unprobeable,
            };
            (rung.name, verdict)
        })
        .collect()
}

/// The ladder's one-glance summary (the doctor's human line and the
/// JSON field ride this): how many rungs the release meets, and the
/// missed rungs' names in table order. On an unparsable release the
/// count is honestly zero — the same all-false shape the shape
/// facts have always claimed (the probe cannot verify, so it does
/// not).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LadderSummary {
    /// The ladder's total rung count (the table's length).
    pub rungs: usize,
    /// How many rungs the release meets.
    pub met: usize,
    /// The missed rungs' names, table order. Empty on a full ladder.
    pub missed: Vec<&'static str>,
}

/// Summarize the ladder for one release string (pure; see
/// [`rung_verdicts`]).
#[must_use]
pub fn ladder_summary(release: &str) -> LadderSummary {
    let verdicts = rung_verdicts(release);
    let missed: Vec<&'static str> = verdicts
        .iter()
        .filter(|(_, v)| *v == RungVerdict::Missed)
        .map(|(name, _)| *name)
        .collect();
    // Only a MET verdict counts as met — an unparsable release is
    // unprobeable, never silently promoted to "met" (the honesty
    // law: the probe cannot verify, so it does not).
    let met = verdicts
        .iter()
        .filter(|(_, v)| *v == RungVerdict::Met)
        .count();
    LadderSummary {
        rungs: LADDER.len(),
        met,
        missed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::kernel_floor::KERNEL_FLOOR;

    /// The gate (night-frontier-Z5's law): a rung ABOVE the floor
    /// cannot land without a named graceful-degradation plan. Today
    /// every row sits at or below the floor, so this passes
    /// vacuously — the day a future helper's row carries a since
    /// above 5.15, this test demands the plan in the same commit.
    #[test]
    fn a_rung_above_the_floor_carries_a_named_degradation() {
        for rung in LADDER {
            if rung.since > KERNEL_FLOOR {
                assert!(
                    rung.above_floor_plan.is_some(),
                    "rung {} (introduced {}.{} — above the floor) must name its \
                     graceful degradation plan",
                    rung.name,
                    rung.since.0,
                    rung.since.1
                );
            }
        }
    }

    /// The Z5 coverage pin: every rung the table carries today is at
    /// or below the 5.15.0 floor — the floor law's guarantee, made
    /// itemized. When a future helper exits the 5.15 set, this test
    /// changes WITH the row (and the gate above demands its plan) —
    /// the forcing function is the review, not a hope.
    #[test]
    fn every_rung_is_guaranteed_by_the_floor_today() {
        for rung in LADDER {
            assert!(
                rung.since <= KERNEL_FLOOR,
                "rung {} ({}.{}) sits above the floor — the gate test demands a \
                 degradation plan, and the floor guarantee no longer covers it",
                rung.name,
                rung.since.0,
                rung.since.1
            );
        }
    }

    /// The ladder names the exact helpers the embedded objects call
    /// (the survey's eight) — the accounting cannot drift from the
    /// call sites without this pin failing at the next table edit.
    #[test]
    fn the_ladder_names_the_helpers_the_objects_call() {
        let names: Vec<&str> = LADDER.iter().map(|r| r.name).collect();
        for helper in [
            "bpf_ktime_get_ns",
            "bpf_skb_load_bytes",
            "bpf_get_socket_cookie",
            "bpf_setsockopt",
            "bpf_skb_cgroup_id",
            "bpf_skb_ancestor_cgroup_id",
            "bpf_skb_ecn_set_ce",
            "bpf_sk_storage_get",
        ] {
            assert!(
                names.contains(&helper),
                "the objects call {helper} but the ladder does not carry it"
            );
        }
        assert_eq!(LADDER.len(), 10, "eight helpers plus two shape rungs");
    }

    /// The ladder climbs since-ascending — the render order is the
    /// table's own order, and a future editor breaking the sort is
    /// caught here, not by the doctor's eye.
    #[test]
    fn the_ladder_climbs_since_ascending() {
        for pair in LADDER.windows(2) {
            assert!(
                pair[0].since <= pair[1].since,
                "the ladder must ascend: {} ({}.{}) then {} ({}.{})",
                pair[0].name,
                pair[0].since.0,
                pair[0].since.1,
                pair[1].name,
                pair[1].since.0,
                pair[1].since.1
            );
        }
    }

    /// The verdicts ride the parsed release, pinned release by
    /// release: full coverage at the floor and above, the exact
    /// missed names below it, the honest all-unprobeable on garbage.
    #[test]
    fn rung_verdicts_ride_the_parsed_release() {
        let met_all = |release: &str| {
            rung_verdicts(release)
                .iter()
                .all(|(_, v)| *v == RungVerdict::Met)
        };
        // At the floor and above: every rung met, by construction.
        for release in ["5.15.0-52-generic", "6.8.0-45", "6.12.27-2-cachyos"] {
            assert!(met_all(release), "{release} must meet every rung");
        }
        // 5.11: only the BPF_ATOMIC ISA predates it.
        let v = ladder_summary("5.11.0");
        assert_eq!(v.met, 9);
        assert_eq!(v.missed, vec!["bpf_atomic_64"]);
        // 5.4: above the sk_storage rung (5.2), below the link and
        // atomic rungs — exactly two miss.
        let v = ladder_summary("5.4.0-42-generic");
        assert_eq!(v.met, 8);
        assert_eq!(v.missed, vec!["bpf_link", "bpf_atomic_64"]);
        // 4.9: the five skb-era rungs miss (ktime and load_bytes hold).
        let v = ladder_summary("4.9.0");
        assert_eq!(v.met, 2);
        // An unparsable release honestly claims nothing — the same
        // all-false shape the shape facts have always carried.
        let v = ladder_summary("unknown");
        assert_eq!(v.met, 0);
        assert_eq!(v.missed.len(), 0);
        assert!(
            rung_verdicts("unknown")
                .iter()
                .all(|(_, q)| *q == RungVerdict::Unprobeable)
        );
        // The summary's rung count is the table's length, always.
        let v = ladder_summary("6.8.0-45");
        assert_eq!(v.rungs, 10);
        assert_eq!(v.met, 10);
        assert!(v.missed.is_empty());
    }

    /// The shape-fact rungs the host-caps derivation reads by name
    /// must exist — a rename of either side fails here before the
    /// doctor can render a silently-false verdict. Two of the three
    /// are Shape rungs (ISA/syscall surfaces); the ECN helper is a
    /// Helper row the derivation also reads by name.
    #[test]
    fn the_shape_facts_derivation_names_resolve() {
        for name in ["bpf_link", "bpf_atomic_64", "bpf_skb_ecn_set_ce"] {
            let row = LADDER.iter().find(|r| r.name == name);
            assert!(row.is_some(), "the shape-fact rung {name} must exist");
        }
        assert_eq!(
            LADDER
                .iter()
                .find(|r| r.name == "bpf_link")
                .expect("checked")
                .kind,
            RungKind::Shape
        );
        assert_eq!(
            LADDER
                .iter()
                .find(|r| r.name == "bpf_atomic_64")
                .expect("checked")
                .kind,
            RungKind::Shape
        );
        assert_eq!(
            LADDER
                .iter()
                .find(|r| r.name == "bpf_skb_ecn_set_ce")
                .expect("checked")
                .kind,
            RungKind::Helper
        );
    }

    /// The doctor's summary numbers are consistent with the verdict
    /// walk on every input shape (met + missed == rungs; an
    /// unparsable release spends the whole count in neither bucket
    /// — it is unprobeable, not missed).
    #[test]
    fn the_summary_buckets_stay_consistent() {
        for release in ["6.8.0-45", "5.15.0", "5.4.0-42-generic", "unknown", ""] {
            let v = ladder_summary(release);
            let unprobeable = rung_verdicts(release)
                .iter()
                .filter(|(_, q)| *q == RungVerdict::Unprobeable)
                .count();
            assert_eq!(v.rungs, LADDER.len());
            assert_eq!(
                v.met + v.missed.len() + unprobeable,
                LADDER.len(),
                "{release}: buckets must cover the ladder"
            );
        }
    }
}
