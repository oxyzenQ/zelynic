// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Target-filter pins (NIGHT-boost-1 lineage; the watched-set
//! contracts of NIGHT-engrave-4 and NIGHT-engrave-6): name tokens
//! expand to every matching cgroup, numeric tokens are IDs verbatim,
//! unmatched names surface as note lines — and the filtered frame
//! tells its OWN story: the board, the census, and the footer speed
//! pair all describe the watched set, never the whole machine. Split
//! from eagle_tests.rs at NIGHT-engrave-6 when the speed-pair pins
//! pushed that file past the owner's LOC cap (cosmostrix Pattern C,
//! #[path]-wired from src/ebpf/render/eagle.rs; `super::` reaches
//! the eagle renderer's own private resolve_targets).

use super::resolve_targets;
use crate::ebpf::identity::{IdentityMap, ProcessIdentity};
use crate::ebpf::limiter::Target;
use crate::ebpf::loader::{CgroupDelta, CounterSummary};
use crate::ebpf::render::eagle::render_eagle_eyes_at;
use crate::ebpf::render::BaselineLane;
use crate::ebpf::render::{FrameGeometry, SessionState};
use std::time::Duration;

fn identity_with(comms: &[(&str, u32)]) -> IdentityMap {
    let mut identity = IdentityMap::new();
    for (comm, cg) in comms {
        identity.insert(ProcessIdentity {
            cgroup_id: *cg,
            uid: 1000,
            comm: (*comm).to_string(),
        });
    }
    identity
}

/// The 80x24 classic terminal (the piped-fallback probe).
fn classic() -> FrameGeometry {
    FrameGeometry {
        width: 80,
        height: 24,
    }
}

/// Target autodetect (NIGHT-boost-1): a name token expands to
/// every matching cgroup; a numeric token is a cgroup ID
/// verbatim — bare or `cg:`-prefixed (the boost-37 round-trip);
/// unmatched names surface as note lines.
///
/// The id SET is compared sorted: `identity.all()` walks a HashMap,
/// so expansion order is per-process random (the renderer re-sorts
/// rows by consumption, so nothing observable depends on it) — the
/// CI catch on 5fa75d1 pinned exactly this; an order-sensitive
/// assert here is flaky by construction.
#[test]
fn name_targets_expand_and_misses_note() {
    let identity = identity_with(&[("brave", 7001), ("brave", 7002), ("firefox", 7003)]);
    let (ids, unresolved) = resolve_targets(
        &[
            Target::parse("brave"),
            Target::parse("73386"),
            Target::parse("cg:7003"),
            Target::parse("chromium"),
        ],
        &identity,
    );
    let mut got = ids.clone();
    got.sort_unstable();
    assert_eq!(
        got,
        vec![7001, 7002, 7003, 73386],
        "name expands + numeric verbatim + cg: prefix round-trips (NIGHT-boost-37)"
    );
    assert_eq!(unresolved, vec!["chromium".to_string()]);

    // The note renders in the frame, and the ranked table filters.
    let summary = CounterSummary {
        total_packets: 5,
        total_bytes: 100,
        total_ingress_packets: 50,
        total_ingress_bytes: 5_000,
        cgroups: vec![
            CgroupDelta {
                cgroup_id: 7001,
                packets: 1,
                bytes: 100,
                total_bytes: 100,
                ingress_packets: 10,
                ingress_bytes: 5_000,
                ingress_total_bytes: 5_000,
            },
            CgroupDelta {
                cgroup_id: 7004,
                packets: 4,
                bytes: 0,
                total_bytes: 0,
                ingress_packets: 40,
                ingress_bytes: 0,
                ingress_total_bytes: 0,
            },
        ],
    };
    let mut lines = Vec::new();
    render_eagle_eyes_at(
        &mut lines,
        &summary,
        &[Target::parse("brave"), Target::parse("chromium")],
        &identity,
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &mut SessionState::new(),
        &BaselineLane::new(),
        Duration::from_secs(70),
        classic(),
    );
    let joined = lines.join("\n");
    assert!(
        joined.contains("no app named 'chromium' — see 'zelynic list-apps'"),
        "unresolved note renders: {joined}"
    );
    assert!(
        joined.contains("cg:7001"),
        "matched target renders: {joined}"
    );
    assert!(
        !joined.contains("cg:7004"),
        "unwatched cgroup is filtered out: {joined}"
    );
    assert!(
        joined.contains("2 targets"),
        "the title names the watched breadth: {joined}"
    );
    assert!(
    joined.contains("11 packets + 1 cgroups"),
    "engrave-4: filtered frames carry their OWN census — the filtered board's session packets (1 ul + 10 dl) and its one cgroup: {joined}"
);
    // NIGHT-engrave-6: the speed pair carries the same filtered
    // scope — MAX is the watched set's peak (cg 7001's own deltas,
    // 5000 dl / 100 ul at interval 1s; cg 7004's traffic is invisible
    // to it exactly as it is to the board), AVG divides the filtered
    // session legs by the 70s uptime. One paragraph, one story.
    assert!(
        joined.contains("total max dl | ul = 5.0 KB/s | 100 B/s"),
        "the filtered frame's peaks are the watched set's own: {joined}"
    );
    assert!(
        joined.contains("total avg dl | ul = 71 B/s | 1 B/s"),
        "the filtered frame's avg divides the watched legs by the uptime: {joined}"
    );
    assert!(
        joined.contains("top consumer is brave"),
        "engrave-4: the consumer headline names the filtered board's champion: {joined}"
    );
}

/// NIGHT-dinner-18 (the duplicate-token false-miss): a repeated name
/// token ('brave/brave') must stay a HIT on both copies. The old
/// combined condition — comm match AND id not already collected —
/// flipped the second copy to a miss (every matching cgroup was
/// already in `ids`, so `matched` never turned true), and the frame
/// rendered "no app named 'brave'" under a live brave.
#[test]
fn duplicate_name_token_is_not_a_false_miss() {
    let identity = identity_with(&[("brave", 7001), ("brave", 7002)]);
    let (ids, unresolved) =
        resolve_targets(&[Target::parse("brave"), Target::parse("brave")], &identity);
    let mut got = ids.clone();
    got.sort_unstable();
    assert_eq!(got, vec![7001, 7002], "both copies match, ids dedup");
    assert!(
        unresolved.is_empty(),
        "a repeated live name must never surface as unresolved, got: {unresolved:?}"
    );
}

/// NIGHT-hunt-Z1 (the monitor residue close): a board row with no
/// live identity entry and no traffic in the current window is a
/// dead transient — the enforcement probe's sacrificial cgroup
/// (folded into the leaderboard during the 3s window it lived,
/// torn down at its close) and every churned systemd scope — and it
/// never renders: no bare `cg:NNNN` dump row, no census seat, no
/// footer-count inflation. The two stay-shapes are pinned beside
/// it: an ACTIVE unnamed cgroup (traffic in this window, identity
/// not yet refreshed) keeps its row, and a LIVE named cgroup keeps
/// its row regardless of window quiet (the idle-stays memory
/// contract, untouched).
#[test]
fn dead_transients_leave_the_board_but_active_unnamed_rows_stay() {
    let identity = identity_with(&[("brave", 7001)]);
    // The session's history: all three cgroups moved once, so all
    // three folded into the board (7003's window is the probe's 3s
    // — it died right after).
    let history = CounterSummary {
        total_packets: 3,
        total_bytes: 900,
        total_ingress_packets: 0,
        total_ingress_bytes: 0,
        cgroups: vec![
            CgroupDelta {
                cgroup_id: 7001,
                packets: 1,
                bytes: 300,
                total_bytes: 300,
                ingress_packets: 0,
                ingress_bytes: 0,
                ingress_total_bytes: 0,
            },
            CgroupDelta {
                cgroup_id: 7002,
                packets: 1,
                bytes: 300,
                total_bytes: 300,
                ingress_packets: 0,
                ingress_bytes: 0,
                ingress_total_bytes: 0,
            },
            CgroupDelta {
                cgroup_id: 7003,
                packets: 1,
                bytes: 300,
                total_bytes: 300,
                ingress_packets: 0,
                ingress_bytes: 0,
                ingress_total_bytes: 0,
            },
        ],
    };
    let mut session = SessionState::new();
    session.absorb(&history);
    // The current window: 7001 (live, named) and 7002 (unnamed but
    // still moving) have traffic; 7003 is dead and silent — the
    // probe's leftover shape exactly.
    let now = CounterSummary {
        total_packets: 2,
        total_bytes: 200,
        total_ingress_packets: 0,
        total_ingress_bytes: 0,
        cgroups: vec![
            CgroupDelta {
                cgroup_id: 7001,
                packets: 1,
                bytes: 100,
                total_bytes: 400,
                ingress_packets: 0,
                ingress_bytes: 0,
                ingress_total_bytes: 0,
            },
            CgroupDelta {
                cgroup_id: 7002,
                packets: 1,
                bytes: 100,
                total_bytes: 400,
                ingress_packets: 0,
                ingress_bytes: 0,
                ingress_total_bytes: 0,
            },
        ],
    };
    let mut lines = Vec::new();
    render_eagle_eyes_at(
        &mut lines,
        &now,
        &[],
        &identity,
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &mut session,
        &BaselineLane::new(),
        Duration::from_secs(70),
        classic(),
    );
    let joined = lines.join("\n");
    assert!(
        joined.contains("brave"),
        "the live named row stays (the idle-stays memory contract): {joined}"
    );
    assert!(
        joined.contains("cg:7002"),
        "an active unnamed cgroup stays while it moves: {joined}"
    );
    assert!(
        !joined.contains("cg:7003"),
        "the dead transient is retired from the frame — no `cg:NNNN` dump: {joined}"
    );
    assert!(
        joined.contains("+ 2 cgroups"),
        "the census counts the filtered board, not the residue: {joined}"
    );
}
