// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Footer saturation pins (NIGHT-boost-16 / safety-security-1, the
//! accumulate-explosion audit): a frame whose deltas and session
//! accumulator sit at u64::MAX must render WITHOUT panic in a debug
//! build, every census figure reading its honest ceiling. Split from
//! footer_tests.rs at NIGHT-engrave-6 when the speed-pair pins
//! pushed that file past the owner's LOC cap — the safety contract
//! is its own file, the same one-file-per-contract split the tier
//! pins took at engrave-4 (cosmostrix Pattern C, #[path]-wired from
//! src/ebpf/render/footer.rs).

use crate::ebpf::identity::{IdentityMap, ProcessIdentity};
use crate::ebpf::loader::{CgroupDelta, CounterSummary};
use crate::ebpf::render::eagle::render_eagle_eyes_at;
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

/// NIGHT-boost-16 / safety-security-1: the accumulate-explosion
/// render pin. A frame whose deltas and session accumulator sit at
/// u64::MAX must render WITHOUT panic in a debug build (the footer
/// sums and the ranking key used to be plain `+` and `sum` — debug
/// panicked, release wrapped to a tiny grand total) and the TOTAL
/// row must carry the honest saturation figure (18.4 EB), not a
/// wrapped number. NIGHT-engrave-4: the census line and the consumer
/// headline ride the same saturated frame without panic — the packet
/// counter saturates at its own honest ceiling.
#[test]
fn saturated_session_renders_without_panic() {
    let identity = identity_with(&[("saturator", 9001)]);
    let summary = CounterSummary {
        total_packets: u64::MAX,
        total_bytes: u64::MAX,
        total_ingress_packets: u64::MAX,
        total_ingress_bytes: u64::MAX,
        cgroups: vec![CgroupDelta {
            cgroup_id: 9001,
            packets: u64::MAX,
            bytes: u64::MAX,
            total_bytes: u64::MAX,
            ingress_packets: u64::MAX,
            ingress_bytes: u64::MAX,
            ingress_total_bytes: u64::MAX,
        }],
    };
    let mut session = SessionState::new();
    // NIGHT-lts-5: the explicit absorb is GONE — render_eagle_eyes_at
    // folds the frame itself (eagle.rs), and the old double-absorb
    // was masked for years by the saturating add clamping the second
    // u64::MAX to the first. The u128 widening made the fold exact
    // and the doubling visible; one absorb, one truth.
    let mut lines = Vec::new();
    render_eagle_eyes_at(
        &mut lines,
        &summary,
        &[],
        &identity,
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &mut session,
        Duration::from_secs(70),
        classic(),
    );
    assert_eq!(lines.len(), 24, "the pin holds at saturation");
    let joined = lines.join("\n");
    // NIGHT-boost-22: the extended SI ladder answers in EB at the
    // ceiling — u64::MAX renders as "18.4 EB" (the old TB-terminal
    // formatter drew "18446744.1 TB", five digits, the ragged
    // column the promotion contract forbids everywhere else).
    assert!(
        joined.contains("18.4 EB"),
        "the saturated session total renders the u64 ceiling honestly: {joined}"
    );
    assert!(
        lines.iter().any(|l| l.contains("total usage internet in")),
        "the total row survives saturation"
    );
    // NIGHT-engrave-4: the census saturates at its own honest
    // ceiling — no panic, no wrap. NIGHT-engrave-7: the count rides
    // the SI compact ladder, so the u64 ceiling reads "18.4E" —
    // the same honest figure the byte ladder's "18.4 EB" carries,
    // one glance instead of twenty digits.
    assert!(
        joined.contains("18.4E packets + 1 cgroups"),
        "the saturated packet counter renders the compact ceiling: {joined}"
    );
    assert!(
        joined.contains("top consumer is saturator"),
        "the consumer headline rides the saturated frame: {joined}"
    );
    // NIGHT-engrave-6: the speed pair saturates honestly — the peak
    // deltas sit at u64::MAX, so the max line reads the SI ladder's
    // ceiling figure per direction; the avg line divides the
    // saturated session legs by the 70s uptime without panic (the
    // f64 divide saturates on the cast back, the boost-22 audit's
    // documented discipline). No wrap, no BLOCKED verdict, no ragged
    // five-digit tier.
    assert!(
        joined.contains("total max dl | ul = 18.4 EB/s | 18.4 EB/s"),
        "the saturated max renders the honest ceiling per direction: {joined}"
    );
    assert!(
        joined.contains("total avg dl | ul = 263.5 PB/s | 263.5 PB/s"),
        "the saturated avg divides the ceiling by the uptime without panic: {joined}"
    );
}
