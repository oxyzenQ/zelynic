// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the eagle-eyes --depth network-traffic focus
//! (NIGHT-private-research-3, the think-like-light-years-3 upgrade):
//! the window composition (kernel totals, per-endpoint attribution,
//! movers-first ranking), the section rendering (the [dl X | ul Y]
//! vocabulary the live view owns, the no-traffic verdict, the honest
//! not-measured note), and the cap contract the basic listing
//! carried. All fixture-driven, never the host — the composition is
//! pure over (deltas, census, cookie join), exactly what the handler
//! assembles after the observer's window closes.

use super::*;

use crate::ebpf::connections::{CgroupConnections, ProcessDetail, Proto, SocketInfo};
use crate::ebpf::loader::SocketBytes;

/// One delta row for fixtures (upload bytes, download bytes — the
/// closing poll's per-cgroup window book).
fn delta(cgroup_id: u32, bytes: u64, ingress_bytes: u64) -> CgroupDelta {
    CgroupDelta {
        cgroup_id,
        packets: 0,
        bytes,
        total_bytes: 0,
        ingress_packets: 0,
        ingress_bytes,
        ingress_total_bytes: 0,
    }
}

/// One displayable endpoint in the fixture census, optionally with
/// a cookie the join can resolve.
fn socket(remote: &str, cookie: Option<u64>) -> SocketInfo {
    SocketInfo {
        proto: Proto::Tcp,
        remote: remote.to_string(),
        state: "ESTABLISHED",
        queued: false,
        cookie,
    }
}

/// The fixture census: curl holds the two movers, cat-test holds the
/// quiet endpoint, and a LISTEN row rides along to pin the noise
/// gate.
fn census() -> ConnectionMap {
    let mut conns = ConnectionMap::new();
    conns.insert(
        1234,
        CgroupConnections {
            total_procs: 2,
            socket_holders: vec![
                ProcessDetail {
                    pid: 4242,
                    comm: "curl".to_string(),
                    sockets: vec![
                        socket("142.250.191.78:443", Some(1001)),
                        socket("93.184.216.34:443", Some(1002)),
                    ],
                },
                ProcessDetail {
                    pid: 1234,
                    comm: "cat-test".to_string(),
                    sockets: vec![
                        socket("10.0.0.9:22", Some(1003)),
                        SocketInfo {
                            proto: Proto::Tcp,
                            remote: "0.0.0.0:8080".to_string(),
                            state: "LISTEN",
                            queued: false,
                            cookie: None,
                        },
                    ],
                },
            ],
        },
    );
    conns
}

/// The cookie join fixture: cookie 1001 is the fat mover (10 MB dl),
/// 1002 a small one, 1003 silent (no entry — the honest absence).
fn join() -> std::collections::HashMap<u64, SocketBytes> {
    let mut bytes = std::collections::HashMap::new();
    bytes.insert(
        1001,
        SocketBytes {
            dl: 10_000_000,
            ul: 300_000,
        },
    );
    bytes.insert(
        1002,
        SocketBytes {
            dl: 20_000,
            ul: 40_000,
        },
    );
    bytes
}

/// The composition contract: the kernel's window totals ride the
/// focus value verbatim (dl from the ingress delta, ul from the
/// egress delta), the endpoint rows carry the joined bytes, the
/// movers rank first, the LISTEN noise row never renders, and the
/// cookie join rides the value for the JSON consumer.
#[test]
fn traffic_focus_composes_totals_attribution_and_ranking() {
    let conns = census();
    let focus = traffic_focus(
        1234,
        3,
        &[delta(1234, 300_000, 10_020_000)],
        Some(&conns),
        &join(),
    );

    assert_eq!(focus.window_secs, 3, "the window is the honest denominator");
    assert_eq!(focus.dl_bytes, 10_020_000, "dl rides the ingress delta");
    assert_eq!(focus.ul_bytes, 300_000, "ul rides the egress delta");
    assert!(focus.moved(), "10 MB of download is movement");

    // Movers first: 1001 (10.3 MB total) before 1002 (60 KB) before
    // the byteless 1003; the LISTEN row never joined the section.
    assert_eq!(
        focus.endpoints.len(),
        3,
        "the displayable set, not the raw census"
    );
    assert_eq!(focus.endpoints[0].remote, "142.250.191.78:443");
    assert_eq!(focus.endpoints[0].dl, Some(10_000_000));
    assert_eq!(focus.endpoints[0].ul, Some(300_000));
    assert_eq!(focus.endpoints[1].remote, "93.184.216.34:443");
    assert_eq!(focus.endpoints[2].remote, "10.0.0.9:22");
    assert_eq!(
        focus.endpoints[2].dl, None,
        "a silent socket renders no figures"
    );

    // The bytes table rides the value: the exact join the JSON
    // document's per-socket fields read.
    assert_eq!(
        focus.bytes.get(&1001),
        Some(&SocketBytes {
            dl: 10_000_000,
            ul: 300_000
        })
    );
    assert!(
        !focus.bytes.contains_key(&1003),
        "no entry = no fabricated zero"
    );
}

/// A quiet window is a measurement, not a failure: zero totals and a
/// zero delta row compose the no-traffic verdict the header renders.
#[test]
fn quiet_window_is_a_verdict_not_a_failure() {
    let conns = census();
    let focus = traffic_focus(
        1234,
        2,
        &[],
        Some(&conns),
        &std::collections::HashMap::new(),
    );
    assert!(!focus.moved(), "nothing booked in the window");
    let lines = traffic_section_lines(&focus);
    let text = lines.join("\n");
    assert!(
        text.contains("no traffic in the window"),
        "the honest quiet verdict, got: {text}"
    );
}

/// The section rendering: the header carries the window and the
/// kernel totals, the rows carry the live view's [dl X | ul Y]
/// vocabulary, byteless rows stay lean, and the mover outranks the
/// quiet endpoint.
#[test]
fn traffic_section_renders_the_window_and_ranked_rows() {
    let conns = census();
    let focus = traffic_focus(
        1234,
        5,
        &[delta(1234, 300_000, 10_020_000)],
        Some(&conns),
        &join(),
    );
    let lines = traffic_section_lines(&focus);
    let text = lines.join("\n");

    assert!(
        text.contains("network traffic (5s focus): dl 10.0 MB · ul 300.0 KB"),
        "the header names the window and both totals, got: {text}"
    );
    assert!(
        text.contains(
            "curl (4242) → 142.250.191.78:443 tcp ESTABLISHED [dl 10.0 MB | ul 300.0 KB]"
        ),
        "the mover's row carries the byte vocabulary, got: {text}"
    );
    assert!(
        text.contains("cat-test (1234) → 10.0.0.9:22 tcp ESTABLISHED"),
        "the byteless row renders, got: {text}"
    );
    assert!(
        !text.contains("10.0.0.9:22 tcp ESTABLISHED ["),
        "the byteless row stays lean (no figures suffix), got: {text}"
    );
    assert!(
        !text.contains("0.0.0.0:8080"),
        "LISTEN noise never enters the traffic section, got: {text}"
    );
    // Ranking: the mover's row lands above the quiet endpoint's.
    let mover = text.find("142.250.191.78").expect("the mover renders");
    let quiet = text
        .find("10.0.0.9:22")
        .expect("the quiet endpoint renders");
    assert!(mover < quiet, "movers rank first, got: {text}");
}

/// The not-measured note: an observer that could not attach leaves
/// the basic census intact and says why — one grey line under the
/// section header, the honest absence (a reader who knows the
/// ability exists learns it failed, not that it forgot).
#[test]
fn not_measured_note_names_the_reason() {
    let line = traffic_not_measured_line("observer attach failed: cgroup v2 not found");
    assert!(
        line.contains("network traffic: not measured — observer attach failed"),
        "the note carries the reason, got: {line}"
    );
}

/// The section cap: the readable budget the basic listing owned
/// (SOCKET_LINES_CAP) folds the overflow into the +N note — the JSON
/// document carries every row.
#[test]
fn traffic_section_caps_overflow_honestly() {
    let mut conns = ConnectionMap::new();
    let sockets: Vec<SocketInfo> = (0..15)
        .map(|i| socket(&format!("10.0.0.{i}:443"), Some(9000 + i)))
        .collect();
    conns.insert(
        1234,
        CgroupConnections {
            total_procs: 1,
            socket_holders: vec![ProcessDetail {
                pid: 4242,
                comm: "curl".to_string(),
                sockets,
            }],
        },
    );
    let focus = traffic_focus(
        1234,
        3,
        &[delta(1234, 1, 1)],
        Some(&conns),
        &std::collections::HashMap::new(),
    );
    let lines = traffic_section_lines(&focus);
    let text = lines.join("\n");
    assert!(
        text.contains("+3 more"),
        "12 shown, 3 folded, the JSON carries the rest, got: {text}"
    );
}

/// A cgroup the closing poll never booked (no delta row) composes a
/// zero-total window — the honest verdict for a target that moved
/// nothing, never an error, never a fabricated entry.
#[test]
fn missing_delta_row_composes_zero_totals() {
    let conns = census();
    let focus = traffic_focus(999, 3, &[delta(1234, 1, 1)], Some(&conns), &join());
    assert_eq!(focus.dl_bytes, 0);
    assert_eq!(focus.ul_bytes, 0);
    assert!(!focus.moved());
    assert!(focus.endpoints.is_empty(), "no census for cg 999, no rows");
}
