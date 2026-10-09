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
//!
//! night-private-research-7: the figures are now ARRIVAL RATES — the
//! header carries the arrival label and every figure divides by the
//! window's own seconds, the same per-second vocabulary the
//! enforcement line speaks.

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

/// The section rendering: the header carries the window, the ARRIVAL
/// label, and the window's own rates; the rows carry the live view's
/// [dl X | ul Y] rate vocabulary, byteless rows stay lean, and the
/// mover outranks the quiet endpoint.
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
        text.contains("network traffic (5s focus · arrival): dl 2.0 MB/s · ul 60.0 KB/s"),
        "the header names the window, the arrival label, and both rates, got: {text}"
    );
    assert!(
        text.contains(
            "curl (4242) → 142.250.191.78:443 tcp ESTABLISHED [dl   2.0 MB/s | ul  60.0 KB/s]"
        ),
        "the mover's row carries the rate vocabulary, got: {text}"
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

/// night-audit-6 pin: a CONNECTED UDP socket (the QUIC-client shape,
/// /proc/net/udp state 01) reaches the depth report's traffic rows —
/// the former census gate accepted only CLOSE rows, which hid every
/// connected-UDP endpoint from the focus window's text report while
/// the JSON document kept carrying it. The row renders with the udp
/// tag and its joined window figures when the cookie resolves.
#[test]
fn connected_udp_reaches_the_traffic_rows() {
    let mut conns = ConnectionMap::new();
    let udp_sock = SocketInfo {
        proto: Proto::Udp,
        remote: "142.250.191.78:443".to_string(),
        state: "ESTABLISHED",
        queued: false,
        cookie: Some(2001),
    };
    let tcp_sock = socket("93.184.216.34:443", Some(1001));
    conns.insert(
        1234,
        CgroupConnections {
            total_procs: 1,
            socket_holders: vec![ProcessDetail {
                pid: 4242,
                comm: "brave".to_string(),
                sockets: vec![tcp_sock, udp_sock],
            }],
        },
    );
    let mut bytes = join();
    bytes.insert(1001, SocketBytes { dl: 300, ul: 100 });
    bytes.insert(2001, SocketBytes { dl: 5000, ul: 700 });

    let focus = traffic_focus(1234, 3, &[delta(1234, 100, 5000)], Some(&conns), &bytes);
    let text = traffic_section_lines(&focus).join("\n");
    assert!(
        text.contains("142.250.191.78:443 udp ESTABLISHED [dl   1.7 KB/s | ul    233 B/s]"),
        "the connected-UDP row renders with its figures over the 3s window (5000/3 rounds 1667 B/s), got: {text}"
    );
    // Movers-first: the UDP socket out-ate the TCP one, so it ranks first.
    let udp_line = focus
        .endpoints
        .iter()
        .find(|e| e.proto == "udp")
        .expect("the connected-UDP endpoint survives the census gate");
    assert_eq!(udp_line.pid, 4242);
    assert_eq!(udp_line.dl, Some(5000));
}

/// night-improve-57 pin: a raw socket (SOCK_RAW from /proc/net/raw)
/// reaches the depth report's traffic rows. Before this round the
/// raw tables were not in the read_socket_tables walk, so a process
/// using a raw socket showed its bytes in the cgroup total but no
/// detail line in the eagle-eyes tree (the BPF observer is
/// protocol-agnostic — keyed on cgroup + socket cookie — so the
/// bytes were counted, just not attributed to an endpoint). This pin
/// mirrors the night-audit-6 connected-UDP pin for the raw arm: a
/// raw socket with a resolved cookie joins to its window bytes and
/// renders with the `raw` tag. The remote may be `0.0.0.0:0` for an
/// unconnected raw socket (sendto-based tools), so the row spells
/// `0.0.0.0:0 raw CLOSE [dl X | ul Y]` honestly.
#[test]
fn raw_socket_reaches_the_traffic_rows() {
    let mut conns = ConnectionMap::new();
    let raw_sock = SocketInfo {
        proto: Proto::Raw,
        remote: "1.2.3.4:0".to_string(),
        state: "ESTABLISHED",
        queued: false,
        cookie: Some(3001),
    };
    let tcp_sock = socket("93.184.216.34:443", Some(1001));
    conns.insert(
        1234,
        CgroupConnections {
            total_procs: 1,
            socket_holders: vec![ProcessDetail {
                pid: 4242,
                comm: "ping".to_string(),
                sockets: vec![tcp_sock, raw_sock],
            }],
        },
    );
    let mut bytes = join();
    bytes.insert(1001, SocketBytes { dl: 300, ul: 100 });
    bytes.insert(3001, SocketBytes { dl: 8000, ul: 200 });

    let focus = traffic_focus(1234, 3, &[delta(1234, 100, 8000)], Some(&conns), &bytes);
    let text = traffic_section_lines(&focus).join("\n");
    assert!(
        text.contains("1.2.3.4:0 raw ESTABLISHED [dl   2.7 KB/s | ul     67 B/s]"),
        "the raw socket row renders with its figures over the 3s window (8000/3 rounds 2667 B/s), got: {text}"
    );
    // Movers-first: the raw socket out-ate the TCP one (8.3 KB vs
    // 400 B), so it ranks first — the operator sees the raw socket
    // at the top of the section, exactly the visibility the round
    // opened.
    let raw_line = focus
        .endpoints
        .iter()
        .find(|e| e.proto == "raw")
        .expect("the raw endpoint survives the census gate");
    assert_eq!(raw_line.pid, 4242);
    assert_eq!(raw_line.dl, Some(8000));
    assert_eq!(raw_line.ul, Some(200));
    // Movers-first ordering: the raw endpoint ranks above the TCP one.
    assert_eq!(focus.endpoints[0].proto, "raw");
    assert_eq!(focus.endpoints[1].proto, "tcp");
}

/// night-improve-57 pin: an UNCONNECTED raw socket (the sendto-based
/// shape — nmap, custom IP tools) reaches the traffic rows too. The
/// remote is `0.0.0.0:0` because the kernel reports no destination
/// for a raw socket that hasn't called connect(), but the bytes ARE
/// counted by the BPF observer and the cookie join attributes them
/// to this socket. The row spells `0.0.0.0:0 raw CLOSE [dl X | ul Y]`
/// — the honest shape: the operator sees "this process has a raw
/// socket moving bytes" even when the destination is unknown to
/// /proc/net/raw.
#[test]
fn unbound_raw_socket_reaches_the_traffic_rows() {
    let mut conns = ConnectionMap::new();
    let raw_sock = SocketInfo {
        proto: Proto::Raw,
        remote: "0.0.0.0:0".to_string(),
        state: "CLOSE",
        queued: false,
        cookie: Some(3001),
    };
    conns.insert(
        1234,
        CgroupConnections {
            total_procs: 1,
            socket_holders: vec![ProcessDetail {
                pid: 4242,
                comm: "nmap".to_string(),
                sockets: vec![raw_sock],
            }],
        },
    );
    let mut bytes = join();
    bytes.insert(3001, SocketBytes { dl: 500, ul: 1500 });

    let focus = traffic_focus(1234, 3, &[delta(1234, 1500, 500)], Some(&conns), &bytes);
    let text = traffic_section_lines(&focus).join("\n");
    assert!(
        text.contains("0.0.0.0:0 raw CLOSE [dl    167 B/s | ul    500 B/s]"),
        "the unbound raw socket row renders with its figures over the 3s window (500/3 rounds 167 B/s), got: {text}"
    );
    let raw_line = focus
        .endpoints
        .iter()
        .find(|e| e.proto == "raw")
        .expect("the unbound raw endpoint survives the census gate");
    assert_eq!(raw_line.remote, "0.0.0.0:0");
    assert_eq!(raw_line.state, "CLOSE");
}

/// night-private-research-7 pin: the window's own denominator — the
/// exact shape of the owner's transcript. A 30s window that booked
/// 1.2 MB renders 40 KB/s (not the raw 1.2 MB a reader once mistook
/// for a rate against a 200 KB/s policy), and the endpoint figure
/// rides the same denominator as the header it sits under.
#[test]
fn window_figures_divide_by_the_windows_own_seconds() {
    let conns = census();
    let mut bytes = join();
    bytes.insert(
        1001,
        SocketBytes {
            dl: 1_200_000,
            ul: 28_200,
        },
    );
    let focus = traffic_focus(
        1234,
        30,
        &[delta(1234, 33_300, 1_200_000)],
        Some(&conns),
        &bytes,
    );
    let text = traffic_section_lines(&focus).join("\n");
    assert!(
        text.contains("network traffic (30s focus · arrival): dl 40.0 KB/s · ul 1.1 KB/s"),
        "1.2 MB over 30s is 40 KB/s — the owner's own transcript math, got: {text}"
    );
    assert!(
        text.contains("142.250.191.78:443 tcp ESTABLISHED [dl  40.0 KB/s | ul    940 B/s]"),
        "the endpoint rides the same denominator (28_200/30 = 940 B/s), got: {text}"
    );
}
