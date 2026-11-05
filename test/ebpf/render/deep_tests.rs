// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! Pins for the --deep figure family's honesty contracts
//! (night-netrunner-4): the row deep line's four flavors (TCP with a
//! readable window, TCP whose read was refused, the QUIC tag, the
//! raw tag), the focus view's per-endpoint suffixes, and the
//! hungriest-endpoint ranking the row line rides. Wired into
//! `src/ebpf/render/deep.rs` via #[path] (cosmostrix Pattern C).

use super::*;

/// The row deep line's four flavors, pinned fixture by fixture: the
/// TCP window renders the kernel's own figures, the refused read
/// renders the em dashes, and the unmeasurable protocols render
/// their tags — never a fabricated zero anywhere.
#[test]
fn row_deep_line_renders_figures_or_honest_absence() {
    use crate::ebpf::connections::{
        CgroupConnections, ConnectionMap, ProcessDetail, Proto, SocketInfo, TcpDeepWindow,
    };
    use std::collections::HashMap;

    let sock = |proto: Proto, cookie: Option<u64>| SocketInfo {
        inode: 42,
        proto,
        remote: "142.250.185.78:443".to_string(),
        state: "ESTABLISHED",
        queued: false,
        cookie,
        deep: None,
    };

    // Flavor 1 — TCP with a readable window: the kernel's figures.
    let mut conns = ConnectionMap::new();
    conns.install_deep_windows(HashMap::from([(
        100u64,
        TcpDeepWindow {
            rtt_us: 19_000,
            rttvar_us: 9_000,
            retrans_window: 1,
            segs_out_window: 712,
        },
    )]));
    conns.insert(
        7001,
        CgroupConnections {
            total_procs: 1,
            socket_holders: vec![ProcessDetail {
                pid: 42,
                comm: "curl".to_string(),
                sockets: vec![sock(Proto::Tcp, Some(100))],
            }],
        },
    );
    let line = row_deep_line(Some(&conns), 7001).expect("a displayable socket has a deep line");
    assert_eq!(
        line,
        "rtt 19ms ±9ms · retrans 1/712 segs (0.14%) · 1 tcp eps"
    );

    // Flavor 2 — TCP whose window was never readable (first walk,
    // dup refused): the em dashes, never zeros.
    let mut conns = ConnectionMap::new();
    conns.insert(
        7001,
        CgroupConnections {
            total_procs: 1,
            socket_holders: vec![ProcessDetail {
                pid: 42,
                comm: "curl".to_string(),
                sockets: vec![sock(Proto::Tcp, Some(100))],
            }],
        },
    );
    let line = row_deep_line(Some(&conns), 7001).expect("a displayable socket has a deep line");
    assert_eq!(line, "rtt — · retrans — · 1 tcp eps");

    // Flavor 3 — QUIC-only row: the tag, honestly.
    let mut conns = ConnectionMap::new();
    conns.insert(
        7001,
        CgroupConnections {
            total_procs: 1,
            socket_holders: vec![ProcessDetail {
                pid: 42,
                comm: "brave".to_string(),
                sockets: vec![sock(Proto::Udp, Some(200))],
            }],
        },
    );
    assert_eq!(
        row_deep_line(Some(&conns), 7001).as_deref(),
        Some("[encrypted/quic]")
    );

    // Flavor 4 — raw only: the no-truth tag.
    let mut conns = ConnectionMap::new();
    conns.insert(
        7001,
        CgroupConnections {
            total_procs: 1,
            socket_holders: vec![ProcessDetail {
                pid: 42,
                comm: "ping".to_string(),
                sockets: vec![sock(Proto::Raw, Some(300))],
            }],
        },
    );
    assert_eq!(
        row_deep_line(Some(&conns), 7001).as_deref(),
        Some("[no l4 truth]")
    );

    // Flavor 5 — nothing displayable: no deep line at all (absence,
    // not an empty promise).
    let mut conns = ConnectionMap::new();
    conns.insert(
        7001,
        CgroupConnections {
            total_procs: 1,
            socket_holders: vec![ProcessDetail {
                pid: 42,
                comm: "sshd".to_string(),
                sockets: vec![SocketInfo {
                    inode: 44,
                    proto: Proto::Tcp,
                    remote: "0.0.0.0:22".to_string(),
                    state: "LISTEN",
                    queued: false,
                    cookie: Some(400),
                    deep: None,
                }],
            }],
        },
    );
    assert_eq!(row_deep_line(Some(&conns), 7001), None);
}

/// The hungriest-endpoint law: the row line rides the byte join's
/// biggest mover — a UDP mover out-hungrying a TCP idle socket
/// renders the QUIC tag (the row's truth is its biggest eater), and
/// a TCP mover out-hungrying everything renders that TCP socket's
/// window figures.
#[test]
fn row_deep_line_rides_the_hungriest_endpoint() {
    use crate::ebpf::connections::{
        CgroupConnections, ConnectionMap, ProcessDetail, Proto, SocketInfo, TcpDeepWindow,
    };
    use crate::ebpf::loader::SocketBytes;
    use std::collections::HashMap;

    let sock = |proto: Proto, remote: &str, cookie: Option<u64>| SocketInfo {
        inode: 42,
        proto,
        remote: remote.to_string(),
        state: "ESTABLISHED",
        queued: false,
        cookie,
        deep: None,
    };
    let mut conns = ConnectionMap::new();
    conns.install_deep_windows(HashMap::from([(
        100u64,
        TcpDeepWindow {
            rtt_us: 19_000,
            rttvar_us: 9_000,
            retrans_window: 1,
            segs_out_window: 712,
        },
    )]));
    conns.insert(
        7001,
        CgroupConnections {
            total_procs: 1,
            socket_holders: vec![ProcessDetail {
                pid: 42,
                comm: "brave".to_string(),
                sockets: vec![
                    sock(Proto::Tcp, "142.250.185.78:443", Some(100)),
                    sock(Proto::Udp, "8.8.8.8:443", Some(200)),
                ],
            }],
        },
    );

    // The UDP socket is the mover (500 KB/s this frame), the TCP one
    // idle: the row's deep line speaks the QUIC tag.
    conns.apply_socket_bytes(HashMap::from([(
        200u64,
        SocketBytes { dl: 500_000, ul: 0 },
    )]));
    assert_eq!(
        row_deep_line(Some(&conns), 7001).as_deref(),
        Some("[encrypted/quic]")
    );

    // The TCP socket out-hungries: the window figures lead.
    conns.apply_socket_bytes(HashMap::from([
        (100u64, SocketBytes { dl: 900_000, ul: 0 }),
        (200u64, SocketBytes { dl: 500_000, ul: 0 }),
    ]));
    let line = row_deep_line(Some(&conns), 7001).expect("the mover has a line");
    assert!(
        line.starts_with("rtt 19ms"),
        "the TCP window figures lead: {line}"
    );
}

/// The focus view's suffix family: TCP gains the bracketed figures
/// (or the em-dash pair), UDP the tag, raw the no-truth tag — the
/// inline suffix the endpoint line appends.
#[test]
fn endpoint_suffixes_carry_the_tag_family() {
    use crate::ebpf::connections::{ConnectionMap, Proto, SocketInfo, TcpDeepWindow};
    use std::collections::HashMap;

    let sock = |proto: Proto, cookie: Option<u64>| SocketInfo {
        inode: 42,
        proto,
        remote: "142.250.185.78:443".to_string(),
        state: "ESTABLISHED",
        queued: false,
        cookie,
        deep: None,
    };
    let mut conns = ConnectionMap::new();
    conns.install_deep_windows(HashMap::from([(
        100u64,
        TcpDeepWindow {
            rtt_us: 19_000,
            rttvar_us: 9_000,
            retrans_window: 1,
            segs_out_window: 712,
        },
    )]));

    assert_eq!(
        endpoint_deep_suffix(&sock(Proto::Tcp, Some(100)), Some(&conns)),
        " [rtt 19ms ±9ms · retrans 1/712 segs (0.14%)]"
    );
    assert_eq!(
        endpoint_deep_suffix(&sock(Proto::Tcp, Some(999)), Some(&conns)),
        " [rtt — · retrans —]"
    );
    assert_eq!(
        endpoint_deep_suffix(&sock(Proto::Udp6, Some(200)), Some(&conns)),
        " [encrypted/quic]"
    );
    assert_eq!(
        endpoint_deep_suffix(&sock(Proto::Raw6, Some(300)), Some(&conns)),
        " [no l4 truth]"
    );
    // No conns at all: the honest dashes on TCP, the tags everywhere.
    assert_eq!(
        endpoint_deep_suffix(&sock(Proto::Tcp, Some(100)), None),
        " [rtt — · retrans —]"
    );
}

/// The RTT formatter's ladder: whole milliseconds, one decimal below
/// 10 ms when fractional, microseconds below 1 ms.
#[test]
fn rtt_formatter_ladder() {
    assert_eq!(format_rtt_us(19_000), "19ms");
    assert_eq!(format_rtt_us(8_500), "8.5ms");
    assert_eq!(format_rtt_us(950), "950us");
    assert_eq!(format_rtt_us(0), "0us");
    assert_eq!(format_rtt_us(1_234_000), "1234ms");
    assert_eq!(format_jitter_us(9_000), "±9ms");
}

/// The retrans share carries the count AND the ratio; a zero
/// denominator renders the count without a fabricated ratio.
#[test]
fn retrans_share_shows_count_and_ratio() {
    assert_eq!(retrans_share(1, 712), "1/712 segs (0.14%)");
    assert_eq!(retrans_share(0, 0), "0/0 segs");
    assert_eq!(retrans_share(3, 900), "3/900 segs (0.33%)");
}

/// The legend line is fixed text — the contract a script (or a
/// screenshot diff) can pin byte-for-byte.
#[test]
fn footer_legend_is_the_pinned_sentence() {
    assert_eq!(
        footer_legend_line(),
        "deep: rtt ± is RFC 6298 rttvar · retrans counted per 3s walk · quic = [encrypted/quic]"
    );
}
