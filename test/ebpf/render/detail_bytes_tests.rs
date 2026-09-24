// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the per-endpoint byte attribution (NIGHT-boost-26, the
//! 2.4 frontier closed): the `[dl X | ul Y]` figures riding the tree
//! lines, the lean byteless row, the focus view's bytes-desc endpoint
//! ranking, and the deduped socket_cookies join-key set. Split from
//! detail_tests.rs when these pins pushed it past the owner's LOC
//! cap — one file per contract, the footer tree's own split
//! discipline. Wired into `src/ebpf/render/detail.rs` via #[path]
//! (cosmostrix Pattern C).

use super::*;
/// NIGHT-boost-26 pin: the per-endpoint byte join rides the tree —
/// a socket whose cookie joined renders `[dl X | ul Y]` (the footer
/// speed pair's vocabulary, SI one-decimal), while a byteless
/// sibling keeps its lean row: the suffix appears only when there
/// ARE bytes, and absence — not a fabricated zero — is the honest
/// no-figures signal.
#[test]
fn endpoint_bytes_ride_the_tree_lines() {
    use crate::ebpf::connections::{
        CgroupConnections, ConnectionMap, ProcessDetail, Proto, SocketInfo,
    };
    use crate::ebpf::loader::SocketBytes;
    use std::collections::HashMap;

    let socket = |remote: &str, cookie: Option<u64>| SocketInfo {
        proto: Proto::Tcp,
        remote: remote.to_string(),
        state: "ESTABLISHED",
        queued: false,
        cookie,
    };
    let mut conns = ConnectionMap::new();
    conns.insert(
        7001,
        CgroupConnections {
            total_procs: 2,
            socket_holders: vec![
                ProcessDetail {
                    pid: 4242,
                    comm: "curl".to_string(),
                    // Cookie 100 has bytes; cookie 200 moved nothing
                    // since attach; the third socket resolved no
                    // cookie (the pidfd_getfd-refused shape) and the
                    // eagle cap shows the two walk-first children.
                    sockets: vec![
                        socket("142.250.185.78:443", Some(100)),
                        socket("104.18.32.7:443", Some(200)),
                        socket("93.184.216.34:80", None),
                    ],
                },
                ProcessDetail {
                    pid: 4243,
                    comm: "wget".to_string(),
                    // The cookie-less INLINE shape: one socket, no
                    // join entry — renders exactly as before.
                    sockets: vec![socket("1.1.1.1:80", None)],
                },
            ],
        },
    );
    let mut bytes = HashMap::new();
    bytes.insert(
        100,
        SocketBytes {
            dl: 10_200_000_000,
            ul: 180_000,
        },
    );
    conns.apply_socket_bytes(bytes);

    let lines = detail_lines(Some(&conns), 7001);
    assert_eq!(
        lines.len(),
        4,
        "header + two children + one inline (the DETAIL_LINE_CAP): {lines:?}"
    );
    assert_eq!(
        lines[0], "    └ curl (4242) 3 sockets:",
        "the header still carries the socket count: {lines:?}"
    );
    assert!(
        lines[1].contains("142.250.185.78:443 [dl 10.2 GB | ul 180.0 KB]"),
        "the joined endpoint carries its own byte figures: {}",
        lines[1]
    );
    assert!(
        !lines[2].contains("[dl"),
        "the zero-traffic sibling keeps its lean row: {}",
        lines[2]
    );
    assert!(
        !lines[3].contains("[dl"),
        "the cookie-less inline neighbor renders exactly as before: {}",
        lines[3]
    );
}

/// NIGHT-boost-26 pin: the focus view RANKS each process's endpoints
/// by their joined bytes — the hungriest endpoint first (the 2.4
/// promise), byteless endpoints keeping the walk's established-first
/// order behind the traffic-carriers (Rust's stable sort).
#[test]
fn focus_ranks_endpoints_by_bytes() {
    use crate::ebpf::connections::{
        CgroupConnections, ConnectionMap, ProcessDetail, Proto, SocketInfo,
    };
    use crate::ebpf::loader::SocketBytes;
    use std::collections::HashMap;

    let socket = |remote: &str, cookie: Option<u64>| SocketInfo {
        proto: Proto::Tcp,
        remote: remote.to_string(),
        state: "ESTABLISHED",
        queued: false,
        cookie,
    };
    let mut conns = ConnectionMap::new();
    conns.insert(
        7001,
        CgroupConnections {
            total_procs: 1,
            socket_holders: vec![ProcessDetail {
                pid: 4242,
                comm: "firefox".to_string(),
                // Walk order: alpha, bravo, charlie, delta. The join
                // makes BRAVO the eater — it must render first; the
                // byteless tail keeps its walk order.
                sockets: vec![
                    socket("10.0.0.1:443", Some(1)),
                    socket("10.0.0.2:443", Some(2)),
                    socket("10.0.0.3:443", Some(3)),
                    socket("10.0.0.4:443", None),
                ],
            }],
        },
    );
    let mut bytes = HashMap::new();
    bytes.insert(1, SocketBytes { dl: 500, ul: 0 });
    bytes.insert(
        2,
        SocketBytes {
            dl: 9_500_000,
            ul: 500_000,
        },
    );
    // Cookie 3 joined nothing: moved zero bytes since attach.
    conns.apply_socket_bytes(bytes);

    let lines = full_detail_lines(Some(&conns), 7001);
    let joined = lines.join("\n");
    let bravo = joined.find("10.0.0.2:443").expect("bravo renders");
    let alpha = joined.find("10.0.0.1:443").expect("alpha renders");
    let charlie = joined.find("10.0.0.3:443").expect("charlie renders");
    let delta = joined.find("10.0.0.4:443").expect("delta renders");
    assert!(
        bravo < alpha && alpha < charlie && charlie < delta,
        "bytes-desc first (bravo 10.0 MB), byteless keeping walk order: {joined}"
    );
    assert!(
        joined.contains("10.0.0.2:443 [dl 9.5 MB | ul 500.0 KB]"),
        "the ranking figure rides the line: {joined}"
    );
}

/// NIGHT-boost-26 pin: socket_cookies() is the deduped join key set
/// the loader point-looks-up — every resolved cookie exactly once,
/// cookie-less sockets absent.
#[test]
fn socket_cookies_are_the_deduped_join_keys() {
    use crate::ebpf::connections::{
        CgroupConnections, ConnectionMap, ProcessDetail, Proto, SocketInfo,
    };

    let socket = |cookie: Option<u64>| SocketInfo {
        proto: Proto::Tcp,
        remote: "10.0.0.9:443".to_string(),
        state: "ESTABLISHED",
        queued: false,
        cookie,
    };
    let mut conns = ConnectionMap::new();
    conns.insert(
        7001,
        CgroupConnections {
            total_procs: 1,
            socket_holders: vec![ProcessDetail {
                pid: 4242,
                comm: "curl".to_string(),
                sockets: vec![
                    socket(Some(7)),
                    socket(Some(7)),
                    socket(Some(9)),
                    socket(None),
                ],
            }],
        },
    );
    let mut cookies = conns.socket_cookies();
    cookies.sort_unstable();
    assert_eq!(cookies, vec![7, 9], "deduped, cookie-less absent");
}
