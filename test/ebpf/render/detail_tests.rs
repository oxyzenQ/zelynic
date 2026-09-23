// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the eagle-eyes connection-detail tree (NIGHT-boost-21):
//! the label suffix, the cap-aware ranked-table composition, and the
//! uncapped focus-view expansion. Wired into
//! `src/ebpf/render/detail.rs` via #[path] (cosmostrix Pattern C).

use super::*;

/// Label enrichment (NIGHT-hunt-8): multi-tenant cgroups say so.
#[test]
fn label_with_count_shapes() {
    use crate::ebpf::connections::CgroupConnections;
    use crate::ebpf::identity::ProcessIdentity;

    let mut identity = IdentityMap::new();
    identity.insert(ProcessIdentity {
        cgroup_id: 7001,
        uid: 1000,
        comm: "alacritty".to_string(),
    });

    // No connection map: plain identity label.
    assert_eq!(
        label_with_count(&identity, None, 7001),
        "cg:7001 (alacritty)"
    );

    // Single process: count adds nothing.
    let mut conns = crate::ebpf::connections::ConnectionMap::new();
    conns.insert(
        7001,
        CgroupConnections {
            total_procs: 1,
            socket_holders: Vec::new(),
        },
    );
    assert_eq!(
        label_with_count(&identity, Some(&conns), 7001),
        "cg:7001 (alacritty)"
    );

    // Four processes: "(alacritty +3)" — the row stops lying.
    conns.insert(
        7001,
        CgroupConnections {
            total_procs: 4,
            socket_holders: Vec::new(),
        },
    );
    assert_eq!(
        label_with_count(&identity, Some(&conns), 7001),
        "cg:7001 (alacritty +3)"
    );

    // Unresolved identity: no paren to splice, label untouched.
    assert_eq!(label_with_count(&identity, Some(&conns), 9999), "cg:9999");
}

/// Comm extraction tolerates the "+N" suffix and rejects
/// unknown/empty comms.
#[test]
fn comm_from_label_shapes() {
    assert_eq!(
        comm_from_label("cg:7001 (alacritty +3)").as_deref(),
        Some("alacritty")
    );
    assert_eq!(comm_from_label("cg:7001 (curl)").as_deref(), Some("curl"));
    assert_eq!(comm_from_label("cg:7001 (unknown)"), None);
    assert_eq!(comm_from_label("cg:7001 ()"), None);
    assert_eq!(comm_from_label("cg:7001"), None);
}

/// Fixture builder: the owner's curl-inside-alacritty shape plus the
/// listener noise the display filter must skip.
fn fixture() -> (
    crate::ebpf::connections::ConnectionMap,
    crate::ebpf::identity::IdentityMap,
) {
    use crate::ebpf::connections::{
        CgroupConnections, ConnectionMap, ProcessDetail, Proto, SocketInfo,
    };
    use crate::ebpf::identity::{IdentityMap, ProcessIdentity};

    let socket = |proto: Proto, remote: &str, state: &'static str, queued: bool| SocketInfo {
        proto,
        remote: remote.to_string(),
        state,
        queued,
    };

    let mut identity = IdentityMap::new();
    identity.insert(ProcessIdentity {
        cgroup_id: 7001,
        uid: 1000,
        comm: "alacritty".to_string(),
    });

    let mut conns = ConnectionMap::new();
    conns.insert(
        7001,
        CgroupConnections {
            total_procs: 4,
            socket_holders: vec![
                ProcessDetail {
                    pid: 4242,
                    comm: "curl".to_string(),
                    sockets: vec![
                        socket(Proto::Tcp, "10.90.170.143:443", "ESTABLISHED", true),
                        socket(Proto::Tcp, "1.1.1.1:443", "ESTABLISHED", false),
                    ],
                },
                ProcessDetail {
                    pid: 4243,
                    comm: "wget".to_string(),
                    sockets: vec![socket(Proto::Tcp, "93.184.216.34:80", "ESTABLISHED", false)],
                },
                ProcessDetail {
                    pid: 5000,
                    comm: "nc".to_string(),
                    sockets: vec![socket(Proto::Udp, "8.8.8.8:53", "CLOSE", false)],
                },
                ProcessDetail {
                    pid: 6000,
                    comm: "sshd".to_string(),
                    sockets: vec![socket(Proto::Tcp, "0.0.0.0:22", "LISTEN", false)],
                },
                ProcessDetail {
                    pid: 7000,
                    comm: "vim".to_string(),
                    sockets: vec![socket(Proto::Tcp, "9.9.9.9:22", "ESTABLISHED", false)],
                },
                // NIGHT-hunt-15 pin: a bound-only UDP listener
                // (state 07, remote 0.0.0.0:0 — the chronyd /
                // systemd-resolved shape) is NOT traffic and must
                // not produce a detail line nor inflate the
                // "+N more" count.
                ProcessDetail {
                    pid: 8000,
                    comm: "chronyd".to_string(),
                    sockets: vec![socket(Proto::Udp, "0.0.0.0:0", "CLOSE", false)],
                },
            ],
        },
    );
    (conns, identity)
}

/// Eagle-eyes tree composition (NIGHT-boost-21): the multi-socket
/// holder expands to header plus two children, the cap holds at the
/// flat list's four lines, listeners stay skipped, and the summary
/// counts every unseen holder honestly.
#[test]
fn detail_lines_tree_eagle_eyes() {
    let (conns, _) = fixture();

    let lines = detail_lines(Some(&conns), 7001);
    assert_eq!(
        lines,
        vec![
            "    └ curl (4242) 2 sockets:".to_string(),
            "        ├ 10.90.170.143:443 [busy]".to_string(),
            "        └ 1.1.1.1:443".to_string(),
            "    └ +3 more socket-holding processes".to_string(),
        ]
    );

    // No map, no detail — the monitor degrades to plain rows.
    assert!(detail_lines(None, 7001).is_empty());
    // Unknown cgroup: no detail.
    assert!(detail_lines(Some(&conns), 1234).is_empty());
}

/// Eagle-eyes cap behavior across the holder mixes: an expansion
/// plus an inline neighbor fits exactly; four singles render three
/// plus the summary (the flat contract's own shape); a lone
/// expansion rides without any summary.
#[test]
fn detail_lines_tree_budget() {
    use crate::ebpf::connections::{
        CgroupConnections, ConnectionMap, ProcessDetail, Proto, SocketInfo,
    };

    let tcp = |remote: &str| SocketInfo {
        proto: Proto::Tcp,
        remote: remote.to_string(),
        state: "ESTABLISHED",
        queued: false,
    };
    let holder = |pid: u32, comm: &str, socks: Vec<SocketInfo>| ProcessDetail {
        pid,
        comm: comm.to_string(),
        sockets: socks,
    };

    // Expansion (3 lines) + inline neighbor (1 line): exactly the
    // four-line budget, no summary needed.
    let mut conns = ConnectionMap::new();
    conns.insert(
        7001,
        CgroupConnections {
            total_procs: 2,
            socket_holders: vec![
                holder(
                    4242,
                    "curl",
                    vec![tcp("10.90.170.143:443"), tcp("1.1.1.1:443")],
                ),
                holder(4243, "wget", vec![tcp("93.184.216.34:80")]),
            ],
        },
    );
    assert_eq!(
        detail_lines(Some(&conns), 7001),
        vec![
            "    └ curl (4242) 2 sockets:".to_string(),
            "        ├ 10.90.170.143:443".to_string(),
            "        └ 1.1.1.1:443".to_string(),
            "    └ wget (4243) → 93.184.216.34:80".to_string(),
        ]
    );

    // Five single-socket holders: three inline plus the summary —
    // the flat list's exact composition, now under the tree banner.
    let singles: Vec<ProcessDetail> = (0..5)
        .map(|i| holder(5000 + i, "app", vec![tcp(&format!("10.0.0.{i}:443"))]))
        .collect();
    conns.insert(
        7002,
        CgroupConnections {
            total_procs: 5,
            socket_holders: singles,
        },
    );
    assert_eq!(
        detail_lines(Some(&conns), 7002),
        vec![
            "    └ app (5000) → 10.0.0.0:443".to_string(),
            "    └ app (5001) → 10.0.0.1:443".to_string(),
            "    └ app (5002) → 10.0.0.2:443".to_string(),
            "    └ +2 more socket-holding processes".to_string(),
        ]
    );

    // One lone expansion: header plus children, nothing withheld.
    conns.insert(
        7003,
        CgroupConnections {
            total_procs: 1,
            socket_holders: vec![holder(
                4242,
                "curl",
                vec![tcp("10.90.170.143:443"), tcp("1.1.1.1:443")],
            )],
        },
    );
    assert_eq!(
        detail_lines(Some(&conns), 7003),
        vec![
            "    └ curl (4242) 2 sockets:".to_string(),
            "        ├ 10.90.170.143:443".to_string(),
            "        └ 1.1.1.1:443".to_string(),
        ]
    );
}

/// Focus-view full tree (NIGHT-boost-21): every holder renders,
/// multi-socket holders expand ALL their endpoints as children, and
/// single-socket holders stay inline — the deep "who exactly" view.
#[test]
fn full_detail_lines_tree() {
    let (conns, _) = fixture();

    let lines = full_detail_lines(Some(&conns), 7001);
    assert_eq!(
        lines,
        vec![
            "  processes with sockets (4 total processes):".to_string(),
            "  └ curl (4242) 2 sockets:".to_string(),
            "      ├ 10.90.170.143:443 [busy]".to_string(),
            "      └ 1.1.1.1:443".to_string(),
            "  └ wget (4243) → 93.184.216.34:80".to_string(),
            "  └ nc (5000) → udp 8.8.8.8:53".to_string(),
            "  └ vim (7000) → 9.9.9.9:22".to_string(),
        ]
    );

    // Degradation contract: no map, unknown cgroup, or a cgroup with
    // no socket holders at all renders nothing.
    assert!(full_detail_lines(None, 7001).is_empty());
    assert!(full_detail_lines(Some(&conns), 1234).is_empty());
}

/// A three-endpoint holder (NIGHT-boost-21): the eagle view caps the
/// children at two while the header's count carries the scale; the
/// focus view shows all three with the last child closing the tree.
#[test]
fn detail_lines_three_endpoints() {
    use crate::ebpf::connections::{
        CgroupConnections, ConnectionMap, ProcessDetail, Proto, SocketInfo,
    };

    let tcp = |remote: &str| SocketInfo {
        proto: Proto::Tcp,
        remote: remote.to_string(),
        state: "ESTABLISHED",
        queued: false,
    };
    let mut conns = ConnectionMap::new();
    conns.insert(
        7001,
        CgroupConnections {
            total_procs: 1,
            socket_holders: vec![ProcessDetail {
                pid: 4242,
                comm: "firefox".to_string(),
                sockets: vec![
                    tcp("142.250.191.78:443"),
                    tcp("172.217.16.14:443"),
                    tcp("8.8.8.8:53"),
                ],
            }],
        },
    );

    assert_eq!(
        detail_lines(Some(&conns), 7001),
        vec![
            "    └ firefox (4242) 3 sockets:".to_string(),
            "        ├ 142.250.191.78:443".to_string(),
            "        └ 172.217.16.14:443".to_string(),
        ]
    );
    assert_eq!(
        full_detail_lines(Some(&conns), 7001),
        vec![
            "  processes with sockets (1 total processes):".to_string(),
            "  └ firefox (4242) 3 sockets:".to_string(),
            "      ├ 142.250.191.78:443".to_string(),
            "      ├ 172.217.16.14:443".to_string(),
            "      └ 8.8.8.8:53".to_string(),
        ]
    );
}
