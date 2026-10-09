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
//!
//! night-private-research-7: the figures are now ARRIVAL RATES — the
//! fixtures install a frame's movers directly (the differencing the
//! monitor loop owns is upstream of this map) and the assertions
//! read per-second spellings over the one-second fixture window.

use super::*;

/// The fixtures' frame window (night-private-research-7): one second,
/// the monitor's default cadence — every rate the pins assert against
/// divides by exactly this.
const WINDOW: Duration = Duration::from_secs(1);

/// NIGHT-boost-26 pin: the per-endpoint byte join rides the tree —
/// a socket whose cookie joined renders `[dl X | ul Y]` (the footer
/// speed pair's vocabulary, SI one-decimal, per-second since
/// night-private-research-7), while a byteless sibling keeps its
/// lean row: the suffix appears only when there ARE bytes, and
/// absence — not a fabricated zero — is the honest no-figures
/// signal.
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
                    // Cookie 100 is this frame's mover; cookie 200
                    // moved nothing this frame (the differenced join
                    // carries movers only); the third socket resolved
                    // no cookie (the pidfd_getfd-refused shape) and the
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

    let lines = detail_lines(Some(&conns), 7001, WINDOW);
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
        lines[1].contains("142.250.185.78:443 [dl  10.2 GB/s | ul 180.0 KB/s]"),
        "the joined endpoint carries its own arrival rates: {}",
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
    // Cookie 3 joined nothing: moved zero bytes this frame.
    conns.apply_socket_bytes(bytes);

    let lines = full_detail_lines(Some(&conns), 7001, WINDOW);
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
        joined.contains("10.0.0.2:443 [dl   9.5 MB/s | ul 500.0 KB/s]"),
        "the ranking figure rides the line: {joined}"
    );
}

/// NIGHT-hunt-38 pin: the RANKED view's capped tree ranks its
/// endpoints bytes-desc too — the focus view's own law, applied
/// where truncation makes it matter most. The fixture walks the
/// eater LAST: without the ranking, the two-slot cap would show
/// the two quiet walk-first endpoints and bury the answer; with
/// it, the cap shows the hungriest two, the eater's figures on
/// the first child line.
#[test]
fn the_ranked_tree_cap_shows_the_hungriest_endpoints() {
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
                comm: "brave".to_string(),
                // Walk order: three quiet sockets first, the EATER
                // last — the owner's own transcript shape (7
                // sockets, the hungry one anywhere among them).
                sockets: vec![
                    socket("10.0.0.1:443", Some(1)),
                    socket("10.0.0.2:443", Some(2)),
                    socket("10.0.0.3:443", Some(3)),
                    socket("47.239.88.7:443", Some(4)),
                ],
            }],
        },
    );
    let mut bytes = HashMap::new();
    bytes.insert(
        1,
        SocketBytes {
            dl: 26_400,
            ul: 25_200,
        },
    );
    bytes.insert(2, SocketBytes { dl: 1_000, ul: 900 });
    bytes.insert(3, SocketBytes { dl: 800, ul: 700 });
    bytes.insert(
        4,
        SocketBytes {
            dl: 126_600,
            ul: 61_400,
        },
    );
    conns.apply_socket_bytes(bytes);

    let lines = detail_lines(Some(&conns), 7001, WINDOW);
    let joined = lines.join("\n");
    assert!(
        joined.contains("brave (4242) 4 sockets:"),
        "the header carries the honest count: {joined}"
    );
    // The two slots are the hungriest by joined bytes: the eater
    // (188.0 KB joined) and the 51.6 KB sibling — the two quiet
    // ones (1.9 KB, 1.5 KB) are what the cap hides.
    let eater = joined
        .find("47.239.88.7:443 [dl 126.6 KB/s | ul  61.4 KB/s]")
        .expect("the walked-LAST eater renders first under the cap");
    let sibling = joined
        .find("10.0.0.1:443 [dl  26.4 KB/s | ul  25.2 KB/s]")
        .expect("the second-hungriest takes the second slot");
    assert!(
        eater < sibling,
        "the cap orders its two slots bytes-desc: {joined}"
    );
    assert!(
        !joined.contains("10.0.0.2:443"),
        "the byte-quiet walk-first sockets are what the cap hides: {joined}"
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

/// NIGHT-total-lts-6 pin: the HashSet dedup preserves the FIRST-SEEN
/// order the Vec::contains scan produced — the join is
/// order-independent (loader.rs socket_bytes folds into a HashMap),
/// but the contract freezes anyway so the O(n) swap can never drift
/// an observable byte: cookie 7 first seen before 9, the duplicate
/// 7 between them moves nothing.
#[test]
fn socket_cookies_preserve_first_seen_order() {
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
                // First-seen order: 42, 7, 9 — the trailing 42 is a
                // duplicate and must not repeat or reorder anything.
                sockets: vec![
                    socket(Some(42)),
                    socket(Some(7)),
                    socket(Some(9)),
                    socket(Some(42)),
                    socket(None),
                ],
            }],
        },
    );
    assert_eq!(
        conns.socket_cookies(),
        vec![42, 7, 9],
        "first-seen order, duplicates absorbed: {:?}",
        conns.socket_cookies()
    );
}

/// NIGHT-total-lts-6 pin: the dense-host shape the O(n) dedup exists
/// for — many cgroups, many sockets, shared cookies across cgroups
/// (the shared-socket-table-row shape) — stays correct at a scale
/// the quadratic scan would have paid millions of comparisons for:
/// every distinct cookie exactly once, the count exact, the dedup
/// linear.
#[test]
fn socket_cookies_dense_fixture_stays_exact() {
    use crate::ebpf::connections::{
        CgroupConnections, ConnectionMap, ProcessDetail, Proto, SocketInfo,
    };

    // 64 cgroups x 64 sockets = 4096 walked sockets, cookies cycling
    // modulo 1024 — 1024 distinct values, each seen exactly 4 times,
    // spread across cgroups AND holders.
    const CGROUPS: u32 = 64;
    const SOCKETS_PER_HOLDER: usize = 64;
    let mut conns = ConnectionMap::new();
    for cg in 0..CGROUPS {
        let sockets: Vec<SocketInfo> = (0..SOCKETS_PER_HOLDER)
            .map(|i| SocketInfo {
                proto: Proto::Tcp,
                remote: format!("10.{}.{}.{}:443", cg, i / 256, i % 256),
                state: "ESTABLISHED",
                queued: false,
                cookie: Some(((cg as u64 * SOCKETS_PER_HOLDER as u64 + i as u64) % 1024) + 1),
            })
            .collect();
        conns.insert(
            cg,
            CgroupConnections {
                total_procs: 1,
                socket_holders: vec![ProcessDetail {
                    pid: 10_000 + cg,
                    comm: "worker".to_string(),
                    sockets,
                }],
            },
        );
    }

    let cookies = conns.socket_cookies();
    // 4096 sockets over a 1024-value cycle: every value 1..=1024
    // appears, each exactly once in the output.
    assert_eq!(
        cookies.len(),
        1024,
        "every distinct cookie once: {cookies:?}"
    );
    let mut sorted = cookies.clone();
    sorted.sort_unstable();
    let expected: Vec<u64> = (1..=1024).collect();
    assert_eq!(sorted, expected, "the exact distinct set");
    // And no duplicates in the first-seen output itself.
    let mut seen = std::collections::HashSet::new();
    assert!(
        cookies.iter().all(|c| seen.insert(*c)),
        "no duplicate in the returned order"
    );
}

// ── the steady rate field (night-improve-59, the Bloomberg cut) ────

/// The field law: every figure lands right-aligned in the fixed
/// 10-column RATE budget (improve-13's own width — "999.9 KB/s"
/// is the widest the SI ladder renders), so the columns never
/// shift when a rate crosses a tier, and a zero leg renders the
/// honest "0 B/s" — never the limiter's BLOCKED verdict (the
/// footer's own law: the observer does not judge).
#[test]
fn steady_rate_field_lands_in_the_ten_column_budget() {
    // The honest zero, in budget.
    assert_eq!(steady_rate_field(0), "     0 B/s");
    // The B tier pads to the budget.
    assert_eq!(steady_rate_field(500), "   500 B/s");
    // The full-width figure: zero pad, the budget's own edge.
    assert_eq!(steady_rate_field(257_000), "257.0 KB/s");
    // The tier-promotion edge renders the next unit, still in
    // budget (999,950 B/s promotes to "1.0 MB/s", never the
    // ragged "1000.0 KB/s").
    assert_eq!(steady_rate_field(999_950), "  1.0 MB/s");
    // Every figure is exactly 10 columns — the jitter-free
    // contract the whole cut exists for.
    for rate in [
        0,
        7,
        999,
        1_000,
        257_000,
        999_949,
        999_950,
        18_400_000_000_000_000_000,
    ] {
        assert_eq!(steady_rate_field(rate).chars().count(), 10, "rate {rate}");
    }
}

/// The zero LEG (the audit's find): a mover that moved bytes on
/// one direction only renders the quiet leg as the honest
/// "0 B/s" — the pre-improve-59 shape rendered `format_rate(0)`'s
/// "BLOCKED", a POLICY verdict the observer surface must never
/// speak (the footer's own documented law, now pinned where the
/// bug lived).
#[test]
fn the_quiet_leg_renders_an_honest_zero_never_blocked() {
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
                comm: "dnscache".to_string(),
                // The one-way mover: a DNS-style exchange that
                // downloaded a payload and uploaded nothing this
                // frame (the movers map carries it for the dl leg).
                sockets: vec![socket("1.1.1.1:53", Some(11))],
            }],
        },
    );
    let mut bytes = HashMap::new();
    bytes.insert(11, SocketBytes { dl: 257_000, ul: 0 });
    conns.apply_socket_bytes(bytes);

    let lines = detail_lines(Some(&conns), 7001, WINDOW);
    let joined = lines.join("\n");
    assert!(
        joined.contains("1.1.1.1:53 [dl 257.0 KB/s | ul      0 B/s]"),
        "the quiet leg renders the honest zero in budget: {joined}"
    );
    assert!(
        !joined.contains("BLOCKED"),
        "the observer never speaks the limiter's policy verdict: {joined}"
    );
}
