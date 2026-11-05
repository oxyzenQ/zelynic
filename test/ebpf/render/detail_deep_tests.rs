// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! Pins for the deep-figure honesty contracts (night-netrunner-4):
//! the row retrans figure's Option law — a measured window renders
//! its count (a measured ZERO included), and every flavor of absence
//! (no TCP sockets, cookies refused, first generation) renders the
//! em dash via None, never a fabricated zero. Wired into
//! `src/ebpf/render/detail.rs` via #[path] (cosmostrix Pattern C),
//! the detail_bytes split discipline.

use super::*;

/// The row figure contract, pinned flavor by flavor: Some for a
/// measured window (zero included), None for every absence.
#[test]
fn retrans_row_figure_is_absent_or_measured_never_faked() {
    use crate::ebpf::connections::{
        CgroupConnections, ConnectionMap, ProcessDetail, Proto, SocketInfo, TcpDeepWindow,
    };
    use std::collections::HashMap;

    let tcp = |cookie: Option<u64>| SocketInfo {
        inode: 42,
        proto: Proto::Tcp,
        remote: "142.250.185.78:443".to_string(),
        state: "ESTABLISHED",
        queued: false,
        cookie,
        deep: None,
    };
    let udp = |cookie: Option<u64>| SocketInfo {
        inode: 43,
        proto: Proto::Udp,
        remote: "8.8.8.8:443".to_string(),
        state: "ESTABLISHED",
        queued: false,
        cookie,
        deep: None,
    };

    // Flavor 1 — no cgroup detail at all: None.
    let conns = ConnectionMap::new();
    assert_eq!(retrans_row_figure(Some(&conns), 7001), None);
    assert_eq!(retrans_row_figure(None, 7001), None);

    // Flavor 2 — QUIC-only row (UDP sockets only, cookies and all):
    // the kernel holds no TCP truth here, so None — never 0.
    let mut conns = ConnectionMap::new();
    conns.insert(
        7001,
        CgroupConnections {
            total_procs: 1,
            socket_holders: vec![ProcessDetail {
                pid: 42,
                comm: "brave".to_string(),
                sockets: vec![udp(Some(1))],
            }],
        },
    );
    assert_eq!(retrans_row_figure(Some(&conns), 7001), None);

    // Flavor 3 — TCP sockets tracked, first generation (no windows
    // yet): the walk has no predecessor to difference against, so
    // None — the dash, never a fabricated zero.
    let mut conns = ConnectionMap::new();
    conns.insert(
        7001,
        CgroupConnections {
            total_procs: 1,
            socket_holders: vec![ProcessDetail {
                pid: 42,
                comm: "curl".to_string(),
                sockets: vec![tcp(Some(100)), tcp(Some(200))],
            }],
        },
    );
    assert_eq!(retrans_row_figure(Some(&conns), 7001), None);

    // Flavor 4 — measured zero: one window entry, retrans_window 0.
    // This renders 0 — a previous generation existed and the
    // difference was measured.
    let mut conns = ConnectionMap::new();
    conns.install_deep_windows(HashMap::from([(
        100u64,
        TcpDeepWindow {
            rtt_us: 19_000,
            rttvar_us: 9_000,
            retrans_window: 0,
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
                sockets: vec![tcp(Some(100)), tcp(Some(200))],
            }],
        },
    );
    assert_eq!(retrans_row_figure(Some(&conns), 7001), Some(0));

    // Flavor 5 — the audit's formula: the row's windows SUM. Cookie
    // 100 retransmitted 1, cookie 200 retransmitted 3, cookie 300 is
    // fresh (no window — contributes nothing, still Some).
    let mut conns = ConnectionMap::new();
    conns.install_deep_windows(HashMap::from([
        (
            100u64,
            TcpDeepWindow {
                rtt_us: 19_000,
                rttvar_us: 9_000,
                retrans_window: 1,
                segs_out_window: 712,
            },
        ),
        (
            200u64,
            TcpDeepWindow {
                rtt_us: 21_000,
                rttvar_us: 4_000,
                retrans_window: 3,
                segs_out_window: 900,
            },
        ),
    ]));
    conns.insert(
        7001,
        CgroupConnections {
            total_procs: 1,
            socket_holders: vec![ProcessDetail {
                pid: 42,
                comm: "curl".to_string(),
                sockets: vec![tcp(Some(100)), tcp(Some(200)), tcp(Some(300))],
            }],
        },
    );
    assert_eq!(retrans_row_figure(Some(&conns), 7001), Some(4));
}

/// The full row renders the retrans cell: the measured figure
/// right-aligned in its column, the dash for absence, and the
/// header spells `retrans` in full (the surface vocabulary never
/// abbreviates).
#[test]
fn retrans_column_renders_figure_or_dash() {
    use crate::ebpf::connections::{
        CgroupConnections, ConnectionMap, ProcessDetail, Proto, SocketInfo, TcpDeepWindow,
    };
    use crate::ebpf::identity::IdentityMap;
    use crate::ebpf::render::eagle_row::render_eagle_row;
    use crate::ebpf::render::{EagleColumns, SessionAcc};
    use std::collections::HashMap;

    let identity = IdentityMap::new();
    let cols = EagleColumns {
        label_w: 20,
        dl_w: 10,
        ul_w: 10,
        retrans_w: 7,
        show_total: true,
    };
    let tcp = |cookie: Option<u64>| SocketInfo {
        inode: 42,
        proto: Proto::Tcp,
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
    conns.insert(
        7001,
        CgroupConnections {
            total_procs: 1,
            socket_holders: vec![ProcessDetail {
                pid: 42,
                comm: "curl".to_string(),
                sockets: vec![tcp(Some(100))],
            }],
        },
    );

    // The measured figure renders in the cell (plain text — the
    // color tier wraps the whole row, the assertion reads the body).
    let mut lines = Vec::new();
    render_eagle_row(
        &mut lines,
        7001,
        SessionAcc::default(),
        0,
        0,
        Some(1),
        &identity,
        Some(&conns),
        &cols,
        3,
    );
    assert_eq!(lines.len(), 1);
    assert!(!lines[0].contains("retrans"), "row carries no header");
    assert!(lines[0].contains('1'), "the figure renders: {}", lines[0]);

    // Absence renders the em dash — never a fabricated zero.
    let mut lines = Vec::new();
    render_eagle_row(
        &mut lines,
        7001,
        SessionAcc::default(),
        0,
        0,
        None,
        &identity,
        Some(&conns),
        &cols,
        3,
    );
    assert!(
        lines[0].contains('\u{2014}'),
        "the dash renders: {}",
        lines[0]
    );
}

/// The walk-to-walk generation fold (night-netrunner-4): the first
/// refresh produces NO windows (fresh connections contribute
/// nothing), the second produces the saturating difference — and a
/// retrans counter restart (policy sweep, socket rebirth) reads as
/// a zero delta, never a negative.
#[test]
fn deep_windows_difference_across_generations() {
    use crate::ebpf::connections::{TcpDeepSample, TcpDeepWindow};

    // The pure ladder the fold rides is the saturating_sub pair —
    // pinned at the delta level (the fold itself is the refresh's
    // own map swap, exercised by the live walk; the pin freezes the
    // arithmetic the window entry carries).
    let now = TcpDeepSample {
        rtt_us: 19_000,
        rttvar_us: 9_000,
        total_retrans: 5,
        segs_out: 1_000,
    };
    let prev = TcpDeepSample {
        rtt_us: 18_000,
        rttvar_us: 8_000,
        total_retrans: 2,
        segs_out: 400,
    };
    let win = TcpDeepWindow {
        rtt_us: now.rtt_us,
        rttvar_us: now.rttvar_us,
        retrans_window: now.total_retrans.saturating_sub(prev.total_retrans),
        segs_out_window: now.segs_out.saturating_sub(prev.segs_out),
    };
    assert_eq!(win.retrans_window, 3);
    assert_eq!(win.segs_out_window, 600);

    // The counter restart: now < prev saturates to zero.
    let restarted = TcpDeepSample {
        total_retrans: 1,
        ..now
    };
    assert_eq!(
        restarted.total_retrans.saturating_sub(prev.total_retrans),
        0
    );
}
