// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Frame benchmark harness (NIGHT-hunt-7 A/B protocol; retargeted
//! to the eagle-eyes renderer by NIGHT-boost-1).
//!
//! Renders synthetic eagle-eyes frames through the REAL render path
//! so scripts/frame-bench.py can compute the owner's visual and
//! performance metrics (density gini, frame entropy, fps, dirty
//! cells, emit bytes). Synthetic traffic evolves from a fixed-seed
//! LCG, so a run BEFORE a layout change and one AFTER see
//! byte-identical data — the only variable is the layout engine
//! itself.
//!
//! Root/eBPF is NOT required: the render layer is exercised with an
//! in-memory CounterSummary, so the harness runs in sandboxes where
//! `eagle-eyes` cannot attach (the same constraint the NIGHT-hunt-6
//! commit documented for the system benchmark).
//!
//! NIGHT-hunt-8: the harness also installs a synthetic ConnectionMap
//! (deterministic fixture, no /proc), so the eagle-eyes detail lines
//! are rendered and measured — the frame cost of socket detail is
//! part of the A/B contract, not an unmeasured add-on.
//!
//! NIGHT-improve-2 protocol extension: each captured frame carries
//! BOTH the logical content (the lines the renderer produced — the
//! visual-parity surface, directly comparable with pre-diff captures)
//! AND the diff engine's actual emission size
//! (`###EMIT### bytes=N`). The emission goes to a real sink (/dev/null
//! — one write syscall per frame, the honest per-frame I/O cost of
//! the new engine; the pipe carries only markers + logical lines so
//! the captures stay splitlines-clean). The engine is pinned to a
//! deterministic 80x40 screen so the strategy choice (sparse vs
//! sequential) is a property of the engine, not of the piped
//! fallback probe.

use std::time::{Duration, Instant};

use super::render_eagle_eyes;
use crate::ebpf::connections::{
    CgroupConnections, ConnectionMap, ProcessDetail, Proto, SocketInfo,
};
use crate::ebpf::identity::{IdentityMap, ProcessIdentity};
use crate::ebpf::loader::{CgroupDelta, CounterSummary};
use crate::terminal::DiffScreen;

#[test]
#[ignore = "benchmark harness: run via scripts/frame-bench.py"]
fn frame_bench_eagle() {
    /// Wall-clock render budget (owner rule: 10s A/B benchmark).
    const FRAME_BUDGET: Duration = Duration::from_secs(10);
    /// Synthetic cgroup count (25 cgroups + their eagle-eyes detail
    /// lines overflow the 80x40 row budget, so the harness exercises
    /// the truncation path too — NIGHT-boost-1 removed the hard row
    /// cap, the window is the budget).
    const CGROUPS: usize = 25;

    // Quick mode: 1s budget for smoke runs (driven by
    // scripts/frame-bench.py --quick through the environment).
    let quick = std::env::var_os("ZELYNIC_FRAME_BENCH_QUICK").is_some_and(|v| v == "1");
    let budget = if quick {
        Duration::from_secs(1)
    } else {
        FRAME_BUDGET
    };

    // Fixed-seed LCG (Numerical Recipes constants): deterministic
    // across runs, layouts, and machines.
    let mut lcg: u64 = 0x5EED_CAFE_F00D_0001;
    let mut next = move |modulus: u64| {
        lcg = lcg
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (lcg >> 33) % modulus
    };

    // Realistic label set: short and long comms, including ones long
    // enough to hit the label-column truncation path.
    let comms: [&str; CGROUPS] = [
        "alacritty",
        "firefox",
        "systemd-journald",
        "curl",
        "wget",
        "brave",
        "chrome_crashpad",
        "spotify",
        "code",
        "pipewire",
        "pacman",
        "ssh",
        "systemd-resolve",
        "kwin_wayland",
        "plasmashell",
        "dbus-daemon",
        "NetworkManager",
        "chrome",
        "telegram_desktop",
        "discord",
        "vlc",
        "git",
        "rust-analyzer proc-macro srv",
        "node",
        "thunderbird",
    ];

    let mut identity = IdentityMap::new();
    let mut conns = ConnectionMap::new();
    let mut ul_total: [u64; CGROUPS] = [0; CGROUPS];
    let mut dl_total: [u64; CGROUPS] = [0; CGROUPS];

    // Every third cgroup is multi-tenant with socket detail — the
    // owner's exact complaint shape (curl/wget inside "alacritty").
    // The busy flags toggle with the frame counter so detail lines
    // contribute realistic dirty-cell churn.
    let remotes = [
        "142.250.191.78:443",
        "1.1.1.1:443",
        "8.8.8.8:53",
        "93.184.216.34:80",
    ];

    for (i, comm) in comms.iter().enumerate() {
        let cg = i as u32 + 7_000;
        identity.insert(ProcessIdentity {
            cgroup_id: cg,
            uid: 1000,
            comm: (*comm).to_string(),
        });

        if i % 3 == 0 {
            let socket = |idx: usize| SocketInfo {
                proto: if idx == 2 { Proto::Udp } else { Proto::Tcp },
                remote: remotes[idx % remotes.len()].to_string(),
                state: if idx == 2 { "CLOSE" } else { "ESTABLISHED" },
                queued: false,
            };
            conns.insert(
                cg,
                CgroupConnections {
                    total_procs: 4,
                    socket_holders: vec![
                        ProcessDetail {
                            pid: 4_000 + i as u32,
                            comm: "curl".to_string(),
                            sockets: vec![socket(0), socket(1)],
                        },
                        ProcessDetail {
                            pid: 5_000 + i as u32,
                            comm: "wget".to_string(),
                            sockets: vec![socket(2)],
                        },
                    ],
                },
            );
        }
    }

    // Re-stamp socket busy flags per frame (fixtures stay
    // deterministic: pure function of the frame counter).
    let mut frame_no: u64 = 0;

    // NIGHT-improve-2: the diff engine + a real write sink. /dev/null
    // keeps the one-syscall-per-frame write cost in the timing without
    // polluting the marker protocol (the emitted ANSI stream contains
    // newlines and would corrupt the splitlines-based capture). Fall
    // back to an in-memory sink only if /dev/null is unavailable.
    let mut screen = DiffScreen::new();
    let mut lines: Vec<String> = Vec::with_capacity(48);
    let mut devnull = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .ok();
    let mut mem_sink = Vec::new();

    let start = Instant::now();
    let mut frames: u64 = 0;

    while start.elapsed() < budget {
        for i in (0..CGROUPS).step_by(3) {
            if let Some(detail) = conns.get_mut(i as u32 + 7_000) {
                for proc in &mut detail.socket_holders {
                    for (idx, socket) in proc.sockets.iter_mut().enumerate() {
                        socket.queued = (frame_no + idx as u64).is_multiple_of(3);
                    }
                }
                // Keep the fixture sorted the way refresh() would.
                detail.socket_holders.sort_by_key(|p| {
                    (
                        std::cmp::Reverse(p.sockets.len()),
                        std::cmp::Reverse(p.sockets.iter().any(|s| s.queued)),
                        p.pid,
                    )
                });
            }
        }
        frame_no += 1;

        let mut cgroups = Vec::with_capacity(CGROUPS);
        for i in 0..CGROUPS {
            let ul_delta = next(240_000);
            let dl_delta = next(1_400_000);
            let ul_pkts = next(200) + 1;
            let dl_pkts = next(900) + 1;
            ul_total[i] += ul_delta;
            dl_total[i] += dl_delta;
            cgroups.push(CgroupDelta {
                cgroup_id: i as u32 + 7_000,
                packets: ul_pkts,
                bytes: ul_delta,
                total_bytes: ul_total[i],
                ingress_packets: dl_pkts,
                ingress_bytes: dl_delta,
                ingress_total_bytes: dl_total[i],
            });
        }

        let summary = CounterSummary {
            total_packets: cgroups.iter().map(|c| c.packets).sum(),
            total_bytes: cgroups.iter().map(|c| c.bytes).sum(),
            total_ingress_packets: cgroups.iter().map(|c| c.ingress_packets).sum(),
            total_ingress_bytes: cgroups.iter().map(|c| c.ingress_bytes).sum(),
            cgroups,
        };

        // Frame capture protocol (NIGHT-improve-2): logical content
        // first (visual metrics + A-comparable), then the diff
        // engine's real emission (byte count reported, bytes written
        // to the sink). Pinned 80x40 — see the module docs.
        lines.clear();
        render_eagle_eyes(
            &mut lines,
            &summary,
            &[],
            &identity,
            Some(&conns),
            Duration::from_secs(1),
        );
        println_safe!("###FRAME###");
        for line in &lines {
            println_safe!("{line}");
        }
        let emitted = match &mut devnull {
            Some(sink) => screen.emit_at(80, 40, &mut lines, sink),
            None => screen.emit_at(80, 40, &mut lines, &mut mem_sink),
        };
        println_safe!("###EMIT### bytes={emitted}");
        frames += 1;
    }

    println_safe!(
        "###META### frames={frames} elapsed_ms={}",
        start.elapsed().as_millis()
    );
}
