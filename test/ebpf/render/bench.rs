// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Frame benchmark harness (NIGHT-hunt-7 A/B protocol; retargeted
//! to the eagle-eyes renderer by NIGHT-boost-1).
//!
//! Renders synthetic eagle-eyes frames through the REAL render path
//! so scripts/bench/frame-bench.py can compute the owner's visual and
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
//! NIGHT-hunt-29 (the lts-7 residual closed): the fixture now
//! RESOLVES synthetic cookies — every socket carries a kernel-shaped
//! u64 (unique per socket, one dup'd-fd pair sharing a cookie, the
//! shared-socket-table-row shape the dedup exists for) and every
//! frame runs the monitor's exact join wiring: socket_cookies() (the
//! deduped key set, the lts-7 HashSet path at frame cadence), a
//! synthetic cookie-map result (the figures the loader's point
//! lookups would return — lifetime counters, deterministic in
//! (cookie, frame), never an LCG draw so the traffic stream the A/B
//! protocol freezes stays untouched), and apply_socket_bytes (the
//! install the renderers read). The cookie: None era's blind spot —
//! a bench whose byte-exactness claims never covered the join lane —
//! is closed: the dedup, the install, and the [dl X | ul Y] figure
//! rendering are measured frame work now.
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

use super::BaselineLane;
use crate::ebpf::render::ScrollState;
use std::time::{Duration, Instant};

use super::{SessionState, render_eagle_eyes};
use crate::ebpf::connections::{
    CgroupConnections, ConnectionMap, ProcessDetail, Proto, SocketInfo,
};
use crate::ebpf::identity::{IdentityMap, ProcessIdentity};
use crate::ebpf::loader::{CgroupDelta, CounterSummary, SocketBytes};
use crate::terminal::DiffScreen;

#[test]
#[ignore = "benchmark harness: run via scripts/bench/frame-bench.py"]
fn frame_bench_eagle() {
    /// Wall-clock render budget (owner rule: 10s A/B benchmark).
    const FRAME_BUDGET: Duration = Duration::from_secs(10);
    /// Synthetic cgroup count (25 cgroups + their eagle-eyes detail
    /// lines overflow the 80x40 row budget, so the harness exercises
    /// the truncation path too — NIGHT-boost-1 removed the hard row
    /// cap, the window is the budget).
    const CGROUPS: usize = 25;

    // Quick mode: 1s budget for smoke runs (driven by
    // scripts/bench/frame-bench.py --quick through the environment).
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
            // NIGHT-hunt-29: RESOLVED synthetic cookies, kernel-shaped
            // u64s unique per socket across the fixture, plus ONE
            // dup'd-fd pair (fd 3 holds fd 0's socket again — same
            // remote, same cookie, the shared-socket-table-row shape
            // the walk matches twice and the dedup absorbs). The
            // cookie: None era was lts-7's documented residual: the
            // join lane (dedup + install + figure rendering) never
            // ran under this harness.
            let cookie_base = 0x5EED_0000_u64 + 16 * i as u64;
            let socket = |idx: usize| SocketInfo {
                proto: if idx == 2 { Proto::Udp } else { Proto::Tcp },
                remote: remotes[if idx == 3 { 0 } else { idx } % remotes.len()].to_string(),
                state: if idx == 2 { "CLOSE" } else { "ESTABLISHED" },
                queued: false,
                cookie: Some(match idx {
                    // fd 3 is the dup'd fd: fd 0's socket, fd 0's
                    // cookie — the dedup's collapse case.
                    3 => cookie_base + 1,
                    _ => cookie_base + 1 + idx as u64,
                }),
            };
            conns.insert(
                cg,
                CgroupConnections {
                    total_procs: 4,
                    socket_holders: vec![
                        ProcessDetail {
                            pid: 4_000 + i as u32,
                            comm: "curl".to_string(),
                            sockets: vec![socket(0), socket(1), socket(3)],
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

    // NIGHT-boost-5: the session leaderboard rides the harness the
    // same way monitor.rs wires it — every frame's deltas fold in, so
    // the TOTAL column and the session ranking are part of the
    // measured render path, not an unmeasured add-on.
    let mut session = SessionState::new();
    // night-private-research-7: the previous frame's ABSOLUTE join —
    // the differencing baseline the arrival fold below subtracts
    // (the monitor loop's own join_prev twin, so the bench measures
    // the fold's per-frame cost).
    let mut join_prev: std::collections::HashMap<u64, SocketBytes> =
        std::collections::HashMap::new();
    // night-improve-58: the resting scroll state (the harness
    // renders the pre-scroll layout, A/B-comparable).
    let mut scroll = ScrollState::new();

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

        // The per-frame cookie join (NIGHT-hunt-29): the monitor
        // loop's exact wiring on synthetic cookies — socket_cookies()
        // for the deduped key set (the lts-7 HashSet path, now
        // measured at frame cadence: 36 walked sockets, 27 distinct
        // keys, the dup'd fd absorbed), a synthetic cookie-map result
        // standing in for the loader's point-lookups (absolute
        // counters, a pure function of (cookie, frame) — NO LCG
        // draws, so the traffic stream the A/B protocol freezes stays
        // byte-identical and the only visual delta vs the cookie:
        // None era is the figures themselves).
        // night-private-research-7: the monitor's EXACT arrival fold
        // rides here too — the absolutes are differenced against the
        // previous frame's join (join_prev below) and only the
        // frame's movers install, so the A/B measures the differencing
        // pass as real frame work (the renderers then divide by the
        // span, the per-second vocabulary the suffix pins froze).
        let cookies = conns.socket_cookies();
        let mut join = std::collections::HashMap::with_capacity(cookies.len());
        for &cookie in &cookies {
            let lane = (cookie % 97) + 1;
            // night-improve-59 (the fixture's own blind spot,
            // closed): the absolutes now step their per-frame
            // deltas on a 3-frame cycle — the real-world shape the
            // arrival fold actually sees (mover deltas that CHANGE
            // frame to frame, rates crossing SI tiers), which the
            // constant-delta era could not measure at all: a
            // steady-rate-column layout change was invisible to the
            // harness (the rates never changed, so the suffixes
            // never churned) and the whole measured delta was the
            // busy-toggle shift on wider suffixes. Still a pure
            // function of (cookie, frame) — the A/B stream stays
            // frozen for before/after comparisons.
            let dl_step = 12_000 + (frame_no % 3) * 6_000;
            let ul_step = 1_400 + (frame_no % 3) * 900;
            join.insert(
                cookie,
                SocketBytes {
                    dl: lane * 78_000 + frame_no * lane * dl_step,
                    ul: lane * 9_000 + frame_no * lane * ul_step,
                },
            );
        }
        let movers: std::collections::HashMap<u64, SocketBytes> = join
            .iter()
            .filter_map(|(cookie, now)| {
                let prev = join_prev.get(cookie).copied().unwrap_or_default();
                let frame = SocketBytes {
                    dl: now.dl.saturating_sub(prev.dl),
                    ul: now.ul.saturating_sub(prev.ul),
                };
                (frame.dl > 0 || frame.ul > 0).then_some((*cookie, frame))
            })
            .collect();
        conns.apply_socket_bytes(movers);
        join_prev = join;

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
            Duration::from_secs(1),
            &mut session,
            &BaselineLane::new(),
            // Pinned uptime (NIGHT-boost-17): a FIXED 90s so A/B
            // captures stay byte-comparable across layout changes —
            // a live clock would drift the footer text between runs.
            Duration::from_secs(90),
            &mut scroll,
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
