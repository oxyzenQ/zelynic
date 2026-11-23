// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The focus view's zero pin (night-frontier-Z13-5 stage 5;
//! night-frontier-Z13-6 moves it to its own file at the 600-LOC
//! owner cap — one file per contract, the bench module's own
//! wiring discipline, Pattern C like every test/ file).
//!
//! `steady_state_focus_frame_allocates_zero` extends the lens to the
//! single-cgroup focus frame: one watched token, one live cgroup, the
//! deep detail tree, the signature engraving, the whole focus walk —
//! and the counting allocator reads ZERO heap events on the quietest
//! of N busy frames. The lens ceiling reaches the single-cgroup
//! frame; the htop/tmux/vim class allocates per frame, this one does
//! not (the craft ceiling the Z13 section records).

use super::BaselineLane;
use super::{SessionState, render_eagle_eyes};
use crate::ebpf::connections::{
    CgroupConnections, ConnectionMap, ProcessDetail, Proto, SocketInfo,
};
use crate::ebpf::identity::{IdentityMap, ProcessIdentity};
use crate::ebpf::loader::{CgroupDelta, CounterSummary, SocketBytes};
use crate::ebpf::render::ScrollState;
use crate::terminal::DiffScreen;
use std::time::Duration;

// ━━ the focus view's allocation pin (night-frontier-Z13 stage 5) ━
// The lens extended to the single-cgroup view: the focus frame is a
// steady-state frame too (the monitor spends WHOLE EPISODES inside
// it — an operator dissecting one app), so its composition carries
// the same zero-heap law the ranked frame earned in stage 4c. The
// fixture is the focus view's own shape: ONE cgroup, two socket
// holders (the tree's both shapes — one inline single-endpoint,
// one header plus children), RESOLVED cookies whose per-frame
// movers install (the endpoint figures branch renders), and a LIVE
// baseline word seeded through the lane's own fold (the conditional
// grey row renders — the empty-lane shape would dodge the phrase
// family the ranked pin never windowed). The busy flags and the
// movers step per frame on the same 3-cycle discipline — the BUSY
// path, where a lazy pool would leak allocations an idle frame
// never touches. Fixture assembly sits OUTSIDE every lens window;
// the window covers exactly render -> emit -> recycle, and the
// sink discards without allocating.
#[test]
fn steady_state_focus_frame_allocates_zero() {
    use super::alloc_lens;
    use super::recycle_frame_lines;
    use crate::ebpf::limiter::Target;

    struct DiscardSink;
    impl std::io::Write for DiscardSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    const CGROUP: u32 = 7_000;
    const REMOTES: [&str; 4] = [
        "142.250.191.78:443",
        "1.1.1.1:443",
        "8.8.8.8:53",
        "93.184.216.34:80",
    ];

    // Static fixture: the focused cgroup's identity and its socket
    // detail — holder one carries two TCP endpoints (the header plus
    // children shape), holder two one UDP endpoint (the inline
    // shape); every socket rides a resolved cookie so the per-frame
    // mover install lights the endpoint figures.
    let mut identity = IdentityMap::new();
    let mut conns = ConnectionMap::new();
    identity.insert(ProcessIdentity {
        cgroup_id: CGROUP,
        uid: 1000,
        comm: "brave".to_string(),
    });
    let cookie_base = 0x5EED_00F0_u64;
    let socket = |idx: usize| SocketInfo {
        inode: 42,
        proto: if idx == 2 { Proto::Udp } else { Proto::Tcp },
        remote: REMOTES[idx % REMOTES.len()].to_string(),
        state: if idx == 2 { "CLOSE" } else { "ESTABLISHED" },
        queued: false,
        cookie: Some(cookie_base + 1 + idx as u64),
        deep: None,
    };
    conns.insert(
        CGROUP,
        CgroupConnections {
            total_procs: 2,
            socket_holders: vec![
                ProcessDetail {
                    pid: 4_001,
                    comm: "brave".to_string(),
                    sockets: vec![socket(0), socket(1)],
                },
                ProcessDetail {
                    pid: 4_002,
                    comm: "curl".to_string(),
                    sockets: vec![socket(2)],
                },
            ],
        },
    );
    let cookies: [u64; 3] = [cookie_base + 1, cookie_base + 2, cookie_base + 3];

    let mut screen = DiffScreen::new();
    let mut lines: Vec<String> = Vec::with_capacity(48);
    let mut session = SessionState::new();
    let mut scroll = ScrollState::new();
    let mut lane = BaselineLane::new();
    // A live baseline word: the focus frame's conditional grey row
    // renders through the lane's own fold (seed_for_pins, the eagle
    // composition pins' seam) — the phrase family is IN this window.
    lane.seed_for_pins(CGROUP, 128_000);

    let mut sink = DiscardSink;
    let tokens = [Target::CgroupId(CGROUP)];

    // The busy stream: the focused cgroup's totals step per frame on
    // the 3-cycle, so the key/value rows re-render every frame; the
    // sockets' movers install from stepping absolute counters, the
    // same differencing fold the monitor loop runs.
    let summary_for = |frame: u64| -> CounterSummary {
        let dl_delta = 1_400_000 + (frame % 3) * 250_000;
        let ul_delta = 90_000 + (frame % 3) * 60_000;
        CounterSummary {
            total_packets: 141,
            total_bytes: ul_delta,
            total_ingress_packets: 1001,
            total_ingress_bytes: dl_delta,
            cgroups: vec![CgroupDelta {
                cgroup_id: CGROUP,
                packets: 141,
                bytes: ul_delta,
                total_bytes: ul_delta * (frame + 1),
                ingress_packets: 1001,
                ingress_bytes: dl_delta,
                ingress_total_bytes: dl_delta * (frame + 1),
            }],
        }
    };

    // Warmup: pool, engine buffers, session maps, and the lane's
    // ring reach their steady shapes (the first frames allocate).
    let mut join_prev: std::collections::HashMap<u64, SocketBytes> =
        std::collections::HashMap::new();
    for frame in 0..12u64 {
        for holder in &mut conns.get_mut(CGROUP).unwrap().socket_holders {
            for (idx, s) in holder.sockets.iter_mut().enumerate() {
                s.queued = (frame + idx as u64).is_multiple_of(3);
            }
        }
        let mut join: std::collections::HashMap<u64, SocketBytes> =
            std::collections::HashMap::new();
        for (i, cookie) in cookies.iter().enumerate() {
            let lane_no = (cookie % 97) + 1;
            let dl_step = 12_000 + (frame % 3) * 6_000;
            let ul_step = 1_400 + (frame % 3) * 900;
            join.insert(
                *cookie,
                SocketBytes {
                    dl: lane_no * 78_000 + frame * lane_no * dl_step + 1_000 * i as u64,
                    ul: lane_no * 9_000 + frame * lane_no * ul_step + 100 * i as u64,
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

        let summary = summary_for(frame);
        render_eagle_eyes(
            &mut lines,
            &summary,
            &tokens,
            &identity,
            Some(&conns),
            Duration::from_secs(1),
            Duration::from_secs(1),
            &mut session,
            &lane,
            Duration::from_secs(90),
            &mut scroll,
            false,
        );
        screen.emit_at(80, 40, &mut lines, &mut sink);
        recycle_frame_lines(&mut lines);
    }

    // Measured: 32 busy frames, each one a closed lens window, the
    // QUIETEST frame the statistic (the ranked pin's contamination
    // law — the counter is GLOBAL, the battery's parallel tests leak
    // into a window, and a real regression raises EVERY frame).
    let mut quiet = usize::MAX;
    for frame in 12u64..44 {
        for holder in &mut conns.get_mut(CGROUP).unwrap().socket_holders {
            for (idx, s) in holder.sockets.iter_mut().enumerate() {
                s.queued = (frame + idx as u64).is_multiple_of(3);
            }
        }
        let mut join: std::collections::HashMap<u64, SocketBytes> =
            std::collections::HashMap::new();
        for (i, cookie) in cookies.iter().enumerate() {
            let lane_no = (cookie % 97) + 1;
            let dl_step = 12_000 + (frame % 3) * 6_000;
            let ul_step = 1_400 + (frame % 3) * 900;
            join.insert(
                *cookie,
                SocketBytes {
                    dl: lane_no * 78_000 + frame * lane_no * dl_step + 1_000 * i as u64,
                    ul: lane_no * 9_000 + frame * lane_no * ul_step + 100 * i as u64,
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

        let summary = summary_for(frame);
        let before = alloc_lens::count();
        render_eagle_eyes(
            &mut lines,
            &summary,
            &tokens,
            &identity,
            Some(&conns),
            Duration::from_secs(1),
            Duration::from_secs(1),
            &mut session,
            &lane,
            Duration::from_secs(90),
            &mut scroll,
            false,
        );
        screen.emit_at(80, 40, &mut lines, &mut sink);
        recycle_frame_lines(&mut lines);
        let allocs = alloc_lens::count() - before;
        if allocs < quiet {
            quiet = allocs;
        }
    }
    // The floor pin (night-frontier-Z13 stage 5): the QUIETEST of
    // the 32 busy focus frames must sit at FLOOR heap events. The
    // observed quiet counts on the glibc dev box: 114 at the probe
    // (the fresh lens window), 85 after stage 5a (the focus tree's
    // retained scratch and its pooled rows), 7 after stage 5b (the
    // key/value block and the frame chrome pooled, the into-twin
    // formatters carrying the bytes), 2 after stage 5c's first half
    // (the resolver's stack lane and the phrase twins), and 0 once
    // the stage closed the LAST event — the title scratch's missing
    // recycle, the one slot the frame popped and never returned, the
    // starvation the closing row's pop paid every frame. The floor is
    // the zero the ladder climbed to, the ranked pin's law carried to
    // the single-cgroup view. A change that closes a named site
    // LOWERS the floor (and should, in the same commit that closes
    // it); a change that RAISES it trips the pin.
    const FLOOR: usize = 0;
    // The measured number on the record: every run prints the quiet
    // count, so the floor's own trend is visible in the battery's
    // output (the print is its receipt).
    eprintln!(
        "steady-state FOCUS frame allocations: quietest of 32 frames = {quiet} (floor {FLOOR})"
    );
    assert_eq!(
        quiet, FLOOR,
        "steady-state FOCUS frame allocations: the quietest of 32 frames allocated {quiet} \
         (floor {FLOOR}) — the focus view's zero-heap law regressed: some frame \
         allocated, and the pin holds the floor the ladder climbed to"
    );
}