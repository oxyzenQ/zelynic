// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The steady-state floor pin (night-frontier-Z11 stage ladder;
//! night-frontier-Z13-6 moves it to its own file at the 600-LOC
//! owner cap — one file per contract, the bench module's own
//! wiring discipline, Pattern C like every test/ file).
//!
//! `steady_state_frame_composition_allocates_zero` measures the
//! QUIETEST of N busy frames through the counting global allocator
//! ([`super::alloc_lens`]) and asserts the Z13 ceiling: the full-duty
//! ranked frame's composition allocates ZERO heap events — title, bar,
//! board, footer, panel, pin, the whole walk. The ladder's ratchet:
//! the ceiling lowers in the same commit that closes a named site.

use super::BaselineLane;
use super::{SessionState, render_eagle_eyes};
use crate::ebpf::connections::{
    CgroupConnections, ConnectionMap, ProcessDetail, Proto, SocketInfo,
};
use crate::ebpf::identity::{IdentityMap, ProcessIdentity};
use crate::ebpf::loader::{CgroupDelta, CounterSummary};
use crate::ebpf::render::ScrollState;
use crate::terminal::DiffScreen;
use std::time::Duration;

// ━━ the allocation pin (night-frontier-Z4) ━━━━━━━━━━━━━━━━━━━━━━
// The lens's consumer: the live frame's steady state must perform
// ZERO heap events — the composition pops pooled lines, the engine
// diffs through its retained buffers (NIGHT-blade-16), and the
// recycle returns the frame's strings for the next frame to
// consume. The fixture is the harness's own shape shrunk to nine
// cgroups (three carrying socket detail, the busy flags toggling on
// the same 3-frame cycle); the summary's totals step per frame so
// every row re-renders — the BUSY path, where a lazy pool would
// leak allocations an idle frame never touches. Fixture assembly
// sits OUTSIDE every lens window; the window covers exactly
// render -> emit -> recycle, and the sink discards without
// allocating (the bench's /dev/null costs a syscall; the pin costs
// nothing).

#[test]
fn steady_state_frame_composition_allocates_zero() {
    use super::alloc_lens;
    use super::recycle_frame_lines;

    struct DiscardSink;
    impl std::io::Write for DiscardSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    const CGROUPS: usize = 9;
    const COMMS: [&str; CGROUPS] = [
        "alacritty",
        "firefox",
        "systemd-journald",
        "curl",
        "wget",
        "brave",
        "chrome",
        "spotify",
        "code",
    ];
    const REMOTES: [&str; 4] = [
        "142.250.191.78:443",
        "1.1.1.1:443",
        "8.8.8.8:53",
        "93.184.216.34:80",
    ];

    // Static fixture: identity + socket detail, the harness's shape
    // (every third cgroup multi-tenant with RESOLVED cookies, one
    // dup'd-fd pair — the dedup's collapse case — riding along).
    let mut identity = IdentityMap::new();
    let mut conns = ConnectionMap::new();
    for (i, comm) in COMMS.iter().enumerate() {
        let cg = i as u32 + 7_000;
        identity.insert(ProcessIdentity {
            cgroup_id: cg,
            uid: 1000,
            comm: (*comm).to_string(),
        });
        if i % 3 == 0 {
            let cookie_base = 0x5EED_0000_u64 + 16 * i as u64;
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

    let mut screen = DiffScreen::new();
    let mut lines: Vec<String> = Vec::with_capacity(48);
    let mut session = SessionState::new();
    let mut scroll = ScrollState::new();
    let lane = BaselineLane::new();
    let mut sink = DiscardSink;

    // The busy stream: totals step per frame on the 3-cycle, so the
    // rate columns (and every row) re-render every frame.
    let mut dl_totals = [0u64; CGROUPS];
    let mut ul_totals = [0u64; CGROUPS];
    let summary_for = |frame: u64, dl: &mut [u64], ul: &mut [u64]| {
        let dl_step = 400_000 + (frame % 3) * 250_000;
        let ul_step = 90_000 + (frame % 3) * 60_000;
        let mut cgroups = Vec::with_capacity(CGROUPS);
        for (i, slot) in dl.iter_mut().enumerate().take(CGROUPS) {
            let dl_delta = dl_step + 1_000 * i as u64;
            let ul_delta = ul_step + 300 * i as u64;
            *slot += dl_delta;
            ul[i] += ul_delta;
            cgroups.push(CgroupDelta {
                cgroup_id: i as u32 + 7_000,
                packets: ul_delta / 900 + 1,
                bytes: ul_delta,
                total_bytes: ul[i],
                ingress_packets: dl_delta / 1_400 + 1,
                ingress_bytes: dl_delta,
                ingress_total_bytes: *slot,
            });
        }
        CounterSummary {
            total_packets: cgroups.iter().map(|c| c.packets).sum(),
            total_bytes: cgroups.iter().map(|c| c.bytes).sum(),
            total_ingress_packets: cgroups.iter().map(|c| c.ingress_packets).sum(),
            total_ingress_bytes: cgroups.iter().map(|c| c.ingress_bytes).sum(),
            cgroups,
        }
    };

    // Warmup: pool, engine buffers, and session maps reach their
    // steady shapes (the first frames allocate — that is the point).
    for frame in 0..12 {
        let summary = summary_for(frame, &mut dl_totals, &mut ul_totals);
        render_eagle_eyes(
            &mut lines,
            &summary,
            &[],
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

    // Measured: busy frames, each one a closed lens window, walked
    // until a contamination-free window proves the composition's own
    // count. The lens's counter is GLOBAL, so the battery's parallel
    // tests leak allocations into a window (the musl twin read 394
    // worst where the quiet count was ~172 — contamination only
    // ADDS). The honest statistic is the QUIETEST frame: a
    // contamination-free window reads the composition's own count,
    // and a real regression raises EVERY frame including the
    // quietest one. night-frontier-Z13-12: the original walk sampled
    // 32 windows and the musl twin's battery landed a run where ALL
    // 32 saw foreign events (quietest = 3 on a loaded runner, the
    // pins reading zero on every uncontaminated lane) — the walk
    // keeps STEPPING now, bounded at 4096 busy windows, and stops at
    // the first contamination-free one. A real regression never reads
    // the zero its floor demands, so the assert keeps its power; the
    // scheduler lottery is out of the verdict's way.
    // The patience budget: 4096 busy windows bound the walk (each is
    // microseconds; the battery never feels it — the point is that an
    // all-contaminated 32-window sample, a scheduling artifact, does
    // not fail the pin).
    const QUIET_WALK: u64 = 4096;
    let mut quiet = usize::MAX;
    let mut walked = 0usize;
    for frame in 12..12 + QUIET_WALK {
        let summary = summary_for(frame, &mut dl_totals, &mut ul_totals);
        let before = alloc_lens::count();
        render_eagle_eyes(
            &mut lines,
            &summary,
            &[],
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
        walked += 1;
        if quiet == FLOOR {
            // The zero is proven: one window carried no foreign event
            // and no composition event. The walk stops here.
            break;
        }
    }
    // The floor pin (night-frontier-Z4, stage 1; Z11 stages 1-2
    // lower): the QUIETEST of the walked busy frames must stay under
    // FLOOR heap events. The observed quiet counts on the glibc dev box:
    // 249 pre-pool, 164 after Z4's pool (~172 musl), 150 after Z11
    // stage 1 (the title bar, the grid lines, the sweep memo's clone
    // path, and the rail escapes ride into-twins), 100 after stage 2
    // (the border wrap composes IN the pooled rows now — the fit, the
    // background splice, and the rails write into the buffer the
    // call site handed over; the closing row and the background
    // escape ride retained buffers too) — the walk COUNT is code, the
    // heap events are code x allocator, so the ceiling carries
    // cross-allocator headroom. FLOOR sits below the pre-pool era, so
    // the pool's win is locked — reverting it trips this pin, as does
    // any regression that raises every frame past the ceiling. The
    // named remainder (each a stage-4 reopen, the NIGHT-blade-16
    // staged ladder): the detail tree's holders' walk scratch (the
    // outer Vec plus one Vec per holder, a handful of events), the
    // signature engraving's internals (the output layer's identity
    // seat), and the focus view's own tree (full_detail_lines, the
    // ranked board's Vec - outside this pin's window). Z11 stage 3
    // closed the footer's owned-Vec builders (every census, speed
    // pair, limit, legend, status, and signature row writes into a
    // pooled row now) and the detail tree's line composition; the
    // quiet count measured 34 on the same box (86 after stage 3a,
    // 100 after stage 2, 150 after stage 1, 164 after Z4's pool,
    // 249 pre-pool — and 30 after Z13 stage 4a, the holders' walk
    // scratch closed: the outer Vec, the per-holder endpoint Vecs,
    // and the ranked copy all ride the capacity-warm HOLDER_WALK
    // index buffer now — and 27 after stage 4b, the signature
    // engraving's static seat (the footer's push_str reads a
    // &'static str; the per-frame format! and brand wrap are gone).
    // Z13 stage 4c closed the REST of the walk: the board composes
    // in the session's own scratch and filters in place, the footer
    // assembles into its retained block with the headline name
    // resolving into a warm buffer, the per-row detail block rides
    // its retained scratch (every dropped row handed back to the
    // pool — the grey_trim swap and the scroll note included), the
    // panel docks from its retained block, the blank pad rows pop
    // the pool instead of growing zero-capacity strings under the
    // wrap, and the pool's fresh carve covers the steady row shapes.
    // The quiet count measured 0: the composition half of the render
    // loop allocates NOTHING in steady state — the floor is the
    // zero it always climbed toward. A change that closes a named
    // site LOWERS the floor (and should, in the same commit that
    // closes it); a change that RAISES it trips the pin.
    const FLOOR: usize = 0;
    // The measured number on the record: every run prints the quiet
    // count, so the floor's own trend is visible in the battery's
    // output (night-frontier-Z11's ladder law — a closed site LOWERS
    // this number, and the print is its receipt).
    eprintln!(
        "steady-state frame allocations: quietest of {walked} walked frames = {quiet} (floor {FLOOR})"
    );
    assert_eq!(
        quiet, FLOOR,
        "steady-state frame allocations: the quietest of {walked} walked frames allocated \
         {quiet} (floor {FLOOR}) — the composition's zero-heap law regressed: every \
         window the walk sampled, contamination-free ones included, allocated, and \
         the pin holds the zero the ladder climbed to"
    );
}
