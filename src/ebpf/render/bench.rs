// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Frame benchmark harness (NIGHT-hunt-7 A/B protocol).
//!
//! Renders synthetic observe frames through the REAL print path so
//! scripts/frame-bench.py can compute the owner's visual and
//! performance metrics (density gini, frame entropy, fps, dirty
//! cells). Synthetic traffic evolves from a fixed-seed LCG, so a run
//! BEFORE a layout change and one AFTER see byte-identical data —
//! the only variable is the layout engine itself.
//!
//! Root/eBPF is NOT required: the render layer is exercised with an
//! in-memory CounterSummary, so the harness runs in sandboxes where
//! `observe` cannot attach (the same constraint the NIGHT-hunt-6
//! commit documented for the system benchmark).

use std::time::{Duration, Instant};

use super::render_observe_frame;
use crate::ebpf::identity::{IdentityMap, ProcessIdentity};
use crate::ebpf::loader::{CgroupDelta, CounterSummary};

#[test]
#[ignore = "benchmark harness: run via scripts/frame-bench.py"]
fn frame_bench_observe() {
    /// Wall-clock render budget (owner rule: 10s A/B benchmark).
    const FRAME_BUDGET: Duration = Duration::from_secs(10);
    /// Synthetic cgroup count (25 > the 20-row display cap, so the
    /// harness exercises the row-truncation path too).
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
    let mut ul_total: [u64; CGROUPS] = [0; CGROUPS];
    let mut dl_total: [u64; CGROUPS] = [0; CGROUPS];

    for (i, comm) in comms.iter().enumerate() {
        identity.insert(ProcessIdentity {
            cgroup_id: i as u32 + 7_000,
            uid: 1000,
            comm: (*comm).to_string(),
        });
    }

    let start = Instant::now();
    let mut frames: u64 = 0;

    while start.elapsed() < budget {
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
            });
        }

        let summary = CounterSummary {
            total_packets: cgroups.iter().map(|c| c.packets).sum(),
            total_bytes: cgroups.iter().map(|c| c.bytes).sum(),
            total_ingress_packets: cgroups.iter().map(|c| c.ingress_packets).sum(),
            total_ingress_bytes: cgroups.iter().map(|c| c.ingress_bytes).sum(),
            cgroups,
        };

        // Frame delimiter consumed by scripts/frame-bench.py.
        println_safe!("###FRAME###");
        render_observe_frame(&summary, &identity, Duration::from_secs(1));
        frames += 1;
    }

    println_safe!(
        "###META### frames={frames} elapsed_ms={}",
        start.elapsed().as_millis()
    );
}
