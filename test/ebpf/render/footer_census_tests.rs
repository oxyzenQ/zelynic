// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Footer census pins (NIGHT-engrave-7) — the counter-explosion
//! ladder and the limit line's brand tier, split from footer_tests.rs
//! when the new pins pushed that file past the owner's LOC cap (one
//! file per contract, the footer tree's own split discipline).
//! Helpers are local: the classic 80x24 geometry the pinned frames
//! render at.

use crate::ebpf::identity::IdentityMap;
use crate::ebpf::loader::{CgroupDelta, CounterSummary};
use crate::ebpf::render::eagle::render_eagle_eyes_at;
use crate::ebpf::render::{FrameGeometry, SessionState};
use std::time::Duration;

/// The 80x24 classic terminal (the piped-fallback probe).
fn classic() -> FrameGeometry {
    FrameGeometry {
        width: 80,
        height: 24,
    }
}

/// A one-cgroup traffic frame (the footer_tests shape, local copy —
/// the split keeps each pin file self-contained).
fn frame(cg: u32, dl: u64, ul: u64) -> CounterSummary {
    CounterSummary {
        total_packets: 1,
        total_bytes: ul,
        total_ingress_packets: 1,
        total_ingress_bytes: dl,
        cgroups: vec![CgroupDelta {
            cgroup_id: cg,
            packets: 1,
            bytes: ul,
            total_bytes: ul,
            ingress_packets: 1,
            ingress_bytes: dl,
            ingress_total_bytes: dl,
        }],
    }
}

/// NIGHT-engrave-7 (the counter-explosion hardening): the census
/// line's packet count rides the SI compact ladder. The owner's
/// report — "24 packets" at open, "2244843 packets" eight hours
/// later — ends here: the session accumulator still counts every
/// packet, the display reads what a human parses at a glance.
#[test]
fn footer_census_packets_ride_the_si_compact_ladder() {
    let mut lines = Vec::new();
    let summary = CounterSummary {
        total_packets: 2_244_843,
        total_bytes: 700_000,
        total_ingress_packets: 2_244_843,
        total_ingress_bytes: 900_000,
        cgroups: vec![CgroupDelta {
            cgroup_id: 7001,
            packets: 1_122_421,
            bytes: 700_000,
            total_bytes: 700_000,
            ingress_packets: 1_122_422,
            ingress_bytes: 900_000,
            ingress_total_bytes: 900_000,
        }],
    };
    render_eagle_eyes_at(
        &mut lines,
        &summary,
        &[],
        &IdentityMap::new(),
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &mut SessionState::new(),
        Duration::from_secs(3600),
        classic(),
    );
    let joined = lines.join("\n");
    assert!(
        joined.contains("2.2M packets + 1 cgroups"),
        "the eight-hour census reads the compact figure, got: {joined:?}"
    );
    // The fresh-start figure stays exact — the small-count contract.
    let mut fresh = Vec::new();
    render_eagle_eyes_at(
        &mut fresh,
        &frame(7001, 500, 500),
        &[],
        &IdentityMap::new(),
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &mut SessionState::new(),
        Duration::from_secs(2),
        classic(),
    );
    assert!(
        fresh.join("\n").contains("2 packets + 1 cgroups"),
        "small counts render verbatim, never 1.0K"
    );
}

/// NIGHT-engrave-7: the limit line's command rides the ACTIVE
/// theme's brand tier — purple under netrunner, each theme's own
/// accent under itself (the owner's call). A source-scan pin (the
/// mouse-contract precedent — process-wide capability forcing is
/// OnceLock-poisoned in the shared test binary, so composition pins
/// of this shape ride the source): the footer must paint the
/// suggestion through `brand(...)`, never the CLI's hardwired
/// suggestion white.
#[test]
fn limit_line_rides_the_brand_tier() {
    let footer_src =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ebpf/render/footer.rs");
    let src = std::fs::read_to_string(&footer_src)
        .unwrap_or_else(|e| panic!("footer source readable: {e}"));
    assert!(
        src.contains("brand(&format!(\"'sudo zelynic ss {name} {SUGGESTED_LIMIT}'\"))"),
        "the limit command must render through brand() — the theme-aware tier"
    );
    assert!(
        !src.contains("suggestion("),
        "suggestion white is the CLI error surface's own tier; the monitor's \
         actionable line follows the theme"
    );
}
