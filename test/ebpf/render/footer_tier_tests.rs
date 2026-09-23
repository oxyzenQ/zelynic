// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Footer tier pins (NIGHT-engrave-4): the compression ladder the
//! short-terminal degradation walks down, and the RENDERED frames at
//! each tier — which lines survive where. Split from footer_tests.rs
//! when the engrave-4 rebuild pushed that file past the owner's LOC
//! cap (cosmostrix Pattern C: one file per contract, #[path]-wired
//! from src/ebpf/render/footer.rs exactly like the composition pins).

use super::{plan_footer_tier, FooterTier};
use crate::ebpf::identity::{IdentityMap, ProcessIdentity};
use crate::ebpf::loader::{CgroupDelta, CounterSummary};
use crate::ebpf::render::eagle::render_eagle_eyes_at;
use crate::ebpf::render::{FrameGeometry, SessionState};
use std::time::Duration;

fn identity_with(comms: &[(&str, u32)]) -> IdentityMap {
    let mut identity = IdentityMap::new();
    for (comm, cg) in comms {
        identity.insert(ProcessIdentity {
            cgroup_id: *cg,
            uid: 1000,
            comm: (*comm).to_string(),
        });
    }
    identity
}

/// A one-cgroup traffic frame.
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

/// Footer compression ladder (NIGHT-boost-14; NIGHT-engrave-4 re-cut
/// it for the rebuilt block — 9/8/5/3): the classic 80x24 carries
/// the full engraved block; a 13-row window drops to Compact (the
/// air above the status line goes, the owner's copyright gap
/// stays), 12 to Minimal, and the survival floor holds from 9 down.
/// The rare identities-unresolved note costs one line and moves the
/// Full boundary with it.
#[test]
fn footer_tier_ladder() {
    assert_eq!(plan_footer_tier(24, 0), FooterTier::Full);
    assert_eq!(
        plan_footer_tier(14, 0),
        FooterTier::Full,
        "14 = 4 chrome + 9 footer + 1 row"
    );
    assert_eq!(plan_footer_tier(13, 0), FooterTier::Compact);
    assert_eq!(plan_footer_tier(12, 0), FooterTier::Minimal);
    assert_eq!(plan_footer_tier(11, 0), FooterTier::Minimal);
    assert_eq!(plan_footer_tier(10, 0), FooterTier::Minimal);
    assert_eq!(plan_footer_tier(9, 0), FooterTier::Tiny);
    assert_eq!(plan_footer_tier(5, 0), FooterTier::Tiny, "survival floor");
    // The rare identities-unresolved note rides the footer and is
    // accounted: it costs one line, so every boundary moves up one.
    assert_eq!(plan_footer_tier(15, 1), FooterTier::Full);
    assert_eq!(plan_footer_tier(14, 1), FooterTier::Compact);
    assert_eq!(plan_footer_tier(10, 1), FooterTier::Tiny);
}

/// The tier degradation ladder on rendered frames (NIGHT-engrave-4
/// re-cut: 9/8/5/3): Compact drops the air above the status line
/// (the owner's gap above the copyright survives), Minimal drops the
/// census and the limit suggestion (the consumer headline survives —
/// the owner's #1 ask), Tiny drops the grid and the headline too —
/// the total row, the status line, and the copyright are the
/// survivors, as they have been since engrave-3. Rendered heights
/// carry the closing border row, so the ladder sees height-1.
#[test]
fn footer_tiers_degrade_in_the_engraved_order() {
    let identity = identity_with(&[("alacritty", 7001)]);

    let render = |height: usize| -> Vec<String> {
        let mut lines = Vec::new();
        render_eagle_eyes_at(
            &mut lines,
            &frame(7001, 500_000, 5_000),
            &[],
            &identity,
            None,
            Duration::from_secs(1),
            &mut SessionState::new(),
            Duration::from_secs(70),
            FrameGeometry { width: 80, height },
        );
        lines
    };

    // Compact (rendered height 14 — the closing border row eats
    // one, so the ladder sees 13): every line, the air above the
    // status line gone — but the owner's gap above the copyright
    // survives (the engrave-3 paragraph call): one blank, and only
    // that one.
    let compact = render(14);
    assert_eq!(compact.len(), 14, "pinned to the terminal height");
    assert!(compact
        .iter()
        .any(|l| l.contains("top consumer is alacritty")));
    assert!(compact.iter().any(|l| l.contains("packets + 1 cgroups")));
    assert!(compact.iter().any(|l| l.contains("limit target with")));
    assert!(compact
        .iter()
        .any(|l| l.contains("total usage internet in")));
    // Footer spans the block below the table territory: rows 5..13.
    let footer_rows = &compact[5..13];
    let blank_row = format!("│{}│", " ".repeat(78));
    assert_eq!(
        footer_rows.iter().filter(|l| **l == blank_row).count(),
        1,
        "Compact carries exactly one blank — the owner's gap above the copyright: {:?}",
        footer_rows
    );
    assert!(
        footer_rows[6] == blank_row && footer_rows[7].starts_with("│  v"),
        "the one blank sits directly above the copyright: {:?}",
        footer_rows
    );

    // Minimal (rendered height 11, ladder sees 10): the census and
    // the limit suggestion drop, the consumer headline and the roof
    // grid survive.
    let minimal = render(11);
    assert_eq!(minimal.len(), 11);
    assert!(minimal
        .iter()
        .any(|l| l.contains("top consumer is alacritty")));
    assert!(!minimal.iter().any(|l| l.contains("packets +")));
    assert!(!minimal.iter().any(|l| l.contains("limit target")));
    assert!(minimal
        .iter()
        .any(|l| l.contains("total usage internet in")));

    // Tiny (rendered height 10, ladder sees 9): the survival floor —
    // the grid and the headline go too; the total row, the status
    // line, and the copyright are the last three rows of content.
    let tiny = render(10);
    assert_eq!(tiny.len(), 10);
    assert!(!tiny.iter().any(|l| l.contains("top consumer")));
    assert!(!tiny.iter().any(|l| l.contains("packets +")));
    assert!(tiny.iter().any(|l| l.contains("total usage internet in")));
    assert!(tiny.iter().any(|l| l.contains("1s realtime")));
    assert!(tiny.iter().any(|l| l.contains(") by oxyzenQ")));
    // No roof grid at survival height: the row above the total row
    // is the table's own territory (the header grid or a data row),
    // never the footer's roof.
    let total_idx = tiny
        .iter()
        .position(|l| l.contains("total usage internet in"))
        .expect("total row in tiny");
    assert!(
        !tiny[total_idx - 1].starts_with("│─"),
        "the roof grid is gone at survival height: {}",
        tiny[total_idx - 1]
    );
}
