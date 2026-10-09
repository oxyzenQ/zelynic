// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! NIGHT-engrave-10 dock pins: the baseline panel's bottom-dock
//! contract. The panel renders into a scratch buffer in the eagle
//! composition and lands flush against the pinned footer — the
//! blank slack rides between the table and the panel's opening
//! separator, NEVER between the verdict rows and the top-consumer
//! headline they answer to. Took its own tree when the pin pushed
//! eagle_tests past the owner's LOC cap (the same one-file-per-
//! contract split the target filter and the CJK width family took).

use super::*;
use crate::ebpf::loader::CgroupDelta;
use crate::ebpf::render::ScrollState;

/// One traffic frame for `cg` with the given per-frame deltas (the
/// eagle_tests fixture, carried self-contained — Pattern C's rule).
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

/// The dock law, pinned at both a tall and the classic height: the
/// law holds at every size, the slack is simply whatever each
/// height leaves. The lane is seeded through the cfg(test) seam
/// (one read carrying one live window); the footer grid riding
/// DIRECTLY under the panel's last row is the owner's exact
/// masterclass shape — the baseline police section keeps near the
/// bottom, just above "top consumer".
#[test]
fn baseline_panel_docks_flush_above_the_footer() {
    for height in [40, 24] {
        let mut lane = BaselineLane::new();
        lane.seed_for_pins(7001, 40_000);
        let mut lines = Vec::new();
        render_eagle_eyes_at(
            &mut lines,
            &frame(7001, 1_400_000, 240_000),
            &[],
            &IdentityMap::new(),
            None,
            Duration::from_secs(1),
            Duration::from_secs(1),
            &mut SessionState::new(),
            &lane,
            Duration::from_secs(70),
            FrameGeometry { width: 80, height },
            &mut ScrollState::new(),
        );
        assert_eq!(lines.len(), height, "the frame stays pinned to the height");
        let joined = lines.join("\n");
        // The panel's verdict row: the seeded read folds the whole
        // completed horizon — six quiet windows (real zero samples,
        // the lane's own law) plus the one live window, so the
        // verdict reads `learning 7/8`.
        let row = lines
            .iter()
            .position(|l| l.contains("learning 7/8"))
            .unwrap_or_else(|| panic!("height {height}: no panel row in: {joined}"));
        // The masterclass law: the footer's roof grid lands DIRECTLY
        // under the panel's last row — no blank slack below the
        // panel, at any height.
        assert!(
            lines[row + 1].contains('─'),
            "engrave-10: the footer grid rides directly under the panel's last row \
             (height {height}): {:?}",
            lines[row + 1]
        );
        assert!(
            lines[row + 2].contains("top consumer is"),
            "the consumer headline follows its roof grid (height {height}): {:?}",
            lines[row + 2]
        );
        // The panel's own shape is intact: header above the row.
        assert!(
            lines[row - 1].contains("baseline · policy aggregate"),
            "the lens header rides above the verdict row (height {height})"
        );
        // The slack lives strictly ABOVE the panel: blanks between
        // the table's last row and the panel's opening air (row-3),
        // never a blank at row-2 or row-1 (the panel's grid and
        // header) — the gap the owner drew moved, not grew. A blank
        // row is rails and spaces only (the border wrap pads every
        // line, so trim() alone can never see one).
        let blank = |l: &str| l.chars().all(|c| c == ' ' || c == '│');
        assert!(
            !blank(&lines[row - 2]) && !blank(&lines[row - 1]),
            "the panel's grid and header are solid rows (height {height})"
        );
        let rank1 = lines
            .iter()
            .position(|l| l.starts_with(" │    1  "))
            .unwrap_or_else(|| panic!("height {height}: no rank-1 row in: {joined}"));
        let slack = (rank1 + 1..row - 3).filter(|i| blank(&lines[*i])).count();
        assert!(
            slack >= 1,
            "engrave-10: the blank slack rides between the table and the panel \
             (height {height}): {joined}"
        );
    }
}
