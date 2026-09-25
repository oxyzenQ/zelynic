// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Eagle-eyes display-width pins (NIGHT-lts-1): the CJK/fullwidth
//! contract — a comm whose glyphs render two terminal columns per
//! char must not dent the frame. The width budget family
//! (truncate_label, the label padding, title_bar's fill, the border
//! fit) routes through the output layer's display-width module;
//! these pins hold the end-to-end frame composition. Lives under the
//! single test/ tree (cosmostrix Pattern C) and is #[path]-wired
//! from src/ebpf/render/eagle.rs, one file per contract like the
//! filter and session pin families.

// NON_LATIN_FIXTURE: the CJK literals below are runtime
// width-measurement coverage (a five-ideograph comm is the honest
// CJK app-name class the sanitizer deliberately passes), not prose
// (scripts/gates/check-language.sh exemption).

use crate::ebpf::identity::{IdentityMap, ProcessIdentity};
use crate::ebpf::loader::{CgroupDelta, CounterSummary};
use crate::ebpf::render::eagle::render_eagle_eyes_at;
use crate::ebpf::render::{FrameGeometry, SessionState};
use std::time::Duration;

/// One traffic frame for `cg` with the given per-frame deltas (the
/// eagle_tests shape, local to this contract file).
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

/// The 80x24 classic terminal, the geometry every plain
/// `render_eagle_eyes` call sees.
fn classic() -> FrameGeometry {
    FrameGeometry {
        width: 80,
        height: 24,
    }
}

/// NIGHT-lts-1 (the CJK width contract, end to end): a cgroup whose
/// comm is five ideographs (ten rendered columns) must not dent the
/// frame. The pre-lts-1 forms counted chars, so the label sat inside
/// every budget while painting twice it: the row ran past the
/// content width and the right rail jagged. Pin: with a CJK label on
/// the board, EVERY composed row renders exactly the frame's display
/// width and the label degrades to whole ideographs plus the
/// ellipsis inside its column.
#[test]
fn cjk_label_keeps_the_rails_straight() {
    use crate::output::display_width;
    let mut identity = IdentityMap::new();
    identity.insert(ProcessIdentity {
        cgroup_id: 7001,
        uid: 1000,
        // Five ideographs: 15 bytes (the kernel comm cap), ten
        // rendered columns.
        comm: "谷歌浏览器".to_string(),
    });
    let mut lines = Vec::new();
    render_eagle_eyes_at(
        &mut lines,
        &frame(7001, 1_400_000, 240_000),
        &[],
        &identity,
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &mut SessionState::new(),
        Duration::from_secs(70),
        classic(),
    );
    let joined = lines.join("\n");
    // The label row exists and carries the ideographs (truncated to
    // the label budget by RENDERED columns, never past it).
    let rank1 = lines
        .iter()
        .find(|l| l.starts_with(" │   1  "))
        .unwrap_or_else(|| panic!("no rank-1 row in: {joined}"));
    assert!(
        rank1.contains("谷歌"),
        "the CJK label renders (width-aware truncation keeps it): {rank1}"
    );
    // Every row composes to the same rendered width: 80 - 1 (the
    // unpainted final column, NIGHT-engrave-8) — the rails are one
    // straight edge, the CJK row included.
    for (i, row) in lines.iter().enumerate() {
        assert_eq!(
            display_width(row),
            79,
            "row {i} renders the frame width exactly (CJK included): {row}"
        );
    }
}
