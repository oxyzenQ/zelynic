// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Eagle-eyes focus renderer (NIGHT-boost-1): the deep single-target
//! view — per-direction deltas, rate, lifetime totals, and every
//! socket-holding process with its endpoints, uncapped. Reached
//! automatically when the positional TARGETS spec is one token that
//! resolves to one cgroup (the old `observe --cgroup <id>` depth).
//!
//! NIGHT-boost-14 aligned the focus view with the ranked frame's
//! composition: the same breathing gap under the title, the process
//! lines capped to the terminal height (an honest "+N more hidden"
//! note instead of a clipped frame — the uncapped view still shows
//! everything on any sane terminal), and the signature footer pinned
//! near the bottom, never floating after the last detail line.

use std::time::Duration;

use super::{format_rate_or_dash, label_with_count, rate_bps, title_bar, FrameGeometry};
use crate::ebpf::connections::ConnectionMap;
use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter::format_bytes;
use crate::ebpf::loader::CounterSummary;
use crate::output::signature_footer;

/// Render the focus frame for one cgroup.
///
/// The single-cgroup view switches to a key/value block: with one
/// process, the delta, rate, and lifetime totals are the interesting
/// numbers and a table wastes the width. Line-building contract per
/// the render tree (NIGHT-improve-2: the caller submits the vector
/// to the diff-based screen engine).
///
/// `geo` is the frame geometry (NIGHT-boost-14: the focus view pins
/// its footer the same way the ranked view does, so the layout is
/// height-aware here too — the caller already probed it once).
#[allow(clippy::too_many_arguments)]
pub fn render_eagle_focus(
    lines: &mut Vec<String>,
    summary: &CounterSummary,
    identity: &IdentityMap,
    conns: Option<&ConnectionMap>,
    cgroup_id: u32,
    interval: Duration,
    geo: FrameGeometry,
) {
    lines.push(title_bar(
        &format!("zelynic eagle-eyes — {}", identity.label(cgroup_id)),
        "q quit",
        geo.width,
    ));

    // The breathing gap (NIGHT-boost-14): same air under the title
    // as the ranked frame — one composition, two views.
    lines.push(String::new());

    // Overhead the fixed frame claims: title, gap, the five key/value
    // rows, and the pinned footer (blank + copyright).
    const FOCUS_CHROME: usize = 8;

    if let Some(c) = summary.cgroups.iter().find(|c| c.cgroup_id == cgroup_id) {
        lines.push(format!(
            "  process   {}",
            label_with_count(identity, conns, cgroup_id)
        ));
        lines.push(format!(
            "  download  {} ({})",
            format_bytes(c.ingress_bytes),
            c.ingress_packets
        ));
        lines.push(format!(
            "  upload    {} ({})",
            format_bytes(c.bytes),
            c.packets
        ));
        lines.push(format!(
            "  rate      {}",
            format_rate_or_dash(rate_bps(c.ingress_bytes + c.bytes, interval))
        ));
        lines.push(format!(
            "  lifetime  {}",
            // Both lifetime counters (improve-13 precision): the ingress
            // map's cumulative download + the egress map's cumulative
            // upload — one horizon, since attach. The old sum mixed a
            // per-poll download delta in, so the row shrank frame over
            // frame on a 1s refresh.
            format_bytes(c.ingress_total_bytes + c.total_bytes)
        ));

        // Full eagle-eyes view for the focused cgroup: every
        // socket-holding process with its endpoints, uncapped (the
        // single-cgroup view exists precisely to answer "who exactly")
        // — except when the terminal cannot hold them: the cap counts
        // one honest "more hidden" note (NIGHT-boost-14 adaptive
        // compact), and degenerate heights drop the block entirely.
        let mut details = super::full_detail_lines(conns, cgroup_id);
        let room = geo.height.saturating_sub(FOCUS_CHROME);
        if details.len() > room {
            if room == 0 {
                details.clear();
            } else {
                let hidden = details.len() - (room - 1);
                details.truncate(room - 1);
                details.push(format!("  └ +{hidden} more hidden — raise the window"));
            }
        }
        for line in details {
            lines.push(line);
        }
    } else {
        lines.push(format!("  no traffic for cg:{cgroup_id} since last check"));
    }

    // The pin (NIGHT-boost-14): blank padding absorbs the middle, the
    // signature footer sits near the bottom of the terminal — never
    // floating up with the last detail line.
    let footer_len = 2;
    while lines.len() + footer_len < geo.height {
        lines.push(String::new());
    }
    if lines.len() + footer_len <= geo.height {
        lines.push(String::new());
        lines.push(format!("  {}", signature_footer()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::identity::ProcessIdentity;
    use crate::ebpf::loader::CgroupDelta;

    /// improve-13 precision pin (ported from the observe-filtered
    /// tests): the lifetime row sums the two LIFETIME counters,
    /// never a per-poll delta — with delta 5 MB but lifetime ingress
    /// 900 MB, the row must read the lifetime figure.
    #[test]
    fn focus_lifetime_uses_lifetime_counters() {
        let mut identity = IdentityMap::new();
        identity.insert(ProcessIdentity {
            cgroup_id: 7001,
            uid: 1000,
            comm: "brave".to_string(),
        });
        let summary = CounterSummary {
            total_packets: 5,
            total_bytes: 10_000_000,
            total_ingress_packets: 50,
            total_ingress_bytes: 5_000_000,
            cgroups: vec![CgroupDelta {
                cgroup_id: 7001,
                packets: 5,
                bytes: 10_000_000,
                total_bytes: 90_000_000,
                ingress_packets: 50,
                ingress_bytes: 5_000_000,
                ingress_total_bytes: 900_000_000,
            }],
        };
        let mut lines = Vec::new();
        render_eagle_focus(
            &mut lines,
            &summary,
            &identity,
            None,
            7001,
            Duration::from_secs(1),
            FrameGeometry {
                width: 80,
                height: 24,
            },
        );
        let joined = lines.join("\n");
        // lifetime = 900 MB (dl lifetime) + 90 MB (ul lifetime) — the
        // mixed-horizon "5 MB + 90 MB" figure must not appear.
        assert!(
            joined.contains("lifetime  990.0 MB"),
            "lifetime sums both lifetime counters: {joined}"
        );
        assert!(
            joined.starts_with("  ─── zelynic eagle-eyes — cg:7001 (brave)"),
            "guttered title names the focused target: {joined}"
        );
    }

    /// Idle focus frame: a cgroup with no traffic yet renders the
    /// title + the honest no-traffic note, the pinned footer last
    /// (NIGHT-boost-14: gap under the title, copyright at the
    /// bottom, frame pinned to the probed height).
    #[test]
    fn focus_without_traffic_says_so() {
        let mut lines = Vec::new();
        render_eagle_focus(
            &mut lines,
            &CounterSummary::default(),
            &IdentityMap::new(),
            None,
            73386,
            Duration::from_secs(1),
            FrameGeometry {
                width: 80,
                height: 24,
            },
        );
        assert_eq!(lines.len(), 24, "pinned frame spans the terminal height");
        assert!(lines[0].starts_with("  ─── zelynic eagle-eyes — cg:73386"));
        assert_eq!(lines[1], "", "breathing gap under the title");
        assert!(lines.contains(&"  no traffic for cg:73386 since last check".to_string()));
        assert!(
            lines[23].starts_with("  zelynic v"),
            "copyright pinned to the last row: {}",
            lines[23]
        );
    }
}
