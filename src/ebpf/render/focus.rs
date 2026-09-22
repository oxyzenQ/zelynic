// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Eagle-eyes focus renderer (NIGHT-boost-1): the deep single-target
//! view — per-direction deltas, rate, lifetime totals, and every
//! socket-holding process with its endpoints, uncapped. Reached
//! automatically when the positional TARGETS spec is one token that
//! resolves to one cgroup (the old `observe --cgroup <id>` depth).

use std::time::Duration;

use super::{format_rate_or_dash, label_with_count, rate_bps, title_bar};
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
pub fn render_eagle_focus(
    lines: &mut Vec<String>,
    summary: &CounterSummary,
    identity: &IdentityMap,
    conns: Option<&ConnectionMap>,
    cgroup_id: u32,
    interval: Duration,
) {
    let geo = super::FrameGeometry::probe();

    lines.push(title_bar(
        &format!("zelynic eagle-eyes — {}", identity.label(cgroup_id)),
        "q quit",
        geo.width,
    ));

    let Some(c) = summary.cgroups.iter().find(|c| c.cgroup_id == cgroup_id) else {
        lines.push(format!("  no traffic for cg:{cgroup_id} since last check"));
        return;
    };

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
    // single-cgroup view exists precisely to answer "who exactly").
    for line in super::full_detail_lines(conns, cgroup_id) {
        lines.push(line);
    }

    // Signature footer (NIGHT-boost-5): bottom-left identity stamp,
    // one blank line of breathing room above it — every flagship
    // frame signs its work.
    lines.push(String::new());
    lines.push(format!("  {}", signature_footer()));
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
    /// title + the honest no-traffic note, nothing else.
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
        );
        assert_eq!(lines.len(), 2, "idle focus = title + no-traffic note");
        assert!(lines[0].starts_with("  ─── zelynic eagle-eyes — cg:73386"));
        assert_eq!(lines[1], "  no traffic for cg:73386 since last check");
    }
}
