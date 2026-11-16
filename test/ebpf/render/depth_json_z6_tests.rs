// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The Z6 depth-pack JSON pins (night-frontier-Z6, schema v36): the
//! mirror's field law — the self_cost block's null absence, the
//! sampled shape, and the field-order tail — compiled beside the
//! writer it pins (the z1 sibling-split lineage, one era per file).

use super::tests::report_fixture;
use super::*;
use crate::ebpf::limiter::selfcost::fold_self_cost;

/// night-frontier-Z6 (schema v36): the mirror's field law — the
/// self_cost block rides the doc-level tail beside bypass_audit,
/// null while no packet has sampled (the honest absence), and the
/// sampled shape carries the sampling cadence, the folded buckets,
/// the bucket-bounded quantiles, and the exact aggregates.
#[test]
fn json_carries_the_self_cost_block() {
    use crate::ebpf::limiter::selfcost::SelfCostRowRaw;

    // The absence: a fresh pin answers null, never a zero dressed
    // as a measurement.
    let doc = depth_doc_json(&[report_fixture(Enforcement::Unlimited)], &[], None, None);
    let text = doc.to_json();
    assert!(
        text.contains("\"self_cost\":null"),
        "an unsampled machine must answer self_cost null: {text}"
    );

    // The sampled shape: one CPU's row folded in — two samples in
    // bucket 10 (1024 ns each), the exact mass the kernel's own word
    // carries, the bounds riding the buckets (the bucket-bounded
    // read the C77 leg's verifier budget chose over the exact
    // min/max words).
    let mut row = SelfCostRowRaw::default();
    row.buckets[10] = 2;
    row.sum_ns = 2_048;
    let folded = fold_self_cost(&[row]);
    let doc = depth_doc_json(
        &[report_fixture(Enforcement::Unlimited)],
        &[],
        None,
        Some(&folded),
    );
    let text = doc.to_json();
    for field in [
        "\"sample_shift\":10",
        "\"count\":2",
        "\"p50\":1024",
        "\"p95\":1024",
        "\"p99\":1024",
        "\"sum_ns\":2048",
        // The bucket-bounded bounds read: both ends ride bucket 10's
        // band ([1024, 2048)) — the log2 resolution's own honesty.
        "\"min_ns\":1024",
        "\"max_ns\":2047",
        "\"mean_ns\":1024",
    ] {
        assert!(
            text.contains(field),
            "the self_cost block must carry {field}"
        );
    }
    // The folded buckets ride the doc verbatim (32 entries, two in
    // bucket 10): a script turns counts into packet counts via the
    // shift.
    let buckets_head = "\"buckets\":[0,0,0,0,0,0,0,0,0,0,2,";
    assert!(
        text.contains(buckets_head),
        "the folded buckets must ride the doc: {text}"
    );
    // The field order contract: self_cost rides the doc tail, after
    // bypass_audit (declaration order is wire order).
    let tail_pos = text.find("\"bypass_audit\":").unwrap();
    let sc_pos = text.find("\"self_cost\":").unwrap();
    assert!(sc_pos > tail_pos, "self_cost must ride the doc tail");
}
