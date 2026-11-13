// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! night-frontier-Z1 (schema v35) pins: the depth pack's JSON wire —
//! the exact aggregates (count/sum/min/max/mean, the kernel's own
//! words riding beside the bucket bounds) and the tail story list
//! (the worst-by-size slots with ktime stamps, the socket cookie,
//! the endpoint the walk's census resolves — null while it missed,
//! never a fabricated name). Split from depth_json_tests.rs at the
//! 600-line LOC law (the sibling-split lineage); `report_fixture`
//! rides the sibling pins module pub(crate), the one shared helper.
//! Wired into depth_json/mod.rs via #[path] (cosmostrix Pattern C).

use super::depth_doc_json;
use super::tests::report_fixture;
use crate::ebpf::limiter::hist::{HistRowRaw, HistTailRaw};
use crate::ebpf::render::{Enforcement, HistSection};

/// The histogram block carries the Z1 exact words and the tail list.
#[test]
fn json_histogram_block_carries_the_z1_exact_words_and_tail() {
    let mut row = HistRowRaw::default();
    row.size[10] = 600; // the 1 KiB class
    row.size[13] = 400; // the 8 KiB class
    row.srtt[19] = 3; // the 1 s class (the RTT lane's harvest)
    row.srtt_sum = 3 * 19_000; // the mass the three srtt samples carry
    // The exact words + one live tail slot. The fixture's census owns
    // no cookies — the endpoint stays the honest None. The count is
    // derived (the buckets sum to 1000 — the assert pins that).
    row.size_sum = 600 * 1024 + 400 * 8192;
    row.size_min = 1024;
    row.size_max = 8192;
    row.tail[0] = HistTailRaw {
        ts_ns: 123_456,
        size: 8192,
        srtt_us: 19_000,
        cookie: 999,
    };
    let mut report = report_fixture(Enforcement::Unlimited);
    report.histogram = Some(HistSection {
        download: Some(row),
        upload: None,
    });
    let text = depth_doc_json(&[report], &[], None).to_json();
    // The exact aggregates ride beside the bounds — the kernel's own
    // words, mean the sum's division.
    assert!(
        text.contains("\"count\":1000"),
        "the exact count word rides"
    );
    assert!(text.contains("\"sum\":3891200"), "the exact sum word rides");
    assert!(text.contains("\"min\":1024"), "the exact min word rides");
    assert!(text.contains("\"max\":8192"), "the exact max word rides");
    assert!(
        text.contains("\"mean\":3891"),
        "the mean is the sum's division"
    );
    // The srtt half's mean rides its own division (the derived count
    // makes a present half's mean always a real figure — the honest
    // null lives on the whole-half level, the absent upload row).
    assert!(
        text.contains("\"mean\":19000"),
        "the srtt mean is its own division"
    );
    // The tail story list rides with its raw cookie; the endpoint
    // stays null while the walk's census owns no such cookie.
    assert!(
        text.contains("\"tail\":[{\"ts_ns\":123456,\"size\":8192,\"srtt_us\":19000,\"cookie\":999,\"endpoint\":null}]"),
        "the live tail slot renders its full story row"
    );
}
