// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! night-frontier-Z2 (Dive 2 at -1000m) pins: the tail-aware clamp
//! bracket's law, its render row, and its additive JSON wire. The
//! law tests drive the pure `clamp_bracket` over fixture rows (the
//! exact min word, the 32 log2 srtt buckets); the render and JSON
//! pins drive fixtures, never the host — the report pins' own
//! discipline. Wired into bracket_section.rs via #[path] (cosmostrix
//! Pattern C).

use crate::ebpf::identity::depth::{CgroupDepth, CgroupResources, ProcessFacts};
use crate::ebpf::limiter::hist::{HistRowRaw, quantile_permille};
use crate::ebpf::limiter::{PolicyRaw, format_bytes};
use crate::ebpf::render::{DepthReport, Enforcement, depth_doc_json, depth_report_lines};

use super::{BracketVerdict, bracket_sentence, clamp_bracket};

/// A raw policy row for fixtures (rate, matching burst, group 0) —
/// the report pins' own shape.
fn policy(rate_bps: u64) -> Option<PolicyRaw> {
    Some(PolicyRaw {
        rate_bps,
        burst_bytes: rate_bps,
        floor_bps: 0,
        ceil_bps: 0,
        group_id: 0,
        flags: 0,
    })
}

/// A srtt half with `fast` samples in the fast bucket (2^fast_b
/// microseconds lower bound) and the rest in the slow bucket — the
/// one-fast-socket-among-many shape the mixed-path story is. The
/// exact min word rides `min_us` (0 = the unmeasured sentinel).
fn srtt_row(min_us: u64, fast_b: usize, fast_n: u64, slow_b: usize, slow_n: u64) -> HistRowRaw {
    let mut row = HistRowRaw::default();
    row.srtt[fast_b] = fast_n;
    row.srtt[slow_b] = slow_n;
    row.srtt_sum = fast_n * (1u64 << fast_b) + slow_n * (1u64 << slow_b);
    row.srtt_min = min_us;
    // The physical max: the largest SAMPLED bucket's upper edge minus
    // one (a value in [2^b, 2^(b+1)) — never a bound above the fleet
    // the buckets actually recorded).
    row.srtt_max = if slow_n > 0 {
        (1u64 << (slow_b + 1)) - 1
    } else {
        (1u64 << (fast_b + 1)) - 1
    };
    row
}

/// The honest absences: no rate, no min word, no p99 — each is an
/// absent bracket, never a zero dressed as a measurement.
#[test]
fn bracket_absent_on_every_honest_absence() {
    let row = srtt_row(10_000, 13, 1, 19, 999);
    // A block verdict (rate 0) shapes no window — the recwn_lane's
    // own filter, the bracket rides it.
    assert_eq!(clamp_bracket(0, &row), None, "rate zero: no bracket");
    // The min word's 0-sentinel: no min yet, or the cross-CPU lag
    // the row doc names — an infinite ratio would be a fabrication.
    let unminned = srtt_row(0, 13, 1, 19, 999);
    assert_eq!(
        clamp_bracket(1_000_000, &unminned),
        None,
        "min sentinel: no bracket"
    );
    // An empty srtt half: no p99 the buckets can bound yet.
    let empty = HistRowRaw::default();
    assert_eq!(
        clamp_bracket(1_000_000, &empty),
        None,
        "no samples: no bracket"
    );
    // Sub-p99 sampling: 999 fast samples and NOTHING above the 99th
    // percentile's own reach still yields a p99 (the bucket bound
    // exists); the absence law under test is the empty half only.
    let p99 = quantile_permille(&row.srtt, 990);
    assert_eq!(
        p99,
        Some(1u64 << 19),
        "the p99 bound is the slow bucket's floor"
    );
}

/// The collapse clause: the ratio CROSSED the octave, but both ends
/// ride the 200 ms cadence floor derivation (both RTTs sub-cadence)
/// — the law answers byte-identical windows and one clamp DOES
/// serve. Refusing here would be noise dressed as rigor.
#[test]
fn single_when_the_cadence_floor_absorbs_the_spread() {
    // One fast sample (10 ms) among 999 at the 65 ms bucket: the
    // p99 bound reads 65536 us, the ratio crosses the octave
    // (6553 permille), yet the law floors BOTH ends at the 200 ms
    // cadence (rate 100 kb/s: both derive 20000 bytes).
    let row = srtt_row(10_000, 13, 1, 16, 999);
    let bracket = clamp_bracket(100_000, &row).expect("the sampled row carries a bracket");
    assert_eq!(bracket.verdict, BracketVerdict::Single);
    assert_eq!(bracket.min_rtt_us, 10_000);
    assert_eq!(bracket.p99_rtt_us, 1 << 16);
    assert_eq!(
        bracket.ceiling_bytes, 20_000,
        "the min end rides the floor law"
    );
    assert_eq!(
        bracket.floor_bytes, 20_000,
        "the p99 end rides the floor law too"
    );
    assert_eq!(bracket.clamp_bytes, Some(20_000));
    // The honesty ratio is computed from the RAW words (p99/min),
    // not from the collapsed windows — the metric grades the fleet,
    // the verdict grades the clamp.
    assert_eq!(bracket.honesty_ratio_permille, 6_553);
    let line = bracket_sentence(&bracket);
    assert!(
        line.contains("20.0 KB single clamp") && line.contains("honesty ratio >=6.6x"),
        "the single line names the clamp and the ratio: {line}"
    );
}

/// Above-cadence single: the tail within one octave of the exact
/// min — the same path class as far as the instrument certifies —
/// and the recommended clamp is the LARGER end (the pipe no
/// measured socket under-fills).
#[test]
fn single_when_the_tail_runs_within_the_octave() {
    // min 250 ms (one sample, bucket 17's range), 999 samples at
    // the 262144 us bucket: p99 bound 262144, ratio 1048 permille.
    let row = srtt_row(250_000, 18, 1_000, 19, 0);
    let bracket = clamp_bracket(1_000_000, &row).expect("the sampled row carries a bracket");
    assert_eq!(bracket.verdict, BracketVerdict::Single);
    assert_eq!(bracket.honesty_ratio_permille, 1_048);
    assert_eq!(
        bracket.ceiling_bytes, 250_000,
        "the min end extends to the true pipe"
    );
    assert_eq!(bracket.floor_bytes, 262_144, "the p99 end extends likewise");
    assert_eq!(
        bracket.clamp_bytes,
        Some(262_144),
        "the larger end recommends: no measured socket under-fills"
    );
}

/// The octave gate is INCLUSIVE at permille 2000: exactly one
/// octave reads Single (the divergence clause alone cannot refuse —
/// the ratio must CROSS the octave).
#[test]
fn the_octave_gate_is_inclusive_at_2000_permille() {
    // min exactly 262144 (bucket 18's bound), p99 bound exactly
    // 524288 (bucket 19): ratio 2000 permille on the nose, ends
    // diverged (both above cadence). Single — the gate is not
    // crossed.
    let row = srtt_row(262_144, 18, 1, 19, 999);
    let bracket = clamp_bracket(1_000_000, &row).expect("the sampled row carries a bracket");
    assert_eq!(bracket.honesty_ratio_permille, 2_000);
    assert_eq!(bracket.verdict, BracketVerdict::Single);
    assert_eq!(bracket.clamp_bytes, Some(524_288));
}

/// Mixed: the tail past one octave with the law's ends diverged —
/// the refusal IS the answer, no clamp_bytes, and the line names
/// the per-socket door that already exists.
#[test]
fn mixed_when_the_tail_crosses_the_octave() {
    // One fast sample (10 ms), 999 at 524 ms: ratio 52428 permille,
    // ceiling rides the cadence floor (20000... rate 1 MB/s:
    // 200000), floor extends to 524288. Refused.
    let row = srtt_row(10_000, 13, 1, 19, 999);
    let bracket = clamp_bracket(1_000_000, &row).expect("the sampled row carries a bracket");
    assert_eq!(bracket.verdict, BracketVerdict::Mixed);
    assert_eq!(bracket.clamp_bytes, None, "the refusal carries no clamp");
    assert_eq!(
        bracket.ceiling_bytes, 200_000,
        "the fast end rides the floor law"
    );
    assert_eq!(bracket.floor_bytes, 524_288, "the tail end extends");
    let line = bracket_sentence(&bracket);
    assert!(
        line.starts_with("no single clamp"),
        "the refusal leads the mixed line: {line}"
    );
    assert!(
        line.contains("mixed local+remote paths") && line.contains("per-socket"),
        "the mixed line names the mixing and the per-socket door: {line}"
    );
    assert!(
        line.contains("floor >=524.3 KB") && line.contains("ceiling 200.0 KB"),
        "the ends ride their >= and exact forms: {line}"
    );
}

/// The bracket composition over the assembled report: the download
/// rate against the download half — and no bracket for an
/// upload-only tree (the RECWN lane shapes receive windows only).
#[test]
fn the_report_composition_is_download_lane_only() {
    let row = srtt_row(10_000, 13, 1, 19, 999);
    let hist = Some(super::HistSection {
        download: Some(row),
        upload: Some(HistRowRaw::default()),
    });
    // Download-limited: the bracket composes.
    let dl = super::clamp_bracket_for_report(
        &hist,
        &Enforcement::Limited {
            download: policy(1_000_000),
            upload: None,
        },
    );
    assert!(dl.is_some(), "the download lane carries the bracket");
    // Upload-only: no receive window is shaped, no bracket exists.
    let ul = super::clamp_bracket_for_report(
        &hist,
        &Enforcement::Limited {
            download: None,
            upload: policy(1_000_000),
        },
    );
    assert_eq!(ul, None, "an upload-only tree names no clamp bracket");
    // Unlimited: no rate, no BDP, no bracket.
    assert_eq!(
        super::clamp_bracket_for_report(&hist, &Enforcement::Unlimited),
        None
    );
}

fn member_fixture() -> ProcessFacts {
    ProcessFacts {
        pid: 1234,
        comm: "cat-test".to_string(),
        uid: 1000,
        user: Some("cat".to_string()),
        ppid: 1,
        state: "S (sleeping)".to_string(),
        threads: 4,
        rss_kb: 1234,
        exe: Some("/home/cat/cat-test".to_string()),
        exe_deleted: false,
        kind: Some("binary"),
        script: None,
        mode: Some("755".to_string()),
        cwd: Some("/home/cat".to_string()),
        cmdline: Some("./cat-test --serve".to_string()),
        started_ago_secs: Some(620),
        started_epoch: Some(1_758_900_000),
    }
}

fn report_fixture(enforcement: Enforcement, hist: Option<super::HistSection>) -> DepthReport {
    DepthReport {
        target: "cg:1234".to_string(),
        cgroup_id: 1234,
        name: "cat-test".to_string(),
        depth: CgroupDepth {
            rel_path: Some("/cat-test".to_string()),
            resources: CgroupResources::default(),
            procs: vec![member_fixture()],
        },
        enforcement,
        enforcement_stats: None,
        conns: None,
        traffic: None,
        traffic_note: None,
        histogram: hist,
        lanes: None,
    }
}

/// The text report's bracket row: present under the histogram when
/// the lane composes, absent (no row, no placeholder) when the
/// inputs cannot back it.
#[test]
fn the_text_report_renders_the_bracket_row() {
    let row = srtt_row(10_000, 13, 1, 19, 999);
    let hist = Some(super::HistSection {
        download: Some(row),
        upload: None,
    });
    let mixed = report_fixture(
        Enforcement::Limited {
            download: policy(1_000_000),
            upload: None,
        },
        hist,
    );
    let lines = depth_report_lines(&[mixed], 120);
    let bracket: Vec<&String> = lines
        .iter()
        .filter(|l| l.contains("clamp bracket"))
        .collect();
    assert_eq!(bracket.len(), 1, "one bracket row, under the histogram");
    assert!(
        bracket[0].contains("no single clamp") && bracket[0].contains("honesty ratio"),
        "the row carries the verdict and the metric: {}",
        bracket[0]
    );
    // The honest absence: no histogram, no row — and no "clamp
    // bracket" placeholder text anywhere.
    let bare = report_fixture(
        Enforcement::Limited {
            download: policy(1_000_000),
            upload: None,
        },
        None,
    );
    let lines = depth_report_lines(&[bare], 120);
    assert!(
        !lines.iter().any(|l| l.contains("clamp bracket")),
        "no bracket row without samples"
    );
}

/// The `clamp_bracket` wire fragment's parsed shape (the CodeQL
/// cleartext-logging boundary, alerts #34/#35/#36): the pins used to
/// interpolate the whole depth JSON document into their assert
/// messages, and the document carries the report's process-identity
/// payload (uid, user, exe, cmdline) — sensitive data reaching a
/// panic-formatted sink. The pins now parse the fragment into these
/// plain number fields and the failure messages carry measurements
/// only, never the document. None = the additive null (the honest
/// absence) or a fragment too malformed to parse (the assert on the
/// parsed fields fails, the message stays literal).
#[derive(Debug, PartialEq)]
struct BracketWire {
    min_rtt_us: u64,
    p99_rtt_us: u64,
    ceiling_bytes: u64,
    floor_bytes: u64,
    honesty_ratio_permille: u64,
    verdict: String,
    clamp_bytes: Option<u64>,
}

/// Extract and parse the `"clamp_bracket":{...}` fragment's fields —
/// numbers and the verdict word only, the boundary the struct's doc
/// names.
fn bracket_wire(text: &str) -> Option<BracketWire> {
    let key = "\"clamp_bracket\":";
    let start = text.find(key)? + key.len();
    let rest = &text[start..];
    if rest.starts_with("null") {
        return None;
    }
    let end = rest.find('}')?;
    let body = &rest[..=end];
    let num = |name: &str| -> Option<u64> {
        let k = format!("\"{name}\":");
        let i = body.find(&k)? + k.len();
        let j = i + body[i..].find([',', '}'])?;
        body[i..j].parse().ok()
    };
    let verdict = {
        let k = "\"verdict\":\"";
        let i = body.find(k)? + k.len();
        let j = i + body[i..].find('"')?;
        body[i..j].to_string()
    };
    let clamp = {
        let k = "\"clamp_bytes\":";
        let i = body.find(k)? + k.len();
        let v = &body[i..];
        if v.starts_with("null") {
            None
        } else {
            Some(v[..v.find([',', '}'])?].parse().ok()?)
        }
    };
    Some(BracketWire {
        min_rtt_us: num("min_rtt_us")?,
        p99_rtt_us: num("p99_rtt_us")?,
        ceiling_bytes: num("ceiling_bytes")?,
        floor_bytes: num("floor_bytes")?,
        honesty_ratio_permille: num("honesty_ratio_permille")?,
        verdict,
        clamp_bytes: clamp,
    })
}

/// The JSON wire: `clamp_bracket` rides the target additively (the
/// last key), null on the honest absence, the law's own words when
/// it composes — verdict "mixed" carries clamp_bytes null, verdict
/// "single" carries the recommendation. The wire-order pin rides the
/// expected fragment built from literals (untainted — the message
/// may echo it); the field-wise pins ride the parsed struct, whose
/// failure output carries numbers only.
#[test]
fn the_json_wire_carries_the_bracket_additively() {
    // Absence first: the null every pre-Z2 script reads through.
    let bare = report_fixture(
        Enforcement::Limited {
            download: policy(1_000_000),
            upload: None,
        },
        None,
    );
    let text = depth_doc_json(&[bare], &[], None).to_json();
    assert!(
        text.contains("\"clamp_bracket\":null") && bracket_wire(&text).is_none(),
        "the absence rides the additive null"
    );
    // Single: the full object with the recommendation.
    let single_row = srtt_row(262_144, 18, 1, 19, 999);
    let single = report_fixture(
        Enforcement::Limited {
            download: policy(1_000_000),
            upload: None,
        },
        Some(super::HistSection {
            download: Some(single_row),
            upload: None,
        }),
    );
    let text = depth_doc_json(&[single], &[], None).to_json();
    let expected = concat!(
        "\"clamp_bracket\":{\"min_rtt_us\":262144,\"p99_rtt_us\":524288,",
        "\"ceiling_bytes\":262144,\"floor_bytes\":524288,",
        "\"honesty_ratio_permille\":2000,\"verdict\":\"single\",",
        "\"clamp_bytes\":524288}"
    );
    assert!(
        text.contains(expected),
        "the single bracket rides the law's exact words, expected: {expected}"
    );
    let wire = bracket_wire(&text).expect("the single bracket parses");
    assert_eq!(
        wire,
        BracketWire {
            min_rtt_us: 262_144,
            p99_rtt_us: 524_288,
            ceiling_bytes: 262_144,
            floor_bytes: 524_288,
            honesty_ratio_permille: 2_000,
            verdict: "single".to_string(),
            clamp_bytes: Some(524_288),
        }
    );
    // Mixed: clamp_bytes null — the refusal IS the answer.
    let mixed_row = srtt_row(10_000, 13, 1, 19, 999);
    let mixed = report_fixture(
        Enforcement::Limited {
            download: policy(1_000_000),
            upload: None,
        },
        Some(super::HistSection {
            download: Some(mixed_row),
            upload: None,
        }),
    );
    let text = depth_doc_json(&[mixed], &[], None).to_json();
    let expected = "\"clamp_bracket\":{\"min_rtt_us\":10000,\"p99_rtt_us\":524288,\"ceiling_bytes\":200000,\"floor_bytes\":524288,\"honesty_ratio_permille\":52428,\"verdict\":\"mixed\",\"clamp_bytes\":null}";
    assert!(
        text.contains(expected),
        "the mixed bracket refuses by the null clamp, expected: {expected}"
    );
    let wire = bracket_wire(&text).expect("the mixed bracket parses");
    assert_eq!(wire.verdict, "mixed");
    assert_eq!(wire.min_rtt_us, 10_000);
    assert_eq!(wire.p99_rtt_us, 524_288);
    assert_eq!(wire.honesty_ratio_permille, 52_428);
    assert_eq!(wire.clamp_bytes, None, "the refusal carries no clamp");
}

/// The bytes figure the sentence leads with IS format_bytes' own
/// vocabulary (the house ladder, decimal units) — the pin holds the
/// exact spellings the mixed/single lines lead with.
#[test]
fn the_sentence_bytes_ride_the_house_formatter() {
    assert_eq!(format_bytes(20_000), "20.0 KB");
    assert_eq!(format_bytes(200_000), "200.0 KB");
    assert_eq!(format_bytes(524_288), "524.3 KB");
}
