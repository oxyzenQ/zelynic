// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the `eagle-eyes --depth --print-json` scripting document
//! (NIGHT-master-1; moved whole from report_tests.rs at NIGHT-blade-5
//! when the JSON half of the depth report split into the depth_json
//! sibling — same fixtures, same stable v11 vocabulary, plus the
//! blade-5 ledger and controller-resource fields).

use super::*;

use crate::ebpf::identity::depth::{CgroupDepth, CgroupResources, ProcessFacts};
use crate::ebpf::limiter::{LimiterStatsRaw, PolicyRaw};
use crate::ebpf::render::report::{DepthReport, Enforcement};

/// A raw policy row for fixtures (rate, matching burst, group 0).
fn policy(rate_bps: u64) -> Option<PolicyRaw> {
    Some(PolicyRaw {
        rate_bps,
        burst_bytes: rate_bps,
        group_id: 0,
    })
}

/// The owner's example member (the report_tests twin).
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

fn report_fixture(enforcement: Enforcement) -> DepthReport {
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
    }
}

/// The JSON document is the scripting contract: the targets array
/// wraps per-target reports, a partial miss rides as its own entry,
/// and the field names are the stable v11 API vocabulary (the
/// NIGHT-blade-5 additions ride beside, never instead).
#[test]
fn json_document_shape_is_the_scripting_contract() {
    let report = report_fixture(Enforcement::Limited {
        download: policy(100_000),
        upload: policy(100_000),
    });
    let doc = depth_doc_json(
        &[report],
        &[("ghost".to_string(), "no live cgroup matches".to_string())],
    );
    let text = serde_json::to_string(&doc).expect("the document serializes");
    assert!(text.starts_with("{\"targets\":[{"), "got: {text}");
    for field in [
        "\"target\":\"cg:1234\"",
        "\"cgroup_id\":1234",
        "\"name\":\"cat-test\"",
        "\"cgroup_path\":\"/sys/fs/cgroup/cat-test\"",
        "\"uid\":1000",
        "\"user\":\"cat\"",
        "\"enforcement\":\"limited\"",
        "\"download_bps\":100000",
        "\"upload_bps\":100000",
        "\"group_id\":0",
        "\"oldest_started_secs\":620",
        "\"processes\":1",
        "\"pid\":1234",
        "\"comm\":\"cat-test\"",
        "\"kind\":\"binary\"",
        "\"permission\":\"755\"",
        "\"cwd\":\"/home/cat\"",
        "\"started_ago_secs\":620",
        "\"target\":\"ghost\"",
        "\"error\":\"no live cgroup matches\"",
        // NIGHT-blade-7: the deletion flag rides every process row
        // (additive — a script that ignores it is untouched).
        "\"exe_deleted\":false",
    ] {
        assert!(
            text.contains(field),
            "the JSON contract must carry {field}, got:\n{text}"
        );
    }
    // The unlimited shape: nulls, never fabricated zeroes.
    let doc = depth_doc_json(&[report_fixture(Enforcement::Unlimited)], &[]);
    let text = serde_json::to_string(&doc).expect("serializes");
    assert!(text.contains("\"enforcement\":\"unlimited\""));
    assert!(text.contains("\"download_bps\":null"));
    assert!(text.contains("\"upload_bps\":null"));
    // The blade-5 layers are null in the unlimited shape too.
    assert!(text.contains("\"enforcement_stats\":null"));
    assert!(text.contains("\"cgroup_memory_bytes\":null"));
    assert!(text.contains("\"cgroup_cpu_usage_usec\":null"));
}

/// NIGHT-blade-7: the deleted-on-disk exe flag rides the scripting
/// document as a boolean — a triage pipeline filters on it instead of
/// parsing the text report's marker.
#[test]
fn json_carries_the_deleted_exe_flag() {
    let mut report = report_fixture(Enforcement::Unlimited);
    report.depth.procs[0].exe_deleted = true;
    let doc = depth_doc_json(&[report], &[]);
    let text = serde_json::to_string(&doc).expect("serializes");
    assert!(
        text.contains("\"exe_deleted\":true"),
        "the deleted marker must serialize as true, got:\n{text}"
    );
}

/// NIGHT-blade-5: the ledger and the controller's resource view ride
/// the document when they resolved — exact figures, flat names, the
/// same null-not-zero honesty as every optional field.
#[test]
fn json_carries_the_ledger_and_controller_resources() {
    let mut report = report_fixture(Enforcement::Limited {
        download: policy(100_000),
        upload: policy(0),
    });
    report.enforcement_stats = Some(LimiterStatsRaw {
        packets_allowed: 9_001,
        packets_dropped: 42,
        bytes_allowed: 1_400_000_000,
        bytes_dropped: 6_200_000,
    });
    report.depth.resources = CgroupResources {
        memory_current_bytes: Some(2_500_000),
        cpu_usage_usec: Some(62_000_000),
    };
    let doc = depth_doc_json(&[report], &[]);
    let text = serde_json::to_string(&doc).expect("serializes");
    for field in [
        "\"enforcement_stats\":{\"packets_allowed\":9001",
        "\"packets_dropped\":42",
        "\"bytes_allowed\":1400000000",
        "\"bytes_dropped\":6200000",
        "\"cgroup_memory_bytes\":2500000",
        "\"cgroup_cpu_usage_usec\":62000000",
    ] {
        assert!(
            text.contains(field),
            "the blade-5 JSON contract must carry {field}, got:\n{text}"
        );
    }
}
