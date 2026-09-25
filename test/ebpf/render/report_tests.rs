// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the eagle-eyes --depth report composition
//! (NIGHT-master-1): the package-name ladder, the enforcement
//! verdict vocabulary, the owner's field spine on the text report,
//! the socket cap, and the JSON document's scripting contract — all
//! driven by fixtures, never the host.

use super::*;

/// A raw policy row for fixtures (rate, matching burst, group 0).
fn policy(rate_bps: u64) -> Option<PolicyRaw> {
    Some(PolicyRaw {
        rate_bps,
        burst_bytes: rate_bps,
        group_id: 0,
    })
}

/// The owner's example member: 620 seconds old is exactly the
/// "10m:20s" of the spec.
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
            procs: vec![member_fixture()],
        },
        enforcement,
        conns: None,
    }
}

/// The name ladder (the owner's "unknown/cat-test jika ada nama"):
/// comm wins, the cgroup path's basename is the fallback, a bare id
/// stays honestly unknown.
#[test]
fn package_name_ladder_comm_then_basename_then_unknown() {
    assert_eq!(
        package_name(Some("brave"), Some("/user.slice/x.scope")),
        "brave"
    );
    assert_eq!(package_name(Some(""), Some("/cat-test")), "cat-test");
    assert_eq!(package_name(None, Some("/cat-test")), "cat-test");
    assert_eq!(package_name(None, Some("/")), "unknown");
    assert_eq!(package_name(None, None), "unknown");
}

/// The enforcement vocabulary: unlimited / blocked / limited, with
/// the summary sentence carrying per-direction truth.
#[test]
fn enforcement_words_and_sentences_match_the_verdicts() {
    assert_eq!(enforcement_word(&Enforcement::Unlimited), "unlimited");
    assert_eq!(enforcement_sentence(&Enforcement::Unlimited), "unlimited");

    let blocked = Enforcement::Limited {
        download: policy(0),
        upload: policy(0),
    };
    assert_eq!(enforcement_word(&blocked), "blocked");
    assert_eq!(enforcement_sentence(&blocked), "blocked");

    let mixed = Enforcement::Limited {
        download: policy(100_000),
        upload: policy(0),
    };
    assert_eq!(enforcement_word(&mixed), "limited");
    let sentence = enforcement_sentence(&mixed);
    assert!(sentence.starts_with("limited — dl "), "got: {sentence}");
    assert!(sentence.contains("ul blocked"), "got: {sentence}");

    let one_sided = Enforcement::Limited {
        download: policy(100_000),
        upload: None,
    };
    assert!(enforcement_sentence(&one_sided).contains("ul unlimited"));
}

/// The text report carries the owner's field spine verbatim — every
/// field the depth spec named — and no line escapes the width budget.
#[test]
fn report_lines_carry_the_owner_field_spine() {
    let report = report_fixture(Enforcement::Limited {
        download: policy(100_000),
        upload: policy(100_000),
    });
    let lines = depth_report_lines(&[report], 90);
    let text = lines.join("\n");
    // Label and value asserted separately: the labels ride a padded
    // 15-column block, so a label+value single string would pin the
    // padding by accident.
    for label in [
        "zelynic eagle-eyes --depth",
        "cg:1234 — cat-test",
        "package id:",
        "package name:",
        "run from user:",
        "run from path:",
        "cgroup path:",
        "enforcement:",
        "time:",
        "command:",
    ] {
        assert!(
            text.contains(label),
            "the report must carry '{label}', got:\n{text}"
        );
    }
    for value in [
        "cat-test",
        "uid 1000 (cat)",
        "/home/cat",
        "/sys/fs/cgroup/cat-test",
        "since started at 10m:20s ago",
        "./cat-test --serve",
        "binary",
        "755",
        "/home/cat/cat-test",
    ] {
        assert!(
            text.contains(value),
            "the report must carry '{value}', got:\n{text}"
        );
    }
    for line in &lines {
        assert!(
            crate::output::display_width(line) <= 90,
            "a report line escaped the width budget: {line}"
        );
    }
}

/// An empty cgroup reports the honest census — zero processes, no
/// crash, the "empty or exited" note the owner needs to trust.
#[test]
fn empty_cgroup_renders_the_empty_census() {
    let mut report = report_fixture(Enforcement::Unlimited);
    report.depth = CgroupDepth::default();
    let lines = depth_report_lines(&[report], 90);
    let text = lines.join("\n");
    assert!(text.contains("no live processes"), "got: {text}");
    assert!(text.contains("package name:"), "got: {text}");
    assert!(text.contains("unknown"), "got: {text}");
}

/// The socket section lists endpoints and folds the overflow into
/// the honest "+N more" note (the JSON document carries every row).
#[test]
fn socket_section_lists_endpoints_and_caps_overflow() {
    use crate::ebpf::connections::{CgroupConnections, ProcessDetail, Proto, SocketInfo};
    let sockets: Vec<SocketInfo> = (0..15)
        .map(|i| SocketInfo {
            proto: Proto::Tcp,
            remote: format!("10.0.0.{i}:443"),
            state: "ESTABLISHED",
            queued: false,
            cookie: None,
        })
        .collect();
    let mut report = report_fixture(Enforcement::Unlimited);
    report.conns = Some(CgroupConnections {
        total_procs: 1,
        socket_holders: vec![ProcessDetail {
            pid: 4242,
            comm: "curl".to_string(),
            sockets,
        }],
    });
    let lines = depth_report_lines(&[report], 100);
    let text = lines.join("\n");
    assert!(text.contains("sockets:"), "got: {text}");
    assert!(
        text.contains("curl (4242) → 10.0.0.0:443 tcp ESTABLISHED"),
        "got: {text}"
    );
    assert!(text.contains("+3 more"), "12 shown, 3 folded, got: {text}");
}

/// The JSON document is the scripting contract: the targets array
/// wraps per-target reports, a partial miss rides as its own entry,
/// and the field names are the stable v11 API vocabulary.
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
}
