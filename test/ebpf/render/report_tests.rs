// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the eagle-eyes --depth report composition
//! (NIGHT-master-1): the package-name ladder, the enforcement
//! verdict vocabulary, the owner's field spine on the text report,
//! the socket cap, and — since NIGHT-blade-5 — the accounting
//! line's ledger math, the controller-resource rows, the census's
//! thr/rss columns, and the act-on-this tail — all driven by
//! fixtures, never the host. The JSON document's scripting contract
//! pins live in depth_json_tests.rs (the split that followed the
//! code).

use super::*;

// The blade-5 fixture family: the controller's resource view and
// the kernel's enforcement ledger, the two layers the depth upgrade
// added to the composition.
use crate::ebpf::identity::depth::CgroupResources;
use crate::ebpf::limiter::LimiterStatsRaw;

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

// The JSON document pins moved with the code: the scripting
// contract lives in depth_json_tests.rs since the NIGHT-blade-5
// split (same fixtures, same vocabulary, plus the ledger and
// controller-resource fields).

/// NIGHT-blade-5: the accounting line — the kernel's ledger as one
/// glance. The drop share is of everything that ARRIVED (allowed +
/// dropped), and a zero-traffic ledger says so instead of dividing
/// by zero.
#[test]
fn accounting_sentence_carries_the_ledger_math() {
    let heavy = LimiterStatsRaw {
        packets_allowed: 900,
        packets_dropped: 100,
        bytes_allowed: 900_000,
        bytes_dropped: 100_000,
    };
    let sentence = accounting_sentence(&heavy);
    assert!(
        sentence.contains("dropped"),
        "the sentence must carry the drop leg, got: {sentence}"
    );
    assert!(
        sentence.ends_with("10.00% of what arrived)"),
        "100 KiB of 1000 KiB is exactly 10 percent, got: {sentence}"
    );

    let quiet = LimiterStatsRaw {
        packets_allowed: 0,
        packets_dropped: 0,
        bytes_allowed: 0,
        bytes_dropped: 0,
    };
    assert_eq!(
        accounting_sentence(&quiet),
        "enforced, nothing booked yet",
        "a zero ledger stays honest"
    );
}

/// NIGHT-blade-5: the report renders the accounting and
/// controller-resource rows only when the layers actually resolved —
/// None is the honest absence, never a fabricated zero.
#[test]
fn ledger_and_resource_rows_render_only_when_present() {
    let mut report = report_fixture(Enforcement::Limited {
        download: policy(100_000),
        upload: policy(100_000),
    });
    let without = depth_report_lines(&[report.clone()], 100).join("\n");
    assert!(
        !without.contains("accounting:"),
        "no ledger, no accounting row, got:\n{without}"
    );
    assert!(
        !without.contains("cgroup memory:"),
        "no controller view, no memory row, got:\n{without}"
    );

    report.enforcement_stats = Some(LimiterStatsRaw {
        packets_allowed: 900,
        packets_dropped: 100,
        bytes_allowed: 900_000,
        bytes_dropped: 100_000,
    });
    report.depth.resources = CgroupResources {
        memory_current_bytes: Some(2_500_000),
        cpu_usage_usec: Some(62_000_000),
    };
    let with = depth_report_lines(&[report], 100).join("\n");
    assert!(
        with.contains("accounting:"),
        "the ledger row must render, got:\n{with}"
    );
    assert!(
        with.contains("cgroup memory:"),
        "the memory row must render, got:\n{with}"
    );
    assert!(
        with.contains("cgroup cpu:"),
        "the cpu row must render, got:\n{with}"
    );
}

/// NIGHT-blade-5: the census table shows the thread count and the
/// resident memory per member — the resource cost the JSON always
/// carried, now on the readable surface too.
#[test]
fn census_table_carries_threads_and_rss_columns() {
    let report = report_fixture(Enforcement::Unlimited);
    let lines = depth_report_lines(&[report], 110);
    let text = lines.join("\n");
    assert!(
        text.contains(" thr "),
        "the census header must name the thread column, got:\n{text}"
    );
    assert!(
        text.contains(" rss "),
        "the census header must name the memory column, got:\n{text}"
    );
    // NIGHT-blade-7: the state column joins the census — the /proc
    // state letter (S/R/D/Z) the JSON carried as full words.
    assert!(
        text.contains(" st "),
        "the census header must name the state column, got:\n{text}"
    );
    // The fixture member: 4 threads, 1234 KiB RSS. The census row
    // (not the headline) carries the type column — "binary" pins it.
    let row = text
        .lines()
        .find(|l| l.contains("cat-test") && l.contains("binary"))
        .expect("the census row renders");
    assert!(row.contains(" 4 "), "thread count 4, got: {row}");
    assert!(
        row.contains("1.3 MB"),
        "1234 KiB is 1,263,616 bytes, one-decimal 1.3 MB, got: {row}"
    );
    // NIGHT-blade-7: the state letter rides the census row — the
    // fixture member is "S (sleeping)", so "S" is the cell.
    assert!(
        row.contains(" S "),
        "the sleeping state letter rides the census row, got: {row}"
    );
    for line in &lines {
        assert!(
            crate::output::display_width(line) <= 110,
            "a report line escaped the width budget: {line}"
        );
    }
}

/// NIGHT-blade-7: a member whose on-disk binary was replaced or
/// removed keeps its exe path and gains the kernel's own
/// " (deleted)" marker — the update-mid-run / self-deleting loader
/// indicator stays visible on the readable surface.
#[test]
fn census_marks_the_deleted_exe() {
    let mut report = report_fixture(Enforcement::Unlimited);
    report.depth.procs[0].exe_deleted = true;
    let lines = depth_report_lines(&[report], 110);
    let text = lines.join("\n");
    let row = text
        .lines()
        .find(|l| l.contains("cat-test") && l.contains("binary"))
        .expect("the census row renders");
    assert!(
        row.contains("/home/cat/cat-test (deleted)"),
        "the deleted marker rides the exe cell, got: {row}"
    );
    for line in &lines {
        assert!(
            crate::output::display_width(line) <= 110,
            "a report line escaped the width budget: {line}"
        );
    }
}

/// NIGHT-blade-5: the act-on-this tail — every report block ends
/// with the three copy-paste commands, keyed to the exact cgroup the
/// report just dissected (the cg: id round-trips through the same
/// autodetection that resolved the target).
#[test]
fn report_ends_with_the_act_on_this_tail() {
    let report = report_fixture(Enforcement::Unlimited);
    let text = depth_report_lines(&[report], 100).join("\n");
    for tip in [
        "act on this:",
        "zelynic strict-single cg:1234 500kb",
        "zelynic block-single cg:1234",
        "zelynic ee cg:1234",
    ] {
        assert!(
            text.contains(tip),
            "the report tail must carry '{tip}', got:\n{text}"
        );
    }
}
