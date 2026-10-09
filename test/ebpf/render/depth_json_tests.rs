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

use std::collections::HashMap;

/// A raw policy row for fixtures (rate, matching burst, group 0).
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
        window_dropped: 0,
        traffic: None,
        traffic_note: None,
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
        None,
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
    let doc = depth_doc_json(&[report_fixture(Enforcement::Unlimited)], &[], None);
    let text = serde_json::to_string(&doc).expect("serializes");
    assert!(text.contains("\"enforcement\":\"unlimited\""));
    assert!(text.contains("\"download_bps\":null"));
    assert!(text.contains("\"upload_bps\":null"));
    // The blade-5 layers are null in the unlimited shape too.
    assert!(text.contains("\"enforcement_stats\":null"));
    assert!(text.contains("\"cgroup_memory_bytes\":null"));
    assert!(text.contains("\"cgroup_cpu_usage_usec\":null"));
    // NIGHT-private-research-3: an unmeasured window is null too — a
    // script can tell "no window ran" from "zero traffic moved".
    assert!(text.contains("\"traffic\":null"));
    // NIGHT-upgrade-charger-core-1-a: the audit is null when no
    // window ran — absence, never a fabricated clean.
    assert!(text.contains("\"bypass_audit\":null"));
}

/// NIGHT-upgrade-charger-core-1-a: the bypass-shadow audit rides the
/// scripting document with the whole verdict vocabulary and the
/// honest null — a triage script gates on "verdict" without parsing
/// the text report's block.
#[test]
fn json_carries_the_bypass_audit() {
    use crate::ebpf::bypass::{
        shadow_audit, NicTotals, ShadowVerdict, SHADOW_RX_FLOOR_BYTES, SHADOW_TX_FLOOR_BYTES,
    };

    let clean = shadow_audit(
        Some(NicTotals {
            tx_bytes: 0,
            rx_bytes: 0,
        }),
        Some(NicTotals {
            tx_bytes: 10_000_000,
            rx_bytes: 11_000_000,
        }),
        9_800_000,
        10_700_000,
        3,
    );
    let doc = depth_doc_json(&[report_fixture(Enforcement::Unlimited)], &[], Some(&clean));
    let text = serde_json::to_string(&doc).expect("serializes");
    assert!(
        text.contains("\"bypass_audit\":{\"window_secs\":3"),
        "the audit object carries the window, got: {text}"
    );
    assert!(
        text.contains("\"nic_tx_bytes\":10000000"),
        "the interface totals ride, got: {text}"
    );
    assert!(
        text.contains("\"bpf_tx_bytes\":9800000"),
        "the hook totals ride, got: {text}"
    );
    assert!(
        text.contains("\"shadow_tx_bytes\":200000"),
        "the shadow is the gap, got: {text}"
    );
    assert!(
        text.contains("\"verdict\":\"clean\""),
        "a healthy window is clean, got: {text}"
    );

    // The flagged shape: every side of the verdict vocabulary the
    // constructor can produce.
    let flagged = shadow_audit(
        Some(NicTotals {
            tx_bytes: 0,
            rx_bytes: 0,
        }),
        Some(NicTotals {
            tx_bytes: SHADOW_TX_FLOOR_BYTES + 10 * 1024 * 1024,
            rx_bytes: 0,
        }),
        0,
        0,
        3,
    );
    assert_eq!(flagged.verdict, ShadowVerdict::BypassedTx);
    let rx_flagged = shadow_audit(
        Some(NicTotals {
            tx_bytes: 0,
            rx_bytes: 0,
        }),
        Some(NicTotals {
            tx_bytes: 0,
            rx_bytes: SHADOW_RX_FLOOR_BYTES + 10 * 1024 * 1024,
        }),
        0,
        0,
        3,
    );
    assert_eq!(rx_flagged.verdict, ShadowVerdict::BypassedRx);
    let doc = depth_doc_json(
        &[report_fixture(Enforcement::Unlimited)],
        &[],
        Some(&flagged),
    );
    let text = serde_json::to_string(&doc).expect("serializes");
    assert!(
        text.contains("\"verdict\":\"bypassed_tx\""),
        "the flagged verdict names its side, got: {text}"
    );

    // The unavailable shape: a window that ran against unreadable
    // counters is a named verdict, never a silent clean.
    let unreadable = shadow_audit(None, None, 1000, 2000, 3);
    assert_eq!(unreadable.verdict, ShadowVerdict::Unavailable);
    let doc = depth_doc_json(
        &[report_fixture(Enforcement::Unlimited)],
        &[],
        Some(&unreadable),
    );
    let text = serde_json::to_string(&doc).expect("serializes");
    assert!(
        text.contains("\"verdict\":\"unavailable\""),
        "the sysfs failure is honest, got: {text}"
    );
}

/// NIGHT-blade-7: the deleted-on-disk exe flag rides the scripting
/// document as a boolean — a triage pipeline filters on it instead of
/// parsing the text report's marker.
#[test]
fn json_carries_the_deleted_exe_flag() {
    let mut report = report_fixture(Enforcement::Unlimited);
    report.depth.procs[0].exe_deleted = true;
    let doc = depth_doc_json(&[report], &[], None);
    let text = serde_json::to_string(&doc).expect("serializes");
    assert!(
        text.contains("\"exe_deleted\":true"),
        "the deleted marker must serialize as true, got:\n{text}"
    );
}

/// NIGHT-private-research-3: the focus-window measurement rides the
/// document — the kernel's own window totals under `traffic`, the
/// per-endpoint attribution under each endpoint row's byte fields.
/// A socket the join resolved carries figures; a cookie-less or
/// silent socket carries nulls (the honest absence, never a
/// fabricated zero); a window that never ran carries `traffic: null`
/// (distinguishable from a zero-traffic window that DID run).
#[test]
fn json_carries_the_traffic_focus_window() {
    use crate::ebpf::connections::{CgroupConnections, ProcessDetail, Proto, SocketInfo};
    use crate::ebpf::loader::{CgroupDelta, SocketBytes};
    use crate::ebpf::render::depth_traffic::{traffic_focus, TrafficFocus};

    let mut conns = crate::ebpf::connections::ConnectionMap::new();
    conns.insert(
        1234,
        CgroupConnections {
            total_procs: 1,
            socket_holders: vec![ProcessDetail {
                pid: 4242,
                comm: "curl".to_string(),
                sockets: vec![
                    SocketInfo {
                        proto: Proto::Tcp,
                        remote: "142.250.191.78:443".to_string(),
                        state: "ESTABLISHED",
                        queued: false,
                        cookie: Some(1001),
                    },
                    SocketInfo {
                        proto: Proto::Tcp,
                        remote: "93.184.216.34:443".to_string(),
                        state: "ESTABLISHED",
                        queued: false,
                        cookie: Some(1002),
                    },
                ],
            }],
        },
    );
    let mut socket_bytes = HashMap::new();
    socket_bytes.insert(
        1001,
        SocketBytes {
            dl: 10_000_000,
            ul: 300_000,
        },
    );
    // cookie 1002 stays unjoined: the honest-absence branch.
    let deltas = vec![CgroupDelta {
        cgroup_id: 1234,
        packets: 3,
        bytes: 300_000,
        total_bytes: 0,
        ingress_packets: 100,
        ingress_bytes: 10_000_000,
        ingress_total_bytes: 0,
    }];
    let focus: TrafficFocus = traffic_focus(1234, 3, &deltas, Some(&conns), &socket_bytes);

    let mut report = report_fixture(Enforcement::Unlimited);
    report.conns = conns.get(1234).cloned();
    report.traffic = Some(focus);
    let doc = depth_doc_json(&[report], &[], None);
    let text = serde_json::to_string(&doc).expect("serializes");
    for field in [
        "\"traffic\":{\"window_secs\":3,\"download_bytes\":10000000,\"upload_bytes\":300000}",
        "\"remote\":\"142.250.191.78:443\"",
        "\"download_bytes\":10000000",
        "\"upload_bytes\":300000",
        "\"remote\":\"93.184.216.34:443\"",
        "\"download_bytes\":null",
        "\"upload_bytes\":null",
    ] {
        assert!(
            text.contains(field),
            "the private-research-3 JSON contract must carry {field}, got:\n{text}"
        );
    }
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
    let doc = depth_doc_json(&[report], &[], None);
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

// ── charger-core-3c: the depth JSON's per-socket honesty pins ────

/// A per-socket policy's depth row carries the boolean markers (and
/// the bps figures stay exactly the rates); a cgroup-lane row omits
/// them — the additive rule, the same skip-when-false shape the
/// status JSON owns.
#[test]
fn per_socket_fields_join_the_depth_row() {
    let enforcement = Enforcement::Limited {
        download: Some(PolicyRaw {
            rate_bps: 500_000,
            burst_bytes: 500_000,
            floor_bps: 0,
            ceil_bps: 0,
            group_id: 0,
            flags: 1,
        }),
        upload: policy(200_000),
    };
    let report = report_fixture(enforcement);
    let doc = depth_doc_json(&[report], &[], None);
    let text = serde_json::to_string(&doc).unwrap();
    assert!(
        text.contains("\"download_per_socket\":true"),
        "the dl marker serializes, got: {text}"
    );
    assert!(
        !text.contains("\"upload_per_socket\""),
        "the false ul marker is omitted, got: {text}"
    );
    assert!(text.contains("\"download_bps\":500000"));
}
