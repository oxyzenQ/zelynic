// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! Pins for the identity drift alarm (night-frontier-Z3) — the pure
//! cores (the file-name law, the line format, the verdict reduction,
//! the warning wording) plus the tempdir-driven IO round trips (the
//! unpin_dir discipline: every production wrapper is a thin
//! IDENTITY_DIR call over the same code the pins drive).

use super::*;
use std::fs;

// ── the file-name law ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn pin_file_name_accepts_the_lanes_names() {
    assert_eq!(
        pin_file_name(NETNS_LANE, "sandbox").as_deref(),
        Some("netns_sandbox.pin")
    );
    assert_eq!(
        pin_file_name(IFACE_LANE, "vrf0").as_deref(),
        Some("iface_vrf0.pin")
    );
}

#[test]
fn pin_file_name_refuses_the_grammar_breakers() {
    // A foreign lane is not this alarm's to write.
    assert!(pin_file_name("docker", "web").is_none());
    // The URI grammar's own bans, re-checked at the file boundary.
    assert!(pin_file_name(NETNS_LANE, "").is_none());
    assert!(pin_file_name(NETNS_LANE, "a/b").is_none());
    assert!(pin_file_name(NETNS_LANE, "a:b").is_none());
    assert!(pin_file_name(NETNS_LANE, "a b").is_none());
    assert!(pin_file_name(NETNS_LANE, "a\nb").is_none());
    assert!(pin_file_name(NETNS_LANE, &"x".repeat(65)).is_none());
}

// ── the line format ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn sample_pin() -> IdentityPin {
    IdentityPin {
        uri: "netns://sandbox".to_string(),
        lane: NETNS_LANE.to_string(),
        name: "sandbox".to_string(),
        cgroup_id: 1234,
        identity: 4026532500,
    }
}

#[test]
fn pin_line_format_round_trips() {
    let pin = sample_pin();
    let parsed = parse_pin(&serialize_pin(&pin)).expect("the five-line form parses");
    assert_eq!(parsed, pin);
}

#[test]
fn parse_pin_refuses_garbage() {
    assert!(parse_pin("").is_none());
    assert!(parse_pin("uri=netns://x\n").is_none()); // missing keys
    assert!(parse_pin("uri=netns://x\nlane=netns\nname=x\ncgroup=abc\nidentity=1\n").is_none());
    assert!(parse_pin("uri=netns://x\nlane=netns\nname=x\ncgroup=1\nidentity=abc\n").is_none());
    assert!(parse_pin("garbage line\n").is_none());
    assert!(parse_pin("uri=a\nuri=b\nlane=netns\nname=x\ncgroup=1\nidentity=2\n").is_none());
}

// ── the verdict reduction ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn drift_verdict_truth_table() {
    // Same word — the watch points where it pointed.
    assert_eq!(drift_verdict(100, Some(100)), DriftVerdict::Live);
    // Source gone against a recorded identity — the corpse.
    assert_eq!(drift_verdict(100, None), DriftVerdict::Removed);
    // Different word — recreated.
    assert_eq!(
        drift_verdict(100, Some(200)),
        DriftVerdict::Recreated { current: 200 }
    );
    // The 0 sentinel: no identity at attach, source still absent —
    // the honest silence.
    assert_eq!(drift_verdict(0, None), DriftVerdict::Unverifiable);
    // The 0 sentinel with the source APPEARING — a change the
    // operator should see.
    assert_eq!(
        drift_verdict(0, Some(5)),
        DriftVerdict::Recreated { current: 5 }
    );
}

// ── the warning wording ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn removed_warning_names_the_corpse_and_both_doors() {
    let pin = sample_pin();
    let lines = warning_lines(&pin, &DriftVerdict::Removed);
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("STALE: netns://sandbox is gone"));
    assert!(lines[0].contains("policy cg:1234"));
    assert!(lines[0].contains("the watch points at a corpse"));
    assert!(lines[1].contains("tip: re-apply"));
    assert!(lines[1].contains("zelynic u cg:1234"));
}

#[test]
fn recreated_warning_carries_both_identities() {
    let pin = sample_pin();
    let lines = warning_lines(
        &pin,
        &DriftVerdict::Recreated {
            current: 4026539999,
        },
    );
    assert!(lines[0].starts_with("STALE: netns://sandbox was recreated"));
    assert!(lines[0].contains("4026532500 -> 4026539999"));
    assert!(lines[0].contains("policy cg:1234"));
}

#[test]
fn live_and_unverifiable_print_nothing() {
    let pin = sample_pin();
    assert!(warning_lines(&pin, &DriftVerdict::Live).is_empty());
    assert!(warning_lines(&pin, &DriftVerdict::Unverifiable).is_empty());
}

#[test]
fn iface_warnings_name_the_vrf_domain() {
    let pin = IdentityPin {
        uri: "iface://vrf0".to_string(),
        lane: IFACE_LANE.to_string(),
        name: "vrf0".to_string(),
        cgroup_id: 7,
        identity: 5,
    };
    let lines = warning_lines(&pin, &DriftVerdict::Removed);
    assert!(lines[0].contains("dead VRF domain"));
}

// ── the IO round trips (tempdir-driven) ━━━━━━━━━━━━━━━━━━━━━━━━━━

fn tempdir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "zelynic-drift-pin-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).expect("tempdir creates");
    dir
}

#[test]
fn write_read_round_trip() {
    let dir = tempdir();
    let pin = sample_pin();
    write_identity_pin_in(&dir, &pin).expect("the write lands");
    assert_eq!(read_identity_pins_in(&dir), vec![pin]);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn read_skips_unparsable_files_and_missing_dir_is_empty() {
    let dir = tempdir();
    assert!(read_identity_pins_in(&dir).is_empty());
    fs::write(dir.join("foreign.txt"), "not a pin").ok();
    write_identity_pin_in(&dir, &sample_pin()).expect("the write lands");
    assert_eq!(read_identity_pins_in(&dir).len(), 1);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn drop_for_cgroups_takes_only_the_matching_ids() {
    let dir = tempdir();
    let mut pin = sample_pin();
    write_identity_pin_in(&dir, &pin).expect("the write lands");
    pin.uri = "netns://other".to_string();
    pin.name = "other".to_string();
    pin.cgroup_id = 99;
    write_identity_pin_in(&dir, &pin).expect("the write lands");
    assert_eq!(drop_identity_pins_for_cgroups_in(&dir, &[1234]), 1);
    let rest = read_identity_pins_in(&dir);
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].cgroup_id, 99);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn drop_for_uri_takes_only_the_matching_uri() {
    let dir = tempdir();
    let mut pin = sample_pin();
    write_identity_pin_in(&dir, &pin).expect("the write lands");
    pin.uri = "netns://other".to_string();
    pin.name = "other".to_string();
    pin.cgroup_id = 99;
    write_identity_pin_in(&dir, &pin).expect("the write lands");
    assert_eq!(drop_identity_pins_for_uri_in(&dir, "netns://sandbox"), 1);
    let rest = read_identity_pins_in(&dir);
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].uri, "netns://other");
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn verify_drops_ghost_pins_and_reports_drifted_ones() {
    let dir = tempdir();
    let mut pin = sample_pin();
    // A live pin whose handle file CHANGED identity: recreated.
    let handle = dir.join("netns_sandbox.pin");
    write_identity_pin_in(&dir, &pin).expect("the write lands");
    // A ghost pin: no policy holds cg:99.
    pin.uri = "netns://ghost".to_string();
    pin.name = "ghost".to_string();
    pin.cgroup_id = 99;
    write_identity_pin_in(&dir, &pin).expect("the write lands");

    // Only cg:1234 is live. The ghost's file is gone after the visit.
    let live: HashSet<u32> = [1234u32].into_iter().collect();
    // The netns lane's IO probe reads /run/netns — absent in this
    // view, so the live pin's verdict is Removed (identity recorded,
    // source gone) — the corpse case the alarm exists for.
    let drifted = verify_identity_pins_in(&dir, &live);
    assert_eq!(drifted.len(), 1);
    assert_eq!(drifted[0].0.uri, "netns://sandbox");
    assert_eq!(drifted[0].1, DriftVerdict::Removed);
    assert!(handle.exists()); // the live pin's file stays
    assert!(!dir.join("netns_ghost.pin").exists()); // the ghost's goes
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn sweep_takes_the_whole_directory() {
    let dir = tempdir();
    write_identity_pin_in(&dir, &sample_pin()).expect("the write lands");
    assert_eq!(sweep_identity_dir_in(&dir), 1);
    assert!(!dir.exists());
    // An empty sweep is honest zero, twice (idempotent).
    assert_eq!(sweep_identity_dir_in(&dir), 0);
}

// ── the mouth order (night-depth-hardening-1) ━━━━━━━━━━━━━━━━━━━━

#[test]
fn read_returns_pins_in_uri_order_regardless_of_readdir_order() {
    let dir = tempdir();
    // Written in a deliberately shuffled order; readdir owes no
    // order at all, so the read's uri-ascending list is the pins'
    // own total order, never the filesystem's.
    for (lane, name) in [
        (IFACE_LANE, "vrf-b"),
        (NETNS_LANE, "alpha"),
        (IFACE_LANE, "vrf-a"),
        (NETNS_LANE, "zulu"),
    ] {
        let pin = IdentityPin {
            uri: format!("{lane}://{name}"),
            lane: lane.to_string(),
            name: name.to_string(),
            cgroup_id: 7,
            identity: 5,
        };
        write_identity_pin_in(&dir, &pin).expect("the write lands");
    }
    let uris: Vec<String> = read_identity_pins_in(&dir)
        .into_iter()
        .map(|p| p.uri)
        .collect();
    assert_eq!(
        uris,
        [
            "iface://vrf-a",
            "iface://vrf-b",
            "netns://alpha",
            "netns://zulu"
        ]
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn verify_reports_drifted_pins_in_uri_order() {
    let dir = tempdir();
    // Three live watches written shuffled; the lane probes find no
    // /sys/class/net here, so each recorded identity reads Removed —
    // the corpse case — and the STALE lines' order must be
    // uri-ascending, the mouths' total order.
    for name in ["vrf-c", "vrf-a", "vrf-b"] {
        let pin = IdentityPin {
            uri: format!("iface://{name}"),
            lane: IFACE_LANE.to_string(),
            name: name.to_string(),
            cgroup_id: 11,
            identity: 5,
        };
        write_identity_pin_in(&dir, &pin).expect("the write lands");
    }
    let live: HashSet<u32> = [11u32].into_iter().collect();
    let drifted = verify_identity_pins_in(&dir, &live);
    let uris: Vec<&str> = drifted.iter().map(|(p, _)| p.uri.as_str()).collect();
    assert_eq!(uris, ["iface://vrf-a", "iface://vrf-b", "iface://vrf-c"]);
    assert!(drifted.iter().all(|(_, v)| *v == DriftVerdict::Removed));
    fs::remove_dir_all(&dir).ok();
}
