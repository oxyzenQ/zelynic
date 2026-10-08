// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the docker half of the container-native resolution —
//! the API-entry matching, the HTTP reply parser, the liveness
//! verdict (charger-core-2d: State.Running plus State.Status,
//! parsed defensively), the stopped-container refusal line, and the
//! docker cgroup matcher with its bounded-walk find. Split from
//! container_tests.rs at the 500-LOC owner cap when the 2d pins
//! grew the file past it (the same sibling-split lineage as
//! docker.rs itself); wired under docker.rs so `super::` is the
//! docker module and `super::super::` the shared container core.
//!
//! The IO wrappers (the socket, /sys/fs/cgroup) stay the
//! root-machine lane — every decision they make is one of these
//! pinned cores.

use super::super::find_cgroup_dir;
use super::*;
use std::path::{Path, PathBuf};

// ── the docker API matching ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn entry(id: &str, names: &[&str]) -> DockerEntry {
    DockerEntry {
        id: id.to_string(),
        names: names.iter().map(|n| n.to_string()).collect(),
        // Unknown liveness: the pre-2d shape — the matching pins
        // stay about matching, not state.
        state: None,
    }
}

fn entry_with_state(id: &str, names: &[&str], state: Option<DockerState>) -> DockerEntry {
    DockerEntry {
        id: id.to_string(),
        names: names.iter().map(|n| n.to_string()).collect(),
        state,
    }
}

fn running_state(running: bool, status: &str) -> Option<DockerState> {
    Some(DockerState {
        running,
        status: status.to_string(),
    })
}

#[test]
fn docker_entry_matches_by_name_and_id_prefix() {
    let e = entry(
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        &["/nginx"],
    );
    assert!(
        docker_entry_matches(&e, "nginx"),
        "name match (API prefix stripped)"
    );
    assert!(
        docker_entry_matches(&e, "abcdef12345678"),
        "long id prefix match"
    );
    assert!(
        !docker_entry_matches(&e, "abc"),
        "short id prefix (<4) must not match"
    );
    assert!(
        !docker_entry_matches(&e, "ngin"),
        "name must match exactly, not by prefix"
    );
    assert!(!docker_entry_matches(&e, "redis"), "no match");
}

#[test]
fn docker_match_verdicts() {
    let full = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    // One by name.
    assert_eq!(
        docker_match(&[entry(full, &["/nginx"])], "nginx"),
        DockerMatch::One {
            id: full.to_string(),
            state: None,
        }
    );
    // None.
    assert_eq!(
        docker_match(&[entry(full, &["/nginx"])], "redis"),
        DockerMatch::None
    );
    // Ambiguous: a too-short id prefix hitting two containers.
    let e2 = entry(
        "abcdef999999999999abcdef9999999999abcdef9999999999abcdef9999999999",
        &["/redis"],
    );
    match docker_match(&[entry(full, &["/nginx"]), e2.clone()], "abcdef") {
        DockerMatch::Ambiguous(labels) => {
            assert_eq!(labels, vec!["nginx".to_string(), "redis".to_string()])
        }
        other => panic!("ambiguous prefix must name both containers, got {other:?}"),
    }
    // Docker enforces unique names, but the verdict stays honest if
    // the API ever returns duplicates.
    match docker_match(&[entry(full, &["/nginx"]), e2], "nginx") {
        DockerMatch::One { id, .. } => assert_eq!(id, full),
        other => panic!("one name match must resolve, got {other:?}"),
    }
}

/// charger-core-2d: the One verdict carries the matched entry's
/// liveness state — the stopped-container refusal needs the
/// daemon's own verdict, not a cgroup-tree miss.
#[test]
fn docker_match_carries_the_liveness_state() {
    let full = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let stopped = entry_with_state(full, &["/nginx"], running_state(false, "exited"));
    assert_eq!(
        docker_match(&[stopped], "nginx"),
        DockerMatch::One {
            id: full.to_string(),
            state: running_state(false, "exited"),
        }
    );
    let live = entry_with_state(full, &["/nginx"], running_state(true, "running"));
    assert_eq!(
        docker_match(&[live], "nginx"),
        DockerMatch::One {
            id: full.to_string(),
            state: running_state(true, "running"),
        }
    );
}

/// The HTTP reply parser: a canned 200 reply parses to entries; a
/// non-200 status is a daemon answer, not a container miss.
#[test]
fn parse_docker_reply_ok_and_non_200() {
    let body = r#"[{"Id":"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890","Names":["/nginx"],"State":{"Status":"running","Running":true}}]"#;
    let reply = format!("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{body}");
    let entries = parse_docker_reply(reply.into_bytes()).expect("canned 200 reply must parse");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].names, vec!["/nginx".to_string()]);
    assert_eq!(entries[0].state, running_state(true, "running"));

    let bad = b"HTTP/1.0 500 Internal Server Error\r\n\r\n{}".to_vec();
    assert!(parse_docker_reply(bad).is_err(), "non-200 must be an error");
}

// ── night-hunt-40: the daemon-lane sanitizer contract ━━━━━━━━━━━

/// Every daemon-supplied string passes sanitize_comm at the parse
/// choke point: control characters in an Id, a Name, or a State
/// status become '?' before any consumer (refusal line, ambiguous
/// list, display label, cgroup matcher) can render them — the
/// sanitize.rs contract extended to the docker lane. Honest strings
/// ride the fast path byte-identical (the ok/non-200 pin above
/// asserts the clean shape unchanged).
#[test]
fn daemon_supplied_strings_are_sanitized_at_the_choke_point() {
    let value = serde_json::json!([{
        "Id": "abc\u{1b}]52;p;SGVsbG8=\u{7}def1234567890",
        "Names": ["/evil\u{a}nginx"],
        "State": {"Status": "run\u{d}ning", "Running": true},
    }]);
    let body = serde_json::to_string(&value).unwrap();
    let reply = format!("HTTP/1.0 200 OK\r\n\r\n{body}");
    let entries = parse_docker_reply(reply.into_bytes()).expect("canned reply must parse");
    let e = &entries[0];
    assert!(
        !e.id.contains('\u{1b}') && !e.id.contains('\u{7}'),
        "ESC/BEL must not survive in the id: {:?}",
        e.id
    );
    assert_eq!(e.names[0], "/evil?nginx");
    assert_eq!(e.state, running_state(true, "run?ning"));
}

/// The short id is CHAR-boundary safe: a lying daemon's multi-byte
/// Id never panics the slice (the old `&id[..12.min(len)]` did),
/// and honest hex ids still truncate to their first 12 chars.
#[test]
fn short_id_is_char_boundary_safe() {
    assert_eq!(short_id("abcdef1234567890"), "abcdef123456");
    let multi = "\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}";
    assert_eq!(short_id(multi).chars().count(), 12);
}

/// The ambiguous verdict rides the same char-safe truncation: two
/// id-prefix-matched entries with NO names fall back to the short
/// id — the old byte slice panicked when byte 12 fell mid-char.
#[test]
fn ambiguous_verdict_survives_a_multibyte_id() {
    // The same 2-char (4-byte) prefix makes both ids match the typed
    // prefix; the diverging byte keeps them distinct containers.
    let a = "\u{3b1}\u{3b1}1\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}";
    let b = "\u{3b1}\u{3b1}2\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}\u{3b1}";
    let entries = [entry(a, &[]), entry(b, &[])];
    match docker_match(&entries, "\u{3b1}\u{3b1}") {
        DockerMatch::Ambiguous(names) => {
            assert_eq!(names[0].chars().count(), 12);
            assert_eq!(names[1].chars().count(), 12);
        }
        other => panic!("expected the ambiguous verdict, got {other:?}"),
    }
}

// ── the liveness verdict (charger-core-2d) ━━━━━━━━━━━━━━━━━━━━━━━

/// The State parser: the modern object shape (Running + Status),
/// the modern object without Status (the word is derived, never
/// invented), the ancient bare-string shape, and the unknown shapes
/// (null, a number, an object with no Running bool) — unknown never
/// guesses, so the caller keeps its old error wording.
#[test]
fn docker_state_parse_shapes() {
    let obj: serde_json::Value =
        serde_json::from_str(r#"{"Status":"exited","Running":false}"#).unwrap();
    assert_eq!(docker_state_parse(&obj), running_state(false, "exited"));

    // No Status word: derived from the bool.
    let obj: serde_json::Value = serde_json::from_str(r#"{"Running":true}"#).unwrap();
    assert_eq!(docker_state_parse(&obj), running_state(true, "running"));
    let obj: serde_json::Value = serde_json::from_str(r#"{"Running":false}"#).unwrap();
    assert_eq!(docker_state_parse(&obj), running_state(false, "stopped"));

    // The ancient bare-string shape: "running" is the only live word.
    let obj: serde_json::Value = serde_json::from_str("\"paused\"").unwrap();
    assert_eq!(docker_state_parse(&obj), running_state(false, "paused"));
    let obj: serde_json::Value = serde_json::from_str("\"running\"").unwrap();
    assert_eq!(docker_state_parse(&obj), running_state(true, "running"));

    // Unknown shapes: null, a number, an object without a Running
    // bool — None keeps the caller's old error wording.
    assert_eq!(docker_state_parse(&serde_json::Value::Null), None);
    assert_eq!(docker_state_parse(&serde_json::json!(7)), None);
    let obj: serde_json::Value = serde_json::from_str(r#"{"Status":"running"}"#).unwrap();
    assert_eq!(docker_state_parse(&obj), None);

    // A missing State field parses as unknown too (the entry-level
    // lane — the same None through the reply parser).
    let body = r#"[{"Id":"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890","Names":["/nginx"]}]"#;
    let reply = format!("HTTP/1.0 200 OK\r\n\r\n{body}");
    let entries = parse_docker_reply(reply.into_bytes()).unwrap();
    assert_eq!(
        entries[0].state, None,
        "no State field is unknown, not dead"
    );
}

/// The stopped-container refusal line: names the container, carries
/// the daemon's own status word verbatim, and points at the one
/// tool for the leftover (a policy against the dead cgroup is an
/// orphan for 'zelynic recover'). The line must NOT blame the
/// cgroup driver layout — the layout is fine, the workload is gone
/// (the charger-core-2d close: the k8s lane's "pod is not running"
/// distinction, mirrored onto the docker lane).
#[test]
fn stopped_container_line_names_the_real_cause() {
    let line = stopped_container_line("nginx", "exited");
    assert!(
        line.contains("container 'nginx' is not running"),
        "the line names the container and the verdict: {line}"
    );
    assert!(
        line.contains("docker status: exited"),
        "the daemon's status word rides verbatim: {line}"
    );
    assert!(
        line.contains("'zelynic recover' removes it"),
        "the orphan tip rides: {line}"
    );
    assert!(
        !line.contains("unrecognized cgroup driver layout"),
        "a stopped container must not be blamed on the layout: {line}"
    );
}

// ── the docker cgroup matcher ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn docker_cgroup_matches_both_drivers() {
    let full = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    // systemd driver: docker-<id>.scope, at any slice depth.
    assert!(docker_cgroup_matches(
        Path::new("/sys/fs/cgroup/system.slice")
            .join(format!("docker-{full}.scope"))
            .as_path(),
        full
    ));
    assert!(docker_cgroup_matches(
        Path::new("/sys/fs/cgroup/user.slice/user-1000.slice")
            .join(format!("docker-{full}.scope"))
            .as_path(),
        full
    ));
    // cgroupfs driver: <id> under a docker directory.
    assert!(docker_cgroup_matches(
        Path::new("/sys/fs/cgroup/docker").join(full).as_path(),
        full
    ));
    // Wrong shapes: id outside a docker parent, wrong id, a scope
    // for another container.
    assert!(!docker_cgroup_matches(
        Path::new("/sys/fs/cgroup").join(full).as_path(),
        full
    ));
    assert!(!docker_cgroup_matches(
        Path::new("/sys/fs/cgroup/docker")
            .join("deadbeef")
            .as_path(),
        full
    ));
    assert!(!docker_cgroup_matches(
        Path::new("/sys/fs/cgroup/system.slice")
            .join(format!("docker-{full}.scope"))
            .as_path(),
        "1111111111111111111111111111111111111111111111111111111111111111"
    ));
}

// ── the bounded walk, docker lane (tempdir tree) ━━━━━━━━━━━━━━━━━

fn temp_tree(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zelynic-dt-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The walk finds the docker scope under a nested slice, exactly the
/// systemd-driver layout, and returns the directory the id is
/// stat()ed from.
#[test]
fn walk_finds_docker_scope_in_nested_tree() {
    let root = temp_tree("scope");
    let full = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let scope = root
        .join("system.slice")
        .join(format!("docker-{full}.scope"));
    std::fs::create_dir_all(&scope).unwrap();
    std::fs::create_dir_all(root.join("init.scope")).unwrap();

    let hit = find_cgroup_dir(&root, &|p| docker_cgroup_matches(p, full));
    assert_eq!(hit, Some(scope));
    let _ = std::fs::remove_dir_all(&root);
}
