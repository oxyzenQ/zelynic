// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the container-native target resolution
//! (NIGHT-upgrade-charger-core-2, TIER A #5) — the pure cores: the
//! URI grammar (and its round-trip through Target::parse), the
//! /var/log/pods directory-name parser, the pod cgroup matcher,
//! and the bounded cgroup walk over a tempdir tree. The docker
//! lane's own pins (API-entry matching, the reply parser, the
//! liveness verdict, the docker cgroup matcher) split into
//! docker_tests.rs, wired under docker.rs, when the charger-
//! core-2d pins grew this file past the 500-LOC owner cap — the
//! same sibling-split lineage as docker.rs itself. The IO wrappers
//! (socket, /var/log/pods, /sys/fs/cgroup) stay the root-machine
//! lane — every decision they make is one of these pinned cores.

use super::*;

// ── the URI grammar ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn parse_docker_uri() {
    let Some(ContainerRef::Docker { name }) = parse_container("docker://nginx") else {
        panic!("docker://nginx must parse");
    };
    assert_eq!(name, "nginx");
}

#[test]
fn parse_k8s_uri() {
    let Some(ContainerRef::K8s { namespace, pod }) = parse_container("k8s://prod/pod-abc") else {
        panic!("k8s://prod/pod-abc must parse");
    };
    assert_eq!(namespace, "prod");
    assert_eq!(pod, "pod-abc");
}

/// Malformed shapes return None — they fall back to the
/// process-name lane (the graceful no-match), never a half-parsed
/// container reference.
#[test]
fn parse_rejects_malformed_uris() {
    for bad in [
        "docker://",     // empty name
        "docker://a/b",  // '/' in name
        "docker://a:b",  // ':' in name (breaks the colon grammar)
        "k8s://prod",    // no pod part
        "k8s://prod/",   // empty pod
        "k8s:///pod",    // empty namespace
        "k8s://a/b/c",   // more than one '/'
        "docker:/nginx", // single slash — not the URI form
        "podman://x",    // unknown scheme is a name, not a URI
        "brave",         // plain process name
        "cg:48181",      // the canonical display prefix stays an id
        "73386",         // bare numeric id
    ] {
        assert!(
            parse_container(bad).is_none(),
            "'{bad}' must not parse as a container reference"
        );
    }
}

/// The display form round-trips: every surface that prints a
/// container target produces a command that works verbatim.
#[test]
fn display_round_trips_through_parse() {
    for c in [
        ContainerRef::Docker {
            name: "nginx".into(),
        },
        ContainerRef::K8s {
            namespace: "prod".into(),
            pod: "pod-abc".into(),
        },
    ] {
        let displayed = c.display();
        assert_eq!(
            parse_container(&displayed),
            Some(c),
            "{displayed} must round-trip"
        );
    }
}

/// Target::parse integration: the URI forms become Container
/// targets BEFORE the numeric/name lanes see them, and those lanes
/// are untouched for every other shape.
#[test]
fn target_parse_routes_container_uris() {
    assert!(matches!(
        crate::ebpf::limiter::Target::parse("docker://nginx"),
        crate::ebpf::limiter::Target::Container(_)
    ));
    assert!(matches!(
        crate::ebpf::limiter::Target::parse("k8s://prod/pod-abc"),
        crate::ebpf::limiter::Target::Container(_)
    ));
    assert!(matches!(
        crate::ebpf::limiter::Target::parse("brave"),
        crate::ebpf::limiter::Target::ProcessName(_)
    ));
    assert!(matches!(
        crate::ebpf::limiter::Target::parse("cg:48181"),
        crate::ebpf::limiter::Target::CgroupId(48181)
    ));
}

/// Target::label: the display form every surface prints.
#[test]
fn target_label_prints_the_uri_verbatim() {
    use crate::ebpf::limiter::Target;
    let c = Target::parse("docker://nginx");
    assert_eq!(c.label(), "docker://nginx");
    assert_eq!(Target::parse("cg:48181").label(), "cg:48181");
    assert_eq!(Target::parse("brave").label(), "brave");
}

// ── the /var/log/pods directory-name grammar ━━━━━━━━━━━━━━━━━━━━━

const UID: &str = "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d";

#[test]
fn uuid_shape_check() {
    assert!(uid_looks_like_uuid(UID));
    assert!(!uid_looks_like_uuid("short"));
    assert!(!uid_looks_like_uuid(
        "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d1a2b3c4"
    )); // 36, no dashes
    assert!(!uid_looks_like_uuid("1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6z")); // non-hex
    assert!(!uid_looks_like_uuid("1a2b3c4d_5e6f_7a8b_9c0d_1e2f3a4b5c6d")); // underscores
}

#[test]
fn parse_pod_log_dir_names() {
    assert_eq!(
        parse_pod_log_dir(&format!("prod_web-abc_{UID}")),
        Some(("prod".into(), "web-abc".into(), UID.into()))
    );
    // kubelet writes agent-side files too — only 3-part, UUID-uid
    // names are pods. (A UUID carries dashes, not underscores, so
    // the 3-part split is exact for every real pod dir.)
    assert_eq!(parse_pod_log_dir("kube-root-ca.crt"), None);
    assert_eq!(parse_pod_log_dir(&format!("prod_web_extra_{UID}")), None); // 4 parts
    assert_eq!(parse_pod_log_dir(&format!("prod_{UID}")), None); // 2 parts
    assert_eq!(parse_pod_log_dir(&format!("prod__{UID}")), None); // empty pod
    assert_eq!(parse_pod_log_dir("prod_web_12345"), None); // uid not a UUID
    assert_eq!(
        parse_pod_log_dir(&format!("prod_web_{UID}")),
        Some(("prod".into(), "web".into(), UID.into()))
    );
}

#[test]
fn pod_uid_matches_filters_namespace_and_pod() {
    let dirs = vec![
        ("prod".to_string(), "web-abc".to_string(), UID.to_string()),
        ("prod".to_string(), "web-def".to_string(), "b".repeat(36)),
        ("default".to_string(), "web-abc".to_string(), "c".repeat(36)),
    ];
    assert_eq!(
        pod_uid_matches(&dirs, "prod", "web-abc"),
        vec![UID.to_string()]
    );
    assert!(pod_uid_matches(&dirs, "dev", "web-abc").is_empty());
}

// ── the cgroup directory matchers ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn pod_cgroup_matches_both_drivers() {
    // systemd driver: kubepods[-<qos>]-pod<uid>.slice — suffix match
    // (the QoS prefix varies).
    for name in [
        format!("kubepods-pod{UID}.slice"),
        format!("kubepods-burstable-pod{UID}.slice"),
        format!("kubepods-besteffort-pod{UID}.slice"),
    ] {
        assert!(
            pod_cgroup_matches(Path::new("/sys/fs/cgroup").join(&name).as_path(), UID),
            "{name}"
        );
    }
    // cgroupfs driver: exact pod<uid> directory.
    assert!(pod_cgroup_matches(
        Path::new("/sys/fs/cgroup/kubepods")
            .join(format!("pod{UID}"))
            .as_path(),
        UID
    ));
    // Other pods do not match.
    assert!(!pod_cgroup_matches(
        Path::new("/sys/fs/cgroup")
            .join(format!(
                "kubepods-pod{}.slice",
                UID.chars().rev().collect::<String>()
            ))
            .as_path(),
        UID
    ));
}

// ── the bounded walk (tempdir tree) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn temp_tree(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zelynic-ct-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The walk finds the docker scope under a nested slice, exactly the
/// systemd-driver layout, and returns the directory the id is
/// stat()ed from.
#[test]
fn walk_finds_and_misses_pod_slice() {
    let root = temp_tree("pod");
    let slice = root
        .join("kubepods.slice")
        .join("kubepods-burstable.slice")
        .join(format!("kubepods-burstable-pod{UID}.slice"));
    std::fs::create_dir_all(&slice).unwrap();

    let hit = find_cgroup_dir(&root, &|p| pod_cgroup_matches(p, UID));
    assert_eq!(hit, Some(slice));
    assert_eq!(
        find_cgroup_dir(&root, &|p| pod_cgroup_matches(
            p,
            "ffffffff-1111-2222-3333-444455556666"
        )),
        None,
        "an absent pod must be a clean miss"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The walk never descends past the depth cap: a matcher that lives
/// deeper than WALK_MAX_DEPTH is not found (the bounded-tree
/// contract — a hostile tree cannot wedge a CLI invocation).
#[test]
fn walk_respects_the_depth_cap() {
    let root = temp_tree("depth");
    let mut deep = root.clone();
    for i in 0..(WALK_MAX_DEPTH + 2) {
        deep = deep.join(format!("d{i}"));
    }
    std::fs::create_dir_all(&deep).unwrap();
    let name = deep.file_name().unwrap().to_str().unwrap().to_string();
    assert_eq!(
        find_cgroup_dir(&root, &|p| p.file_name().and_then(|n| n.to_str())
            == Some(&name)),
        None
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The cgroup id of a directory is the kernfs inode (the same
/// resolution pid_cgroup_id applies), truncated to u32 — a real
/// stat() over the tempdir, so the resolution lane itself is
/// exercised rootlessly.
#[test]
fn cgroup_id_of_reads_the_inode() {
    let root = temp_tree("ino");
    let id = cgroup_id_of(&root).expect("a real directory must stat");
    let meta = std::fs::metadata(&root).unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_eq!(id, meta.ino() as u32);
    assert_eq!(
        cgroup_id_of(Path::new("/nonexistent-zelynic-test/nope")),
        None
    );
    let _ = std::fs::remove_dir_all(&root);
}
