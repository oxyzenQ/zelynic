// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! Pins for the iface:// lane (night-T-2) — the pure cores: the URI
//! grammar arm (shared with the container lanes' parse, and its
//! round-trip through Target::parse) and the vrf-parent cgroup matcher
//! (the iproute2 `ip vrf exec` contract). The IO wrappers (the
//! cgroup walk, the cgroup.procs liveness read) stay the root-machine
//! lane — every decision they make is one of these pinned cores.

use super::super::find_cgroup_dir;
use super::*;
use crate::ebpf::identity::container::{ContainerRef, parse_container};
use std::path::PathBuf;

// ── the URI grammar ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn parse_iface_uri() {
    let Some(ContainerRef::Iface { name }) = parse_container("iface://red") else {
        panic!("iface://red must parse");
    };
    assert_eq!(name, "red");
}

/// The display form round-trips — every surface that prints the
/// target produces a command that works verbatim.
#[test]
fn display_round_trips() {
    let c = ContainerRef::Iface {
        name: "red".to_string(),
    };
    assert_eq!(c.display(), "iface://red");
    assert_eq!(parse_container("iface://red"), Some(c));
}

/// Malformed shapes return None — they fall back to the
/// process-name lane (the graceful no-match), never a half-parsed
/// reference. The name law is the docker lane's verbatim:
/// non-empty, no '/', no ':'.
#[test]
fn parse_rejects_malformed_iface_uris() {
    for bad in [
        "iface://",     // empty name
        "iface://a/b",  // '/' in name
        "iface://a:b",  // ':' in name (breaks the embedded grammars)
        "iface://a::b", // the list separator can never ride the name
    ] {
        assert_eq!(parse_container(bad), None, "{bad} must not parse");
    }
}

/// The parse rides Target::parse first — an iface URI is a Container
/// target, not a process name (the sibling lanes' ride).
#[test]
fn target_parse_rides_iface() {
    use crate::ebpf::limiter::Target;
    let Target::Container(ContainerRef::Iface { name }) = Target::parse("iface://red") else {
        panic!("iface://red must parse as a container target");
    };
    assert_eq!(name, "red");
}

// ── the vrf-parent matcher ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn temp_tree(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zelynic-if-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The matcher accepts `<name>` under a parent named `vrf` — the
/// iproute2 `ip vrf exec` contract, the shape `ip vrf identify` reads
/// back from /proc/<pid>/cgroup — at ANY depth (the caller's cgroup
/// path prefixes the vrf/ subtree). Anything else is an impostor.
#[test]
fn matcher_requires_the_vrf_parent() {
    let root = temp_tree("parent");
    let domain = root.join("vrf").join("red");
    std::fs::create_dir_all(&domain).unwrap();
    let nested = root
        .join("system.slice")
        .join("work.scope")
        .join("vrf")
        .join("red");
    std::fs::create_dir_all(&nested).unwrap();
    let impostor = root.join("red");
    std::fs::create_dir_all(&impostor).unwrap();
    let wrong_parent = root.join("slices").join("red");
    std::fs::create_dir_all(&wrong_parent).unwrap();

    assert!(iface_cgroup_matches(&domain, "red"));
    assert!(iface_cgroup_matches(&nested, "red"));
    assert!(
        !iface_cgroup_matches(&impostor, "red"),
        "a depth-1 directory with no vrf parent is an impostor"
    );
    assert!(
        !iface_cgroup_matches(&wrong_parent, "red"),
        "a same-named directory under a non-vrf parent is an impostor"
    );
    assert!(
        !iface_cgroup_matches(&root.join("vrf").join("blue"), "red"),
        "a different name is a clean miss"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The walk over a tempdir tree finds the domain (the vrf/<name>
/// shape, nested or not) and misses cleanly when only the impostor
/// exists — the bounded walk and the matcher compose into the
/// resolver's find.
#[test]
fn walk_finds_the_vrf_domain_only() {
    let root = temp_tree("walk");
    let domain = root.join("vrf").join("red");
    std::fs::create_dir_all(&domain).unwrap();

    let hit = find_cgroup_dir(&root, &|p| iface_cgroup_matches(p, "red"));
    assert_eq!(hit, Some(domain));

    let impostor_root = temp_tree("walk2");
    let impostor = impostor_root.join("system.slice").join("red");
    std::fs::create_dir_all(&impostor).unwrap();
    assert_eq!(
        find_cgroup_dir(&impostor_root, &|p| iface_cgroup_matches(p, "red")),
        None,
        "an impostor without the vrf parent must be a clean miss"
    );
    let _ = std::fs::remove_dir_all(&impostor_root);
    let _ = std::fs::remove_dir_all(&root);
}
