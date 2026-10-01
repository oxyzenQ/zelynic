// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the id-to-path resolver (NIGHT-repair-1): the
//! truncating match rule (the numbering the /proc lane and the
//! walk must agree on), the mount-relative path shape, and the
//! never-panic contract of the bounded walk itself — plus the live
//! lane the fleet beds ride: the mount root resolves by inode with
//! no member process anywhere in sight.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::*;

/// The truncating match: an inode wider than 32 bits truncates to
/// the u32 the maps key on — the walk can never disagree with the
/// /proc lane about which directory an id names.
#[test]
fn inode_match_truncates_like_the_proc_lane() {
    assert!(inode_is(42, 42));
    assert!(inode_is(0x1_0000_002A, 42));
    assert!(!inode_is(0x1_0000_002A, 41));
    assert!(!inode_is(43, 42));
}

/// The rel-path shape: the mount root itself is "/" (the
/// memberless root the /proc lane can never name), a nested bed
/// carries the leading slash the "0::<path>" lanes print.
#[test]
fn rel_paths_carry_the_leading_slash() {
    assert_eq!(rel_path_of(Path::new("/sys/fs/cgroup")), "/");
    assert_eq!(rel_path_of(Path::new("/sys/fs/cgroup/a")), "/a");
    assert_eq!(rel_path_of(Path::new("/sys/fs/cgroup/a/b")), "/a/b");
}

/// The resolver never panics on an absent id — the honest None,
/// the same contract the /proc walk's absent-cgroup pin owns.
#[test]
fn resolver_never_panics_on_absent_id() {
    assert!(rel_path_by_id(u32::MAX).is_none());
}

/// The live lane (the one the fleet beds ride): the mount root
/// resolves by inode with NO member process — stat the mount,
/// resolve that id, and the walk must name it "/" even though no
/// /proc line ever could. zelynic is Linux-only with cgroup v2 as
/// a hard prerequisite (the limiter bails without the mount), so
/// the assert stands loud on every supported host.
#[test]
fn walk_resolves_the_mount_root_by_inode() {
    let meta = std::fs::metadata("/sys/fs/cgroup")
        .expect("cgroup v2 mount absent — the limiter's own prerequisite");
    let got = rel_path_by_id(meta.ino() as u32);
    assert_eq!(got.as_deref(), Some("/"));
}
