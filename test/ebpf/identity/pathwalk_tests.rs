// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the id-to-path resolver (NIGHT-repair-1): the
//! truncating match rule (the numbering the /proc lane and the
//! walk must agree on), the mount-relative path shape, and the
//! never-panic contract of the bounded walk itself — plus the live
//! lane the fleet beds ride: the mount root resolves by inode with
//! no member process anywhere in sight. The cgroupfs id census
//! (the zombie sweep's death proof) pins beside its resolver
//! sibling: the live walk admits the mount, and the synthetic
//! trees pin the complete-or-nothing law — a census that did not
//! finish proves nothing.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

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

// ── the cgroupfs id census (the death proof) ───────────────────────

/// A unique scratch tree for one pin — created empty, removed
/// best-effort on drop (the tests that use it never assert on
/// cleanup: a leaked scratch dir under /tmp is a CI nuisance, not
/// a false verdict).
struct ScratchTree(PathBuf);

impl ScratchTree {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("zelynic-pathwalk-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch tree root");
        ScratchTree(dir)
    }

    fn dir(&self, rel: &str) -> PathBuf {
        let path = self.0.join(rel);
        std::fs::create_dir_all(&path).expect("scratch dir");
        path
    }

    fn file(&self, rel: &str) -> PathBuf {
        let path = self.0.join(rel);
        std::fs::write(&path, b"pin").expect("scratch file");
        path
    }
}

impl Drop for ScratchTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The live census admits the mount: the walk completes on every
/// supported host (cgroup v2 is the limiter's own prerequisite)
/// and the set carries the mount root's own inode — the id the
/// resolver pin above resolves — plus a full subtree's worth of
/// real cgroups, none fabricated.
#[test]
fn census_admits_the_live_mount() {
    let set = cgroupfs_id_census().expect("census must complete on a supported host");
    let meta = std::fs::metadata("/sys/fs/cgroup")
        .expect("cgroup v2 mount absent — the limiter's own prerequisite");
    assert!(set.contains(&(meta.ino() as u32)));
    // A real hierarchy always carries more than the mount root
    // (the boot's own init.scope et al); the census sees them all.
    assert!(set.len() > 1);
}

/// The complete-or-nothing law, synthetic edition: the census
/// names every DIRECTORY in a finished walk (the truncating u32
/// numbering the maps key on) and never a file — cgroup.procs and
/// friends are not cgroups.
#[test]
fn census_names_every_directory_and_no_file() {
    let tree = ScratchTree::new("complete");
    let root_ino = std::fs::metadata(&tree.0).unwrap().ino() as u32;
    let a_ino = std::fs::metadata(tree.dir("bed-a")).unwrap().ino() as u32;
    let ab_ino = std::fs::metadata(tree.dir("bed-a/nested")).unwrap().ino() as u32;
    let b_ino = std::fs::metadata(tree.dir("bed-b")).unwrap().ino() as u32;
    let file_ino = std::fs::metadata(tree.file("cgroup.procs")).unwrap().ino() as u32;

    let set =
        collect_id_set(&tree.0, 4096, 32).expect("bounded walk must complete on the scratch tree");
    assert_eq!(set.len(), 4, "exactly the four directories, files skipped");
    for ino in [root_ino, a_ino, ab_ino, b_ino] {
        assert!(set.contains(&ino), "directory inode {ino} must be censused");
    }
    assert!(!set.contains(&file_ino), "files are never cgroup ids");
}

/// The bounds are part of the proof: a tree past the visit ceiling
/// is INCONCLUSIVE (None), never a partial set — a negative cannot
/// be proven by a walk that did not finish, the death proof's own
/// fail-closed floor.
#[test]
fn census_past_the_bounds_is_inconclusive() {
    let tree = ScratchTree::new("bounded");
    for i in 0..8 {
        tree.dir(&format!("bed-{i}"));
    }
    // A ceiling that cannot admit the whole tree: None, and no
    // partial set leaks.
    assert!(collect_id_set(&tree.0, 4, 32).is_none());
    // The depth ceiling holds the same law for a deep tree.
    let deep = ScratchTree::new("deep");
    let mut path = deep.0.clone();
    for _ in 0..6 {
        path = path.join("down");
        std::fs::create_dir_all(&path).expect("scratch dir");
    }
    assert!(collect_id_set(&deep.0, 4096, 3).is_none());
    // And a ceiling that DOES admit the tree completes.
    assert!(collect_id_set(&tree.0, 4096, 32).is_some());
}
