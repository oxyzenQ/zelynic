// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the id-to-path resolver (NIGHT-repair-1): the
//! truncating match rule (the numbering the /proc lane and the
//! walk must agree on), the mount-relative path shape, and the
//! never-panic contract of the bounded walk itself — plus the live
//! lane the fleet beds ride: the mount root resolves by inode with
//! no member process anywhere in sight. The cgroupfs id-to-path
//! census (the zombie sweep's death proof and belt evidence, the
//! values grown id -> path by night-audit-8) pins beside its
//! resolver sibling: the live walk admits the mount, and the
//! synthetic trees pin the complete-or-nothing law — a census that
//! did not finish proves nothing. The belt's own reader
//! (cgroup.events `populated`) pins beside them: the kernel's
//! verdict parses exactly, and every unprovable shape reads None.

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

// ── the cgroupfs id-to-path census (the death proof and belt) ────

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
/// and the map carries the mount root's own inode — the id the
/// resolver pin above resolves — mapped to the mount path itself,
/// plus a full subtree's worth of real cgroups, none fabricated.
#[test]
fn census_admits_the_live_mount() {
    let map = cgroupfs_id_path_census().expect("census must complete on a supported host");
    let meta = std::fs::metadata("/sys/fs/cgroup")
        .expect("cgroup v2 mount absent — the limiter's own prerequisite");
    assert_eq!(
        map.get(&(meta.ino() as u32)).map(PathBuf::as_path),
        Some(Path::new("/sys/fs/cgroup")),
        "the mount root maps to itself"
    );
    // A real hierarchy always carries more than the mount root
    // (the boot's own init.scope et al); the census sees them all.
    assert!(map.len() > 1);
}

/// The complete-or-nothing law, synthetic edition: the census
/// names every DIRECTORY in a finished walk (the truncating u32
/// numbering the maps key on) mapped to its own path, and never a
/// file — cgroup.procs and friends are not cgroups. The PATH is
/// the belt's whole point (night-audit-8): the map must hand back
/// the very directory whose cgroup.events the sweep reads.
#[test]
fn census_names_every_directory_and_its_path() {
    let tree = ScratchTree::new("complete");
    let root_ino = std::fs::metadata(&tree.0).unwrap().ino() as u32;
    let a = tree.dir("bed-a");
    let ab = tree.dir("bed-a/nested");
    let b = tree.dir("bed-b");
    let a_ino = std::fs::metadata(&a).unwrap().ino() as u32;
    let ab_ino = std::fs::metadata(&ab).unwrap().ino() as u32;
    let b_ino = std::fs::metadata(&b).unwrap().ino() as u32;
    let file_ino = std::fs::metadata(tree.file("cgroup.procs")).unwrap().ino() as u32;

    let map = collect_id_paths(&tree.0, 4096, 32)
        .expect("bounded walk must complete on the scratch tree");
    assert_eq!(map.len(), 4, "exactly the four directories, files skipped");
    assert_eq!(map.get(&root_ino), Some(&tree.0), "the root maps to itself");
    assert_eq!(map.get(&a_ino), Some(&a), "the directory's own path");
    assert_eq!(map.get(&ab_ino), Some(&ab), "the nested directory's path");
    assert_eq!(map.get(&b_ino), Some(&b), "the sibling's path");
    assert!(!map.contains_key(&file_ino), "files are never cgroup ids");
}

/// The bounds are part of the proof: a tree past the visit ceiling
/// is INCONCLUSIVE (None), never a partial map — a negative cannot
/// be proven by a walk that did not finish, the death proof's own
/// fail-closed floor.
#[test]
fn census_past_the_bounds_is_inconclusive() {
    let tree = ScratchTree::new("bounded");
    for i in 0..8 {
        tree.dir(&format!("bed-{i}"));
    }
    // A ceiling that cannot admit the whole tree: None, and no
    // partial map leaks.
    assert!(collect_id_paths(&tree.0, 4, 32).is_none());
    // The depth ceiling holds the same law for a deep tree.
    let deep = ScratchTree::new("deep");
    let mut path = deep.0.clone();
    for _ in 0..6 {
        path = path.join("down");
        std::fs::create_dir_all(&path).expect("scratch dir");
    }
    assert!(collect_id_paths(&deep.0, 4096, 3).is_none());
    // And a ceiling that DOES admit the tree completes.
    assert!(collect_id_paths(&tree.0, 4096, 32).is_some());
}

// ── the belt's reader (cgroup.events populated) ───────────────────

/// The kernel's verdict parses exactly: `populated 0` and
/// `populated 1` are the only two spellings that conclude, and the
/// belt pins both — the alive root's veto and the memberless
/// subtree's pass — on the scratch tree the synthetic census pins
/// already ride. (No live-mount pin here on purpose: cgroup.events
/// is a v2 file and the dev container mounts v1, so the unit tree
/// pins every parse branch synthetically and the LIVE proof rides
/// the supermassive zombie stage, which retires real zombies
/// through the real belt on CI's v2 hosts.)
#[test]
fn cgroup_events_populated_parses_the_kernel_verdict() {
    let tree = ScratchTree::new("events");
    let alive = tree.dir("alive");
    std::fs::write(alive.join("cgroup.events"), b"populated 1\nfrozen 0\n").expect("events file");
    let empty = tree.dir("empty");
    std::fs::write(empty.join("cgroup.events"), b"populated 0\nfrozen 0\n").expect("events file");
    assert_eq!(cgroup_events_populated(&alive), Some(true));
    assert_eq!(cgroup_events_populated(&empty), Some(false));

    // The unprovable shapes, one line each: garbage values, a
    // missing populated line, a missing file — None, the veto the
    // caller owns (fail-closed, the census's own posture).
    let garbage = tree.dir("garbage");
    std::fs::write(garbage.join("cgroup.events"), b"populated yes\n").expect("events file");
    let frozen_only = tree.dir("frozen-only");
    std::fs::write(frozen_only.join("cgroup.events"), b"frozen 0\n").expect("events file");
    let missing = tree.dir("missing");
    assert_eq!(cgroup_events_populated(&garbage), None);
    assert_eq!(cgroup_events_populated(&frozen_only), None);
    assert_eq!(cgroup_events_populated(&missing), None);
}
