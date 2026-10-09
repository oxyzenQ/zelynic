// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The cgroup id-to-path resolver — the identity family's INVERSE
//! boundary (NIGHT-repair-1).
//!
//! `cgroup_id_from_path` walks one direction (stat the path: the
//! kernfs node id IS the inode), and the depth family's /proc walk
//! answers "who lives here" by member processes. The enforcement
//! probe's target resolution fell in the gap between them: it
//! derived the target cgroup's PATH from the first live member's
//! /proc/<pid>/cgroup line, so a cgroup that EXISTS but holds no
//! live process — the supermassive fleet beds between worker
//! spawns, a drained worker pool, an app whose every process
//! exited while its limit stands — read as "unresolvable" and the
//! probe degraded to an instant UNVERIFIED without ever opening
//! its measurement window (the fast-exit class every CI leg named
//! with the same note: "target cgroup path unresolvable (its
//! processes exited?)").
//!
//! This resolver closes the gap: members first (the /proc walk
//! stays the fast, canonical lane), then a bounded walk of the
//! cgroupfs itself — stat directories under the mount and match
//! the inode, the exact inverse of the numbering `pid_cgroup_id`
//! truncates to the u32 the maps key on. The bounds keep the walk
//! honest on a huge or hostile tree: past the visit or depth
//! ceiling it degrades to None (the caller names its own
//! unverified lane), unreadable directories are skipped, never
//! fatal, and only real subdirectories of the mount are followed.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The visit ceiling: a one-shot CLI walk must stay bounded on a
/// huge tree (a container host with thousands of cgroups). Past
/// the cap the resolver degrades to None — the caller names its
/// own unverified lane, never a hang. 4096 sits far above every
/// fleet the verified matrix exercised (the dense battery's 64)
/// and below anything that could read as a stall.
const MAX_VISITS: usize = 4096;

/// The depth ceiling: cgroup v2 nesting is shallow by design (the
/// deepest slice stacks run single digits); 32 is a defensive
/// bound against a pathological tree shape, not a contract.
const MAX_DEPTH: usize = 32;

/// Resolve a cgroup v2 path (leading '/', the "0::<path>" shape
/// the /proc walk yields) from a cgroup id: members first, then
/// the cgroupfs walk. None means the id names no directory the
/// mount admits — a gone cgroup, or a tree past the bounds.
pub fn rel_path_by_id(cgroup_id: u32) -> Option<String> {
    if let Some(rel) = super::depth_walk::deep_collect(cgroup_id).rel_path {
        return Some(rel);
    }
    let mut visits = 0usize;
    walk_rel_path(Path::new("/sys/fs/cgroup"), cgroup_id, 0, &mut visits)
}

/// One level of the bounded walk: stat this directory against the
/// target, then descend. Every failure is a skip, never a panic —
/// a foreign or unreadable tree degrades to None exactly like the
/// /proc walks it backs up.
fn walk_rel_path(dir: &Path, target: u32, depth: usize, visits: &mut usize) -> Option<String> {
    if depth > MAX_DEPTH || *visits >= MAX_VISITS {
        return None;
    }
    *visits += 1;
    if dir_matches(dir, target) {
        return Some(rel_path_of(dir));
    }
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let path = entry.path();
        if dir_matches(&path, target) {
            return Some(rel_path_of(&path));
        }
        if let Some(hit) = walk_rel_path(&path, target, depth + 1, visits) {
            return Some(hit);
        }
    }
    None
}

/// A directory matches when its kernfs inode truncates to the
/// target id — the stat is best-effort (an unreadable directory
/// simply does not match).
fn dir_matches(dir: &Path, target: u32) -> bool {
    fs::metadata(dir)
        .map(|m| inode_is(m.ino(), target))
        .unwrap_or(false)
}

/// The matching rule (pure, pinned): kernfs publishes the node id
/// as st_ino, the maps key on the truncated u32, and
/// `pid_cgroup_id` casts the same way — the walk matches in that
/// numbering or not at all, so the two lanes can never disagree
/// about an id (an inode wider than 32 bits truncates, never a
/// 64-bit near-miss).
fn inode_is(ino: u64, target: u32) -> bool {
    ino as u32 == target
}

/// The mount-relative path with the leading slash — the exact
/// shape the /proc lane prints: "/a/b" for a nested bed, "/" for
/// the mount root itself (a memberless root the /proc lane can
/// never name; the walk resolves it by inode).
fn rel_path_of(dir: &Path) -> String {
    let rel = dir.strip_prefix("/sys/fs/cgroup").unwrap_or(dir);
    let rendered = rel.to_string_lossy();
    if rendered.is_empty() {
        "/".to_string()
    } else {
        format!("/{rendered}")
    }
}

// The cgroupfs id census (the zombie sweep's death proof, the
// absent-lens residual's own lane) lives beside the resolver — same
// family, same bounds, one contract harder: the census proves a
// NEGATIVE, so its walk must be COMPLETE or nothing. night-audit-8
// grew the values from ids to id -> PATH: the sweep's liveness belt
// (cgroup.events) needs the directory itself, not just its name.

/// The cgroupfs id-to-path census (NIGHT-hunt-43's absent-lens
/// residual, owner-approved; night-audit-8's belt values): ONE
/// bounded walk of the mount collecting every directory's id AND
/// the path it lives at. `Some(map)` means the walk was COMPLETE —
/// the whole tree enumerated within the bounds, not one read or
/// stat failed — so an id absent from the map names no cgroup the
/// mount holds: kernel-proven death (the kernel destroys a cgroup
/// only after its last process left, so nothing can ever deliver
/// from it again — a STRONGER verdict than the ring's silence,
/// which only proves it did not). An id PRESENT names the very
/// directory whose `cgroup.events` the belt reads. `None` is
/// inconclusive — a tree past the bounds, an unreadable directory —
/// never "empty": the caller must veto exactly as it would without
/// the census (fail-closed for reclamation, the sweep's own
/// posture).
///
/// The census trusts the walker's own cgroupfs view, the same view
/// every identity resolution in this family already reads — a
/// cgroup-namespace reader sees its subtree, not the host's whole
/// hierarchy (the named residual in the hunt-43 audit's terms).
pub fn cgroupfs_id_path_census() -> Option<HashMap<u32, PathBuf>> {
    collect_id_paths(Path::new("/sys/fs/cgroup"), MAX_VISITS, MAX_DEPTH)
}

/// The census walk core, generic over root and bounds so the pins
/// can drive complete-vs-bounded semantics against synthetic trees
/// without touching the live mount. Every failure is total (None):
/// a skipped directory could be the target's hiding place, and a
/// negative cannot be proven by a walk that did not finish.
fn collect_id_paths(
    dir: &Path,
    max_visits: usize,
    max_depth: usize,
) -> Option<HashMap<u32, PathBuf>> {
    let mut ids = HashMap::new();
    walk_id_paths(dir, 0, &mut 0, max_visits, max_depth, &mut ids)?;
    Some(ids)
}

fn walk_id_paths(
    dir: &Path,
    depth: usize,
    visits: &mut usize,
    max_visits: usize,
    max_depth: usize,
    ids: &mut HashMap<u32, PathBuf>,
) -> Option<()> {
    if depth > max_depth || *visits >= max_visits {
        return None;
    }
    *visits += 1;
    // The directory's own kernfs inode — the same numbering
    // pid_cgroup_id truncates to the u32 the maps key on — beside
    // the path the belt's cgroup.events read needs.
    ids.insert(fs::metadata(dir).ok()?.ino() as u32, dir.to_path_buf());
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries {
        let entry = entry.ok()?;
        let meta = entry.metadata().ok()?;
        if !meta.is_dir() {
            continue;
        }
        walk_id_paths(&entry.path(), depth + 1, visits, max_visits, max_depth, ids)?;
    }
    Some(())
}

/// The kernel's own subtree-liveness verdict (night-audit-8's belt,
/// the alive-unresolvable-quiet residual's closure): cgroup v2
/// publishes `populated <0|1>` in every directory's cgroup.events —
/// 1 while the cgroup OR ANY DESCENDANT holds a live process, 0
/// when the whole subtree is memberless. This is the one signal
/// the identity walk's blind spot cannot hide behind: a process
/// that entered a cgroup namespace after its apply vanishes from
/// the host-path lane of /proc/<pid>/cgroup, but the kernel never
/// stops counting it here. `None` on any read or parse failure —
/// the caller vetoes on it (fail-closed, the census's own
/// posture).
pub fn cgroup_events_populated(dir: &Path) -> Option<bool> {
    let content = fs::read_to_string(dir.join("cgroup.events")).ok()?;
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() == Some("populated") {
            return match fields.next() {
                Some("0") => Some(false),
                Some("1") => Some(true),
                _ => None,
            };
        }
    }
    None
}

// The pathwalk pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the identity pins.
#[cfg(test)]
#[path = "../../../test/ebpf/identity/pathwalk_tests.rs"]
mod tests;
