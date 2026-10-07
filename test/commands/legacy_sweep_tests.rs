// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The legacy state sweep pins (NIGHT-lts-8's pointer, closed): the
//! pure core behind `unpin_all_bpf`'s limits.json hygiene — the
//! retired persistence pair's litter leaves upgraded hosts on the
//! full-cleanup lane (`u --all`, `recover`, and the no-residue unpin
//! that runs when the last policy leaves), best-effort, never a
//! failed verdict. Pinned rootlessly from a tempdir (the real
//! /var/lib/zelynic path is root-owned territory the rootless
//! battery cannot touch), the same #[path] single-test-tree wiring
//! the dispatch-shared pins ride.

use std::fs;
use std::path::PathBuf;

use super::sweep_legacy_state_at;

/// A per-test scratch directory under the system tempdir, named by
/// process id + label so parallel runs never collide. A previous
/// crashed run's leftovers are swept first so every test starts
/// from a known shape.
fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "zelynic-legacy-sweep-{}-{label}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

#[test]
fn the_pair_s_file_and_its_now_empty_dir_leave_together() {
    let dir = scratch("pair");
    let state = dir.join("limits.json");
    fs::write(&state, b"{}").expect("write state file");
    assert!(sweep_legacy_state_at(&state), "the file was swept");
    assert!(!state.exists(), "the state file is gone");
    // The pair created the directory for this file alone
    // (create_dir_all on the snapshot path): an empty leftover is
    // the same residue, and it leaves with the file.
    assert!(
        !dir.exists(),
        "the pair's now-empty directory leaves with it"
    );
}

#[test]
fn a_dir_with_owner_content_keeps_the_dir() {
    let dir = scratch("sibling");
    let state = dir.join("limits.json");
    fs::write(&state, b"{}").expect("write state file");
    fs::write(dir.join("notes.txt"), b"not zelynic's").expect("write sibling");
    assert!(sweep_legacy_state_at(&state), "the file was swept");
    assert!(!state.exists(), "the state file is gone");
    assert!(dir.exists(), "a non-empty directory is NOT swept");
    assert!(
        dir.join("notes.txt").exists(),
        "the sibling content survives"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_host_that_never_ran_the_pair_is_untouched() {
    let dir = scratch("clean");
    let absent = dir.join("limits.json");
    assert!(!sweep_legacy_state_at(&absent), "nothing was swept");
    assert!(!absent.exists(), "the sweep never creates its path");
    assert!(dir.exists(), "the directory itself is untouched");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_bare_empty_dir_is_not_the_sweep_s_to_take() {
    // Provenance rule: the directory only leaves WITH the file —
    // only the pair's own write proves the directory was the
    // pair's. An empty dir without limits.json (someone deleted
    // just the file) stays: the sweep is litter removal, not
    // guesswork about whose empty directory it is.
    let dir = scratch("empty");
    assert!(!sweep_legacy_state_at(&dir.join("limits.json")));
    assert!(dir.exists(), "the bare empty dir stays");
    let _ = fs::remove_dir_all(&dir);
}
