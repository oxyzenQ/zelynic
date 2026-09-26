// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Unit pins for the verified unpin core (NIGHT-master-4) — kept in
//! the repo's single test/ tree (NIGHT-hunt-17, cosmostrix Pattern C)
//! and #[path]-wired from ebpf/pin.rs. Every pin drives the pure
//! `unpin_dir` core against a throwaway temp directory: the
//! production `unpin_all()` path only ever runs as root against
//! /sys/fs/bpf/zelynic, and the live teardown is exercised by the
//! enforcement handlers instead.
//!
//! The contract under pin (the audit's find): the old implementation
//! discarded every removal error and returned Ok(()) — the verdict
//! "no residue" was fabricated whenever the filesystem refused. The
//! pins hold the three behaviors the fix promises: a verified count
//! on success, Ok(0) idempotence on the missing directory, and a
//! loud error naming the survivors when an entry outlives the pass.

use std::path::{Path, PathBuf};

use super::*;

/// A fresh temp directory unique to this process (the lock pins'
/// pattern): created under std::env::temp_dir(), removed by the test.
fn temp_pin_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zelynic-pin-test-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn touch(dir: &Path, name: &str) {
    std::fs::File::create(dir.join(name)).expect("pin file");
}

/// The happy path: three pin files unlinked, the count is VERIFIED
/// (3, not the pre-count guess), and the directory itself is gone.
#[test]
fn unpin_dir_removes_every_file_and_the_directory() {
    let dir = temp_pin_dir("clean");
    touch(&dir, "enforce_dl");
    touch(&dir, "enforce_ul");
    touch(&dir, "cgroup_policy_dl");

    let removed = unpin_dir(&dir).expect("clean teardown must succeed");
    assert_eq!(removed, 3, "the count must be the verified unlink count");
    assert!(!dir.exists(), "the pin directory itself must be gone");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Idempotence (the recover-after-unstrict-all sequence): a missing
/// directory is a clean Ok(0), never an error — every teardown path
/// must be safe to re-run.
#[test]
fn unpin_dir_missing_directory_is_ok_zero() {
    let dir = std::env::temp_dir().join("zelynic-pin-test-absent-never-created");
    let _ = std::fs::remove_dir_all(&dir);
    let removed = unpin_dir(&dir).expect("missing dir is not an error");
    assert_eq!(removed, 0, "nothing was removed from nothing");
}

/// The audit's exact find, pinned: an entry that survives the
/// removal pass (here a nested directory — remove_file fails EISDIR,
/// standing in for a busy pin or a read-only bpffs) must surface as
/// an ERROR naming the survivor count, never a fabricated Ok. The
/// unlinked siblings still count as removed inside the error's
/// shadow — partial progress is real, the clean verdict is not.
#[test]
fn unpin_dir_surviving_entry_is_an_error_not_a_clean_verdict() {
    let dir = temp_pin_dir("leftover");
    touch(&dir, "enforce_dl");
    // The stubborn survivor: a nested directory (unlink fails EISDIR)
    // holding a file of its own.
    let nested = dir.join("nested");
    std::fs::create_dir(&nested).expect("nested dir");
    touch(&nested, "foreign");

    let err = unpin_dir(&dir).expect_err("a surviving entry must fail the teardown");
    let msg = format!("{err}");
    assert!(
        msg.contains("still holds 1 entry"),
        "the error must name the survivor count, got: {msg}"
    );
    assert!(
        msg.contains("NOT clean"),
        "the error must deny the clean verdict explicitly, got: {msg}"
    );
    // The nested survivor is still on disk — the state really is not
    // clean, which is exactly what the error said.
    assert!(nested.exists(), "the survivor must still exist");
    // The unlinkable sibling WAS removed — partial progress held.
    assert!(
        !dir.join("enforce_dl").exists(),
        "the removable sibling must be gone even when a survivor fails the pass"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Two survivors pluralize honestly (entries, not entry) — the
/// message a scripted recover greps for stays grammatical.
#[test]
fn unpin_dir_survivor_count_pluralizes() {
    let dir = temp_pin_dir("plural");
    for name in ["nested-a", "nested-b"] {
        std::fs::create_dir(dir.join(name)).expect("nested dir");
    }

    let err = unpin_dir(&dir).expect_err("two survivors must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("still holds 2 entries"),
        "two survivors must read 'entries', got: {msg}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Re-running after a successful teardown: the second call finds the
/// directory gone and answers Ok(0) — the recover-after-unstrict-all
/// sequence pinned end to end at the core level.
#[test]
fn unpin_dir_is_idempotent_after_success() {
    let dir = temp_pin_dir("rerun");
    touch(&dir, "cgroup_policy_ul");

    let first = unpin_dir(&dir).expect("first teardown");
    assert_eq!(first, 1);
    let second = unpin_dir(&dir).expect("second teardown on the gone dir");
    assert_eq!(second, 0, "the rerun must be a clean no-op");
}

/// Drift pin (the lock module's pattern): the production path stays
/// the pinned bpffs location — moving it without re-running the
/// security review fails here, the same way the lock path pin does.
#[test]
fn unpin_all_targets_the_pinned_bpffs_directory() {
    assert_eq!(PIN_DIR, "/sys/fs/bpf/zelynic");
}
