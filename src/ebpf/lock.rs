// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! File-based lock to prevent concurrent zelynic operations.
//!
//! ## Why this exists
//!
//! zelynic is fire-and-forget: `strict-single` loads BPF, writes policy,
//! and exits. If two operations run simultaneously (e.g., user runs
//! `strict-single brave 100kb` in one terminal and `unstrict-all` in
//! another), they can corrupt BPF state:
//!
//! 1. Terminal 1: `attach()` loads BPF + pins programs
//! 2. Terminal 2: `unpin_all()` removes all pins
//! 3. Terminal 1: `apply_single()` tries to write policy → map gone → ENOENT
//!
//! The lock prevents this: the second operation fails immediately
//! (non-blocking) with a retry hint until the first completes.
//!
//! ## Security (NIGHT-hunt-14 / security-1 audit)
//!
//! The lock file lives in `/run/zelynic/` — a root-owned `0700`
//! directory zelynic creates on first use — never in a world-writable
//! directory. The former `/tmp/zelynic.lock` location gave any local
//! unprivileged user two attack primitives:
//!
//! - **Lock squatting (DoS):** create the file and hold `flock` on it
//!   forever — every subsequent root operation fails with "another
//!   zelynic operation is in progress" until an admin manually deletes
//!   the file, and the attacker can simply re-plant it.
//! - **Symlink following:** root's `open(O_WRONLY)` on the /tmp path
//!   follows attacker-planted symlinks (no write/truncate happens today,
//!   but the open itself must not follow untrusted links).
//!
//! `/run` is a root-owned tmpfs (same trust class as `/sys/fs/bpf`):
//! only root can create entries inside `/run/zelynic`, so the open can
//! never follow an untrusted link and the lock can never be squatted by
//! an unprivileged process. Every `acquire()` caller runs after
//! `ensure_root()`, so the 0700 root-only policy is exactly the right
//! access matrix. The world-writable-era `/tmp/zelynic.lock` is removed
//! opportunistically (unlink removes the link itself, never the
//! symlink target — symlink-safe by syscall semantics).
//!
//! ## How it works
//!
//! Uses `flock(2)`. The lock is automatically released when the file
//! descriptor is closed (on process exit, including crash/panic/SIGKILL).
//! This is simpler and more robust than PID files.

use anyhow::{bail, Context, Result};
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;

/// Root-owned lock directory (created 0700; /run itself is root-owned,
/// so no unprivileged process can create entries inside it).
const RUN_DIR: &str = "/run/zelynic";

/// Lock file path inside the root-only directory.
const LOCK_FILE: &str = "/run/zelynic/zelynic.lock";

/// Pre-audit location in the world-writable directory — removed
/// opportunistically on acquire for old-install hygiene.
const LEGACY_LOCK_FILE: &str = "/tmp/zelynic.lock";

/// Acquire an exclusive lock on the zelynic lock file.
///
/// Returns a `File` guard. The lock is held as long as the guard is alive.
/// When dropped (on function return, process exit, panic, or SIGKILL),
/// the lock is automatically released.
///
/// Uses non-blocking `flock(LOCK_EX | LOCK_NB)`: if another operation is
/// in progress, returns an error immediately rather than waiting.
pub fn acquire() -> Result<std::fs::File> {
    // Hygiene for pre-audit installations: drop the world-writable-era
    // lock file. remove_file is symlink-safe (unlink semantics remove
    // the link itself, never the target), and removing the path cannot
    // disturb any process still holding an flock on the old inode.
    let _ = std::fs::remove_file(LEGACY_LOCK_FILE);

    create_run_dir()?;
    acquire_locked(LOCK_FILE)
}

/// Create the root-only lock directory (0700). Idempotent: an existing
/// directory gets its mode defensively re-tightened (only root can have
/// created `/run/zelynic`, since `/run` itself is root-owned).
fn create_run_dir() -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(RUN_DIR) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(RUN_DIR, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("failed to tighten {RUN_DIR} permissions"))?;
            Ok(())
        }
        Err(e) => bail!("failed to create lock directory {RUN_DIR}: {e}"),
    }
}

/// Core lock acquisition on an explicit path — separated from
/// [`acquire`] so the unit tests below can exercise the full
/// lock/relock/release cycle against a temp directory without
/// needing root (the production path only ever runs as root).
fn acquire_locked(path: &str) -> Result<std::fs::File> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|e| anyhow::anyhow!("Failed to open lock file {path}: {e}"))?;

    // Non-blocking exclusive lock. If held by another process, return error.
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            bail!(
                "another zelynic operation is in progress. \
                 Wait for it to finish, then retry. \
                 If no operation is running, run 'zelynic recover'."
            );
        }
        bail!("Failed to acquire lock: {err}");
    }

    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lock cycle on a temp path (no root needed — the production path
    /// behind acquire() is root-only and exercised live by the
    /// enforcement handlers): acquire, re-acquire fails, drop, re-acquire
    /// succeeds.
    #[test]
    fn test_acquire_lock_cycle() {
        let dir = std::env::temp_dir().join(format!("zelynic-lock-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("zelynic.lock");
        let path_str = path.to_str().expect("utf-8 temp path");

        let lock = acquire_locked(path_str);
        assert!(lock.is_ok(), "should acquire lock: {:?}", lock.err());

        // Second acquire must fail (lock is held by this process).
        let lock2 = acquire_locked(path_str);
        assert!(lock2.is_err(), "second acquire should fail");

        // Drop the first lock.
        drop(lock);

        // Now should be able to acquire again.
        let lock3 = acquire_locked(path_str);
        assert!(
            lock3.is_ok(),
            "should acquire after drop: {:?}",
            lock3.err()
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    /// NIGHT-hunt-14 drift pin: the production lock path must live in
    /// the root-only /run directory, not in any world-writable location.
    /// Changing the constant without re-running the security review
    /// fails here.
    #[test]
    fn lock_path_lives_in_root_only_run_dir() {
        assert!(
            LOCK_FILE.starts_with("/run/zelynic/"),
            "lock must live in the root-owned 0700 dir, got: {LOCK_FILE}"
        );
        assert_eq!(RUN_DIR, "/run/zelynic");
    }
}
