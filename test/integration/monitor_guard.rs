// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Monitor interactive-stdio pins (NIGHT-boost-28) — the end-to-end
//! refusal contract for `eagle-eyes` on a piped stdout.
//!
//! The subprocess runs piped (Command::output), exactly the owner's
//! fatal shape (`sudo zelynic ee | grep`) minus the root: the guard
//! sits AFTER the root guard by design (the unprivileged piped probe
//! still teaches sudo first — the surface pin's contract), so the
//! verdict branches on the effective uid:
//!
//! - root: the interactive gate refuses — exit 1, stderr names
//!   stdout and the scripted alternative.
//! - non-root: the root guard fires first (exit 1, "root required").
//!
//! Either way the pipe must carry NO chrome bytes: no alt-screen
//! enter, no mouse tracking, no frame — the pre-boost-28 build
//! wrote escape sequences into exactly this pipe.

// Feature-gated with the tests below (NIGHT-boost-34): in a
// default-feature build every test in this file is compiled out,
// and an ungated import of the two helpers became the unused-import
// error that reddened the CI test lane (local gates run without
// `-D warnings` and never saw it).
#[cfg(feature = "ebpf")]
use crate::{euid_is_root, zelynic_cmd};

/// `eagle-eyes` piped: refuses (root) or teaches sudo (non-root),
/// and never leaks terminal chrome into the pipe.
#[cfg(feature = "ebpf")]
#[test]
fn eagle_eyes_piped_refuses_without_leaking_chrome() {
    let output = zelynic_cmd()
        .args(["eagle-eyes", "--interval", "1s"])
        .output()
        .expect("Failed to execute zelynic eagle-eyes");

    assert_eq!(
        output.status.code(),
        Some(1),
        "the piped monitor must refuse, not run: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    if euid_is_root() {
        assert!(
            stderr.contains("stdout is not a terminal"),
            "root + piped stdout must hit the interactive gate, got: {stderr}"
        );
        assert!(
            stderr.contains("status --print-json"),
            "the refusal must teach the scripted alternative, got: {stderr}"
        );
    } else {
        assert!(
            stderr.contains("root required"),
            "non-root + piped must teach sudo first, got: {stderr}"
        );
    }

    // The pipe stays chrome-free in BOTH branches: no ESC byte may
    // reach a non-terminal stdout (the pre-boost-28 fatal wrote
    // ALT_ENTER + frames here).
    assert!(
        !output.stdout.contains(&0x1b),
        "no escape byte may leak into the piped stdout, got {} bytes",
        output.stdout.len()
    );
}
