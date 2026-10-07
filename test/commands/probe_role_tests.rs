// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the enforcement probe's child roles
//! (NIGHT-upgrade-charger-core-1-b): the mode validation (the only
//! user-reachable failure — the roles are hidden), and live
//! rootless loopback smokes of the pair in BOTH directions (no
//! cgroup, no BPF — the socket plumbing and the one-line protocol
//! shape the orchestrator parses; the full cgroup-resident lane is
//! the CI supermassive battery's job, where root exists).
//! NIGHT-hunt-Z1: the server role is direction-aware — dl blasts
//! while ul drains and reports — and the pins cover both shapes.

use super::*;

use std::net::TcpListener;

/// An unknown mode is refused loudly — the orchestrator only ever
/// passes "dl"/"ul", so anything else is a wiring bug that must not
/// ride silently into a zero-byte "measurement".
#[test]
fn the_client_role_refuses_unknown_modes() {
    let err =
        run_client_role("127.0.0.1:1", "sideways", 1).expect_err("an unknown mode must be refused");
    assert!(
        format!("{err}").contains("unknown mode 'sideways'"),
        "the refusal names the mode, got: {err}"
    );
}

/// The server role refuses unknown modes with the same wording
/// shape the client's refusal set — a wiring bug must not ride into
/// a serve loop that measures nothing.
#[test]
fn the_server_role_refuses_unknown_modes() {
    let err = run_server_role(0, "sideways").expect_err("an unknown mode must be refused");
    assert!(
        format!("{err}").contains("unknown mode 'sideways'"),
        "the refusal names the mode, got: {err}"
    );
}

/// The live smoke, download shape: server binds and blasts, client
/// connects, receives for one second, and both exit clean (the
/// graceful shapes: server EOF-reaps its blast thread, client window
/// closes, neither hangs). Rootless — plain loopback sockets, no
/// cgroup entry.
#[test]
fn the_roles_pair_over_loopback_and_exit_clean() {
    // Reserve a port, release it, and pass it to the server (the
    // tiny race window is the test's own, never the verdict's).
    let port = {
        let probe = TcpListener::bind(("127.0.0.1", 0)).expect("reserve a port");
        probe.local_addr().expect("addr").port()
    };
    let server = std::thread::spawn(move || run_server_role(port, "dl"));
    // The server's bind sits behind the same wall clock the real
    // probe's connect retries tolerate; one short settle is plenty.
    std::thread::sleep(Duration::from_millis(150));
    run_client_role(&format!("127.0.0.1:{port}"), "dl", 1).expect("the dl role completes");
    server
        .join()
        .expect("the server role thread must not panic")
        .expect("the server role completes");
}

/// The live smoke, upload shape (NIGHT-hunt-Z1): the server does NOT
/// blast — it drains and counts — and the pair exits clean on the
/// client's zero-linger cut (the RST ends the drain; the received
/// count is the metric the orchestrator reads for upload probes).
/// Rootless like its dl twin.
#[test]
fn the_roles_pair_over_loopback_ul_and_exit_clean() {
    let port = {
        let probe = TcpListener::bind(("127.0.0.1", 0)).expect("reserve a port");
        probe.local_addr().expect("addr").port()
    };
    let server = std::thread::spawn(move || run_server_role(port, "ul"));
    std::thread::sleep(Duration::from_millis(150));
    run_client_role(&format!("127.0.0.1:{port}"), "ul", 1).expect("the ul role completes");
    server
        .join()
        .expect("the server role thread must not panic")
        .expect("the server role completes");
}

// ── The placement family's pure predicate (NIGHT-hunt-29) ────────

/// One row on the id in EITHER direction's set is a policed id — the
/// placement family's shared core, pinned without a loaded Limiter
/// (the IO half's read-failure arm is the caller's "not clean",
/// never a guess; the live cgroup-resident lane is the CI
/// supermassive battery's job, the family's own posture).
#[test]
fn a_root_row_in_either_direction_marks_the_id_policed() {
    use crate::ebpf::limiter::PolicyRaw;
    let row = |id: u32| {
        (
            id,
            PolicyRaw {
                rate_bps: 100_000,
                burst_bytes: 100_000,
                floor_bps: 0,
                ceil_bps: 0,
                group_id: 0,
                flags: 0,
            },
        )
    };
    let root = 4_819;
    // Clean on both sides: the placement premise stands.
    assert!(!cgroup_id_is_policed(root, &[row(7), row(8)], &[row(9)]));
    // A row on the root id in the download set alone breaks it.
    assert!(cgroup_id_is_policed(root, &[row(7), row(root)], &[row(9)]));
    // And in the upload set alone — the counter-direction row is the
    // exact shape a dual apply on `cg:<root-inode>` would write.
    assert!(cgroup_id_is_policed(root, &[row(7)], &[row(root), row(9)]));
    // Empty maps are clean, not "unknown".
    assert!(!cgroup_id_is_policed(root, &[], &[]));
}
