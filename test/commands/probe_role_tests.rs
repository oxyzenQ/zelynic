// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the enforcement probe's child roles
//! (NIGHT-upgrade-charger-core-1-b): the mode validation (the only
//! user-reachable failure — the roles are hidden), and one live
//! rootless loopback smoke of the pair (no cgroup, no BPF — the
//! socket plumbing and the one-line protocol shape the orchestrator
//! parses; the full cgroup-resident lane is the CI supermassive
//! battery's job, where root exists).

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

/// The live smoke: server binds and serves, client connects, moves
/// bytes for one second, and both exit clean (the graceful shapes:
/// server EOF-reaps its blast thread, client window closes, neither
/// hangs). Rootless — plain loopback sockets, no cgroup entry.
#[test]
fn the_roles_pair_over_loopback_and_exit_clean() {
    // Reserve a port, release it, and pass it to the server (the
    // tiny race window is the test's own, never the verdict's).
    let port = {
        let probe = TcpListener::bind(("127.0.0.1", 0)).expect("reserve a port");
        probe.local_addr().expect("addr").port()
    };
    let server = std::thread::spawn(move || run_server_role(port));
    // The server's bind sits behind the same wall clock the real
    // probe's connect retries tolerate; one short settle is plenty.
    std::thread::sleep(Duration::from_millis(150));
    run_client_role(&format!("127.0.0.1:{port}"), "dl", 1).expect("the dl role completes");
    server
        .join()
        .expect("the server role thread must not panic")
        .expect("the server role completes");
}
