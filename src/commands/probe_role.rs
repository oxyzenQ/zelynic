// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The enforcement probe's child roles (NIGHT-upgrade-charger-core-1-b):
//! the hidden `__probe-server` / `__probe-client` entry points — the
//! two sacrificial processes the orchestrator (probe.rs) spawns around
//! the measured window. Both speak one-line stdout protocols the
//! parent parses (PROBE-PORT / PROBE-BYTES), never touch BPF, and
//! exit when their window or their peer ends them.

use anyhow::{bail, Context, Result};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

/// The child's settle grace: the parent writes the pid into the
/// cgroup microseconds after spawn; the child sleeps this long before
/// creating its first socket, so the socket's cgroup association is
/// the migrated one by construction, and the parent's residency check
/// (probe.rs) has time to observe it before any traffic flows.
pub const PROBE_GRACE_MS: u64 = 300;

/// The loopback blast chunk (one GSO-class buffer per write).
pub const CHUNK: usize = 65_536;

/// The server role: settle into the cgroup the parent chose (the
/// grace sleep — the listener MUST be created after the parent's pid
/// write lands, because an accepted socket inherits the LISTENER's
/// cgroup, not the accepting task's), then bind (port 0 = ephemeral),
/// announce the port on stdout (one line, read by the parent), accept
/// ONE connection, and serve both probe shapes — a write blast thread
/// for download probes, a read drain on the main thread for upload
/// probes — until the peer closes (EOF or EPIPE), then exit.
pub(crate) fn run_server_role(port: u16) -> Result<()> {
    std::thread::sleep(Duration::from_millis(PROBE_GRACE_MS));
    let listener = TcpListener::bind(("127.0.0.1", port)).context("probe server bind")?;
    let actual = listener.local_addr().context("probe server addr")?.port();
    // The parent reads exactly this line before spawning the client.
    println_safe!("PROBE-PORT {actual}");
    let (stream, _peer) = listener
        .accept()
        .context("probe server accept (deadline: the client never came)")?;
    let mut writer = stream.try_clone().context("probe server clone")?;
    // The blast half: write until the peer closes (EPIPE ends it).
    std::thread::spawn(move || {
        let chunk = vec![0x5a_u8; CHUNK];
        loop {
            if writer.write_all(&chunk).is_err() {
                break;
            }
            let _ = writer.flush();
        }
    });
    // The drain half: EOF is the client's goodbye — and the process
    // exit reaps the (possibly still-blocked) blast thread with it.
    let mut reader = stream;
    let mut sink = [0_u8; CHUNK];
    loop {
        match reader.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
    Ok(())
}

/// The client role: settle into the cgroup the parent chose (the
/// grace sleep — the parent's pid write lands inside it), connect,
/// then move bytes in `mode` ("dl" receives, "ul" sends) until the
/// window closes, and print the one metric line the parent reads.
pub(crate) fn run_client_role(addr: &str, mode: &str, secs: u64) -> Result<()> {
    std::thread::sleep(Duration::from_millis(PROBE_GRACE_MS));
    if mode != "dl" && mode != "ul" {
        bail!("probe client: unknown mode '{mode}' (dl or ul)");
    }
    // Connect with retries: the server's own grace may still be
    // settling when the client starts.
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut stream = None;
    while stream.is_none() {
        match TcpStream::connect(addr) {
            Ok(s) => stream = Some(s),
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                println_safe!("PROBE-BYTES 0");
                bail!("probe client connect to {addr}: {e}");
            }
        }
    }
    let mut stream = stream.expect("connect loop invariant");
    stream.set_nodelay(true).ok();
    let window = Duration::from_secs(secs);
    let mut count: u64 = 0;
    if mode == "dl" {
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .ok();
        let start = Instant::now();
        let mut buf = vec![0_u8; CHUNK];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => count += n as u64,
                Err(_) => {
                    if start.elapsed() >= window {
                        break;
                    }
                }
            }
            if start.elapsed() >= window {
                break;
            }
        }
    } else {
        stream
            .set_write_timeout(Some(Duration::from_millis(200)))
            .ok();
        let start = Instant::now();
        let chunk = vec![0x5a_u8; CHUNK];
        while start.elapsed() < window {
            if stream.write_all(&chunk).is_err() {
                break;
            }
            count += chunk.len() as u64;
        }
    }
    println_safe!("PROBE-BYTES {count}");
    Ok(())
}

// The role pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the probe orchestrator pins.
#[cfg(test)]
#[path = "../../test/commands/probe_role_tests.rs"]
mod tests;
