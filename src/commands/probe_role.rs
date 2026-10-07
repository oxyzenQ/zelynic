// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The enforcement probe's child roles (NIGHT-upgrade-charger-core-1-b):
//! the hidden `__probe-server` / `__probe-client` entry points — the
//! two sacrificial processes the orchestrator (probe.rs) spawns around
//! the measured window. Both speak one-line stdout protocols the
//! parent parses (PROBE-PORT / PROBE-BYTES), never touch BPF, and
//! exit when their window or their peer ends them.

use anyhow::{anyhow, bail, Context, Result};
use std::io::{BufRead, BufReader};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::Child;
use std::time::{Duration, Instant};

use crate::ebpf::limiter::Direction;

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
/// ONE connection, and serve the probe's direction — a write blast
/// thread for download probes (the client's received count is the
/// measured truth), a counting read drain for upload probes (the
/// server's OWN received count is the measured truth there —
/// NIGHT-hunt-Z1: the client's ul-mode count is its local write
/// buffer, not what the policy let through, so the receiver reports)
/// — until the peer closes (EOF or EPIPE), then exit.
pub(crate) fn run_server_role(port: u16, mode: &str) -> Result<()> {
    std::thread::sleep(Duration::from_millis(PROBE_GRACE_MS));
    if mode != "dl" && mode != "ul" {
        bail!("probe server: unknown mode '{mode}' (dl or ul)");
    }
    let listener = TcpListener::bind(("127.0.0.1", port)).context("probe server bind")?;
    let actual = listener.local_addr().context("probe server addr")?.port();
    // The parent reads exactly this line before spawning the client.
    println_safe!("PROBE-PORT {actual}");
    let (stream, _peer) = listener
        .accept()
        .context("probe server accept (deadline: the client never came)")?;
    let mut writer = stream.try_clone().context("probe server clone")?;
    // The blast half, DOWNLOAD probes only: an upload probe's server
    // must never send — its egress would traverse the target's other
    // direction and pollute the ledger's combined counters.
    if mode == "dl" {
        std::thread::spawn(move || {
            let chunk = vec![0x5a_u8; CHUNK];
            loop {
                if writer.write_all(&chunk).is_err() {
                    break;
                }
                let _ = writer.flush();
            }
        });
    }
    // The drain half: EOF is the client's goodbye — and the process
    // exit reaps the (possibly still-blocked) blast thread with it.
    // For upload probes the drain IS the measurement: every received
    // byte is one the upload policy admitted through.
    let mut reader = stream;
    let mut sink = [0_u8; CHUNK];
    let mut received: u64 = 0;
    loop {
        match reader.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(n) => received += n as u64,
        }
    }
    if mode == "ul" {
        // The one metric line the orchestrator reads for upload
        // probes — the delivered truth, printed once the flow ended.
        println_safe!("PROBE-BYTES {received}");
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
    // The window's close is a hard cut, not a drain (NIGHT-hunt-Z1):
    // without the zero linger the socket would keep flushing its
    // unsent buffer past the window — the server's received count
    // would then include bytes the policy admitted AFTER the window,
    // over-running the window's budget with trailing retransmit
    // backlog. The RST bounds the measurement at what was delivered
    // inside the window (plus at most one in-flight GSO superpacket,
    // exactly the ceiling's slack term). SO_LINGER rides libc's
    // setsockopt directly — std's TcpStream::set_linger is still
    // unstable (tcp_linger, rust#88494), and the tree's nix feature
    // set is deliberately minimal (no socket surface; Cargo.toml's
    // own comment), while libc is already a first-class dependency.
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: a plain setsockopt(2) on the stream's own fd with a
    // properly sized linger word — the call has no memory-safety
    // precondition beyond the fd and pointer being live, both of
    // which the borrow on `stream` guarantees here.
    let _ = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &linger as *const libc::linger as *const libc::c_void,
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    println_safe!("PROBE-BYTES {count}");
    Ok(())
}

// ── The orchestrator's child-waiting family (moved from probe.rs at
// NIGHT-hunt-Z1, when the direction-aware window split pushed the
// orchestrator past the 500-line owner cap — the protocol half of
// the probe belongs with the roles that speak it) ─────────────────

/// The residency belt: /proc/<pid>/cgroup must name the probe cgroup
/// before the window may open (a probe that never entered measures an
/// unlimited path — the false-FAILED lie this check exists to kill).
pub(crate) fn resident_in(pid: u32, needle: &str) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map(|c| c.contains(needle))
        .unwrap_or(false)
}

/// Poll the child's residency until the deadline (the grace window).
pub(crate) fn wait_resident(child: &mut Child, cgroup: &Path) -> bool {
    let needle = cgroup
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if resident_in(child.id(), &needle) {
            return true;
        }
        if let Ok(Some(_)) = child.try_wait() {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Wait for the child with a wall-clock belt (never hangs the CLI on
/// a stuck role). Ok(()) when it exited; Err carries the status when
/// killed at the deadline.
pub(crate) fn wait_with_deadline(child: &mut Child, secs: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(status) = child.try_wait().context("probe child wait")? {
            if status.success() {
                return Ok(());
            }
            bail!("probe child exit: {status}");
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            bail!("probe child hit the wall deadline");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Read the role's one-line protocol from its piped stdout (the
/// metric lines: PROBE-PORT <n> / PROBE-BYTES <n>). Takes the pipe
/// — for children this orchestrator reads exactly one line from.
pub(crate) fn read_metric_line(child: &mut Child, prefix: &str) -> Result<u64> {
    let Some(stdout) = child.stdout.take() else {
        bail!("no stdout pipe");
    };
    read_metric_line_from(&mut BufReader::new(stdout), prefix)
}

/// Read one protocol line from a handle the orchestrator KEEPS (the
/// server's stdout: PROBE-PORT at spawn, PROBE-BYTES after an upload
/// window — NIGHT-hunt-Z1's receiver-side count). The handle stays
/// readable across calls; each line is consumed exactly once.
pub(crate) fn read_metric_line_from(
    stdout: &mut BufReader<std::process::ChildStdout>,
    prefix: &str,
) -> Result<u64> {
    let mut line = String::new();
    stdout
        .read_line(&mut line)
        .with_context(|| format!("read the {prefix} line"))?;
    let value = line
        .trim()
        .strip_prefix(prefix)
        .and_then(|rest| rest.trim().parse::<u64>().ok());
    match value {
        Some(v) => Ok(v),
        None => Err(anyhow!("malformed protocol line: {}", line.trim())),
    }
}

// ── The orchestrator's cgroup mechanics (moved from probe.rs at
// NIGHT-hunt-Z7, when the ledger-verdict family pushed the
// orchestrator past the 500-line owner cap again — the same split
// discipline as the waiting family above: the cgroup plumbing
// belongs with the roles that live in those cgroups) ──────────────

/// One best-effort cgroup mkdir (the harness's mkdir_quiet posture).
pub(crate) fn mkdir_quiet(path: &Path) -> bool {
    std::fs::create_dir(path).is_ok() || path.is_dir()
}

/// Kill AND reap a probe child, then best-effort remove its transient
/// cgroup with retries: an unreaped zombie (or its dying socket's css
/// reference) holds the cgroup alive past a bare rmdir, and a
/// leftover zelynic-probe-* directory per probe run is exactly the
/// residue this tool refuses to leave anywhere else. The retry window
/// (3 x 100ms) outlives the kernel's teardown of an exited child.
pub(crate) fn kill_and_reap(child: &mut Child, cgroup: Option<&Path>) {
    let _ = child.kill();
    let _ = child.wait();
    if let Some(cgroup) = cgroup {
        for _ in 0..3 {
            if std::fs::remove_dir(cgroup).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// The PARENT writes the child's pid into `cgroup.procs` right after
/// spawn (the child's grace sleep makes the write land first).
pub(crate) fn enter_cgroup(path: &Path, child: u32) -> bool {
    std::fs::write(path.join("cgroup.procs"), format!("{child}\n")).is_ok()
}

/// The transient cgroup names (unique per probe invocation).
pub(crate) fn probe_cgroup_name(role: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("zelynic-probe-{role}-{nanos}")
}

/// Does one cgroup id carry a row in either direction's policy set
/// (pure, NIGHT-hunt-29)? The placement family's shared predicate:
/// the chain walk feeds it each ancestor's id, the root gate feeds it
/// the root's own. Pure so the pins drive every shape (a row on the
/// id in EITHER set, clean sets, empty maps) without a loaded
/// Limiter — the same discipline the verdict family keeps its band
/// math in.
pub(crate) fn cgroup_id_is_policed(
    id: u32,
    dl_rows: &[(u32, crate::ebpf::limiter::PolicyRaw)],
    ul_rows: &[(u32, crate::ebpf::limiter::PolicyRaw)],
) -> bool {
    dl_rows.iter().any(|(k, _)| *k == id) || ul_rows.iter().any(|(k, _)| *k == id)
}

/// One cgroup id's cleanliness against BOTH policy maps: an
/// unreadable map is "not clean" — never a guess (the read-failure
/// arm the pure predicate leaves to this IO half).
fn cgroup_id_is_clean(limiter: &crate::ebpf::limiter::Limiter, id: u32) -> bool {
    match (
        limiter.read_policies_public(Direction::Download),
        limiter.read_policies_public(Direction::Upload),
    ) {
        (Ok(dl), Ok(ul)) => !cgroup_id_is_policed(id, &dl, &ul),
        _ => false,
    }
}

/// One cgroup directory's cleanliness: its kernfs-inode id (the same
/// id the policy maps key on) against both direction maps.
fn dir_is_clean(limiter: &crate::ebpf::limiter::Limiter, path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) => cgroup_id_is_clean(limiter, u32::try_from(meta.ino()).unwrap_or(0)),
        Err(_) => false,
    }
}

/// Does the ROOT cgroup itself carry a policy row (NIGHT-hunt-29)?
/// The probe server's transient home is a DIRECT child of the root,
/// so the root is the one ancestor that can police the server's
/// sockets through the object's nearest-ancestor resolution
/// (enforce.rs's ammsp_resolve_root — the same walk that covers the
/// client's subtree). A row there is reachable: `Target::parse`
/// accepts `cg:<root-inode>`, and on minimal or container hosts a
/// root-resident process name resolves to it. The root-level
/// placement's "outside every policed subtree" premise fails exactly
/// then, so the placement family checks the root explicitly instead
/// of assuming it.
pub(crate) fn root_cgroup_is_clean(limiter: &crate::ebpf::limiter::Limiter) -> bool {
    dir_is_clean(limiter, Path::new("/sys/fs/cgroup"))
}

/// Is zelynic's own cgroup chain free of policies (both directions,
/// every ancestor including the root cgroup itself)? The fallback
/// server placement: a policed server would under-measure every probe
/// (the vacuous-VERIFIED shape), so the platform refusing the
/// root-level transient cgroup may only downgrade to this lane when
/// the chain is clean.
pub(crate) fn our_chain_is_clean(limiter: &crate::ebpf::limiter::Limiter) -> bool {
    let Ok(text) = std::fs::read_to_string("/proc/self/cgroup") else {
        return false;
    };
    // Each ancestor's cgroup id is the dir's inode (kernfs); check
    // every one against both policy maps. A failed read is "not
    // clean" — never a guess.
    let mut path = std::path::PathBuf::from("/sys/fs/cgroup");
    if !dir_is_clean(limiter, &path) {
        return false;
    }
    let Some(rel) = text.lines().find_map(|l| l.strip_prefix("0::")) else {
        return false;
    };
    rel.split('/').filter(|s| !s.is_empty()).all(|seg| {
        path.push(seg);
        dir_is_clean(limiter, &path)
    })
}

// ── The orchestrator's map-read family (moved from probe.rs at
// NIGHT-hunt-Z7 with the ledger verdict — the same split discipline
// as the two families above: the passive map reads the verdict
// consumes are support machinery, not verdict logic) ──────────────

/// One leaf's ledger deltas over the probe span (NIGHT-hunt-Z7).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct LeafDelta {
    pub allowed: u64,
    pub dropped: u64,
}

/// Snapshot the ledger for every leaf the target resolved to (ONE
/// map iteration, filtered by id): a leaf with no stats entry yet is
/// the honest zero (a fresh pin, idle traffic — the status
/// contract's own absent-row posture), never a fabricated absence.
pub(crate) fn ledger_snapshots(
    limiter: &crate::ebpf::limiter::Limiter,
    ids: &[u32],
) -> Result<Vec<(u32, crate::ebpf::limiter::LimiterStatsRaw)>> {
    let rows = limiter.read_stats_public()?;
    Ok(ids
        .iter()
        .map(|id| {
            let stats = rows
                .iter()
                .find(|(k, _)| k == id)
                .map(|(_, s)| *s)
                .unwrap_or_default();
            (*id, stats)
        })
        .collect())
}

/// The teardown belt's own read (NIGHT-repair-1, widened at Z7):
/// every policed leg of the probe's leaf must still stand, at the
/// rate this probe measured against. A vanished row is the
/// mid-window removal; a changed rate is a mid-window re-apply;
/// either one breaks the measurement's premise — and a DUAL apply's
/// premise is both legs (the probe's acknowledgments spent the
/// counter-direction's bucket all window long). The read is passive
/// (the same map lane our_chain_is_clean uses).
pub(crate) fn policy_still_stands(
    limiter: &crate::ebpf::limiter::Limiter,
    target_id: u32,
    rates: &crate::ebpf::limiter::RateSpec,
) -> Result<bool> {
    let legs = [
        (Direction::Download, rates.download),
        (Direction::Upload, rates.upload),
    ];
    let mut all_stand = true;
    for (direction, rate) in legs {
        let Some(rate) = rate else { continue };
        let rows = limiter.read_policies_public(direction)?;
        if !rows
            .iter()
            .any(|(k, p)| *k == target_id && p.rate_bps == rate)
        {
            all_stand = false;
        }
    }
    Ok(all_stand)
}

/// night-during (schema v23): the probe's window gate. A window
/// that is not ACTIVE at this instant (a dormant future span, a
/// daily window outside its hours — read-side shapes older builds
/// wrote — or an expired span awaiting sweep) is not policing — a
/// measured flow through it would read unlimited and FAIL the
/// apply dishonestly. Returns the stand-down note when the row's
/// window is dormant, `None` when it is active, absent, or
/// unreadable (the kernel's own absent-entry verdict: enforce —
/// the read never invents a dormancy the map does not carry).
pub(crate) fn window_dormancy_note(
    limiter: &crate::ebpf::limiter::Limiter,
    target_id: u32,
) -> Option<String> {
    limiter
        .read_policy_window(target_id)
        .ok()
        .flatten()
        .and_then(|win| {
            crate::ebpf::limiter::dormancy_note(
                &win,
                crate::ebpf::limiter::wall_now_ns(),
                crate::ebpf::limiter::monotonic_ns(),
            )
        })
}

// The role pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the probe orchestrator pins.
#[cfg(test)]
#[path = "../../test/commands/probe_role_tests.rs"]
mod tests;
