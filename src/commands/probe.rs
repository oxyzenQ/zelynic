// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The self-proving enforcement probe (NIGHT-upgrade-charger-core-1-b,
//! the TIER S ability): "applied" is a claim, "VERIFIED" is a
//! measurement. After strict-single writes the policy, the probe
//! generates REAL traffic through the subtree it just policed and
//! measures what the kernel let through — the success the command
//! prints is earned, not asserted (no other rate limiter verifies its
//! own enforcement; they all print "applied" and hope).
//!
//! Shape: a fresh child cgroup under the target (the subtree
//! contract covers it by construction — the supermassive CI lane),
//! one sacrificial client inside it, one blast server OUTSIDE every
//! policed subtree (a transient root-level cgroup), a
//! fixed 3s window over loopback, and verdict bands derived from the
//! same physics the CI harness uses (BAND_HI 1.30's family). The
//! kernel's own ledger brackets the window as the cross-check; the
//! client's bytes are the measured truth.
//!
//! Honesty contracts: the probe is ONE-SIDED by nature (enforcement
//! can only under-deliver the budget — inside the ceiling VERIFIED,
//! above FAILED, never-happened UNVERIFIED); the child's residency
//! in the target subtree is verified from /proc BEFORE the window
//! opens (an unentered probe measures an unlimited path); the
//! server lives outside every policy for the window (checked
//! against BOTH policy maps); teardown is best-effort and never
//! fails the verdict.

use anyhow::{anyhow, bail, Context, Result};
use std::io::{BufRead, BufReader};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::ebpf::identity::pathwalk;
use crate::ebpf::limiter::{
    default_burst, Direction, Limiter, LimiterStatsRaw, PolicyRaw, RateSpec, Target,
};

use super::eagle::resolve_name;
use super::probe_report::{probe_verdict, ProbeOutcome, ProbeVerdict, CEILING_SLACK_BYTES};

/// The measured window (seconds): long enough that the refill term
/// dominates the burst (3s at 100kb = 300 KB refill vs the 64 KiB
/// cushion), short enough that the whole probe stays under five
/// seconds of an interactive command.
pub const PROBE_SECS: u64 = 3;

// ── The orchestrator ────────────────────────────────────────────────

/// Read the ledger's bytes_allowed for one cgroup (0 when the kernel
/// has not booked it yet — a fresh pin with idle traffic, the honest
/// absence the status contract documents).
fn ledger_allowed(limiter: &Limiter, key: u32) -> Result<u64> {
    let rows: Vec<(u32, LimiterStatsRaw)> = limiter.read_stats_public()?;
    Ok(rows
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, s)| s.bytes_allowed)
        .unwrap_or(0))
}

/// The teardown belt's own read (NIGHT-repair-1): does the target's
/// policy row still stand, at the rate this probe measured against?
/// A vanished row is the mid-window removal; a changed rate is a
/// mid-window re-apply; either one breaks the measurement's premise.
/// The read is passive (the same map lane our_chain_is_clean uses).
fn policy_still_stands(
    limiter: &Limiter,
    target_id: u32,
    direction: Direction,
    rate_bps: u64,
) -> Result<bool> {
    let rows: Vec<(u32, PolicyRaw)> = limiter.read_policies_public(direction)?;
    Ok(rows
        .iter()
        .any(|(k, p)| *k == target_id && p.rate_bps == rate_bps))
}

/// One best-effort cgroup mkdir (the harness's mkdir_quiet posture).
fn mkdir_quiet(path: &Path) -> bool {
    std::fs::create_dir(path).is_ok() || path.is_dir()
}

/// Kill AND reap a probe child, then best-effort remove its transient
/// cgroup with retries: an unreaped zombie (or its dying socket's css
/// reference) holds the cgroup alive past a bare rmdir, and a
/// leftover zelynic-probe-* directory per probe run is exactly the
/// residue this tool refuses to leave anywhere else. The retry window
/// (3 x 100ms) outlives the kernel's teardown of an exited child.
fn kill_and_reap(child: &mut Child, cgroup: Option<&Path>) {
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
fn enter_cgroup(path: &Path, child: u32) -> bool {
    std::fs::write(path.join("cgroup.procs"), format!("{child}\n")).is_ok()
}

/// The residency belt: /proc/<pid>/cgroup must name the probe cgroup
/// before the window may open (a probe that never entered measures an
/// unlimited path — the false-FAILED lie this check exists to kill).
fn resident_in(pid: u32, needle: &str) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map(|c| c.contains(needle))
        .unwrap_or(false)
}

/// The transient cgroup names (unique per probe invocation).
fn probe_cgroup_name(role: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("zelynic-probe-{role}-{nanos}")
}

/// Is zelynic's own cgroup chain free of policies (both directions,
/// every ancestor including the root cgroup itself)? The fallback
/// server placement: a policed server would under-measure every probe
/// (the vacuous-VERIFIED shape), so the platform refusing the
/// root-level transient cgroup may only downgrade to this lane when
/// the chain is clean.
fn our_chain_is_clean(limiter: &Limiter) -> bool {
    let Ok(text) = std::fs::read_to_string("/proc/self/cgroup") else {
        return false;
    };
    // Each ancestor's cgroup id is the dir's inode (kernfs); check
    // every one against both policy maps. A failed read is "not // clean" — never a guess.
    let dir_clean = |path: &Path| match std::fs::metadata(path) {
        Ok(meta) => {
            let id = u32::try_from(meta.ino()).unwrap_or(0);
            [Direction::Download, Direction::Upload].iter().all(|d| {
                limiter
                    .read_policies_public(*d)
                    .map(|rows| rows.iter().all(|(k, _)| *k != id))
                    .unwrap_or(false)
            })
        }
        Err(_) => false,
    };
    let mut path = PathBuf::from("/sys/fs/cgroup");
    if !dir_clean(&path) {
        return false;
    }
    let Some(rel) = text.lines().find_map(|l| l.strip_prefix("0::")) else {
        return false;
    };
    rel.split('/').filter(|s| !s.is_empty()).all(|seg| {
        path.push(seg);
        dir_clean(&path)
    })
}

/// Run the enforcement probe for one freshly applied target (the
/// orchestrator; module header for the shape). Never panics on
/// foreign tree shapes — every failure lane degrades to UNVERIFIED.
pub(crate) fn run_enforcement_probe(
    limiter: &Limiter,
    target: &Target,
    rates: &RateSpec,
    per_socket: bool,
) -> ProbeOutcome {
    let unverified = |note: String| ProbeOutcome {
        verdict: ProbeVerdict::Unverified,
        direction: Direction::Download,
        rate_bps: 0,
        burst_bytes: 0,
        window_secs: PROBE_SECS,
        client_bytes: 0,
        ledger_bytes: 0,
        per_socket,
        note: Some(note),
        teardown: false,
    };

    // Direction: download preferred (the common limit), upload when
    // only that side is policed. A blocked (rate-0) policy needs no
    // probe — the drop ledger IS the verdict.
    let (direction, rate_bps) = match (rates.download, rates.upload) {
        (Some(0), _) | (_, Some(0)) => {
            return unverified(
                "blocked policy — the drop ledger carries the verdict (a block \
                 needs no probe)"
                    .to_string(),
            );
        }
        (Some(dl), _) if dl > 0 => (Direction::Download, dl),
        (_, Some(ul)) if ul > 0 => (Direction::Upload, ul),
        _ => return unverified("no rate to verify".to_string()),
    };
    let mode = match direction {
        Direction::Download => "dl",
        Direction::Upload => "ul",
    };
    let burst = default_burst(rate_bps);

    // The target: first resolved cgroup id + its path (the probe
    // child nests under it; members first, the cgroupfs walk for a
    // memberless bed — identity::pathwalk, NIGHT-repair-1).
    let ids = match target {
        Target::CgroupId(id) => vec![*id],
        Target::ProcessName(name) => resolve_name(name),
        Target::Container(c) => {
            crate::ebpf::identity::container::resolve(c, false).unwrap_or_default()
        }
    };
    let Some(&target_id) = ids.first() else {
        return unverified("target resolved to nothing at probe time".to_string());
    };
    let Some(rel_path) = pathwalk::rel_path_by_id(target_id) else {
        return unverified("target cgroup path unresolvable (no live member, no cgroupfs directory — the cgroup is gone?)".to_string());
    };

    // The server's home: a transient root-level cgroup, outside
    // every policed subtree; refused -> own chain, checked clean.
    let srv_dir = PathBuf::from("/sys/fs/cgroup").join(probe_cgroup_name("srv"));
    let srv_placed = mkdir_quiet(&srv_dir);
    if !srv_placed && !our_chain_is_clean(limiter) {
        return unverified(
            "probe server placement unavailable (no clean cgroup for the \
             unpoliced endpoint)"
                .to_string(),
        );
    }

    // Ledger baseline: the kernel's own count BEFORE the window.
    let baseline = match ledger_allowed(limiter, target_id) {
        Ok(b) => b,
        Err(e) => return unverified(format!("ledger baseline read failed: {e}")),
    };
    // Spawn the server, enter its home, announce the port.
    let mut server = match spawn_role(&["__probe-server", "0"]) {
        Ok(child) => child,
        Err(e) => return unverified(format!("probe server spawn failed: {e}")),
    };
    if srv_placed && !enter_cgroup(&srv_dir, server.id()) {
        kill_and_reap(&mut server, srv_placed.then_some(srv_dir.as_path()));
        return unverified("probe server could not enter its cgroup".to_string());
    }
    if srv_placed && !wait_resident(&mut server, &srv_dir) {
        kill_and_reap(&mut server, srv_placed.then_some(srv_dir.as_path()));
        return unverified("probe server residency unconfirmed".to_string());
    }
    let port = match read_metric_line(&mut server, "PROBE-PORT") {
        Ok(p) => p,
        Err(e) => {
            kill_and_reap(&mut server, srv_placed.then_some(srv_dir.as_path()));
            return unverified(format!("probe server did not announce: {e}"));
        }
    };

    // The client's home: a fresh child UNDER the target — the
    // subtree contract covers it by construction.
    let client_dir = PathBuf::from("/sys/fs/cgroup")
        .join(rel_path.trim_start_matches('/'))
        .join(probe_cgroup_name("cl"));
    if !mkdir_quiet(&client_dir) {
        kill_and_reap(&mut server, srv_placed.then_some(srv_dir.as_path()));
        return unverified("probe cgroup under the target refused (mkdir)".to_string());
    }
    let mut client = match spawn_role(&[
        "__probe-client",
        &format!("127.0.0.1:{port}"),
        mode,
        &PROBE_SECS.to_string(),
    ]) {
        Ok(child) => child,
        Err(e) => {
            let _ = std::fs::remove_dir(&client_dir);
            kill_and_reap(&mut server, srv_placed.then_some(srv_dir.as_path()));
            return unverified(format!("probe client spawn failed: {e}"));
        }
    };
    if !enter_cgroup(&client_dir, client.id()) || !wait_resident(&mut client, &client_dir) {
        kill_and_reap(&mut client, Some(client_dir.as_path()));
        kill_and_reap(&mut server, srv_placed.then_some(srv_dir.as_path()));
        return unverified(
            "probe client could not enter the target subtree — unverified, \
             not failed (an unentered probe measures an unlimited path)"
                .to_string(),
        );
    }

    // The window: the client runs PROBE_SECS and prints its bytes.
    let client_bytes = match (
        wait_with_deadline(&mut client, PROBE_SECS + 15),
        read_metric_line(&mut client, "PROBE-BYTES"),
    ) {
        (Ok(()), Ok(n)) => n,
        (status, metric) => {
            kill_and_reap(&mut client, Some(client_dir.as_path()));
            kill_and_reap(&mut server, srv_placed.then_some(srv_dir.as_path()));
            let detail = match metric {
                Ok(n) => format!("metric {n} but a bad exit ({status:?})"),
                Err(e) => e.to_string(),
            };
            return unverified(format!("probe client did not measure: {detail}"));
        }
    };
    kill_and_reap(&mut server, srv_placed.then_some(srv_dir.as_path()));
    kill_and_reap(&mut client, Some(client_dir.as_path()));

    // Ledger close (the cross-check) + verdict. NIGHT-repair-1: a
    // dead ledger read no longer returns early — the belt below may
    // be the answer to WHY it died (the pinned maps themselves can
    // be gone); it degrades the verdict and rides its own note.
    let ledger_close = ledger_allowed(limiter, target_id);
    let mut outcome = ProbeOutcome {
        verdict: probe_verdict(rate_bps, burst, PROBE_SECS, client_bytes),
        direction,
        rate_bps,
        burst_bytes: burst,
        window_secs: PROBE_SECS,
        client_bytes,
        ledger_bytes: ledger_close
            .map(|close| close.wrapping_sub(baseline))
            .unwrap_or(0),
        note: ledger_close
            .err()
            .map(|e| format!("ledger close read failed: {e}")),
        per_socket,
        teardown: false,
    };
    // The old close-error contract holds where the lane stands: a
    // dead cross-check never gifts a Verified verdict.
    if ledger_close.is_err() && outcome.verdict == ProbeVerdict::Verified {
        outcome.verdict = ProbeVerdict::Unverified;
    }
    // The concurrent-traffic note: the ledger counts the target's
    // OWN traffic too; a ledger far above the client's bytes means a
    // shared window (still valid — the ceiling is the client's own).
    if let Ok(close) = ledger_close {
        let ledger_delta = close.wrapping_sub(baseline);
        let gap = ledger_delta.saturating_sub(client_bytes);
        if gap > client_bytes.saturating_mul(3) / 2 + CEILING_SLACK_BYTES {
            outcome.note = Some(
                "the target had concurrent traffic during the window (the kernel \
                 ledger counts it beside the probe's own flow)"
                    .to_string(),
            );
        }
    }
    // The multi-cgroup note: a name that resolved to several cgroups
    // got an INDIVIDUAL bucket each (group_id 0) — the probe measured
    // the first; the note says so instead of implying it proved them all.
    if outcome.note.is_none() && ids.len() > 1 {
        outcome.note = Some(format!(
            "the target spans {} cgroups (each with its own bucket); \
             the probe measured cg:{target_id}",
            ids.len()
        ));
    }
    // The teardown belt (NIGHT-repair-1): the byte count cannot name
    // a mid-window removal on a pipe slower than the window's budget
    // — the CI micro-VM's loopback sits near the forcing's own rate
    // (the fair-share single round measured 966.4 KB/s under a 1mb
    // policy: the pipe, not the policy, was the constraint), so the
    // post-teardown line rate lands INSIDE the ceiling and the bytes
    // read Verified over a policy that no longer exists. The probe
    // re-reads the policy row it was handed: the row must still
    // stand with the same rate at window close (a vanished row is
    // the mid-window removal, a changed rate a mid-window re-apply —
    // either one breaks the budget the bytes were measured against).
    // A Failed verdict keeps its own measured evidence; only a
    // Verified verdict stands on the premise. An unreadable close
    // read downgrades it — unless the pins died with it, in which
    // case the lane itself was torn down (the Err arm below).
    match policy_still_stands(limiter, target_id, direction, rate_bps) {
        Ok(true) => {}
        Ok(false) => {
            outcome.verdict = ProbeVerdict::Failed;
            outcome.teardown = true;
            outcome.note = Some(
                "the policy row vanished mid-window (a concurrent unstrict or re-apply) — \
                 the budget this window measured against no longer stands"
                    .to_string(),
            );
        }
        Err(close) => {
            // The belt's own read died. When the pins themselves are
            // gone the lane was torn down mid-window (only
            // unstrict-all / recover removes them) — the teardown
            // verdict with the lane's own note; with the pins
            // standing it is a read glitch, and only a Verified
            // verdict steps down to Unverified (never a guess).
            if !Limiter::is_pinned() {
                outcome.verdict = ProbeVerdict::Failed;
                outcome.teardown = true;
                outcome.note = Some(format!(
                    "the policy lane was torn down mid-window (the pinned maps \
                     are gone — a concurrent unstrict-all or recover?); the \
                     ledger cross-check died with it: {close}"
                ));
            } else if outcome.verdict == ProbeVerdict::Verified {
                outcome.verdict = ProbeVerdict::Unverified;
                outcome.note = Some(format!("policy close read failed: {close}"));
            }
        }
    }
    outcome
}

/// Spawn one hidden probe role from this binary (the cgroup entry
/// and residency verification stay with the orchestrator — the
/// parent-side pid write the child's grace sleep orders behind).
fn spawn_role(args: &[&str]) -> Result<Child> {
    let exe = std::env::current_exe().context("resolve the running binary")?;
    Command::new(exe)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn the probe role")
}

/// Poll the child's residency until the deadline (the grace window).
fn wait_resident(child: &mut Child, cgroup: &Path) -> bool {
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
fn wait_with_deadline(child: &mut Child, secs: u64) -> Result<()> {
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
/// metric lines: PROBE-PORT <n> / PROBE-BYTES <n>).
fn read_metric_line(child: &mut Child, prefix: &str) -> Result<u64> {
    let Some(stdout) = child.stdout.take() else {
        bail!("no stdout pipe");
    };
    let mut line = String::new();
    BufReader::new(stdout)
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
