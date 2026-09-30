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
//! Shape: a fresh child cgroup under the target (the subtree contract
//! covers it by construction — the same lane the supermassive CI
//! battery proves), one sacrificial client inside it, one blast server
//! OUTSIDE every policed subtree (a transient root-level cgroup), a
//! fixed 3s window over loopback, and verdict bands derived from the
//! same physics the CI harness uses (BAND_HI 1.30's family). The
//! kernel's own ledger brackets the window as the cross-check; the
//! client's bytes are the measured truth.
//!
//! Honesty contracts: the probe is ONE-SIDED by nature (enforcement
//! can only under-deliver the budget, never over-deliver it — a flow
//! inside the ceiling is VERIFIED, above it is FAILED, and a flow that
//! never happened is UNVERIFIED, never a vacuous pass); the child's
//! residency in the target subtree is verified from /proc BEFORE the
//! window opens (an unentered probe measures an unlimited path and
//! reads a false FAILED — the worst lie a verifier can tell); the
//! server lives outside every policy for the window (zelynic's own
//! chain is checked against BOTH policy maps before the fallback
//! placement — a capped server would silently under-measure); teardown
//! is best-effort and never fails the verdict (kill, reap, rmdir with
//! retries — no zelynic-probe-* residue left behind).

use anyhow::{anyhow, bail, Context, Result};
use std::io::{BufRead, BufReader};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::ebpf::identity::depth;
use crate::ebpf::limiter::{default_burst, Direction, Limiter, LimiterStatsRaw, RateSpec, Target};

use super::eagle::resolve_name;

/// The verdict ceiling: the client may exceed the exact budget by
/// 5% plus one GSO super-packet (in-flight and accounting slack);
/// anything above is FAILED — a working bucket mathematically cannot
/// admit more (tokens cap at burst, refill caps at rate x window).
const CEILING_SLACK_PERCENT: u64 = 5;
const CEILING_SLACK_BYTES: u64 = 65_536;

/// The flow floor: a client that moved under 20% of the window's
/// refill did not measure enforcement (dead server, refused entry, a
/// target too busy feeding its own traffic) — UNVERIFIED, never a
/// vacuous pass.
const FLOW_FLOOR_NUM_PERCENT: u64 = 20;

/// The measured window (seconds). Long enough that the refill term
/// dominates the burst (3s at 100kb = 300 KB of refill against the
/// 64 KiB cushion), short enough that the whole probe — entry,
/// window, teardown — stays under five seconds of an interactive
/// command's time.
pub const PROBE_SECS: u64 = 3;

// ── The verdict (pure, unit-pinned) ─────────────────────────────────

/// What the probe proved about the enforcement it just measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeVerdict {
    /// The measured flow stayed inside the budget the policy admits.
    Verified,
    /// The subtree moved more than the budget allows — the limit is
    /// NOT being enforced (exit 1 territory, the owner's contract).
    Failed,
    /// The probe could not measure (never a pass, never a fail).
    Unverified,
}

/// The verdict bands (pure): `budget` is what a working bucket can
/// admit over the window (burst + rate x secs — the same physics the
/// CI harness's 1.30 band family derives from); the ceiling adds the
/// in-flight slack; the floor is the flow that must have happened
/// before any verdict is meaningful.
#[must_use]
pub fn probe_verdict(
    rate_bps: u64,
    burst_bytes: u64,
    secs: u64,
    client_bytes: u64,
) -> ProbeVerdict {
    let budget = rate_bps.saturating_mul(secs).saturating_add(burst_bytes);
    let ceiling = budget
        .saturating_add(budget / (100 / CEILING_SLACK_PERCENT))
        .saturating_add(CEILING_SLACK_BYTES);
    let floor = (rate_bps
        .saturating_mul(secs)
        .saturating_mul(FLOW_FLOOR_NUM_PERCENT)
        / 100)
        .max(1);
    if client_bytes > ceiling {
        ProbeVerdict::Failed
    } else if client_bytes < floor {
        ProbeVerdict::Unverified
    } else {
        ProbeVerdict::Verified
    }
}

/// The probe's measured result, as the report renders it.
#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    pub verdict: ProbeVerdict,
    pub direction: Direction,
    pub rate_bps: u64,
    pub burst_bytes: u64,
    pub window_secs: u64,
    /// The client's own transferred bytes — the measured truth.
    pub client_bytes: u64,
    /// The ledger's bytes_allowed delta over the window (the kernel's
    /// own count, target traffic included — the cross-check row).
    pub ledger_bytes: u64,
    /// Why an UNVERIFIED probe could not measure, or the concurrent
    /// note when the target fed itself during the window.
    pub note: Option<String>,
}

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
    // Each ancestor's cgroup id is the dir's inode (kernfs: st_ino);
    // check every one against both policy maps. A failed read is
    // "not clean" — never a guess.
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
/// orchestrator; see the module header for the shape and the honesty
/// contracts). Never panics on foreign tree shapes — every failure
/// lane degrades to the UNVERIFIED verdict with its reason.
pub(crate) fn run_enforcement_probe(
    limiter: &Limiter,
    target: &Target,
    rates: &RateSpec,
) -> ProbeOutcome {
    let unverified = |note: String| ProbeOutcome {
        verdict: ProbeVerdict::Unverified,
        direction: Direction::Download,
        rate_bps: 0,
        burst_bytes: 0,
        window_secs: PROBE_SECS,
        client_bytes: 0,
        ledger_bytes: 0,
        note: Some(note),
    };

    // Direction: download preferred (the common limit), upload when
    // only that side is policed. A blocked (rate-0) policy needs no
    // probe — the drop ledger IS the verdict, and a block's "zero
    // goodput" is ambiguous with a dead probe by design.
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
    // child nests under it — the subtree the policy just covered).
    let ids = match target {
        Target::CgroupId(id) => vec![*id],
        Target::ProcessName(name) => resolve_name(name),
    };
    let Some(&target_id) = ids.first() else {
        return unverified("target resolved to nothing at probe time".to_string());
    };
    let Some(rel_path) = depth::deep_collect(target_id).rel_path else {
        return unverified("target cgroup path unresolvable (its processes exited?)".to_string());
    };

    // The server's home: a transient root-level cgroup, outside every
    // policed subtree. Refused -> zelynic's own chain, checked clean.
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

    // The client's home: a fresh child UNDER the target — the subtree
    // contract covers it by construction (the CI battery's own lane).
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

    // Ledger close + verdict.
    let ledger_delta = match ledger_allowed(limiter, target_id) {
        Ok(close) => close.wrapping_sub(baseline),
        Err(e) => {
            return ProbeOutcome {
                verdict: ProbeVerdict::Unverified,
                direction,
                rate_bps,
                burst_bytes: burst,
                window_secs: PROBE_SECS,
                client_bytes,
                ledger_bytes: 0,
                note: Some(format!("ledger close read failed: {e}")),
            };
        }
    };
    let mut outcome = ProbeOutcome {
        verdict: probe_verdict(rate_bps, burst, PROBE_SECS, client_bytes),
        direction,
        rate_bps,
        burst_bytes: burst,
        window_secs: PROBE_SECS,
        client_bytes,
        ledger_bytes: ledger_delta,
        note: None,
    };
    // The concurrent-traffic note: the ledger counts the target's
    // OWN traffic too; a ledger far above the client's bytes means
    // the window was shared (the probe still valid — the client's
    // ceiling is its own — but the reader deserves the context).
    let gap = ledger_delta.saturating_sub(client_bytes);
    if gap > client_bytes.saturating_mul(3) / 2 + CEILING_SLACK_BYTES {
        outcome.note = Some(
            "the target had concurrent traffic during the window (the kernel \
             ledger counts it beside the probe's own flow)"
                .to_string(),
        );
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

// The probe pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the command pins.
#[cfg(test)]
#[path = "../../test/commands/probe_tests.rs"]
mod tests;
