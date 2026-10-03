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
//! fails the verdict. NIGHT-hunt-Z1 adds the measured-truth split:
//! the counted bytes come from whichever end RECEIVES — the client
//! for download probes, the SERVER for upload probes (the client's
//! ul-mode count is its local write buffer, not delivered bytes,
//! and the vacuous VERIFIED it produced is retired with the fix).
//!
//! NIGHT-hunt-Z7 (the dual-limit masterclass hardening): the ledger
//! graduated from display row to VERDICT EVIDENCE. The flow band
//! alone had two live false-negative shapes — a probe whose own TCP
//! acknowledgments ride the POLICED counter-direction (`-d 1kb -u
//! 1kb`) measures ~0 B while the kernel refuses hundreds of KB, and
//! a ceiling above the path's own delivery (`-d 1tb`) can never
//! cross the flow floor. The orchestrator now snapshots the FULL
//! ledger (bytes_allowed AND bytes_dropped) for EVERY leaf the
//! target resolved to, before and after the window, and hands the
//! deltas to the combined verdict: refusals inside the envelope
//! carry a starved flow to VERIFIED on the ledger-refusal proof,
//! admissions beyond the envelope FAIL the apply whatever the flow
//! measured (the leak lane), and the bucket's own token count at
//! window open finally explains a "budget: 68.5 KB" the kernel had
//! already spent. The probes's own traffic remains the measured
//! truth; the ledger is the kernel's.

use crate::ebpf::identity::pathwalk;
use crate::ebpf::limiter::{
    default_burst, format_bytes, format_bytes_exact, format_rate_exact, Direction, Limiter,
    RateSpec, Target,
};
use anyhow::{anyhow, Context, Result};
use std::io::BufReader;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use super::eagle::resolve_name;
use super::probe_report::{
    combined_verdict, ledger_verdict, starved_notes, LedgerVerdict, ProbeOutcome, ProbeVerdict,
    ProofBasis,
};
use super::probe_role::{
    enter_cgroup, kill_and_reap, ledger_snapshots, mkdir_quiet, our_chain_is_clean,
    policy_still_stands, probe_cgroup_name, read_metric_line, read_metric_line_from, wait_resident,
    wait_with_deadline, LeafDelta,
};

/// The measured window (seconds): long enough that the refill term
/// dominates the burst (3s at 100kb = 300 KB refill vs the 64 KiB
/// cushion), short enough that the whole probe stays under five
/// seconds of an interactive command.
pub const PROBE_SECS: u64 = 3;

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
        dropped_bytes: 0,
        counter_rate_bps: None,
        proof: ProofBasis::Flow,
        notes: vec![note],
        per_socket,
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
    let counter_rate_bps = match direction {
        Direction::Download => rates.upload,
        Direction::Upload => rates.download,
    };

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

    // Ledger baseline (NIGHT-hunt-Z7): the kernel's own allowed AND
    // dropped counters, every leaf, BEFORE the window — the pair the
    // combined verdict listens to. The bucket's token count rides
    // the same instant (the budget-truth read: a "burst" the pool
    // already spent is the difference between a nominal budget and
    // the one the window actually had).
    let baseline = match ledger_snapshots(limiter, &ids) {
        Ok(b) => b,
        Err(e) => return unverified(format!("ledger baseline read failed: {e}")),
    };
    let pool_tokens = limiter
        .read_pool_tokens(target_id, direction)
        .ok()
        .flatten();
    // Spawn the server, enter its home, announce the port. The
    // stdout handle stays taken for the whole probe: upload probes
    // read the delivered count from the server's SECOND line, so
    // the pipe that carried PROBE-PORT must survive until then.
    let mut server = match spawn_role(&["__probe-server", "0", mode]) {
        Ok(child) => child,
        Err(e) => return unverified(format!("probe server spawn failed: {e}")),
    };
    let mut server_stdout = server.stdout.take().map(BufReader::new);
    if srv_placed && !enter_cgroup(&srv_dir, server.id()) {
        kill_and_reap(&mut server, srv_placed.then_some(srv_dir.as_path()));
        return unverified("probe server could not enter its cgroup".to_string());
    }
    if srv_placed && !wait_resident(&mut server, &srv_dir) {
        kill_and_reap(&mut server, srv_placed.then_some(srv_dir.as_path()));
        return unverified("probe server residency unconfirmed".to_string());
    }
    let port = match server_stdout
        .as_mut()
        .map(|r| read_metric_line_from(r, "PROBE-PORT"))
        .unwrap_or_else(|| Err(anyhow!("no stdout pipe")))
    {
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

    // The window: the measured truth comes from whichever end
    // RECEIVES it (NIGHT-hunt-Z1) — the client's own count for
    // download probes (every counted byte passed the target's
    // ingress), the SERVER's for upload probes (the client's ul-mode
    // count is its local write buffer — write_all returns when the
    // bytes land in the socket buffer, not when the policy lets them
    // through; the pre-fix shape verified 131,072 buffered bytes
    // against a 10 KB/s limit while the ledger booked 137 B, a
    // vacuous pass the receiver-side count retires). The client's
    // zero-linger close cuts its trailing buffer at the window edge,
    // so the server's count is bounded by the window's admissions.
    let client_bytes = match direction {
        Direction::Download => {
            match (
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
            }
        }
        Direction::Upload => {
            // The pump's exit is the window's close; the server then
            // sees the cut, stops draining, and reports the count.
            if let Err(e) = wait_with_deadline(&mut client, PROBE_SECS + 15) {
                kill_and_reap(&mut client, Some(client_dir.as_path()));
                kill_and_reap(&mut server, srv_placed.then_some(srv_dir.as_path()));
                return unverified(format!("probe client did not finish its window: {e}"));
            }
            match server_stdout
                .as_mut()
                .map(|r| read_metric_line_from(r, "PROBE-BYTES"))
            {
                Some(Ok(n)) => n,
                _ => {
                    kill_and_reap(&mut client, Some(client_dir.as_path()));
                    kill_and_reap(&mut server, srv_placed.then_some(srv_dir.as_path()));
                    return unverified(
                        "probe server did not report the delivered count".to_string(),
                    );
                }
            }
        }
    };
    kill_and_reap(&mut server, srv_placed.then_some(srv_dir.as_path()));
    kill_and_reap(&mut client, Some(client_dir.as_path()));

    // Ledger close (NIGHT-hunt-Z7): the same leaves, the same
    // counters, AFTER the span. A dead close read no longer returns
    // early — the belt below may be the answer to WHY it died (the
    // pinned maps themselves can be gone); it degrades the verdict
    // and rides its own note.
    let ledger_close = ledger_snapshots(limiter, &ids);
    let deltas: Vec<LeafDelta> = match &ledger_close {
        Ok(close) => close
            .iter()
            .zip(baseline.iter())
            .map(|((_, c), (_, b))| LeafDelta {
                allowed: c.bytes_allowed.wrapping_sub(b.bytes_allowed),
                dropped: c.bytes_dropped.wrapping_sub(b.bytes_dropped),
            })
            .collect(),
        Err(_) => ids.iter().map(|_| LeafDelta::default()).collect(),
    };
    let ledger_note = ledger_close
        .as_ref()
        .err()
        .map(|e| format!("ledger close read failed: {e}"));
    let allowed_sum: u64 = deltas.iter().map(|d| d.allowed).sum();
    let dropped_sum: u64 = deltas.iter().map(|d| d.dropped).sum();

    // The per-leaf ledger verdict, aggregated across the target's
    // leaves: any leaf's over-admission is the leak; short of that,
    // any leaf's refusal is the engagement proof. per-socket
    // policies skip the leak lane (the envelope bounds a cgroup
    // bucket; a per-connection bucket's count is unknown).
    let legs: Vec<(u64, u64)> = [rates.download, rates.upload]
        .iter()
        .filter_map(|r| r.map(|r| (r, default_burst(r))))
        .collect();
    let mut ledger = LedgerVerdict::Silent;
    for delta in &deltas {
        match ledger_verdict(&legs, PROBE_SECS, delta.allowed, delta.dropped, per_socket) {
            LedgerVerdict::Leaked => {
                ledger = LedgerVerdict::Leaked;
                break;
            }
            LedgerVerdict::Refused => ledger = LedgerVerdict::Refused,
            LedgerVerdict::Silent => {}
        }
    }

    let (mut verdict, proof) = combined_verdict(rate_bps, burst, PROBE_SECS, client_bytes, ledger);
    // The old close-error contract holds where the lane stands: a
    // dead cross-check never gifts a Verified verdict.
    if ledger_close.is_err() && verdict == ProbeVerdict::Verified {
        verdict = ProbeVerdict::Unverified;
    }

    // The reason stack (NIGHT-hunt-Z7): starvation first (the pure
    // family names its own shapes), then the context notes — the
    // concurrent-traffic gap, the multi-leaf ledger, the budget's
    // own history. Every cause its own row; nothing shares a slot.
    let mut notes = starved_notes(
        client_bytes,
        rate_bps,
        PROBE_SECS,
        counter_rate_bps,
        direction,
        allowed_sum,
        dropped_sum,
    );
    if let Some(note) = ledger_note {
        notes.push(note);
    }
    // The concurrent-traffic note: the ledger counts the target's
    // OWN traffic too; a ledger far above the client's bytes means a
    // shared window (still valid — the ceiling is the client's own).
    // Single-leg applies only: with both legs policed the ledger's
    // counter-direction bookings inflate the gap by construction,
    // and the note would name a cause the dual-lane starvation rows
    // already carry honestly.
    if counter_rate_bps.is_none() {
        if let Some(first) = deltas.first() {
            let gap = first.allowed.saturating_sub(client_bytes);
            if gap > client_bytes.saturating_mul(3) / 2 + super::probe_report::CEILING_SLACK_BYTES {
                notes.push(
                    "the target had concurrent traffic during the window (the kernel \
                     ledger counts it beside the probe's own flow)"
                        .to_string(),
                );
            }
        }
    }
    // The multi-leaf note: a name that resolved to several cgroups
    // got an INDIVIDUAL bucket each (group_id 0) — the probe measured
    // the first; the note says so with the ledger's own per-leaf
    // numbers instead of implying it proved them all.
    if ids.len() > 1 {
        let per_leaf = deltas
            .iter()
            .zip(ids.iter())
            .map(|(d, id)| {
                format!(
                    "cg:{id} {} in / {} refused",
                    format_bytes(d.allowed),
                    format_bytes(d.dropped)
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        notes.push(format!(
            "the target spans {} cgroups (each with its own bucket); the probe \
             measured cg:{target_id} — window ledger: {per_leaf}",
            ids.len()
        ));
    }
    // The budget-truth note: the pool's own token count at window
    // open — a burst the bucket already spent is the difference
    // between the nominal budget line and the budget the window
    // actually had (the owner's re-apply find: a fresh rate on a
    // spent bucket). Both figures render exact (Z7's config-exact
    // rule: the bucket state is the kernel's own integer).
    if let Some(tokens) = pool_tokens {
        if tokens < burst {
            notes.push(format!(
                "the bucket held {} of its {} burst at window start (spent by the \
                 target's own history — tokens refill at {})",
                format_bytes_exact(tokens),
                format_bytes_exact(burst),
                format_rate_exact(rate_bps)
            ));
        }
    }

    let mut outcome = ProbeOutcome {
        verdict,
        direction,
        rate_bps,
        burst_bytes: burst,
        window_secs: PROBE_SECS,
        client_bytes,
        ledger_bytes: allowed_sum,
        dropped_bytes: dropped_sum,
        counter_rate_bps,
        proof,
        notes,
        per_socket,
        teardown: false,
    };
    // The teardown belt (NIGHT-repair-1): the byte count cannot name
    // a mid-window removal on a pipe slower than the window's budget
    // — the CI micro-VM's loopback sits near the forcing's own rate
    // (the fair-share single round measured 966.4 KB/s under a 1mb
    // policy: the pipe, not the policy, was the constraint), so the
    // post-teardown line rate lands INSIDE the ceiling and the bytes
    // read Verified over a policy that no longer exists. The probe
    // re-reads the policy rows it was handed: every policed leg must
    // still stand with the same rate at window close (a vanished row
    // is the mid-window removal, a changed rate a mid-window
    // re-apply — either one breaks the budget the bytes were measured
    // against). A Failed verdict keeps its own measured evidence;
    // only a Verified verdict stands on the premise. An unreadable
    // close read downgrades it — unless the pins died with it, in
    // which case the lane itself was torn down (the Err arm below).
    match policy_still_stands(limiter, target_id, rates) {
        Ok(true) => {}
        Ok(false) => {
            outcome.verdict = ProbeVerdict::Failed;
            outcome.teardown = true;
            outcome.notes.push(
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
                outcome.notes.push(format!(
                    "the policy lane was torn down mid-window (the pinned maps \
                     are gone — a concurrent unstrict-all or recover?); the \
                     ledger cross-check died with it: {close}"
                ));
            } else if outcome.verdict == ProbeVerdict::Verified {
                outcome.verdict = ProbeVerdict::Unverified;
                outcome
                    .notes
                    .push(format!("policy close read failed: {close}"));
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
