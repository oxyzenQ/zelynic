// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The eagle-eyes --depth handler (NIGHT-master-1) — the one-shot
//! deep inspection surface.
//!
//! The live monitor answers "who is eating bandwidth RIGHT NOW" in a
//! TUI; the owner's depth question is the next click: a cg:1234 row
//! from `list-apps` or the leaderboard is often just a number — WHAT
//! process is that, launched by which user, from which binary, is it
//! a script, what permissions does it carry, how long has it run, and
//! is anything enforcing it right now. `--depth` prints that report
//! once and exits: no TUI, no interactive-stdio gate (pipe-friendly),
//! `--print-json` for scripts, the same '/'-separated target grammar
//! and autodetection the live monitor already owns.
//!
//! Assembly is three walks and a map read: the identity depth walk
//! (identity/depth.rs, per-process facts), the connection walk
//! (socket census + endpoints), the majority-vote identity map (the
//! package-name ladder's first rung), and the pinned policy maps (the
//! enforcement verdict, the status contract's honest-read discipline:
//! nothing pinned is honestly "unlimited", a failed read is an error,
//! never a fabricated verdict).
//!
//! NIGHT-blade-7 (the sharpness audit) tightened the walk the report
//! stands on: the census's perm column carries the special bits
//! (setuid 4755 no longer hides as 755), a deleted-on-disk exe is
//! marked, and the argv shebang probe cannot block on a planted FIFO
//! — a root-invoked report never stalls on attacker-controlled paths.

use anyhow::Result;

use crate::ebpf::bypass::{self, ShadowAudit};
use crate::ebpf::connections::ConnectionMap;
use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter::{
    Direction, Limiter, LimiterStatsRaw, PolicyRaw, Target, parse_focus_window, pin_dir_has_files,
    terminal_width,
};
use crate::ebpf::loader::{CgroupDelta, Observer, SocketBytes};
use crate::ebpf::render::{
    DepthReport, Enforcement, bypass_section, depth_doc_json, depth_report_lines, package_name,
    traffic_focus, window_dropped_bytes,
};
use crate::output::{grey, print_json};

use std::collections::HashMap;
use std::time::Duration;

/// Parse the '/'-separated TARGETS spec (the grammar both eagle-eyes
/// modes share, NIGHT-boost-1): each token autodetects per
/// [`Target::parse`] — digits (bare or cg:-prefixed) are cgroup IDs,
/// anything else a process name. A spec that reduces to nothing is a
/// usage error, surfaced BEFORE the root guard like every parse
/// validation in this CLI.
///
/// NIGHT-dinner-16 (the verifier-lineage mandate): an EMPTY segment
/// after the trim is refused, not dropped — the same blade-18
/// contract the colon grammar owns ("empty segments hid a dropped
/// app"). `brave//firefox` used to filter to [brave, firefox] and the
/// hollow middle silently vanished; it can only be a typo, and a
/// typo that hides a dropped watch target is the exact class this
/// grammar now rejects. Whitespace around a slash stays legal
/// (` brave / firefox `) — trim first, refuse only what remains
/// empty.
pub(crate) fn parse_target_spec(spec: &str) -> Result<Vec<Target>> {
    let trimmed: Vec<&str> = spec.split('/').map(str::trim).collect();
    if trimmed.iter().all(|t| t.is_empty()) {
        anyhow::bail!(
            "No targets in '{spec}' — pass process names or cgroup IDs \
             separated by '/' (e.g., 'zelynic eagle-eyes brave/firefox')"
        );
    }
    if trimmed.iter().any(|t| t.is_empty()) {
        anyhow::bail!(
            "empty target in '{spec}' (check the slashes) — pass names or \
             cgroup IDs separated by '/'"
        );
    }
    Ok(trimmed.into_iter().map(Target::parse).collect())
}

/// NIGHT-dinner-18 (the verifier-lineage mandate, the eagle-eyes
/// half): resolve target tokens against a live identity snapshot and
/// separate the matched cgroup ids from the misses — the launch-time
/// existence gate both eagle-eyes modes now share. Before this, the
/// live monitor opened its TUI for ANY target string (a typo'd name
/// entered a fullscreen session that only said so in a frame note,
/// and a dead cgroup id never said anything at all), and the depth
/// report accepted a dead id verbatim and fabricated an empty report
/// around it. The kernel's verifier rejects a program it cannot
/// prove; the CLI holds the same line at the door: a target that
/// names nothing is refused before any TUI or report exists.
///
/// Semantics, per token:
/// - `CgroupId(id)` is LIVE when the identity map holds it. The map's
///   walk inserts an entry for EVERY cgroup carrying a live process —
///   empty-comm entries included, the crash-recovery contract — so
///   `identity.get(id)` is exactly "a live process runs in this
///   cgroup". A dead id misses with its display label (`cg:{id}`),
///   never a fabricated report.
/// - `ProcessName(name)` matches when any identity entry's comm
///   equals the name case-insensitively — the same per-frame
///   resolution the live renderer applies (`render::eagle`'s
///   resolve_targets), so the launch gate can never accept a spec
///   the frame could never show, nor reject one it would. (The depth
///   report's name resolution deliberately keeps the strict-family
///   /proc walk instead — see `resolve_name` — so a name resolves
///   identically there and under `zelynic s <name>`.)
///
/// Pure in its inputs, so the liveness contracts pin rootlessly with
/// a seeded identity map (the cfg(test) insert seam) — pinned in
/// test/commands/eagle_depth_tests.rs.
pub(crate) fn resolve_live_targets(
    tokens: &[Target],
    identity: &IdentityMap,
) -> (Vec<u32>, Vec<String>) {
    let mut ids: Vec<u32> = Vec::new();
    let mut misses: Vec<String> = Vec::new();
    for token in tokens {
        match token {
            Target::CgroupId(id) => {
                if identity.get(*id).is_some() {
                    if !ids.contains(id) {
                        ids.push(*id);
                    }
                } else {
                    misses.push(format!("cg:{id}"));
                }
            }
            Target::ProcessName(name) => {
                let name_lower = name.to_lowercase();
                let mut matched = false;
                for entry in identity.all() {
                    if entry.comm.to_lowercase() == name_lower {
                        matched = true;
                        // The match verdict and the id collection are
                        // SEPARATE concerns: a duplicate token
                        // ('brave/brave') must not flip to a miss just
                        // because its cgroups are already collected
                        // (NIGHT-dinner-18 — the render twin's
                        // resolve_targets carried this exact false-miss
                        // shape, fixed in the same pass).
                        if !ids.contains(&entry.cgroup_id) {
                            ids.push(entry.cgroup_id);
                        }
                    }
                }
                if !matched {
                    misses.push(name.clone());
                }
            }
            // Container targets cannot arrive here — the '/'-separated
            // target grammar splits a URI before Target::parse ever
            // sees one — and this resolver is PURE over the identity
            // map (it cannot walk docker/kubelet metadata), so the
            // conservative miss is the honest bound: never a
            // fabricated row (charger-core-2).
            Target::Container(c) => {
                misses.push(c.display());
            }
        }
    }
    (ids, misses)
}

/// Resolve one name token to its live cgroup ids: the /proc walk the
/// limiter's resolve_target owns, on the same canonical boundaries
/// (NIGHT-optimized-1) — pid_comm + pid_cgroup_id — with the same
/// lowercase exact-match semantics, so a name resolves identically
/// here and under `zelynic s <name>`. Shared with the enforcement
/// probe (NIGHT-upgrade-charger-core-1-b), which must resolve the
/// target the same way the apply just did. NIGHT-hunt-28: the walk
/// itself is `identity::name_walk::resolve_name_set` — the ONE
/// walker every name resolution in the estate rides (single here,
/// batched in the multi lanes and the depth token loop), so the
/// single spelling and the list spelling can never drift.
pub(crate) fn resolve_name(name: &str) -> Vec<u32> {
    let pairs = crate::ebpf::identity::name_walk::resolve_name_set(&[name.to_string()])
        .remove(&name.to_lowercase())
        .unwrap_or_default();
    crate::ebpf::identity::name_walk::matched_pairs_to_ids(&pairs)
}

/// Open the pinned enforcement state when anything is pinned,
/// mirroring the status handler's ladder: no pin files anywhere is
/// honestly `None` (every target unlimited), pins that exist but
/// cannot be opened are the stale-pins error with its recover tip —
/// never a fabricated "unlimited".
fn open_enforcement(verbose: bool) -> Result<Option<Limiter>> {
    if !pin_dir_has_files() {
        return Ok(None);
    }
    if !Limiter::is_pinned() {
        anyhow::bail!("stale pins detected\n  tip: run 'zelynic recover'");
    }
    Ok(Some(Limiter::open_pinned(verbose)?))
}

/// The per-id enforcement join over the maps read ONCE (NIGHT-
/// hunt-30: the old enforcement_for read BOTH full policy maps per
/// id — N ids x 2 map reads x 1024 rows, the same join-class the
/// stats map below closed). Pure over the prebuilt maps, so the
/// join's verdict is pinned by the existing rendering pins; the
/// read itself happens once before the report loop, where read
/// failures still propagate (the NIGHT-hunt-22 status contract:
/// this is a report surface — a fabricated verdict is the exact
/// lie the audit removed).
fn enforcement_join(policies: Option<(&PolicyMaps, &PolicyMaps)>, cgroup_id: u32) -> Enforcement {
    let Some((dl, ul)) = policies else {
        return Enforcement::Unlimited;
    };
    let download = dl.get(&cgroup_id).copied();
    let upload = ul.get(&cgroup_id).copied();
    match (download, upload) {
        (None, None) => Enforcement::Unlimited,
        (download, upload) => Enforcement::Limited { download, upload },
    }
}

/// The policy maps read once for the whole report: (download,
/// upload) keyed by cgroup id. None when no enforcement is pinned
/// (the unlimited report — zero map reads, the ladder it always
/// owned).
type PolicyMaps = HashMap<u32, PolicyRaw>;

/// The focus window's measured result (NIGHT-private-research-3):
/// the closing poll's per-cgroup deltas (the kernel's window totals)
/// plus the per-socket cookie join keyed by the closing census's
/// cookies — the two inputs [`traffic_focus`] composes per target.
/// The bypass audit (charger-core-1-a) rides along unconditionally:
/// the window's interface-vs-hooks shadow verdict.
struct FocusMeasure {
    deltas: Vec<CgroupDelta>,
    socket_bytes: HashMap<u64, SocketBytes>,
    shadow: ShadowAudit,
}

/// Run the network-traffic focus window (NIGHT-private-research-3,
/// the think-like-light-years-3 ability): attach an observer, seed
/// the delta baseline, let `focus_secs` pass, close the window with
/// a second poll, and join the BPF per-socket cookie maps onto the
/// post-window census — the exact machinery the live monitor runs
/// per frame (NIGHT-boost-26), composed once for the one-shot
/// report instead.
///
/// The `conns` census is refreshed at window END (the sockets alive
/// NOW are the rows the report lists and the join keys on); a failed
/// window leaves the caller's baseline census untouched.
///
/// Best-effort by contract, honest about every failure: the return
/// carries the measurement OR the one-line reason it could not run
/// (observer attach refused, a map read failed) — the report renders
/// the basic socket census plus the reason, never a fabricated
/// zero-traffic window (the hunt-22 honest-read discipline). A quiet
/// window (zero deltas) is a MEASUREMENT, not a failure — it
/// composes a zero-total focus that renders the no-traffic verdict.
fn run_focus_window(
    conns: &mut ConnectionMap,
    focus_secs: u64,
    verbose: bool,
) -> (Option<FocusMeasure>, Option<String>) {
    if verbose {
        eprintln_safe!("[eagle-eyes] traffic focus: attaching observer for a {focus_secs}s window");
    }
    let mut observer = match Observer::attach(verbose) {
        Ok(o) => o,
        Err(e) => return (None, Some(format!("observer attach failed: {e}"))),
    };
    // The baseline poll seeds the per-cgroup delta baseline; its own
    // summary is discarded on purpose (bytes between attach and the
    // window start stay out of the ledger — the same horizon
    // contract the live monitor's opening poll owns).
    if let Err(e) = observer.poll_and_summarize() {
        return (None, Some(format!("baseline poll failed: {e}")));
    }
    // Bypass audit baseline (charger-core-1-a): the interface snapshot
    // brackets the window the BPF polls measure — like spans compare.
    let nic_start = bypass::nic_totals();
    std::thread::sleep(Duration::from_secs(focus_secs));
    let summary = match observer.poll_and_summarize() {
        Ok(s) => s,
        Err(e) => return (None, Some(format!("focus poll failed: {e}"))),
    };
    let nic_end = bypass::nic_totals();
    // Fresh census at window end: the closing join keys on exactly
    // the sockets alive NOW (a socket that died mid-window keeps its
    // bytes in the kernel totals but leaves the attribution — both
    // numbers stay true, they answer different questions).
    conns.refresh();
    let cookies = conns.socket_cookies();
    let mut socket_bytes = HashMap::new();
    if !cookies.is_empty() {
        // An Err folds an empty join: the window totals stay (kernel
        // truth), the endpoint figures degrade to honest absence —
        // the one-frame-tolerance contract the live join carries.
        if let Ok(bytes) = observer.socket_bytes(&cookies) {
            socket_bytes = bytes;
        }
    }
    observer.detach();
    let bpf_tx = summary.total_bytes;
    let bpf_rx = summary.total_ingress_bytes;
    let shadow = bypass::shadow_audit(nic_start, nic_end, bpf_tx, bpf_rx, focus_secs);
    (
        Some(FocusMeasure {
            shadow,
            deltas: summary.cgroups,
            socket_bytes,
        }),
        None,
    )
}

/// Handle `zelynic eagle-eyes <targets> --depth` — print the deep
/// report and exit. `--print-json` emits the typed document; the
/// interval flag never reaches here (the dispatcher notes and drops
/// it for the one-shot mode). The `--focus` window
/// (NIGHT-private-research-3) tunes the network-traffic focus
/// (1s..30s, default 3s) — parsed BEFORE the root guard like every
/// flag validation in this CLI.
pub(crate) fn handle_eagle_eyes_depth(
    targets: Option<&str>,
    focus: Option<&str>,
    json: bool,
    verbose: bool,
) -> Result<()> {
    // Parse-before-execute ladder (no privileges needed): a missing
    // target and a spec that reduces to nothing both surface BEFORE
    // the root guard, the same fail-fast order as the live monitor.
    let Some(spec) = targets else {
        anyhow::bail!(
            "eagle-eyes --depth needs a TARGET — pass a cgroup ID or app name\n  \
             tip: e.g. 'zelynic ee 12345 --depth' (find ids with 'zelynic list-apps')"
        );
    };
    let tokens = parse_target_spec(spec)?;
    // The focus window rides the same ladder: a typo'd or
    // out-of-bounds window surfaces before the privilege ask (the
    // duration grammar and its did-you-mean tips are shared with
    // --interval, parse_focus_window's own contract).
    let focus_secs = match focus {
        Some(s) => parse_focus_window(s)?,
        None => 3,
    };

    super::ensure_root()?;

    // One walk each feeds every target: the majority-vote identity
    // map (the name ladder's first rung), the connection census, and
    // the pinned policy maps. NIGHT-blade-5: when enforcement is
    // pinned, the per-cgroup LEDGER rides along — the kernel's own
    // allowed/dropped accounting — so a limited target's report
    // carries what enforcement actually did, not just what it was
    // configured to do.
    let mut identity = IdentityMap::new();
    identity.refresh();
    let mut conns = ConnectionMap::new();
    conns.refresh();
    let limiter = open_enforcement(verbose)?;
    // The ledger's BASELINE read (night-private-research-7): brackets
    // the focus window's START — the dropped counter's delta across
    // the bracket is the window's own shaping verdict (the
    // enforcement line's `(shaping)` tag). The closing read below
    // feeds the accounting line.
    let baseline_stats = match &limiter {
        Some(l) => Some(l.read_stats_public()?),
        None => None,
    };

    // NIGHT-private-research-3 (the think-like-light-years-3 ability):
    // the network-traffic focus window. The one-shot report gains
    // what the live monitor always had — per-endpoint byte
    // attribution — by running the observer for one short measured
    // window instead of a refresh loop. The pause is ANNOUNCED on
    // stderr (a report that silently sleeps is a report that looks
    // hung); stdout stays byte-clean for both output modes. A failed
    // window degrades to the basic socket census with the reason on
    // the report — never a fabricated zero-traffic window.
    eprintln_safe!(
        "{}",
        grey(&format!(
            "[eagle-eyes] traffic focus: measuring a {focus_secs}s window"
        ))
    );
    let (focus_measure, traffic_note) = run_focus_window(&mut conns, focus_secs, verbose);
    // The ledger's CLOSING read (night-private-research-7): the
    // accounting line renders the ledger AS OF PRINT — including the
    // window the report just measured (the pre-window read the line
    // carried before was stale by the whole focus window: a 30s
    // report under-reported its own enforcement by 30 seconds of
    // drops). One extra pinned-map read, bracketing the same span
    // the observer's deltas bracket.
    let closing_stats = match &limiter {
        Some(l) => Some(l.read_stats_public()?),
        None => None,
    };

    let mut reports: Vec<DepthReport> = Vec::new();
    let mut misses: Vec<(String, String)> = Vec::new();
    // NIGHT-hunt-28: the depth spec's names resolve in ONE /proc
    // walk (the per-token resolve_name loop was O(tokens x /proc),
    // the residual hunt-27 named) — same walker, same lowercase
    // exact-match semantics, so a name resolves identically here
    // and under `zelynic s <name>`, however many names the spec
    // carries.
    let name_tokens: Vec<String> = tokens
        .iter()
        .filter_map(|t| match t {
            Target::ProcessName(n) => Some(n.clone()),
            _ => None,
        })
        .collect();
    let resolved_names = crate::ebpf::identity::name_walk::resolve_name_set(&name_tokens);
    // NIGHT-hunt-30: every token resolves FIRST, then ONE depth walk
    // for the whole report's cgroup population — the per-id
    // deep_collect was O(ids x /proc), the same quadratic class
    // improve-50 / hunt-28 / hunt-29 closed (a multi-cgroup target
    // like brave's ~30, or a fleet-scale spec, walked ALL of /proc
    // per id before the report's own data reads ran). Two tokens
    // naming the same cgroup share one facts snapshot now — the
    // same-id rows render the same walk instead of two walks racing
    // process churn.
    let ids_per_token: Vec<Vec<u32>> = tokens
        .iter()
        .map(|token| match token {
            // NIGHT-dinner-18: a named cgroup id must be LIVE — the
            // shared liveness gate (resolve_live_targets owns the
            // semantics; from_ref borrows the single token without an
            // allocation). A dead id is a miss, never the fabricated
            // empty report the verbatim pass used to print around it.
            Target::CgroupId(_) => resolve_live_targets(std::slice::from_ref(token), &identity).0,
            // Names keep the strict-family /proc walk: a name resolves
            // identically here and under `zelynic s <name>` (the
            // documented depth contract — per-process comm matching,
            // not the identity map's majority-vote representative).
            // Container targets take the container resolver — the
            // same lane the apply used (charger-core-2).
            Target::ProcessName(name) => {
                let pairs = resolved_names
                    .get(&name.to_lowercase())
                    .cloned()
                    .unwrap_or_default();
                crate::ebpf::identity::name_walk::matched_pairs_to_ids(&pairs)
            }
            Target::Container(c) => {
                crate::ebpf::identity::container::resolve(c, false).unwrap_or_default()
            }
        })
        .collect();
    let mut all_ids: Vec<u32> = Vec::new();
    let mut seen_ids: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for ids in &ids_per_token {
        for id in ids {
            if seen_ids.insert(*id) {
                all_ids.push(*id);
            }
        }
    }
    let facts_by_id = crate::ebpf::identity::depth_walk::deep_collect_set(&all_ids);
    // The policy maps read once for the whole report (the old
    // enforcement_for read both full maps PER ID — the same
    // join-class). Read failures propagate here, before any report
    // row renders, exactly where the first id's read failed before.
    let policy_maps = match &limiter {
        Some(l) => Some((
            l.read_policies_public(Direction::Download)?
                .into_iter()
                .collect::<PolicyMaps>(),
            l.read_policies_public(Direction::Upload)?
                .into_iter()
                .collect::<PolicyMaps>(),
        )),
        None => None,
    };
    // The stats join as a map (the find-per-id scan was
    // O(ids x rows) — the census row family is 1024-wide, a
    // fleet-scale depth spec paid a 4M-compare scan for nothing).
    // Both bracket sides join the same way (night-private-research-7):
    // closing feeds the accounting line, baseline feeds the window's
    // shaping delta.
    let stats_by_id: Option<HashMap<u32, LimiterStatsRaw>> = closing_stats
        .as_ref()
        .map(|rows| rows.iter().cloned().collect());
    let baseline_by_id: Option<HashMap<u32, LimiterStatsRaw>> = baseline_stats
        .as_ref()
        .map(|rows| rows.iter().cloned().collect());
    for (token, ids) in tokens.iter().zip(ids_per_token) {
        if ids.is_empty() {
            misses.push((token.label(), "no live cgroup matches".to_string()));
            continue;
        }
        if verbose {
            eprintln_safe!("[eagle-eyes] {} -> {} cgroup(s)", token.label(), ids.len());
        }
        for id in ids {
            let target = token.label();
            let facts = facts_by_id.get(&id).cloned().unwrap_or_default();
            let comm = identity.get(id).map(|entry| entry.comm.clone());
            let name = package_name(comm.as_deref(), facts.rel_path.as_deref());
            let enforcement = enforcement_join(policy_maps.as_ref().map(|(dl, ul)| (dl, ul)), id);
            // The ledger row only exists for cgroups the kernel has
            // booked (a limited cgroup with zero traffic on a fresh
            // pin may not have one yet) — None renders no accounting
            // line, the honest absence, never a fabricated zero. The
            // row is the CLOSING bracket (as-of-print, the window
            // included — see the read's comment).
            let enforcement_stats = stats_by_id.as_ref().and_then(|m| m.get(&id)).copied();
            // The window's own shaping verdict: the dropped counter's
            // movement across the bracket (night-private-research-7).
            let window_dropped = window_dropped_bytes(
                stats_by_id.as_ref().and_then(|m| m.get(&id)),
                baseline_by_id.as_ref().and_then(|m| m.get(&id)),
            );
            let conns_view = conns.get(id).cloned();
            // The focus window's per-cgroup composition (pure): the
            // kernel's window totals joined onto this report's census
            // — traffic: None (with the shared note) only when the
            // window could not run at all.
            let traffic = focus_measure
                .as_ref()
                .map(|m| traffic_focus(id, focus_secs, &m.deltas, Some(&conns), &m.socket_bytes));
            reports.push(DepthReport {
                target,
                cgroup_id: id,
                name,
                depth: facts,
                enforcement,
                enforcement_stats,
                conns: conns_view,
                window_dropped,
                traffic,
                traffic_note: traffic_note.clone(),
            });
        }
    }

    // A spec that resolved to NOTHING is an error the owner can act
    // on; a partial miss (multi-target) renders alongside the hits.
    // NIGHT-dinner-18: the refusal rides the shared no-match builder
    // (commands::target_no_match_error) — the same labeled block, tip
    // grammar, and exit 1 the strict family owns, so every
    // names-a-target verb answers in one voice.
    if reports.is_empty() {
        let names: Vec<String> = misses.iter().map(|(t, _)| format!("'{t}'")).collect();
        return Err(super::target_no_match_error(
            format!(
                "No live cgroup matches {} — nothing to inspect",
                names.join(", ")
            ),
            &[super::TIP_LIST_APPS.to_string()],
        ));
    }

    if json {
        print_json(&depth_doc_json(
            &reports,
            &misses,
            focus_measure.as_ref().map(|m| &m.shadow),
        ));
    } else {
        for line in depth_report_lines(&reports, terminal_width()) {
            println_safe!("{line}");
        }
        for (target, reason) in &misses {
            println_safe!("{}", grey(&format!("  {target}: {reason}")));
        }
        // The machine-scope bypass audit (charger-core-1-a), last.
        if let Some(audit) = focus_measure.as_ref().map(|m| &m.shadow) {
            for line in bypass_section(audit) {
                println_safe!("{line}");
            }
        }
    }
    Ok(())
}

// The depth handler pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the monitor pins.
#[cfg(test)]
#[path = "../../test/commands/eagle_depth_tests.rs"]
mod tests;
