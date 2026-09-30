// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The `eagle-eyes --depth` report (NIGHT-master-1) — the one-shot
//! answer to "what IS this cg:1234": the cgroup's identity ladder,
//! its owner, its enforcement state, a per-process census table, and
//! its live sockets.
//!
//! Composition is PURE: the handler (commands/eagle.rs) assembles a
//! [`DepthReport`] from the identity depth walk, the connection walk,
//! and the pinned policy maps; this module turns that struct into
//! lines (the report-table family's eagle-eyes chrome: purple title
//! bar, grey census, green data rows); the typed JSON document
//! (`--print-json`, the stable v11 scripting API shape) lives in the
//! depth_json sibling since NIGHT-blade-5's split. No /proc or
//! map access lives here — the pins drive fixtures, not the host.
//! The blade-5 depth upgrade adds three layers to the text report:
//! the enforcement ACCOUNTING line (the kernel's allowed/dropped
//! ledger under a limit), the cgroup controller's resource view
//! (memory, accumulated CPU), the census's per-process rss/thread
//! columns (facts the walk already collected; the table now shows
//! what the JSON always carried), and the act-on-this tail with
//! copy-paste commands for the cgroup the report just named.
//!
//! NIGHT-blade-7 (the sharpness audit) sharpened the census table
//! two ways: a `st` state column (the /proc state letter — a D-state
//! or zombie member is a first-glance triage signal the JSON carried
//! but the readable table dropped), and the exe cell marks a
//! deleted-on-disk binary with the kernel's own " (deleted)"
//! wording (replaced-by-upgrade or self-deleting loaders — the
//! marker is the fact, not noise).

use std::time::Duration;

use crate::ebpf::connections::CgroupConnections;
use crate::ebpf::identity::depth::{CgroupDepth, ProcessFacts};
use crate::ebpf::limiter::{format_bytes, format_count, format_rate, LimiterStatsRaw, PolicyRaw};
use crate::output::{fit_to_width, grey, ok, pad_to_width};

use super::depth_traffic::{traffic_section, TrafficFocus};
use super::{format_uptime, grid_line, title_bar};

/// The enforcement state of the target cgroup, as the pinned policy
/// maps word it.
#[derive(Debug, Clone)]
pub enum Enforcement {
    /// No policy rows name this cgroup (or nothing is pinned).
    Unlimited,
    /// Policy rows exist; per-direction raw policy (None = that
    /// direction is not limited).
    Limited {
        download: Option<PolicyRaw>,
        upload: Option<PolicyRaw>,
    },
}

/// One target's fully assembled depth report.
#[derive(Debug, Clone)]
pub struct DepthReport {
    /// The target exactly as the owner typed it ("cg:1234", "brave").
    pub target: String,
    pub cgroup_id: u32,
    /// The identity ladder's winner: majority comm, else the cgroup
    /// path's basename, else "unknown" (the owner's spec).
    pub name: String,
    /// The /proc deep walk: cgroup path + the controller's resource
    /// view + per-process facts.
    pub depth: CgroupDepth,
    pub enforcement: Enforcement,
    /// The kernel's enforcement ledger for this cgroup
    /// (NIGHT-blade-5): the cgroup_limiter_stats row — packets/bytes
    /// allowed and dropped — when enforcement is pinned AND the
    /// kernel has booked the cgroup. None = unlimited, or a fresh
    /// pin with no traffic yet (the honest absence, never a
    /// fabricated zero).
    pub enforcement_stats: Option<LimiterStatsRaw>,
    /// The connection walk's census for this cgroup, when it saw one.
    pub conns: Option<CgroupConnections>,
    /// The network-traffic focus window (NIGHT-private-research-3,
    /// the think-like-light-years-3 upgrade): the kernel's own
    /// window totals plus every endpoint's joined bytes, measured
    /// by the handler's short observer attach. None = the window
    /// did not run (the note below says why, when it matters).
    pub traffic: Option<TrafficFocus>,
    /// Why the traffic focus did not run, when it did not
    /// (attach/poll failure, one line): rendered under the socket
    /// section so the honest absence explains itself. None whenever
    /// the window was measured (and for the fixture-driven basic
    /// census — no measurement, no note).
    pub traffic_note: Option<String>,
}

/// The package-name ladder (pure, NIGHT-master-1): a resolved comm
/// names the cgroup; without one, the cgroup path's basename does
/// ("/cat-test" -> "cat-test", a systemd scope names itself); a
/// cgroup seen only as a bare id stays honestly "unknown".
#[must_use]
pub fn package_name(comm: Option<&str>, rel_path: Option<&str>) -> String {
    if let Some(comm) = comm {
        if !comm.is_empty() {
            return comm.to_string();
        }
    }
    if let Some(path) = rel_path {
        if let Some(base) = path.rsplit('/').find(|seg| !seg.is_empty()) {
            return base.to_string();
        }
    }
    "unknown".to_string()
}

/// One direction's verdict word for the summary line: a zero rate is
/// the block family's signature, an absent row is unlimited.
fn direction_word(policy: &Option<PolicyRaw>) -> &'static str {
    match policy {
        Some(p) if p.rate_bps == 0 => "blocked",
        Some(_) => "rate",
        None => "unlimited",
    }
}

/// The machine verdict word for JSON: "unlimited" | "blocked" |
/// "limited" (mixed shapes collapse to "limited" — the per-direction
/// bps fields carry the detail).
#[must_use]
pub fn enforcement_word(enforcement: &Enforcement) -> &'static str {
    match enforcement {
        Enforcement::Unlimited => "unlimited",
        Enforcement::Limited { download, upload } => {
            match (direction_word(download), direction_word(upload)) {
                ("unlimited", "unlimited") => "unlimited",
                (a, b) if a == "blocked" && b == "blocked" => "blocked",
                _ => "limited",
            }
        }
    }
}

/// The summary line's human sentence: "limited — dl 100.0 KB/s · ul
/// blocked", "blocked", or "unlimited" (pure).
#[must_use]
pub fn enforcement_sentence(enforcement: &Enforcement) -> String {
    match enforcement {
        Enforcement::Unlimited => "unlimited".to_string(),
        Enforcement::Limited { download, upload } => {
            let render = |p: &Option<PolicyRaw>| match p {
                Some(raw) if raw.rate_bps == 0 => "blocked".to_string(),
                Some(raw) => format_rate(raw.rate_bps),
                None => "unlimited".to_string(),
            };
            match (direction_word(download), direction_word(upload)) {
                ("unlimited", "unlimited") => "unlimited".to_string(),
                (a, b) if a == "blocked" && b == "blocked" => "blocked".to_string(),
                _ => format!("limited — dl {} · ul {}", render(download), render(upload)),
            }
        }
    }
}

/// The cgroup's absolute path, composed the same way the identity
/// resolver resolves ids (the canonical /sys/fs/cgroup mount).
#[must_use]
pub fn cgroup_abs_path(rel: Option<&str>) -> Option<String> {
    rel.map(|r| format!("/sys/fs/cgroup{r}"))
}

/// The directory of a path (pure, "" for a bare name).
#[must_use]
fn dirname(path: &str) -> String {
    match path.rfind('/') {
        Some(0) => "/".to_string(),
        Some(i) => path[..i].to_string(),
        None => String::new(),
    }
}

/// The oldest member's age in seconds — "since started at" for the
/// summary block (the cgroup's activity horizon).
#[must_use]
pub(super) fn oldest_started_secs(depth: &CgroupDepth) -> Option<u64> {
    depth.procs.iter().filter_map(|p| p.started_ago_secs).max()
}

/// The representative process for the run-from detail lines: the
/// first member whose exe resolved (pid order — stable, and pid order
/// is launch order inside a cgroup).
pub(super) fn representative(depth: &CgroupDepth) -> Option<&ProcessFacts> {
    depth
        .procs
        .iter()
        .find(|p| p.exe.is_some())
        .or_else(|| depth.procs.first())
}

/// One key/value row of the summary block (grey label column, plain
/// value), the shape the owner specced. Shared with the bypass
/// section sibling (NIGHT-upgrade-charger-core-1-a) — one label
/// column shape across the report's every section.
pub(super) fn kv(label: &str, value: &str) -> String {
    format!(
        "  {} {}",
        grey(&pad_to_width(&format!("{label}:"), 15)),
        value
    )
}

/// The enforcement accounting sentence (pure, NIGHT-blade-5): the
/// kernel's allowed/dropped ledger as one glance — what got through,
/// what the limit killed, and the drop share of everything that
/// arrived. A zero-traffic ledger stays honest ("nothing booked yet")
/// rather than dividing by zero.
#[must_use]
fn accounting_sentence(stats: &LimiterStatsRaw) -> String {
    let arrived = stats.bytes_allowed.saturating_add(stats.bytes_dropped);
    if arrived == 0 {
        return "enforced, nothing booked yet".to_string();
    }
    let drop_share = (stats.bytes_dropped as f64 / arrived as f64) * 100.0;
    format!(
        "{} let through, {} dropped ({drop_share:.2}% of what arrived)",
        format_bytes(stats.bytes_allowed),
        format_bytes(stats.bytes_dropped)
    )
}

/// The socket section's cap: the endpoints a readable one-shot report
/// lists before folding the rest into an honest overflow note (the
/// JSON document carries every row). The traffic section (which
/// replaced the basic listing when a focus window ran) shares the
/// cap — the readable report's budget is the same whatever it lists.
pub(super) const SOCKET_LINES_CAP: usize = 12;

/// Render the full text report for one or multiple targets (pure):
/// the title bar once, then a block per target — headline, census,
/// the compact owner's-fields block, the process census table, the
/// network-traffic section (the focus window's totals + ranked
/// endpoints, or the basic socket census when no window ran), and
/// the act-on-this tail. Width is the terminal budget the fixed
/// columns leave the exe cell.
///
/// NIGHT-private-research-3 (the compact-and-simple style pass):
/// the report drops every filler blank line and every restatement
/// — the headline IS the package id + name (the kv spine's twin
/// `package id` / `package name` lines died as duplicates), user
/// and exe directory merge into one `run from` line, the
/// controller's memory/cpu pair merges into one `resources` line,
/// and the act tail loses its header line (the commands name
/// their own verbs). Same facts, denser block — one glance per
/// section instead of a scroll.
#[must_use]
pub fn depth_report_lines(reports: &[DepthReport], width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(title_bar("zelynic eagle-eyes --depth", width));

    for (idx, report) in reports.iter().enumerate() {
        if idx > 0 {
            lines.push(String::new());
        }
        let procs = report.depth.procs.len();
        let holders = report.conns.as_ref().map_or(0, |c| c.socket_holders.len());
        let sockets = report.conns.as_ref().map_or(0, |c| {
            c.socket_holders.iter().map(|p| p.sockets.len()).sum()
        });

        // Headline + census: the two-glance identity of the block.
        lines.push(ok(&format!("  cg:{} — {}", report.cgroup_id, report.name)));
        let census = if procs == 0 {
            "no live processes — the cgroup is empty or its members exited".to_string()
        } else {
            format!(
                "{} processes · {} holders · {} sockets",
                format_count(procs as u64),
                format_count(holders as u64),
                format_count(sockets as u64)
            )
        };
        lines.push(grey(&format!("  {census}")));
        lines.push(grid_line(width));

        // The compact summary block (NIGHT-private-research-3): the
        // owner's field spine with the duplications retired — the
        // headline above already names the package id and name, so
        // the kv block carries everything the headline cannot.
        let rep = representative(&report.depth);
        let run_from_user = match rep.map(|p| p.uid) {
            Some(uid) => {
                let user = rep
                    .and_then(|p| p.user.clone())
                    .unwrap_or_else(|| "unknown".to_string());
                format!("uid {uid} ({user})")
            }
            None => "unknown".to_string(),
        };
        let run_from_path = match rep.and_then(|p| p.exe.clone()) {
            Some(exe) => dirname(&exe),
            None => "unknown".to_string(),
        };
        lines.push(kv(
            "run from",
            &format!("{run_from_user} · {run_from_path}"),
        ));
        match cgroup_abs_path(report.depth.rel_path.as_deref()) {
            Some(abs) => lines.push(kv("cgroup", &abs)),
            None => lines.push(kv("cgroup", "unknown")),
        }
        lines.push(kv(
            "enforcement",
            &enforcement_sentence(&report.enforcement),
        ));
        // NIGHT-blade-5: the accounting line — what the limit DID. The
        // ledger is the kernel's own book (bytes/packets allowed and
        // dropped, both directions combined), so "limited" comes with
        // its consequences attached: "1.4 GB let through, 6.2 MB
        // dropped (0.44% of what arrived)".
        if let Some(stats) = &report.enforcement_stats {
            lines.push(kv("accounting", &accounting_sentence(stats)));
        }
        // NIGHT-blade-5 + private-research-3: the controller's own
        // resource view — the two counters no /proc walk can
        // reconstruct (memory.current includes page-cache and kernel
        // charges; cpu.stat is the scheduler's accounting across every
        // task that ever ran in the cgroup, the exited ones included)
        // — now one line: same facts, same honesty, half the rows.
        let memory = report
            .depth
            .resources
            .memory_current_bytes
            .map(format_bytes);
        let cpu = report
            .depth
            .resources
            .cpu_usage_usec
            .map(|usec| format_uptime(Duration::from_micros(usec)));
        match (memory, cpu) {
            (Some(mem), Some(cpu)) => {
                lines.push(kv("resources", &format!("{mem} memory · {cpu} cpu")));
            }
            (Some(mem), None) => lines.push(kv("resources", &format!("{mem} memory"))),
            (None, Some(cpu)) => lines.push(kv("resources", &format!("{cpu} cpu"))),
            (None, None) => {}
        }
        match oldest_started_secs(&report.depth) {
            Some(secs) => lines.push(kv(
                "started",
                &format!("{} ago", format_uptime(Duration::from_secs(secs))),
            )),
            None => lines.push(kv("started", "unknown")),
        }
        if let Some(cmdline) = rep.and_then(|p| p.cmdline.clone()) {
            lines.push(kv(
                "command",
                &fit_to_width(&cmdline, width.saturating_sub(20)),
            ));
        }
        if let Some(script) = rep.and_then(|p| p.script.clone()) {
            lines.push(kv(
                "script",
                &fit_to_width(&script, width.saturating_sub(20)),
            ));
        }

        // The process census table: list-apps' column discipline.
        // NIGHT-blade-5: the census grows two columns the walk already
        // collected — thread count and resident memory (facts the JSON
        // document has carried since NIGHT-master-1; the readable table
        // showed everything EXCEPT the resource cost each member pays,
        // which is exactly what an expert triaging a fat cgroup wants
        // first). The name column pays for the space (24 -> 20).
        // NIGHT-blade-7: the `st` state column joins (one letter, the
        // /proc state — S/R/D/Z at a glance; the JSON always carried
        // the full words) and the exe cell marks deleted-on-disk
        // binaries with the kernel's own " (deleted)" suffix.
        lines.push(grid_line(width));
        let widths = [7usize, 20, 6, 5, 2, 4, 7, 8];
        let lead = 2;
        let fixed = lead + widths.iter().sum::<usize>() + widths.len();
        let header_cells: Vec<String> =
            ["pid", "name", "type", "perm", "st", "thr", "rss", "started"]
                .iter()
                .zip(widths)
                .map(|(h, w)| pad_to_width(h, w))
                .collect();
        lines.push(grey(&format!("  {}", header_cells.join(" "))));
        for proc in &report.depth.procs {
            let started = proc
                .started_ago_secs
                .map(|s| format_uptime(Duration::from_secs(s)))
                .unwrap_or_else(|| "—".to_string());
            let kind = proc.kind.unwrap_or("unknown");
            let perm = proc.mode.clone().unwrap_or_else(|| "—".to_string());
            // NIGHT-blade-7: the /proc state's first letter — S (sleeping),
            // R (running), D (uninterruptible), Z (zombie), T (stopped).
            // Unreadable state renders the em dash like every other
            // unknown cell.
            let state = proc
                .state
                .chars()
                .next()
                .map_or_else(|| "—".to_string(), |c| c.to_string());
            let thr = if proc.threads == 0 {
                "—".to_string()
            } else {
                proc.threads.to_string()
            };
            let rss = if proc.rss_kb == 0 {
                "—".to_string()
            } else {
                format_bytes(proc.rss_kb.saturating_mul(1024))
            };
            // NIGHT-blade-7: a binary the kernel knows is deleted from
            // disk keeps its path and gains the marker — the update-
            // replaced / self-deleting indicator stays visible.
            let exe_display = match (&proc.exe, proc.exe_deleted) {
                (Some(path), true) => format!("{path} (deleted)"),
                (Some(path), false) => path.clone(),
                (None, _) => "—".to_string(),
            };
            let exe = fit_to_width(&exe_display, width.saturating_sub(fixed + 1));
            lines.push(ok(&format!(
                "  {} {} {} {} {} {} {} {} {}",
                pad_to_width(&proc.pid.to_string(), widths[0]),
                pad_to_width(&proc.comm, widths[1]),
                pad_to_width(kind, widths[2]),
                pad_to_width(&perm, widths[3]),
                pad_to_width(&state, widths[4]),
                pad_to_width(&thr, widths[5]),
                pad_to_width(&rss, widths[6]),
                pad_to_width(&started, widths[7]),
                exe
            )));
        }

        // The network-traffic section (NIGHT-private-research-3, the
        // think-like-light-years-3 upgrade): when a focus window ran,
        // the section IS the window — the kernel's own totals plus
        // every endpoint's joined bytes, movers ranked first (the
        // same `[dl X | ul Y]` vocabulary the live view carries, so
        // one family). When no window ran, the section is the BASIC
        // CURRENT census the report always printed — endpoints and
        // states, no figures — with the not-measured note saying why
        // the focus could not run (the honest absence: a reader who
        // knows the ability exists learns it was the observer that
        // failed, not the report forgetting). Both arms live in the
        // depth_traffic sibling (the section's one concern, one
        // module).
        if report.traffic.is_some() || report.conns.is_some() {
            if let Some(section) = traffic_section(
                report.traffic.as_ref(),
                report.conns.as_ref(),
                report.traffic_note.as_deref(),
            ) {
                lines.push(grid_line(width));
                lines.extend(section);
            }
        }

        // NIGHT-blade-5: the act-on-this tail — the user-friendly half
        // of the depth upgrade. A report that names a cgroup and stops
        // answers "what IS this"; these three copy-paste lines answer
        // "and what can I do about it", with the cg: id (the exact
        // cgroup the report just dissected — round-trips through the
        // same autodetection that resolved the target) so the commands
        // stay correct even when the friendly name is ambiguous or
        // shared by several cgroups. private-research-3 compacting:
        // the header line is gone — the commands name their own verbs
        // (strict-single, block-single, ee) and the `act:` label rides
        // the first line, so the tail spends its lines on commands,
        // not furniture.
        lines.push(grid_line(width));
        lines.push(grey(&format!(
            "  act:  zelynic strict-single cg:{} 500kb",
            report.cgroup_id
        )));
        lines.push(grey(&format!(
            "        zelynic block-single cg:{}",
            report.cgroup_id
        )));
        lines.push(grey(&format!("        zelynic ee cg:{}", report.cgroup_id)));
    }
    lines
}

// The depth report pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the other render pins.
#[cfg(test)]
#[path = "../../../test/ebpf/render/report_tests.rs"]
mod tests;
