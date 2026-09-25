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
//! bar, grey census, green data rows) or into the typed JSON document
//! (`--print-json`, the stable v11 scripting API shape). No /proc or
//! map access lives here — the pins drive fixtures, not the host.

use std::time::Duration;

use crate::ebpf::connections::CgroupConnections;
use crate::ebpf::identity::depth::{CgroupDepth, ProcessFacts};
use crate::ebpf::limiter::{format_count, format_rate, PolicyRaw};
use crate::output::{fit_to_width, grey, ok, pad_to_width};

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
    /// The /proc deep walk: cgroup path + per-process facts.
    pub depth: CgroupDepth,
    pub enforcement: Enforcement,
    /// The connection walk's census for this cgroup, when it saw one.
    pub conns: Option<CgroupConnections>,
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
fn oldest_started_secs(depth: &CgroupDepth) -> Option<u64> {
    depth.procs.iter().filter_map(|p| p.started_ago_secs).max()
}

/// The representative process for the run-from detail lines: the
/// first member whose exe resolved (pid order — stable, and pid order
/// is launch order inside a cgroup).
fn representative(depth: &CgroupDepth) -> Option<&ProcessFacts> {
    depth
        .procs
        .iter()
        .find(|p| p.exe.is_some())
        .or_else(|| depth.procs.first())
}

/// One key/value row of the summary block (grey label column, plain
/// value), the shape the owner specced.
fn kv(label: &str, value: &str) -> String {
    format!(
        "  {} {}",
        grey(&pad_to_width(&format!("{label}:"), 15)),
        value
    )
}

/// The socket section's cap: the endpoints a readable one-shot report
/// lists before folding the rest into an honest overflow note (the
/// JSON document carries every row).
const SOCKET_LINES_CAP: usize = 12;

/// Render the full text report for one or more targets (pure): the
/// title bar once, then a block per target — headline, census, the
/// owner's summary fields, the process census table, the socket
/// list. Width is the terminal budget the fixed columns leave the
/// exe cell.
#[must_use]
pub fn depth_report_lines(reports: &[DepthReport], width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(title_bar("zelynic eagle-eyes --depth", width));
    lines.push(String::new());

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
                "{} processes · {} socket holders · {} sockets",
                format_count(procs as u64),
                format_count(holders as u64),
                format_count(sockets as u64)
            )
        };
        lines.push(grey(&format!("  {census}")));
        lines.push(grid_line(width));

        // The summary block: the owner's field spine.
        let rep = representative(&report.depth);
        lines.push(kv("package id", &format!("cg:{}", report.cgroup_id)));
        lines.push(kv("package name", &report.name));
        match rep.map(|p| p.uid) {
            Some(uid) => {
                let user = rep
                    .and_then(|p| p.user.clone())
                    .unwrap_or_else(|| "unknown".to_string());
                lines.push(kv("run from user", &format!("uid {uid} ({user})")));
            }
            None => lines.push(kv("run from user", "unknown")),
        }
        match rep.and_then(|p| p.exe.clone()) {
            Some(exe) => lines.push(kv("run from path", &dirname(&exe))),
            None => lines.push(kv("run from path", "unknown")),
        }
        if let Some(abs) = cgroup_abs_path(report.depth.rel_path.as_deref()) {
            lines.push(kv("cgroup path", &abs));
        } else {
            lines.push(kv("cgroup path", "unknown"));
        }
        lines.push(kv(
            "enforcement",
            &enforcement_sentence(&report.enforcement),
        ));
        match oldest_started_secs(&report.depth) {
            Some(secs) => lines.push(kv(
                "time",
                &format!(
                    "since started at {} ago",
                    format_uptime(Duration::from_secs(secs))
                ),
            )),
            None => lines.push(kv("time", "unknown")),
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
        lines.push(grid_line(width));
        let widths = [7usize, 24, 8, 5, 8];
        let lead = 2;
        let fixed = lead + widths.iter().sum::<usize>() + widths.len();
        let header_cells: Vec<String> = ["pid", "name", "type", "perm", "started"]
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
            let exe = fit_to_width(
                proc.exe.as_deref().unwrap_or("—"),
                width.saturating_sub(fixed + 1),
            );
            lines.push(ok(&format!(
                "  {} {} {} {} {} {}",
                pad_to_width(&proc.pid.to_string(), widths[0]),
                pad_to_width(&proc.comm, widths[1]),
                pad_to_width(kind, widths[2]),
                pad_to_width(&perm, widths[3]),
                pad_to_width(&started, widths[4]),
                exe
            )));
        }

        // The socket list: every holder's endpoints, capped.
        if let Some(conns) = &report.conns {
            if !conns.socket_holders.is_empty() {
                lines.push(grid_line(width));
                lines.push(grey("  sockets:"));
                let mut shown = 0usize;
                let mut hidden = 0usize;
                for holder in &conns.socket_holders {
                    for socket in &holder.sockets {
                        if shown < SOCKET_LINES_CAP {
                            lines.push(format!(
                                "   {} ({}) → {} {} {}",
                                holder.comm,
                                holder.pid,
                                socket.remote,
                                if socket.proto == crate::ebpf::connections::Proto::Tcp {
                                    "tcp"
                                } else {
                                    "udp"
                                },
                                socket.state
                            ));
                            shown += 1;
                        } else {
                            hidden += 1;
                        }
                    }
                }
                if hidden > 0 {
                    lines.push(grey(&format!(
                        "   +{hidden} more — every endpoint rides the --print-json document"
                    )));
                }
            }
        }
    }
    lines
}

// ── The --print-json document (typed, NIGHT-boost-3 lineage) ──────

/// One process row of the JSON document.
#[derive(serde::Serialize)]
pub struct ProcJson {
    pub pid: u32,
    pub comm: String,
    pub uid: u32,
    pub user: Option<String>,
    pub ppid: u32,
    pub state: String,
    pub threads: usize,
    pub rss_kb: u64,
    pub exe: Option<String>,
    pub kind: Option<&'static str>,
    pub script: Option<String>,
    pub permission: Option<String>,
    pub cwd: Option<String>,
    pub cmdline: Option<String>,
    pub started_ago_secs: Option<u64>,
    pub started_epoch: Option<u64>,
}

/// One endpoint row of the JSON document.
#[derive(serde::Serialize)]
pub struct EndpointJson {
    pub pid: u32,
    pub comm: String,
    pub proto: &'static str,
    pub remote: String,
    pub state: &'static str,
}

/// One resolved target's JSON object.
#[derive(serde::Serialize)]
pub struct DepthTargetJson {
    pub target: String,
    pub cgroup_id: u32,
    pub name: String,
    pub cgroup_path: Option<String>,
    pub uid: Option<u32>,
    pub user: Option<String>,
    pub enforcement: &'static str,
    pub download_bps: Option<u64>,
    pub upload_bps: Option<u64>,
    pub group_id: Option<u32>,
    pub oldest_started_secs: Option<u64>,
    pub processes: usize,
    pub socket_holders: usize,
    pub sockets: usize,
    pub procs: Vec<ProcJson>,
    pub endpoints: Vec<EndpointJson>,
}

/// A target that resolved to nothing (multi-target partial miss).
#[derive(serde::Serialize)]
pub struct DepthMissJson {
    pub target: String,
    pub error: String,
}

/// One entry of the targets array: a report or a miss.
#[derive(serde::Serialize)]
#[serde(untagged)]
pub enum DepthEntryJson {
    Report(Box<DepthTargetJson>),
    Miss(DepthMissJson),
}

/// The whole `--depth --print-json` document.
#[derive(serde::Serialize)]
pub struct DepthDocJson {
    pub targets: Vec<DepthEntryJson>,
}

/// Build the typed JSON document from assembled reports plus the
/// misses (pure — struct assembly only, no io).
#[must_use]
pub fn depth_doc_json(reports: &[DepthReport], misses: &[(String, String)]) -> DepthDocJson {
    let mut targets = Vec::new();
    for report in reports {
        let holders = report.conns.as_ref().map_or(0, |c| c.socket_holders.len());
        let sockets = report.conns.as_ref().map_or(0, |c| {
            c.socket_holders.iter().map(|p| p.sockets.len()).sum()
        });
        let (download, upload, group_id) = match &report.enforcement {
            Enforcement::Unlimited => (None, None, None),
            Enforcement::Limited { download, upload } => (
                download.as_ref().map(|p| p.rate_bps),
                upload.as_ref().map(|p| p.rate_bps),
                download.as_ref().or(upload.as_ref()).map(|p| p.group_id),
            ),
        };
        let rep = representative(&report.depth);
        targets.push(DepthEntryJson::Report(Box::new(DepthTargetJson {
            target: report.target.clone(),
            cgroup_id: report.cgroup_id,
            name: report.name.clone(),
            cgroup_path: cgroup_abs_path(report.depth.rel_path.as_deref()),
            uid: rep.map(|p| p.uid),
            user: rep.and_then(|p| p.user.clone()),
            enforcement: enforcement_word(&report.enforcement),
            download_bps: download,
            upload_bps: upload,
            group_id,
            oldest_started_secs: oldest_started_secs(&report.depth),
            processes: report.depth.procs.len(),
            socket_holders: holders,
            sockets,
            procs: report
                .depth
                .procs
                .iter()
                .map(|p| ProcJson {
                    pid: p.pid,
                    comm: p.comm.clone(),
                    uid: p.uid,
                    user: p.user.clone(),
                    ppid: p.ppid,
                    state: p.state.clone(),
                    threads: p.threads,
                    rss_kb: p.rss_kb,
                    exe: p.exe.clone(),
                    kind: p.kind,
                    script: p.script.clone(),
                    permission: p.mode.clone(),
                    cwd: p.cwd.clone(),
                    cmdline: p.cmdline.clone(),
                    started_ago_secs: p.started_ago_secs,
                    started_epoch: p.started_epoch,
                })
                .collect(),
            endpoints: report.conns.as_ref().map_or_else(Vec::new, |c| {
                c.socket_holders
                    .iter()
                    .flat_map(|h| {
                        h.sockets.iter().map(move |s| EndpointJson {
                            pid: h.pid,
                            comm: h.comm.clone(),
                            proto: if s.proto == crate::ebpf::connections::Proto::Tcp {
                                "tcp"
                            } else {
                                "udp"
                            },
                            remote: s.remote.clone(),
                            state: s.state,
                        })
                    })
                    .collect()
            }),
        })));
    }
    for (target, error) in misses {
        targets.push(DepthEntryJson::Miss(DepthMissJson {
            target: target.clone(),
            error: error.clone(),
        }));
    }
    DepthDocJson { targets }
}

// The depth report pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the other render pins.
#[cfg(test)]
#[path = "../../../test/ebpf/render/report_tests.rs"]
mod tests;
