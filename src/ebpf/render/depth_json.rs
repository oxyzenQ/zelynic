// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The `eagle-eyes --depth --print-json` document (NIGHT-master-1;
//! split from report.rs at NIGHT-blade-5 to hold both files under the
//! 500-LOC owner cap — the JSON half of the depth report moved whole,
//! its contract unchanged apart from the blade-5 additions).
//!
//! Composition is PURE: the handler (commands/eagle.rs) assembles
//! [`DepthReport`] values; this module turns them into the typed
//! scripting document (the stable v11 API shape). No /proc or map
//! access lives here — the pins in test/ebpf/render/ drive fixtures,
//! not the host.
//!
//! NIGHT-blade-5 additions: the enforcement LEDGER
//! ([`EnforcementStatsJson`] — the kernel's own allowed/dropped
//! accounting for a limited cgroup) and the cgroup controller's
//! resource view (memory bytes, accumulated CPU microseconds) ride
//! the document beside the policy verdict, so a script can answer
//! "what did enforcement actually do to this cgroup" and "what does
//! it cost the machine" without re-deriving either from /proc.
//!
//! NIGHT-blade-7 addition: each process row carries `exe_deleted`
//! (additive, script-safe) — true when the kernel marked the exe
//! readlink " (deleted)", the replaced-by-upgrade / self-deleting
//! indicator a scripted triage pipeline wants as a boolean instead
//! of parsing the text report's marker.

use crate::ebpf::bypass::{ShadowAudit, ShadowVerdict};
use crate::ebpf::identity::depth::ProcessFacts;
use crate::ebpf::limiter::types::POLICY_FLAG_PER_SOCKET;
use crate::ebpf::limiter::{LimiterStatsRaw, PolicyRaw};
use crate::ebpf::render::depth_traffic::TrafficFocus;
use crate::ebpf::render::report::{cgroup_abs_path, oldest_started_secs, representative};

use super::report::{DepthReport, Enforcement};

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
    /// NIGHT-blade-7: the kernel marked this member's exe " (deleted)"
    /// — the on-disk binary was replaced or removed after start.
    pub exe_deleted: bool,
    pub kind: Option<&'static str>,
    pub script: Option<String>,
    pub permission: Option<String>,
    pub cwd: Option<String>,
    pub cmdline: Option<String>,
    pub started_ago_secs: Option<u64>,
    pub started_epoch: Option<u64>,
}

/// One endpoint row of the JSON document. The two byte fields
/// (NIGHT-private-research-3) carry the endpoint's focus-window
/// bytes when a window ran and the cookie join resolved this
/// socket; null otherwise — absence, never zero-as-fact.
#[derive(serde::Serialize)]
pub struct EndpointJson {
    pub pid: u32,
    pub comm: String,
    pub proto: &'static str,
    pub remote: String,
    pub state: &'static str,
    /// Focus-window download bytes (null = no measured window, or
    /// the join resolved no entry for this socket's cookie).
    pub download_bytes: Option<u64>,
    /// Focus-window upload bytes (null = the same absence).
    pub upload_bytes: Option<u64>,
}

/// The focus-window measurement for one cgroup
/// (NIGHT-private-research-3): the kernel's own window totals. The
/// per-endpoint attribution rides each endpoint row — its sum can
/// sit below these totals (sockets that died mid-window stay booked
/// in the kernel maps but leave the /proc census), both numbers are
/// true, they answer different questions.
#[derive(serde::Serialize)]
pub struct TrafficJson {
    /// The measured focus window in seconds.
    pub window_secs: u64,
    /// Download bytes the cgroup moved in the window (kernel truth).
    pub download_bytes: u64,
    /// Upload bytes the cgroup moved in the window (kernel truth).
    pub upload_bytes: u64,
}

/// The kernel's enforcement ledger for one cgroup (NIGHT-blade-5):
/// the cgroup_limiter_stats row the BPF programs book under
/// enforcement — the same counters `zelynic rates` reads, carried on
/// the depth document so the verdict line's "limited" comes with its
/// consequences attached.
#[derive(serde::Serialize)]
pub struct EnforcementStatsJson {
    pub packets_allowed: u64,
    pub packets_dropped: u64,
    pub bytes_allowed: u64,
    pub bytes_dropped: u64,
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
    /// charger-core-3c: the bps figures above name per-CONNECTION
    /// budgets when true (skip when false — the additive rule).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub download_per_socket: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub upload_per_socket: bool,
    pub group_id: Option<u32>,
    /// The kernel's allowed/dropped ledger when this cgroup is
    /// enforced and booked (NIGHT-blade-5; null = unlimited, or a
    /// fresh pin the kernel has not booked yet).
    pub enforcement_stats: Option<EnforcementStatsJson>,
    /// The cgroup controller's resident-memory view in bytes
    /// (NIGHT-blade-5; null = the controller file was unreadable).
    pub cgroup_memory_bytes: Option<u64>,
    /// The cgroup controller's accumulated CPU time in microseconds
    /// (NIGHT-blade-5; null = the controller file was unreadable).
    pub cgroup_cpu_usage_usec: Option<u64>,
    pub oldest_started_secs: Option<u64>,
    pub processes: usize,
    pub socket_holders: usize,
    pub sockets: usize,
    /// The focus-window measurement (NIGHT-private-research-3;
    /// null = the window did not run — observer attach or poll
    /// failed, the honest absence a script can distinguish from a
    /// zero-traffic window).
    pub traffic: Option<TrafficJson>,
    pub procs: Vec<ProcJson>,
    pub endpoints: Vec<EndpointJson>,
}

/// A target that resolved to nothing (multi-target partial miss).
#[derive(serde::Serialize)]
pub struct DepthMissJson {
    pub target: String,
    pub error: String,
}

/// The bypass-shadow audit over the report's focus window
/// (NIGHT-upgrade-charger-core-1-a): the machine-scope comparison of
/// interface counters against the cgroup_skb hooks' own totals —
/// `shadow_*_bytes` is the gap, `verdict` one of "clean",
/// "bypassed_tx", "bypassed_rx", "bypassed_both", "unavailable".
#[derive(serde::Serialize)]
pub struct BypassAuditJson {
    pub window_secs: u64,
    pub nic_tx_bytes: u64,
    pub nic_rx_bytes: u64,
    pub bpf_tx_bytes: u64,
    pub bpf_rx_bytes: u64,
    pub shadow_tx_bytes: u64,
    pub shadow_rx_bytes: u64,
    pub verdict: &'static str,
}

/// The audit as JSON (None stays null — the window did not run, the
/// honest absence a script can distinguish from a clean verdict).
fn bypass_audit_json(audit: Option<&ShadowAudit>) -> Option<BypassAuditJson> {
    audit.map(|a| BypassAuditJson {
        window_secs: a.window_secs,
        nic_tx_bytes: a.nic_tx,
        nic_rx_bytes: a.nic_rx,
        bpf_tx_bytes: a.bpf_tx,
        bpf_rx_bytes: a.bpf_rx,
        shadow_tx_bytes: a.shadow_tx,
        shadow_rx_bytes: a.shadow_rx,
        verdict: match a.verdict {
            ShadowVerdict::Clean => "clean",
            ShadowVerdict::BypassedTx => "bypassed_tx",
            ShadowVerdict::BypassedRx => "bypassed_rx",
            ShadowVerdict::BypassedBoth => "bypassed_both",
            ShadowVerdict::Unavailable => "unavailable",
        },
    })
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
    /// The bypass-shadow audit (NIGHT-upgrade-charger-core-1-a;
    /// null = the traffic focus window did not run — see the note
    /// fields). Additive: scripts predating the field ignore it.
    pub bypass_audit: Option<BypassAuditJson>,
}

/// The ledger row as JSON (None stays null — the honest absence).
fn stats_json(stats: &Option<LimiterStatsRaw>) -> Option<EnforcementStatsJson> {
    stats.map(|s| EnforcementStatsJson {
        packets_allowed: s.packets_allowed,
        packets_dropped: s.packets_dropped,
        bytes_allowed: s.bytes_allowed,
        bytes_dropped: s.bytes_dropped,
    })
}

/// The focus-window object as JSON (None stays null — the honest
/// absence, never a fabricated zero-traffic window).
fn traffic_json(focus: &Option<TrafficFocus>) -> Option<TrafficJson> {
    focus.as_ref().map(|f| TrafficJson {
        window_secs: f.window_secs,
        download_bytes: f.dl_bytes,
        upload_bytes: f.ul_bytes,
    })
}

/// Build the typed JSON document from assembled reports plus the
/// misses and the bypass audit (pure — struct assembly only, no io).
#[must_use]
pub fn depth_doc_json(
    reports: &[DepthReport],
    misses: &[(String, String)],
    audit: Option<&ShadowAudit>,
) -> DepthDocJson {
    let mut targets = Vec::new();
    for report in reports {
        let holders = report.conns.as_ref().map_or(0, |c| c.socket_holders.len());
        let sockets = report.conns.as_ref().map_or(0, |c| {
            c.socket_holders.iter().map(|p| p.sockets.len()).sum()
        });
        let per = |p: &Option<PolicyRaw>| {
            p.map(|raw| raw.flags & POLICY_FLAG_PER_SOCKET != 0)
                .unwrap_or(false)
        };
        let (download, upload, group_id, dl_ps, ul_ps) = match &report.enforcement {
            Enforcement::Unlimited => (None, None, None, false, false),
            Enforcement::Limited { download, upload } => (
                download.as_ref().map(|p| p.rate_bps),
                upload.as_ref().map(|p| p.rate_bps),
                download.as_ref().or(upload.as_ref()).map(|p| p.group_id),
                per(download),
                per(upload),
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
            enforcement: super::report::enforcement_word(&report.enforcement),
            download_bps: download,
            upload_bps: upload,
            download_per_socket: dl_ps,
            upload_per_socket: ul_ps,
            group_id,
            enforcement_stats: stats_json(&report.enforcement_stats),
            cgroup_memory_bytes: report.depth.resources.memory_current_bytes,
            cgroup_cpu_usage_usec: report.depth.resources.cpu_usage_usec,
            oldest_started_secs: oldest_started_secs(&report.depth),
            processes: report.depth.procs.len(),
            socket_holders: holders,
            sockets,
            traffic: traffic_json(&report.traffic),
            procs: report
                .depth
                .procs
                .iter()
                .map(|p: &ProcessFacts| ProcJson {
                    pid: p.pid,
                    comm: p.comm.clone(),
                    uid: p.uid,
                    user: p.user.clone(),
                    ppid: p.ppid,
                    state: p.state.clone(),
                    threads: p.threads,
                    rss_kb: p.rss_kb,
                    exe: p.exe.clone(),
                    exe_deleted: p.exe_deleted,
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
                        h.sockets.iter().map(move |s| {
                            // The focus window's cookie join, exact
                            // key: figures when the window ran and
                            // resolved this socket's cookie, null
                            // otherwise (the honest absence — the
                            // same lookup the endpoint rows read).
                            let joined = report.traffic.as_ref().and_then(|f| {
                                s.cookie.and_then(|cookie| f.bytes.get(&cookie).copied())
                            });
                            EndpointJson {
                                pid: h.pid,
                                comm: h.comm.clone(),
                                proto: if s.proto == crate::ebpf::connections::Proto::Tcp {
                                    "tcp"
                                } else {
                                    "udp"
                                },
                                remote: s.remote.clone(),
                                state: s.state,
                                download_bytes: joined.map(|b| b.dl),
                                upload_bytes: joined.map(|b| b.ul),
                            }
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
    DepthDocJson {
        targets,
        bypass_audit: bypass_audit_json(audit),
    }
}

// The depth JSON pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the report pins they grew
// from (NIGHT-blade-5: the JSON contract pins moved with the code).
#[cfg(test)]
#[path = "../../../test/ebpf/render/depth_json_tests.rs"]
mod tests;
