// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Connection detail lines (NIGHT-hunt-8 eagle eyes): the per-cgroup
//! process-count label suffix and the indented socket-endpoint lines
//! rendered under monitor rows. Shared by the eagle-eyes renderers
//! (ranked table + focus view); the single-cgroup focus view uses
//! the uncapped variant.

use crate::ebpf::connections::{ConnectionMap, Proto, SocketInfo};
use crate::ebpf::identity::IdentityMap;

/// Detail lines rendered under one monitor row per socket-holding
/// process (NIGHT-hunt-8 eagle eyes).
const DETAIL_PROC_CAP: usize = 3;

/// Identity label enriched with the cgroup's process count:
/// `cg:73386 (alacritty +3)` when more than one process lives there.
///
/// This is the direct fix for the owner's "alacritty1,2,3,4,5"
/// complaint — a session cgroup whose row name is the first PID the
/// identity walk saw now says out loud that it is multi-tenant, and
/// the detail lines name the actual inhabitants.
#[must_use]
pub(crate) fn label_with_count(
    identity: &IdentityMap,
    conns: Option<&ConnectionMap>,
    cgroup_id: u32,
) -> String {
    let base = identity.label(cgroup_id);
    let Some(conns) = conns else {
        return base;
    };
    let procs = conns.proc_count(cgroup_id);
    if procs > 1 {
        // Splice before the closing paren: "(alacritty)" -> "(alacritty +3)".
        if let Some(stripped) = base.strip_suffix(')') {
            return format!("{stripped} +{})", procs - 1);
        }
    }
    base
}

/// Extract the primary comm from a label, tolerating the "+N" suffix
/// (used by the top-consumer hint).
#[must_use]
pub(crate) fn comm_from_label(label: &str) -> Option<String> {
    let inner = label.split('(').nth(1)?.strip_suffix(')')?;
    let comm = inner.split(" +").next().unwrap_or(inner);
    if comm.is_empty() || comm == "unknown" {
        return None;
    }
    Some(comm.to_string())
}

/// One detail line's endpoint text: UDP is tagged (QUIC-era traffic
/// lives there), busy sockets are flagged.
fn endpoint_text(socket: &SocketInfo) -> String {
    let mut out = String::new();
    if socket.proto == Proto::Udp {
        out.push_str("udp ");
    }
    out.push_str(&socket.remote);
    if socket.queued {
        out.push_str(" [busy]");
    }
    out
}

/// Is this socket worth a detail line? Established TCP and connected
/// UDP carry traffic; LISTEN/TIME_WAIT rows are noise.
///
/// The UDP branch needs the remote guard (NIGHT-hunt-15):
/// /proc/net/udp reports state 07 (CLOSE) for connected AND
/// unconnected sockets alike, so a bound-only listener (chronyd,
/// systemd-resolved, mDNS) would otherwise render as `udp 0.0.0.0:0`
/// noise under its cgroup row. A real remote endpoint never carries
/// port 0, and both `0.0.0.0:0` and `[::]:0` end in `:0`.
fn is_displayable(socket: &SocketInfo) -> bool {
    match socket.proto {
        Proto::Tcp => socket.state == "ESTABLISHED",
        // /proc/net/udp uses state 07 for a connected UDP socket.
        Proto::Udp => socket.state == "CLOSE" && !socket.remote.ends_with(":0"),
    }
}

/// Detail lines for one cgroup row (NIGHT-hunt-8): the actual
/// processes holding network sockets inside the cgroup, first
/// endpoint inline, capped at DETAIL_PROC_CAP process lines plus one
/// summary line.
#[must_use]
pub(crate) fn detail_lines(conns: Option<&ConnectionMap>, cgroup_id: u32) -> Vec<String> {
    let mut lines = Vec::new();
    let Some(conns) = conns else {
        return lines;
    };
    let Some(detail) = conns.get(cgroup_id) else {
        return lines;
    };

    let mut holders_shown = 0;
    for proc in &detail.socket_holders {
        if holders_shown >= DETAIL_PROC_CAP {
            break;
        }
        let endpoints: Vec<_> = proc.sockets.iter().filter(|s| is_displayable(s)).collect();
        if endpoints.is_empty() {
            continue; // listener-only process: not traffic, not news
        }
        let mut line = format!(
            "    └ {} ({}) → {}",
            proc.comm,
            proc.pid,
            endpoint_text(endpoints[0])
        );
        if endpoints.len() > 1 {
            line.push_str(&format!(" +{} more", endpoints.len() - 1));
        }
        lines.push(line);
        holders_shown += 1;
    }

    let remaining = detail
        .socket_holders
        .iter()
        .filter(|p| p.sockets.iter().any(is_displayable))
        .count()
        .saturating_sub(holders_shown);
    if remaining > 0 {
        lines.push(format!("    └ +{remaining} more socket-holding processes"));
    }

    lines
}

/// Uncapped detail view for the single-cgroup monitor (NIGHT-hunt-8):
/// every socket-holding process, first two endpoints inline, the rest
/// counted. Answers "who exactly is talking inside this cgroup".
#[must_use]
pub(crate) fn full_detail_lines(conns: Option<&ConnectionMap>, cgroup_id: u32) -> Vec<String> {
    let mut lines = Vec::new();
    let Some(conns) = conns else {
        return lines;
    };
    let Some(detail) = conns.get(cgroup_id) else {
        return lines;
    };
    if detail.socket_holders.is_empty() {
        return lines;
    }

    lines.push(format!(
        "  processes with sockets ({} total processes):",
        detail.total_procs
    ));
    for proc in &detail.socket_holders {
        let endpoints: Vec<_> = proc.sockets.iter().filter(|s| is_displayable(s)).collect();
        if endpoints.is_empty() {
            continue;
        }
        let shown: Vec<String> = endpoints.iter().take(2).map(|s| endpoint_text(s)).collect();
        let mut line = format!("  └ {} ({}) → {}", proc.comm, proc.pid, shown.join(", "));
        if endpoints.len() > 2 {
            line.push_str(&format!(" +{} more", endpoints.len() - 2));
        }
        lines.push(line);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Label enrichment (NIGHT-hunt-8): multi-tenant cgroups say so.
    #[test]
    fn label_with_count_shapes() {
        use crate::ebpf::connections::CgroupConnections;
        use crate::ebpf::identity::ProcessIdentity;

        let mut identity = IdentityMap::new();
        identity.insert(ProcessIdentity {
            cgroup_id: 7001,
            uid: 1000,
            comm: "alacritty".to_string(),
        });

        // No connection map: plain identity label.
        assert_eq!(
            label_with_count(&identity, None, 7001),
            "cg:7001 (alacritty)"
        );

        // Single process: count adds nothing.
        let mut conns = crate::ebpf::connections::ConnectionMap::new();
        conns.insert(
            7001,
            CgroupConnections {
                total_procs: 1,
                socket_holders: Vec::new(),
            },
        );
        assert_eq!(
            label_with_count(&identity, Some(&conns), 7001),
            "cg:7001 (alacritty)"
        );

        // Four processes: "(alacritty +3)" — the row stops lying.
        conns.insert(
            7001,
            CgroupConnections {
                total_procs: 4,
                socket_holders: Vec::new(),
            },
        );
        assert_eq!(
            label_with_count(&identity, Some(&conns), 7001),
            "cg:7001 (alacritty +3)"
        );

        // Unresolved identity: no paren to splice, label untouched.
        assert_eq!(label_with_count(&identity, Some(&conns), 9999), "cg:9999");
    }

    /// Comm extraction tolerates the "+N" suffix and rejects
    /// unknown/empty comms.
    #[test]
    fn comm_from_label_shapes() {
        assert_eq!(
            comm_from_label("cg:7001 (alacritty +3)").as_deref(),
            Some("alacritty")
        );
        assert_eq!(comm_from_label("cg:7001 (curl)").as_deref(), Some("curl"));
        assert_eq!(comm_from_label("cg:7001 (unknown)"), None);
        assert_eq!(comm_from_label("cg:7001 ()"), None);
        assert_eq!(comm_from_label("cg:7001"), None);
    }

    /// Detail lines: established endpoints named, listeners skipped,
    /// cap plus summary respected (the owner's curl-inside-alacritty
    /// case rendered exactly).
    #[test]
    fn detail_lines_eagle_eyes() {
        use crate::ebpf::connections::{
            CgroupConnections, ConnectionMap, ProcessDetail, Proto, SocketInfo,
        };

        let socket = |proto: Proto, remote: &str, state: &'static str, queued: bool| SocketInfo {
            proto,
            remote: remote.to_string(),
            state,
            queued,
        };

        let mut conns = ConnectionMap::new();
        conns.insert(
            7001,
            CgroupConnections {
                total_procs: 4,
                socket_holders: vec![
                    ProcessDetail {
                        pid: 4242,
                        comm: "curl".to_string(),
                        sockets: vec![
                            socket(Proto::Tcp, "10.90.170.143:443", "ESTABLISHED", true),
                            socket(Proto::Tcp, "1.1.1.1:443", "ESTABLISHED", false),
                        ],
                    },
                    ProcessDetail {
                        pid: 4243,
                        comm: "wget".to_string(),
                        sockets: vec![socket(Proto::Tcp, "93.184.216.34:80", "ESTABLISHED", false)],
                    },
                    ProcessDetail {
                        pid: 5000,
                        comm: "nc".to_string(),
                        sockets: vec![socket(Proto::Udp, "8.8.8.8:53", "CLOSE", false)],
                    },
                    ProcessDetail {
                        pid: 6000,
                        comm: "sshd".to_string(),
                        sockets: vec![socket(Proto::Tcp, "0.0.0.0:22", "LISTEN", false)],
                    },
                    ProcessDetail {
                        pid: 7000,
                        comm: "vim".to_string(),
                        sockets: vec![socket(Proto::Tcp, "9.9.9.9:22", "ESTABLISHED", false)],
                    },
                    // NIGHT-hunt-15 pin: a bound-only UDP listener
                    // (state 07, remote 0.0.0.0:0 — the chronyd /
                    // systemd-resolved shape) is NOT traffic and must
                    // not produce a detail line nor inflate the
                    // "+N more" count.
                    ProcessDetail {
                        pid: 8000,
                        comm: "chronyd".to_string(),
                        sockets: vec![socket(Proto::Udp, "0.0.0.0:0", "CLOSE", false)],
                    },
                ],
            },
        );

        let lines = detail_lines(Some(&conns), 7001);
        assert_eq!(
            lines,
            vec![
                "    └ curl (4242) → 10.90.170.143:443 [busy] +1 more".to_string(),
                "    └ wget (4243) → 93.184.216.34:80".to_string(),
                "    └ nc (5000) → udp 8.8.8.8:53".to_string(),
                "    └ +1 more socket-holding processes".to_string(),
            ]
        );

        // No map, no detail — the monitor degrades to plain rows.
        assert!(detail_lines(None, 7001).is_empty());
        // Unknown cgroup: no detail.
        assert!(detail_lines(Some(&conns), 1234).is_empty());
    }
}
