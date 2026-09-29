// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The eagle-eyes `--depth` network-traffic focus
//! (NIGHT-private-research-3, the think-like-light-years-3 upgrade):
//! the one-shot report's answer to "which endpoint is MOVING, not
//! just which endpoints exist".
//!
//! Before this pass the depth report's socket section was the BASIC
//! CURRENT census — endpoints and states from the /proc walk, zero
//! byte figures. The live monitor already joined the BPF per-socket
//! cookie maps onto its endpoint rows (NIGHT-boost-26); the one-shot
//! report never loaded an observer, so the join never ran there.
//! This module closes that gap: the depth handler attaches an
//! observer, lets a short focus window (default 3s, `--focus 1s..30s`)
//! pass, polls the per-cgroup counters and the per-socket cookie
//! maps, and hands the result here.
//!
//! Composition is PURE: the handler owns every /proc walk, BPF load,
//! and sleep; this module turns the measured window into the
//! [`TrafficFocus`] value the text report and the JSON document
//! render from. The pins in test/ebpf/render/ drive fixtures, never
//! the host.
//!
//! Honesty contracts carried over from the surfaces this joins:
//! - the cgroup window totals come from the kernel's own counter
//!   maps (every byte the cgroup moved in the window, including
//!   sockets that DIED mid-window — their cookie entries stay
//!   booked in the LRU maps even though the /proc walk no longer
//!   knows them);
//! - the per-endpoint figures are best-effort: they cover exactly
//!   the sockets the post-window /proc walk resolved cookies for,
//!   so their sum can sit below the window total — both numbers are
//!   true, they answer different questions (kernel-truth totals vs
//!   live-socket attribution);
//! - absence stays absence: an endpoint without bytes renders no
//!   figures (never a fabricated zero), and an unmeasured window
//!   renders the basic socket census exactly as before.

use crate::ebpf::connections::{CgroupConnections, ConnectionMap};
use crate::ebpf::limiter::format_bytes;
use crate::ebpf::loader::{CgroupDelta, SocketBytes};
use crate::output::grey;

use std::collections::HashMap;

use super::report::SOCKET_LINES_CAP;

/// One endpoint row of the focus window: the /proc census row joined
/// with its cookie's window bytes when the join resolved.
#[derive(Debug, Clone)]
pub struct TrafficEndpoint {
    pub pid: u32,
    pub comm: String,
    /// Remote endpoint as displayed ("142.250.191.78:443").
    pub remote: String,
    pub proto: &'static str,
    pub state: &'static str,
    /// Window download bytes (None = the join resolved no entry —
    /// the socket moved nothing the maps booked, or the cookie
    /// discovery was refused; absence, never zero-as-fact).
    pub dl: Option<u64>,
    /// Window upload bytes (None = the same honest absence).
    pub ul: Option<u64>,
}

impl TrafficEndpoint {
    /// Total window bytes when either direction booked anything.
    fn total(&self) -> u64 {
        self.dl.unwrap_or(0).saturating_add(self.ul.unwrap_or(0))
    }

    /// The row's byte suffix — the live view's exact `[dl X | ul Y]`
    /// vocabulary, so the two surfaces read as one family. Empty for
    /// a byteless row (the lean-row contract, detail::endpoint_text).
    fn bytes_suffix(&self) -> String {
        match (self.dl, self.ul) {
            (Some(dl), Some(ul)) => {
                format!(" [dl {} | ul {}]", format_bytes(dl), format_bytes(ul))
            }
            (Some(dl), None) => format!(" [dl {}]", format_bytes(dl)),
            (None, Some(ul)) => format!(" [ul {}]", format_bytes(ul)),
            (None, None) => String::new(),
        }
    }

    /// The endpoint row as the report prints it (pure).
    fn row(&self) -> String {
        format!(
            "   {} ({}) → {} {} {}{}",
            self.comm,
            self.pid,
            self.remote,
            self.proto,
            self.state,
            self.bytes_suffix()
        )
    }
}

/// One cgroup's measured focus window (NIGHT-private-research-3):
/// the kernel's window totals plus the per-endpoint attribution of
/// every socket the post-window walk resolved.
#[derive(Debug, Clone)]
pub struct TrafficFocus {
    /// The measured window in seconds (the honest denominator: the
    /// handler sleeps exactly this between the baseline and closing
    /// polls; the totals are what the kernel booked in that span).
    pub window_secs: u64,
    /// Download bytes the cgroup moved in the window (kernel truth).
    pub dl_bytes: u64,
    /// Upload bytes the cgroup moved in the window (kernel truth).
    pub ul_bytes: u64,
    /// The window's per-socket cookie join (cookie → dl/ul), the
    /// exact lookup table the endpoint rows and the JSON document
    /// read — mirrors [`ConnectionMap::socket_bytes`]'s role on the
    /// live side: one join, every consumer.
    pub bytes: HashMap<u64, SocketBytes>,
    /// The window's endpoint rows: movers first (bytes descending,
    /// the focus view's own ranking contract), byteless endpoints
    /// behind them in the walk's established-first order.
    pub endpoints: Vec<TrafficEndpoint>,
}

impl TrafficFocus {
    /// Did anything move in the window? A window with zero totals is
    /// a verdict ("no traffic"), not a failure — the header says so
    /// instead of rendering an empty ranking.
    pub fn moved(&self) -> bool {
        self.dl_bytes > 0 || self.ul_bytes > 0
    }

    /// The section header line: the window and the kernel's own
    /// totals, the dl/ul vocabulary every speed pair in the monitor
    /// carries. Zero traffic renders the no-movement verdict.
    fn header(&self) -> String {
        if !self.moved() {
            return grey(&format!(
                "  network traffic ({}s focus): no traffic in the window",
                self.window_secs
            ));
        }
        grey(&format!(
            "  network traffic ({}s focus): dl {} · ul {}",
            self.window_secs,
            format_bytes(self.dl_bytes),
            format_bytes(self.ul_bytes)
        ))
    }
}

/// Compose one cgroup's [`TrafficFocus`] from the focus window's
/// raw measurements (pure): the closing poll's delta row for the
/// cgroup (kernel window totals — bytes upload, ingress_bytes
/// download), the post-window connection census, and the cookie
/// join result. Delta rows the poll did not produce (a quiet
/// cgroup) compose a zero-total window — the honest verdict, never
/// an error.
#[must_use]
pub fn traffic_focus(
    cgroup_id: u32,
    window_secs: u64,
    deltas: &[CgroupDelta],
    conns: Option<&ConnectionMap>,
    socket_bytes: &std::collections::HashMap<u64, SocketBytes>,
) -> TrafficFocus {
    let delta = deltas.iter().find(|d| d.cgroup_id == cgroup_id);
    let (dl_bytes, ul_bytes) = match delta {
        Some(d) => (d.ingress_bytes, d.bytes),
        None => (0, 0),
    };
    let mut endpoints: Vec<TrafficEndpoint> = Vec::new();
    let mut bytes: HashMap<u64, SocketBytes> = HashMap::new();
    if let Some(detail) = conns.and_then(|c| c.get(cgroup_id)) {
        for holder in &detail.socket_holders {
            for socket in &holder.sockets {
                // The window's cookie join, collected for every
                // cookie the census resolved (the bytes table every
                // consumer reads — endpoint rows here, the JSON
                // document's per-socket fields).
                let joined = socket
                    .cookie
                    .and_then(|cookie| socket_bytes.get(&cookie).copied());
                if let (Some(cookie), Some(b)) = (socket.cookie, joined) {
                    bytes.insert(cookie, b);
                }
                // Same displayability gate the live detail lines
                // apply: LISTEN/TIME_WAIT rows are census noise, and
                // the traffic section answers movement questions.
                if !super::detail::is_displayable(socket) {
                    continue;
                }
                endpoints.push(TrafficEndpoint {
                    pid: holder.pid,
                    comm: holder.comm.clone(),
                    remote: socket.remote.clone(),
                    proto: if socket.proto == crate::ebpf::connections::Proto::Tcp {
                        "tcp"
                    } else {
                        "udp"
                    },
                    state: socket.state,
                    dl: joined.map(|b| b.dl),
                    ul: joined.map(|b| b.ul),
                });
            }
        }
    }
    // Movers first, bytes descending; stable within equals so the
    // byteless rows keep the walk's established-first order (the
    // focus view's own ranking contract, full_detail_lines).
    endpoints.sort_by_key(|e| std::cmp::Reverse(e.total()));
    TrafficFocus {
        window_secs,
        dl_bytes,
        ul_bytes,
        bytes,
        endpoints,
    }
}

/// The report's network-traffic section (pure): the header line,
/// the capped endpoint rows (movers first, each carrying its
/// `[dl X | ul Y]` suffix), and the honest overflow note when the
/// census outgrows the readable cap — the same SOCKET_LINES_CAP
/// contract the basic listing carried (every row rides --print-json).
pub(crate) fn traffic_section_lines(focus: &TrafficFocus) -> Vec<String> {
    let mut lines = vec![focus.header()];
    let mut shown = 0usize;
    let mut hidden = 0usize;
    for endpoint in &focus.endpoints {
        if shown < SOCKET_LINES_CAP {
            lines.push(endpoint.row());
            shown += 1;
        } else {
            hidden += 1;
        }
    }
    if hidden > 0 {
        lines.push(grey(&format!(
            "   +{hidden} more — every endpoint rides the --print-json document"
        )));
    }
    lines
}

/// The not-measured note line (pure): a focus window that could not
/// run (observer attach or poll failure) says so under the socket
/// section header instead of silently omitting the ability — the
/// honest-absence contract: a reader who knows the feature exists
/// learns WHY the report lacks it.
pub(crate) fn traffic_not_measured_line(reason: &str) -> String {
    grey(&format!("  network traffic: not measured — {reason}"))
}

/// The whole socket/traffic section of the depth report, both arms
/// (NIGHT-private-research-3): the focus window's own section when a
/// measurement ran, the BASIC CURRENT census (endpoints and states,
/// no figures — exactly the pre-focus report) with the
/// not-measured note when one is owed, and None when there is
/// nothing to show (no window, no sockets). The section's one
/// concern lives in this one module — the report composes, this
/// module renders.
#[must_use]
pub(crate) fn traffic_section(
    focus: Option<&TrafficFocus>,
    conns: Option<&CgroupConnections>,
    traffic_note: Option<&str>,
) -> Option<Vec<String>> {
    if let Some(focus) = focus {
        return Some(traffic_section_lines(focus));
    }
    let conns = conns?;
    if conns.socket_holders.is_empty() {
        return None;
    }
    let mut lines = vec![grey("  sockets:")];
    if let Some(reason) = traffic_note {
        lines.push(traffic_not_measured_line(reason));
    }
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
    Some(lines)
}

// The traffic pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the report pins they
// extend.
#[cfg(test)]
#[path = "../../../test/ebpf/render/depth_traffic_tests.rs"]
mod tests;
