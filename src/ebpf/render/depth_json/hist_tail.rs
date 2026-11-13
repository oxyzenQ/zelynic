// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The depth histogram's tail story builders (night-frontier-Z1,
//! schema v35 — the depth_json sibling-split lineage, the same
//! 600-line LOC law that split write.rs): the cookie→endpoint
//! labels the walk's census owns and the JSON tail list they
//! render. Pure — struct assembly only, no io; the wire writers
//! stay in write.rs.

use super::TailJson;
use crate::ebpf::connections::CgroupConnections;
use crate::ebpf::limiter::hist::{HistTailRaw, tail_entries};

use std::collections::HashMap;

/// The cookie→endpoint labels the walk's census owns (night-
/// frontier-Z1): one flat pass over the holders' sockets, cookie to
/// `remote (comm)` — the tail's "who" without a second walk. A
/// cookie the walk missed (a socket that closed between the sample
/// and the walk) stays unmapped — the raw cookie is the honest
/// remainder, never a fabricated endpoint.
#[must_use]
pub fn tail_labels(conns: Option<&CgroupConnections>) -> HashMap<u64, String> {
    conns.map_or(HashMap::new(), |c| {
        c.socket_holders
            .iter()
            .flat_map(|h| {
                h.sockets.iter().filter_map(|s| {
                    s.cookie
                        .map(|ck| (ck, format!("{} ({})", s.remote, h.comm)))
                })
            })
            .collect()
    })
}

/// The row's tail as JSON (night-frontier-Z1): the live story slots
/// in the kernel's slot order (the worst-by-size REPLACEMENT policy
/// overwrites the weakest slot; the read renders what the kernel
/// kept, no sort fiction). srtt None = the unmeasured sentinel;
/// endpoint None = the walk's census never owned that cookie.
#[must_use]
pub fn tail_json(tail: &[HistTailRaw; 8], labels: &HashMap<u64, String>) -> Vec<TailJson> {
    tail_entries(tail)
        .into_iter()
        .map(|t| TailJson {
            ts_ns: t.ts_ns,
            size: t.size,
            srtt_us: (t.srtt_us > 0).then_some(t.srtt_us),
            cookie: t.cookie,
            endpoint: if t.cookie == 0 {
                None
            } else {
                labels.get(&t.cookie).cloned()
            },
        })
        .collect()
}
