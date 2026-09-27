// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The top-consumer ranking pins (NIGHT-dinner-6): the footer's
//! "busiest process" is the one that moved the most JOINED BYTES,
//! with the walk order standing whenever the join carries no
//! figures. Fixtures ride the ConnectionMap's own seams (the
//! insert() detail install and the apply_socket_bytes() join) — the
//! exact entry shape the footer's gather() sees, no /proc walk.

use std::collections::HashMap;

use crate::ebpf::connections::{
    CgroupConnections, ConnectionMap, ProcessDetail, Proto, SocketInfo,
};
use crate::ebpf::loader::SocketBytes;
use crate::ebpf::render::rank::top_consumer;

fn sock(cookie: Option<u64>) -> SocketInfo {
    SocketInfo {
        proto: Proto::Tcp,
        remote: "10.90.170.143:443".to_string(),
        state: "ESTABLISHED",
        queued: false,
        cookie,
    }
}

fn holder(pid: u32, comm: &str, cookies: &[Option<u64>]) -> ProcessDetail {
    ProcessDetail {
        pid,
        comm: comm.to_string(),
        sockets: cookies.iter().map(|c| sock(*c)).collect(),
    }
}

fn fixture(holders: &[ProcessDetail]) -> ConnectionMap {
    let mut conns = ConnectionMap::default();
    conns.insert(
        7001,
        CgroupConnections {
            total_procs: holders.len(),
            socket_holders: holders.to_vec(),
        },
    );
    conns
}

fn joined(cookie: u64, dl: u64, ul: u64) -> (u64, SocketBytes) {
    (cookie, SocketBytes { dl, ul })
}

/// Bytes outrank socket count: the one-socket download out-ranks the
/// three-socket idle daemon the walk order would have named first.
#[test]
fn bytes_outrank_socket_count() {
    let mut conns = fixture(&[
        holder(101, "idle-daemon", &[None, None, None]),
        holder(202, "curl", &[Some(7)]),
    ]);
    conns.apply_socket_bytes(HashMap::from([joined(7, 900_000_000, 0)]));
    let top = top_consumer(&conns, 7001).expect("a holder exists");
    assert_eq!(top.comm, "curl");
}

/// A later holder with more bytes wins — the ranking is never
/// order-flattered.
#[test]
fn later_holder_with_more_bytes_wins() {
    let mut conns = fixture(&[
        holder(101, "first-small", &[Some(1)]),
        holder(202, "second-big", &[Some(2)]),
    ]);
    conns.apply_socket_bytes(HashMap::from([
        joined(1, 10_000_000, 0),
        joined(2, 800_000_000, 0),
    ]));
    let top = top_consumer(&conns, 7001).expect("a holder exists");
    assert_eq!(top.comm, "second-big");
}

/// No join figures at all: the walk order stands — the pre-dinner-6
/// shape the footer's curl pin rides exactly.
#[test]
fn no_join_keeps_walk_order() {
    let conns = fixture(&[
        holder(101, "first", &[None, Some(1)]),
        holder(202, "second", &[Some(2)]),
    ]);
    let top = top_consumer(&conns, 7001).expect("a holder exists");
    assert_eq!(top.comm, "first");
}

/// An all-zero join is the same honesty case as no join: figures
/// that say nothing reshuffle nothing.
#[test]
fn all_zero_join_keeps_walk_order() {
    let mut conns = fixture(&[
        holder(101, "first", &[Some(1), Some(2)]),
        holder(202, "second", &[Some(3)]),
    ]);
    conns.apply_socket_bytes(HashMap::from([
        joined(1, 0, 0),
        joined(2, 0, 0),
        joined(3, 0, 0),
    ]));
    let top = top_consumer(&conns, 7001).expect("a holder exists");
    assert_eq!(top.comm, "first");
}

/// Both legs count together: a holder dominant in upload only still
/// out-ranks a download-heavy smaller one.
#[test]
fn both_legs_count_together() {
    let mut conns = fixture(&[
        holder(101, "downloader", &[Some(1)]),
        holder(202, "uploader", &[Some(2)]),
    ]);
    conns.apply_socket_bytes(HashMap::from([
        joined(1, 100_000_000, 0),
        joined(2, 0, 500_000_000),
    ]));
    let top = top_consumer(&conns, 7001).expect("a holder exists");
    assert_eq!(top.comm, "uploader");
}

/// A byte tie keeps the first holder in walk order — deterministic,
/// never hash- or iteration-order flattered.
#[test]
fn tie_keeps_first_in_walk_order() {
    let mut conns = fixture(&[
        holder(101, "first", &[Some(1)]),
        holder(202, "second", &[Some(2), Some(3)]),
    ]);
    conns.apply_socket_bytes(HashMap::from([
        joined(1, 400_000_000, 0),
        joined(2, 100_000_000, 0),
        joined(3, 300_000_000, 0),
    ]));
    let top = top_consumer(&conns, 7001).expect("a holder exists");
    assert_eq!(top.comm, "first");
}

/// No socket holders: None — the footer's comm-from-label fallback
/// owns that case (unchanged).
#[test]
fn empty_holders_answer_none() {
    let conns = fixture(&[]);
    assert!(top_consumer(&conns, 7001).is_none());
}

/// An unknown cgroup is the same None — the delegate never
/// fabricates a champion.
#[test]
fn unknown_cgroup_answers_none() {
    let conns = fixture(&[holder(101, "lonely", &[Some(1)])]);
    assert!(top_consumer(&conns, 4242).is_none());
}
