// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The compositional determinism pins (night-depth-hardening-1): the
//! same snapshot must render BYTE-IDENTICAL text and JSON on every
//! supported distro (5.15+), run to run. The hazard class: output
//! rows whose tie order rode a non-contractual walk order (the
//! kernel's /proc hash enumeration, the fd readdir order) could swap
//! across boots, rehashes, and distros even with identical state.
//! The census's two display laws (`sort_sockets_for_display`,
//! `sort_holders_for_display`) are the total orders that close it —
//! these pins exercise THE laws the walk applies (extracted fns, not
//! seam copies), then prove the composition absorbs input-order
//! variance end to end: census → traffic focus → text report → JSON
//! document. All fixtures, never the host; rootless like the rest of
//! the render pins.

use super::*;
use std::collections::HashMap;

use crate::ebpf::connections::{
    CgroupConnections, ConnectionMap, ProcessDetail, SocketInfo, sort_holders_for_display,
    sort_sockets_for_display,
};
use crate::ebpf::identity::depth::CgroupResources;
use crate::ebpf::render::depth_json::depth_doc_json;
use crate::ebpf::render::depth_traffic::{traffic_focus, traffic_section_lines};

/// The window_secs every traffic fixture rides (any fixed value —
/// the rate math is pure).
const WINDOW_SECS: u64 = 10;

/// One tie-class socket: ESTABLISHED, not queued — the exact row the
/// old walk-order tie left unpinned. Inode is the discriminator.
fn tied_socket(inode: u64) -> SocketInfo {
    SocketInfo {
        inode,
        proto: crate::ebpf::connections::Proto::Tcp,
        remote: "142.250.191.78:443".to_string(),
        state: "ESTABLISHED",
        queued: false,
        cookie: None,
        deep: None,
    }
}

fn tied_holder(pid: u32, sockets: Vec<SocketInfo>) -> ProcessDetail {
    ProcessDetail {
        pid,
        comm: format!("app-{pid}"),
        sockets,
    }
}

fn census(holders: Vec<ProcessDetail>) -> CgroupConnections {
    CgroupConnections {
        total_procs: holders.len(),
        socket_holders: holders,
    }
}

fn policy(rate_bps: u64) -> Option<PolicyRaw> {
    Some(PolicyRaw {
        rate_bps,
        burst_bytes: rate_bps,
        floor_bps: 0,
        ceil_bps: 0,
        group_id: 0,
        flags: 0,
    })
}

fn report_with_census(conns: CgroupConnections) -> DepthReport {
    DepthReport {
        target: "cg:1234".to_string(),
        cgroup_id: 1234,
        name: "cat-test".to_string(),
        depth: CgroupDepth {
            rel_path: Some("/cat-test".to_string()),
            resources: CgroupResources::default(),
            procs: Vec::new(),
        },
        enforcement: Enforcement::Limited {
            download: policy(12_000_000),
            upload: None,
        },
        enforcement_stats: None,
        conns: Some(conns),
        traffic: None,
        traffic_note: None,
        histogram: None,
        lanes: None,
    }
}

/// The census map fixture: one cgroup, the given holders — through
/// the same cfg(test) seam the frame benchmark uses.
fn census_map(conns: CgroupConnections) -> ConnectionMap {
    let mut map = ConnectionMap::new();
    map.insert(1234, conns);
    map
}

/// The walk's own two laws, in the order the walk applies them — the
/// fixture's stand-in for `refresh()`: holders first, then each
/// holder's sockets. The pins that feed traffic_focus or the JSON
/// document run BOTH (a census half-ordered would diverge — the
/// endpoints ride the sockets' order untouched).
fn apply_census_order(conns: &mut CgroupConnections) {
    sort_holders_for_display(&mut conns.socket_holders);
    for h in &mut conns.socket_holders {
        sort_sockets_for_display(&mut h.sockets);
    }
}

#[test]
fn socket_order_converges_under_permutation() {
    let a = vec![tied_socket(9), tied_socket(4), tied_socket(2)];
    let b = vec![tied_socket(2), tied_socket(4), tied_socket(9)];
    let mut reference = a.clone();
    let mut permuted = b.clone();
    sort_sockets_for_display(&mut reference);
    sort_sockets_for_display(&mut permuted);
    let inodes_of = |v: &[SocketInfo]| v.iter().map(|s| s.inode).collect::<Vec<u64>>();
    assert_eq!(
        inodes_of(&reference),
        inodes_of(&permuted),
        "the inode tie must absorb input order"
    );
    // The tie itself is pinned to the inode, ascending.
    assert_eq!(
        inodes_of(&reference),
        vec![2, 4, 9],
        "established ties ride the inode"
    );
}

#[test]
fn holder_order_converges_under_permutation() {
    let h1 = tied_holder(20, vec![tied_socket(9), tied_socket(4)]);
    let h2 = tied_holder(7, vec![tied_socket(11), tied_socket(3)]);
    let mut one = vec![h1.clone(), h2.clone()];
    let mut two = vec![h2.clone(), h1.clone()];
    sort_holders_for_display(&mut one);
    sort_holders_for_display(&mut two);
    let shape = |v: &[ProcessDetail]| {
        v.iter()
            .map(|h| {
                (
                    h.pid,
                    h.sockets.iter().map(|s| s.inode).collect::<Vec<u64>>(),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        shape(&one),
        shape(&two),
        "the pid tie must absorb input order"
    );
    // Same socket count, neither queued: pid ascending breaks it.
    assert_eq!(one[0].pid, 7);
    assert_eq!(one[1].pid, 20);
}

#[test]
fn census_converges_under_permutation() {
    let sockets = || vec![tied_socket(9), tied_socket(4)];
    let mut straight = census(vec![tied_holder(20, sockets()), tied_holder(7, sockets())]);
    let mut flipped = census(vec![
        tied_holder(7, {
            let mut s = sockets();
            s.reverse();
            s
        }),
        tied_holder(20, {
            let mut s = sockets();
            s.reverse();
            s
        }),
    ]);
    apply_census_order(&mut straight);
    apply_census_order(&mut flipped);
    let shape = |v: &[ProcessDetail]| {
        v.iter()
            .map(|h| {
                (
                    h.pid,
                    h.sockets.iter().map(|s| s.inode).collect::<Vec<u64>>(),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        shape(&straight.socket_holders),
        shape(&flipped.socket_holders)
    );
}

#[test]
fn traffic_focus_converges_under_census_permutation() {
    let sockets = || vec![tied_socket(9), tied_socket(4)];
    let mut map_a = census_map(census(vec![tied_holder(20, sockets())]));
    let mut map_b = census_map(census(vec![tied_holder(20, {
        let mut s = sockets();
        s.reverse();
        s
    })]));
    apply_census_order(map_a.get_mut(1234).unwrap());
    apply_census_order(map_b.get_mut(1234).unwrap());
    // The empty byte join makes every endpoint byteless — the exact
    // all-tie class the stable sorts leave to the census row order.
    let focus_a = traffic_focus(
        1234,
        WINDOW_SECS,
        &[],
        Some(&map_a),
        &HashMap::new(),
        &HashMap::new(),
    );
    let focus_b = traffic_focus(
        1234,
        WINDOW_SECS,
        &[],
        Some(&map_b),
        &HashMap::new(),
        &HashMap::new(),
    );
    assert_eq!(
        traffic_section_lines(&focus_a),
        traffic_section_lines(&focus_b),
        "the traffic section must not see the census permutation"
    );
    assert_eq!(format!("{focus_a:?}"), format!("{focus_b:?}"));
}

#[test]
fn depth_report_lines_are_byte_identical_across_renders() {
    let report = report_with_census(census(vec![tied_holder(
        20,
        vec![tied_socket(9), tied_socket(4)],
    )]));
    let reports = vec![report.clone(), report];
    let one = depth_report_lines(&reports, 96);
    let two = depth_report_lines(&reports, 96);
    assert_eq!(one, two, "the same snapshot must render the same bytes");
}

#[test]
fn depth_report_lines_converge_under_census_permutation() {
    let mut straight = report_with_census(census(vec![tied_holder(
        20,
        vec![tied_socket(9), tied_socket(4)],
    )]));
    let mut flipped = report_with_census(census(vec![tied_holder(
        20,
        vec![tied_socket(4), tied_socket(9)],
    )]));
    apply_census_order(straight.conns.as_mut().unwrap());
    apply_census_order(flipped.conns.as_mut().unwrap());
    let one = depth_report_lines(&[straight], 96);
    let two = depth_report_lines(&[flipped], 96);
    assert_eq!(one, two, "the text report must absorb the input order");
}

#[test]
fn depth_doc_json_converges_under_census_permutation() {
    let mut straight = report_with_census(census(vec![tied_holder(
        20,
        vec![tied_socket(9), tied_socket(4)],
    )]));
    let mut flipped = report_with_census(census(vec![tied_holder(
        20,
        vec![tied_socket(4), tied_socket(9)],
    )]));
    apply_census_order(straight.conns.as_mut().unwrap());
    apply_census_order(flipped.conns.as_mut().unwrap());
    let one = depth_doc_json(&[straight], &[], None).to_json();
    let two = depth_doc_json(&[flipped], &[], None).to_json();
    assert_eq!(one, two, "the JSON document must absorb the input order");
}
