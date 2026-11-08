// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! Unit pins for the name-first row-order law (night-ux-6) — kept in
//! the repo's single test/ tree (cosmostrix Pattern C) and
//! #[path]-wired from display_order.rs. One sort key owns every
//! name-and-cgroup-ID surface: case-insensitive process name (the
//! DISPLAYED name — the identity map's enriched comm, the string the
//! surface prints), then cgroup ID ascending within one name; the
//! human table and the `--print-json` document of each surface read
//! the same sorted rows, so the two outputs can never disagree.

use super::*;

// ── the list-apps discovery order ───────────────────────────────────────────

/// The row-order pin (night-ux-6): case-insensitive name first,
/// cgroup ID ascending within one name — the exact order the human
/// table prints and the `--print-json` document carries. The fixture
/// reproduces the owner's live find: the old key was ASCII
/// case-sensitive on the name alone, so DiscoverNotifier ('D' < 'a')
/// rendered before agent, and same-name rows (alacritty) stayed in
/// /proc walk order, which is not stable across runs.
#[cfg(feature = "ebpf")]
#[test]
fn discovery_rows_sort_name_insensitive_then_cgroup_id() {
    use crate::ebpf::identity::ProcessIdentity;
    let rows = [
        ProcessIdentity {
            cgroup_id: 11,
            uid: 1000,
            comm: "alacritty".to_string(),
        },
        ProcessIdentity {
            cgroup_id: 2,
            uid: 1000,
            comm: "DiscoverNotifier".to_string(),
        },
        ProcessIdentity {
            cgroup_id: 3,
            uid: 1000,
            comm: "alacritty".to_string(),
        },
        ProcessIdentity {
            cgroup_id: 5,
            uid: 1000,
            comm: "Brave".to_string(),
        },
        ProcessIdentity {
            cgroup_id: 1,
            uid: 1000,
            comm: "agent".to_string(),
        },
        ProcessIdentity {
            cgroup_id: 4,
            uid: 0,
            comm: "brave".to_string(),
        },
    ];
    let mut entries: Vec<&ProcessIdentity> = rows.iter().collect();
    sort_discovery_entries(&mut entries);
    let seen: Vec<String> = entries
        .iter()
        .map(|e| format!("{}:{}", e.comm, e.cgroup_id))
        .collect();
    assert_eq!(
        seen,
        vec![
            "agent:1",
            "alacritty:3",
            "alacritty:11",
            "brave:4",
            "Brave:5",
            "DiscoverNotifier:2",
        ],
        "the discovery order is case-insensitive name, then cgroup ID ascending within one name"
    );
}

// ── the status order ────────────────────────────────────────────────────────

/// The status row-order pin (night-ux-6): the human table and the
/// `--print-json` limits array share ONE name-first sort law — the
/// identity map's enriched comm (the name the `cg:<id> (<name>)`
/// label prints) case-insensitive, then the cgroup ID ascending
/// within one name; a cgroup the identity walk did not resolve sorts
/// as the empty name, before any named row. The fixture reproduces
/// the owner's live find: python3 (3532/3577/3622) rendered before
/// brave (30501) because the old order was cgroup-ID ascending only
/// — the policy maps carry no name, so the sort must ride the
/// identity join both surfaces already make.
#[cfg(feature = "ebpf")]
#[test]
fn status_rows_sort_name_insensitive_then_cgroup_id() {
    use crate::ebpf::identity::ProcessIdentity;
    use crate::ebpf::limiter::types::BracketPair;
    fn row(cgroup_id: u32) -> DisplayData {
        DisplayData {
            window: None,
            download: BracketPair::UNSET,
            upload: BracketPair::UNSET,
            cgroup_id,
            dl_bps: Some(100_000),
            ul_bps: None,
            dl_per_socket: false,
            ul_per_socket: false,
            packets_allowed: 0,
            packets_dropped: 0,
            bytes_allowed: 0,
            bytes_dropped: 0,
            ce_marked_packets: 0,
            ce_marked_bytes: 0,
            bytes_saved_by_edt: 0,
            bytes_saved_by_recwn: 0,
            bytes_saved_by_ecn: 0,
        }
    }

    let mut identity = IdentityMap::new();
    identity.insert(ProcessIdentity {
        cgroup_id: 3532,
        uid: 1000,
        comm: "python3".to_string(),
    });
    identity.insert(ProcessIdentity {
        cgroup_id: 3577,
        uid: 1000,
        comm: "python3".to_string(),
    });
    identity.insert(ProcessIdentity {
        cgroup_id: 30501,
        uid: 1000,
        comm: "brave".to_string(),
    });
    identity.insert(ProcessIdentity {
        cgroup_id: 9,
        uid: 1000,
        comm: "BRAVE".to_string(),
    });

    // Input order is the policy maps' own (cgroup-ID ascending only):
    // python3 pair, then brave, then the unresolved cgroup 777.
    let mut data = vec![row(3532), row(30501), row(777), row(9), row(3577)];
    sort_status_rows(&mut data, &identity);
    let seen: Vec<String> = data.iter().map(|d| d.cgroup_id.to_string()).collect();
    assert_eq!(
        seen,
        vec!["777", "9", "30501", "3532", "3577"],
        "the status order is unnamed cgroups first, then case-insensitive name with \
         cgroup ID ascending within one name"
    );
}
