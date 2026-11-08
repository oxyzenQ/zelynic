// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The name-first row-order law (night-ux-6): ONE sort key for every
//! surface that prints a row carrying a name and a cgroup ID — the
//! process name case-insensitive, then the cgroup ID ascending
//! within one name. Before this law each surface improvised: the
//! list-apps rows sorted ASCII case-sensitive on the name alone
//! (DiscoverNotifier rendered before agent because 'D' < 'a', and
//! same-name rows kept the /proc walk order, which is not stable
//! across runs), and the status rows kept the policy maps'
//! cgroup-ID-ascending order (python3 rendered before brave). Both
//! callers join the DISPLAYED name — the identity map's enriched
//! comm (NIGHT-engrave-7), exactly the string the surface prints —
//! so the visible order always matches the visible name, and each
//! surface sorts before BOTH its outputs (the human table and the
//! `--print-json` document) read the rows: one truth.

use super::display::DisplayData;
use crate::ebpf::identity::{IdentityMap, ProcessIdentity};

/// The discovery rows' order (`zelynic list-apps`, human table and
/// JSON document alike): sort in place on the DISPLAYED name —
/// `comm`, which already carries the enrichment and the 24-column
/// display cap the table prints — case-insensitive, then the cgroup
/// ID ascending within one name. Pure (no `/proc` walk), so the
/// order is unit-pinnable on a fixture.
pub(crate) fn sort_discovery_entries(entries: &mut [&ProcessIdentity]) {
    entries.sort_by(|a, b| {
        a.comm
            .to_lowercase()
            .cmp(&b.comm.to_lowercase())
            .then(a.cgroup_id.cmp(&b.cgroup_id))
    });
}

/// The status rows' order (the human table in `print_status` and the
/// `--print-json` limits array in `status_json`): the identity map's
/// comm — the name the `cg:<id> (<name>)` label prints —
/// case-insensitive, then the cgroup ID ascending within one name; a
/// cgroup the identity walk did not resolve sorts as the empty name,
/// before any named row. The key sorts on the NAME, not the composed
/// label string: the `cg:<id>` prefix would dominate a string
/// compare and produce ID-lexicographic order, never name-first.
pub(crate) fn sort_status_rows(data: &mut [DisplayData], identity: &IdentityMap) {
    data.sort_by(|a, b| {
        let name_a = identity
            .get(a.cgroup_id)
            .map(|i| i.comm.to_lowercase())
            .unwrap_or_default();
        let name_b = identity
            .get(b.cgroup_id)
            .map(|i| i.comm.to_lowercase())
            .unwrap_or_default();
        name_a.cmp(&name_b).then(a.cgroup_id.cmp(&b.cgroup_id))
    });
}

// night-ux-6: the order pins live beside the law — the single test/
// tree wiring (cosmostrix Pattern C), #[path]-ed like the display
// and identity pins.
#[cfg(test)]
#[path = "../../test/ebpf/display_order_tests.rs"]
mod tests;
