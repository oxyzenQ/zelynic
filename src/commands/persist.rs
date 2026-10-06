// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The snapshot/restore lane (NIGHT-private-research-4's
//! owner-approved persistence ask) — "GitOps for bandwidth" without
//! a daemon. The pins under /sys/fs/bpf/zelynic already survive
//! process exit (the whole point of LIBBPF_PIN_BY_NAME); what they
//! cannot survive is a REBOOT — bpffs starts empty, and with it every
//! policy. This module closes that gap with two one-shot verbs and
//! zero background presence:
//!
//!   `zelynic snapshot` — serialize the live policy census to the
//!                        state file (who is limited, which
//!                        direction, what rate, grouping, per-socket)
//!   `zelynic restore`  — re-apply every entry from the state file
//!                        (idempotent, safe to re-run, honest about
//!                        names that no longer resolve)
//!
//! THE HONESTY CONTRACT (the strict-all precedent, one lane over):
//! a reboot changes cgroup IDs, so the file stores NAMES, and a
//! restore best-efforts the fleet — an app that is not running yet
//! (containers start late) is named in the report as skipped, never
//! silently missed, and never an abort for the rest. Re-running
//! restore after the late starter boots picks it up — the systemd
//! oneshot + path/timer pairing an operator wires is their choice;
//! zelynic ships the two verbs, not a daemon.
//!
//! WHAT RIDES ALONG (stated honestly): the snapshot pins the
//! POLICY, not the bucket state — tokens, fractions, DRR carries,
//! and ECN debt are runtime transients the fresh buckets re-derive
//! (a restore is a fresh apply, the same shape every strict-* ride;
//! the burst re-derives from the rate's default law, which is also
//! the only value the CLI surface can write, so the captured and the
//! restored policies agree). The stats ledger starts at zero — it
//! measures THIS boot's enforcement, which is the truth a status
//! reader wants.
//!
//! Everything map-touching is root-gated like the strict family;
//! the pure transforms (rows -> entries, entries -> the restore
//! plan) are test-pinned rootlessly under test/commands/.

use crate::ebpf::limiter::{
    window_persist_form, window_persist_to_spec, Direction, DuringSpec, PolicyRaw, RateSpec,
    WindowPersist,
};

/// Where the serialized policy state lives. A system lane, not a
/// user lane: the policies are root's to write (the strict family's
/// privilege ladder), and /var/lib is the distro-blessed home for
/// reboot-persistent service state (XDG_RUNTIME_DIR is per-boot by
/// contract — exactly the lifetime this file must outlive).
pub(crate) const STATE_FILE: &str = "/var/lib/zelynic/limits.json";

/// The state file's schema tag. Bumped when the entry shape changes
/// (the same one-time contract the pinned map schema rides, at the
/// file's own scale: an unknown tag refuses the restore with the
/// tag in the error, never a best-guess parse).
pub(crate) const STATE_SCHEMA: u32 = 1;

// ── The document (serde both ways: the file is the same JSON the
// --print-json surface emits, one writer discipline) ────────────────

/// One serialized policy leg: a name, a direction, and the policy
/// the map carried for it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct SnapshotEntry {
    /// The process name the /proc walk resolved at capture time (the
    /// stable key across reboots; cgroup IDs are not).
    pub name: String,
    /// "download" or "upload" — the pinned map the row was read from
    /// (`Direction::label()`, the full word: the file is a scripting
    /// surface, not a map-name fragment).
    pub direction: String,
    /// The policy's rate in bits per second.
    pub rate_bps: u64,
    /// The strict-multi group the row belongs to (the map's group_id;
    /// 0 = solo). The ID itself is per-apply randomness — the restore
    /// hands its members ONE NEW shared bucket — but WITHIN the
    /// document it is the grouping key that re-joins the members a
    /// census read apart.
    pub group_id: u32,
    /// True when the policy carried the per-socket flag (every
    /// connection its own budget at the policy rate).
    pub per_socket: bool,
    /// The row's --during window in its WALL-clock persistence form
    /// (night-during, schema v23), absent when the row carried none.
    /// Both leg entries of one row carry the same form; the restore
    /// plan collapses them. The wall form is the cross-reboot shape —
    /// a monotonic deadline would reset with the boot.
    pub during: Option<WindowPersist>,
    /// The row's guarantee floor (improve-40, schema v24): the
    /// per-subprocess minimum both leg entries carry (the one-flag
    /// law — the plan collapses the pair). 0 = unset. serde-defaulted
    /// so a v23 file (the pair absent) restores as the zero sentinel,
    /// the fail-open posture.
    #[serde(default)]
    pub floor_bps: u64,
    /// The row's guarantee ceiling (improve-40, schema v24): the
    /// per-subprocess maximum. 0 = unset, serde-defaulted for the
    /// v23 file.
    #[serde(default)]
    pub ceil_bps: u64,
}

/// The state file's root document.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct SnapshotDoc {
    /// The schema tag; a restore refuses a mismatching tag outright.
    pub schema: u32,
    /// Capture time in unix seconds (std only — the no-chrono
    /// discipline; a reader formats it their own way).
    pub captured_at_unix: u64,
    /// Every policy leg, capture order.
    pub entries: Vec<SnapshotEntry>,
}

impl SnapshotDoc {
    /// Build one direction's half of the document from the census
    /// rows plus the cgroup-id -> name join the identity walk
    /// produced. Pure: the caller owns the map reads and the walk;
    /// this function only shapes — and a census row whose cgroup no
    /// longer has a name lands in the skip list it returns through,
    /// honestly NAMED, never serialized as a bare id the restore
    /// would misresolve.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_rows(
        direction: Direction,
        rows: &[(u32, PolicyRaw)],
        names: &dyn Fn(u32) -> Option<String>,
        per_socket_flag: u32,
        windows: &[(u32, crate::ebpf::limiter::PolicyWindowRaw)],
        wall_now_ns: u64,
        mono_now_ns: u64,
        skip: &mut Vec<u32>,
    ) -> SnapshotDoc {
        let mut entries = Vec::with_capacity(rows.len());
        for (cgroup_id, raw) in rows {
            match names(*cgroup_id) {
                Some(name) => entries.push(SnapshotEntry {
                    name,
                    direction: direction.label().to_string(),
                    rate_bps: raw.rate_bps,
                    group_id: raw.group_id,
                    per_socket: raw.flags & per_socket_flag != 0,
                    // improve-40 (schema v24): the bracket rides the
                    // row verbatim — both legs carry the same pair,
                    // the plan collapses it.
                    floor_bps: raw.floor_bps,
                    ceil_bps: raw.ceil_bps,
                    during: windows
                        .iter()
                        .find(|(id, _)| id == cgroup_id)
                        .map(|(_, w)| window_persist_form(w, wall_now_ns, mono_now_ns)),
                }),
                None => skip.push(*cgroup_id),
            }
        }
        SnapshotDoc {
            schema: STATE_SCHEMA,
            captured_at_unix: 0,
            entries,
        }
    }
}

/// One restore plan step, derived purely from the merged entries:
/// one strict-single or one strict-multi apply, with its resolved
/// rate legs and the per-socket flag (the flag rides the individual
/// lane only — the same constraint the CLI surface carries).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RestoreStep {
    /// The single member (strict-single) or the member list
    /// (strict-multi, one shared bucket).
    pub names: Vec<String>,
    /// The rate legs the entries carried (None on a direction the
    /// member set never had — the apply's unset-direction removal
    /// keeps the restore faithful to a one-direction policy).
    pub rates: RateSpec,
    /// The per-socket flag (individual lane only).
    pub per_socket: bool,
    /// The row's --during window (night-during): the wall-form entry
    /// back into the spec the apply family takes — a fresh bridge
    /// re-translates it at the restore instant. None when the rows
    /// carried no window; a member set whose entries disagree keeps
    /// the FIRST form the census read (the map itself guarantees one
    /// row per root, so disagreement means a torn census).
    pub during: Option<DuringSpec>,
    /// The row's guarantee bracket (improve-40, schema v24): both
    /// legs carried the same pair, the one-flag law — the restore
    /// hands it back to the apply family verbatim (the validation
    /// ladder already accepted it once; a value the restore would
    /// reject means the document was hand-edited, and the apply's
    /// own refusal is the honest verdict for that).
    pub floor_bps: u64,
    pub ceil_bps: u64,
}

/// One solo accumulator leg: (name, dl rate, ul rate, per-socket,
/// window form, guarantee floor, guarantee ceiling).
type SoloLeg = (
    String,
    Option<u64>,
    Option<u64>,
    bool,
    Option<WindowPersist>,
    u64,
    u64,
);

/// One group accumulator leg: (group id, member names, dl rate,
/// ul rate, window form) — the shared-bucket key plus what it
/// carried.
type GroupLeg = (
    u32,
    Vec<String>,
    Option<u64>,
    Option<u64>,
    Option<WindowPersist>,
    u64,
    u64,
);

/// Derive the restore plan from the document's entries: solo rows
/// collapse per-name into one strict-single step (both directions in
/// one RateSpec), grouped rows collapse per member-set into one
/// strict-multi step. Pure — the caller resolves names and applies.
pub(crate) fn restore_plan(doc: &SnapshotDoc) -> Vec<RestoreStep> {
    // Solo legs: name -> (dl rate, ul rate, per_socket).
    let mut solos: Vec<SoloLeg> = Vec::new();
    // Grouped legs: group_id -> (member names, dl rate, ul rate). The
    // ID is the shared-bucket key the map carried — the one link a
    // census read apart keeps between members that share a bucket.
    let mut groups: Vec<GroupLeg> = Vec::new();
    for e in &doc.entries {
        let dl = (e.direction == "download").then_some(e.rate_bps);
        let ul = (e.direction == "upload").then_some(e.rate_bps);
        if e.group_id != 0 {
            let idx = groups.iter().position(|(gid, ..)| *gid == e.group_id);
            match idx {
                Some(i) => {
                    let (_, names, g_dl, g_ul, g_during, g_floor, g_ceil) = &mut groups[i];
                    if dl.is_some() {
                        *g_dl = dl;
                    }
                    if ul.is_some() {
                        *g_ul = ul;
                    }
                    if g_during.is_none() {
                        *g_during = e.during.clone();
                    }
                    // improve-40 (schema v24): both legs carry the
                    // same pair — first-write-wins is verbatim either
                    // way (a torn census is the only disagreement
                    // shape, and the window lane's own posture).
                    *g_floor = e.floor_bps;
                    *g_ceil = e.ceil_bps;
                    if !names.contains(&e.name) {
                        names.push(e.name.clone());
                    }
                }
                None => groups.push((
                    e.group_id,
                    vec![e.name.clone()],
                    dl,
                    ul,
                    e.during.clone(),
                    e.floor_bps,
                    e.ceil_bps,
                )),
            }
        } else {
            let idx = solos.iter().position(|(n, ..)| *n == e.name);
            match idx {
                Some(i) => {
                    let (_, s_dl, s_ul, _, s_during, s_floor, s_ceil) = &mut solos[i];
                    if dl.is_some() {
                        *s_dl = dl;
                    }
                    if ul.is_some() {
                        *s_ul = ul;
                    }
                    if s_during.is_none() {
                        *s_during = e.during.clone();
                    }
                    // improve-40 (schema v24): the solo twin of the
                    // group lane's first-write-wins.
                    *s_floor = e.floor_bps;
                    *s_ceil = e.ceil_bps;
                }
                None => solos.push((
                    e.name.clone(),
                    dl,
                    ul,
                    e.per_socket,
                    e.during.clone(),
                    e.floor_bps,
                    e.ceil_bps,
                )),
            }
        }
    }
    let mut plan: Vec<RestoreStep> = solos
        .into_iter()
        .map(
            |(name, dl, ul, per_socket, during, floor_bps, ceil_bps)| RestoreStep {
                names: vec![name],
                rates: RateSpec {
                    download: dl,
                    upload: ul,
                },
                per_socket,
                during: during.as_ref().and_then(window_persist_to_spec),
                floor_bps,
                ceil_bps,
            },
        )
        .collect();
    plan.extend(
        groups.into_iter().map(
            |(_, names, dl, ul, during, floor_bps, ceil_bps)| RestoreStep {
                names,
                rates: RateSpec {
                    download: dl,
                    upload: ul,
                },
                per_socket: false,
                during: during.as_ref().and_then(window_persist_to_spec),
                floor_bps,
                ceil_bps,
            },
        ),
    );
    plan
}

// NIGHT-private-research-4: the pure-transform pins live under the
// single test/ tree (cosmostrix Pattern C), #[path]-wired exactly
// like the census pins.
#[cfg(test)]
#[cfg(feature = "ebpf")]
#[path = "../../test/commands/persist_tests.rs"]
mod persist_tests;
