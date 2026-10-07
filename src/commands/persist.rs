// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The restore lane (NIGHT-private-research-4's persistence ask,
//! reworked by NIGHT-improve-55) — the surviving half of the
//! "GitOps for bandwidth" pair. The DUMP verb (`snapshot`) is
//! retired: the owner's live-test verdict was that remembering to
//! dump before a reboot is a workflow the operator's own script
//! already owns, and the dump added nothing to it. What survives is
//! the APPLY direction, zero background presence:
//!
//!   /var/lib/zelynic/limits.json — the operator's hand-maintained
//!                        desired state (kept in git, edited by hand:
//!                        who is limited, which direction, what rate,
//!                        grouping, per-socket)
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
//! zelynic ships the verb, not a daemon.
//!
//! WHAT WRITES THE FILE (stated honestly): since NIGHT-improve-55
//! the operator does — the dump verb is gone. The document pins the
//! POLICY, not the bucket state — tokens, fractions, DRR carries,
//! and ECN debt are runtime transients the fresh buckets re-derive
//! (a restore is a fresh apply, the same shape every strict-* ride;
//! the burst re-derives from the rate's default law, which is also
//! the only value the CLI surface can write, so a hand-written and
//! a restored policy agree). The stats ledger starts at zero — it
//! measures THIS boot's enforcement, which is the truth a status
//! reader wants.
//!
//! Everything map-touching is root-gated like the strict family;
//! the pure transform (entries -> the restore plan) is
//! test-pinned rootlessly under test/commands/.

use anyhow::{bail, Result};

use crate::ebpf::limiter::{
    window_persist_to_spec, BracketPair, BracketSpec, DuringSpec, RateSpec, WindowPersist,
};

/// Where the desired-state file lives. A system lane, not a user
/// lane: the policies are root's to write (the strict family's
/// privilege ladder), and /var/lib is the distro-blessed home for
/// reboot-persistent service state (XDG_RUNTIME_DIR is per-boot by
/// contract — exactly the lifetime this file must outlive).
pub(crate) const STATE_FILE: &str = "/var/lib/zelynic/limits.json";

/// The state file's schema tag. Bumped when the entry shape changes
/// (the same one-time contract the pinned map schema rides, at the
/// file's own scale: an unknown tag refuses the restore with the
/// tag in the error, never a best-guess parse).
pub(crate) const STATE_SCHEMA: u32 = 1;

// ── The document (serde both ways: the operator's hand-written
// file and the restore's --print-json report share one JSON
// discipline) ──────────────────────────────────────────────

/// One serialized policy leg: a name, a direction, and the policy
/// the operator wants it to carry.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct SnapshotEntry {
    /// The process name to limit (the stable key across reboots;
    /// cgroup IDs are not — the restore resolves the name fresh at
    /// its own instant).
    pub name: String,
    /// "download" or "upload" — the leg's direction (the full word:
    /// the file is a scripting surface, not a map-name fragment).
    pub direction: String,
    /// The policy's rate in bits per second.
    pub rate_bps: u64,
    /// The strict group-lane bucket the row belongs to (0 = solo).
    /// The ID itself is per-apply randomness — the restore hands its
    /// members ONE NEW shared bucket — but WITHIN the document it is
    /// the grouping key that re-joins the members of one group.
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
    /// The file's last-edit stamp in unix seconds (std only — the
    /// no-chrono discipline; a reader formats it their own way).
    /// Informational: the restore never branches on it.
    pub captured_at_unix: u64,
    /// Every policy leg, the operator's own order (a dump-era file
    /// keeps its capture order — the plan's collapse laws are
    /// order-independent, so both read identically).
    pub entries: Vec<SnapshotEntry>,
}

/// One restore plan step, derived purely from the merged entries:
/// one single-lane or one group-lane strict apply, with its resolved
/// rate legs and the per-socket flag (the flag rides the individual
/// lane only — the same constraint the CLI surface carries).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RestoreStep {
    /// The single member (single lane) or the member list
    /// (group lane, one shared bucket).
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
    /// The row's guarantee bracket (improve-40, schema v24;
    /// improve-40-b the per-direction shape): one pair per
    /// direction, each read off its own leg's entries — the restore
    /// hands it back to the apply family verbatim (the validation
    /// ladder already accepted it once; a value the restore would
    /// reject means the document was hand-edited, and the apply's
    /// own refusal is the honest verdict for that).
    pub bracket: BracketSpec,
}

/// One solo accumulator leg: (name, dl rate, ul rate, per-socket,
/// window form, the per-direction bracket pairs — download's then
/// upload's).
type SoloLeg = (
    String,
    Option<u64>,
    Option<u64>,
    bool,
    Option<WindowPersist>,
    BracketPair,
    BracketPair,
);

/// One group accumulator leg: (group id, member names, dl rate,
/// ul rate, window form, the per-direction bracket pairs) — the
/// shared-bucket key plus what it carried.
type GroupLeg = (
    u32,
    Vec<String>,
    Option<u64>,
    Option<u64>,
    Option<WindowPersist>,
    BracketPair,
    BracketPair,
);

/// Derive the restore plan from the document's entries: solo rows
/// collapse per-name into one single-lane step (both directions in
/// one RateSpec), grouped rows collapse per member-set into one
/// group-lane step. Pure — the caller resolves names and applies.
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
        // improve-40-b: each leg's entry carries ITS direction's
        // pair — the entry is one direction's row, read verbatim.
        let leg_pair = BracketPair {
            floor_bps: e.floor_bps,
            ceil_bps: e.ceil_bps,
        };
        if e.group_id != 0 {
            let idx = groups.iter().position(|(gid, ..)| *gid == e.group_id);
            match idx {
                Some(i) => {
                    let (_, names, g_dl, g_ul, g_during, g_dl_pair, g_ul_pair) = &mut groups[i];
                    if dl.is_some() {
                        *g_dl = dl;
                        // improve-40-b: the download leg's own pair,
                        // first-write-wins (a torn census is the only
                        // disagreement shape, the window lane's own
                        // posture).
                        *g_dl_pair = leg_pair;
                    }
                    if ul.is_some() {
                        *g_ul = ul;
                        *g_ul_pair = leg_pair;
                    }
                    if g_during.is_none() {
                        *g_during = e.during.clone();
                    }
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
                    if dl.is_some() {
                        leg_pair
                    } else {
                        BracketPair::UNSET
                    },
                    if ul.is_some() {
                        leg_pair
                    } else {
                        BracketPair::UNSET
                    },
                )),
            }
        } else {
            let idx = solos.iter().position(|(n, ..)| *n == e.name);
            match idx {
                Some(i) => {
                    let (_, s_dl, s_ul, _, s_during, s_dl_pair, s_ul_pair) = &mut solos[i];
                    if dl.is_some() {
                        *s_dl = dl;
                        // improve-40-b: the solo twin of the group
                        // lane's per-direction first-write-wins.
                        *s_dl_pair = leg_pair;
                    }
                    if ul.is_some() {
                        *s_ul = ul;
                        *s_ul_pair = leg_pair;
                    }
                    if s_during.is_none() {
                        *s_during = e.during.clone();
                    }
                }
                None => solos.push((
                    e.name.clone(),
                    dl,
                    ul,
                    e.per_socket,
                    e.during.clone(),
                    if dl.is_some() {
                        leg_pair
                    } else {
                        BracketPair::UNSET
                    },
                    if ul.is_some() {
                        leg_pair
                    } else {
                        BracketPair::UNSET
                    },
                )),
            }
        }
    }
    let mut plan: Vec<RestoreStep> = solos
        .into_iter()
        .map(
            |(name, dl, ul, per_socket, during, dl_pair, ul_pair)| RestoreStep {
                names: vec![name],
                rates: RateSpec {
                    download: dl,
                    upload: ul,
                },
                per_socket,
                during: during.as_ref().and_then(window_persist_to_spec),
                bracket: BracketSpec {
                    download: dl_pair,
                    upload: ul_pair,
                },
            },
        )
        .collect();
    plan.extend(
        groups
            .into_iter()
            .map(|(_, names, dl, ul, during, dl_pair, ul_pair)| RestoreStep {
                names,
                rates: RateSpec {
                    download: dl,
                    upload: ul,
                },
                per_socket: false,
                during: during.as_ref().and_then(window_persist_to_spec),
                bracket: BracketSpec {
                    download: dl_pair,
                    upload: ul_pair,
                },
            }),
    );
    plan
}

// ━━ The window-kind gate (the restore's honesty rung) ━━

/// Validate every `during` form the document carries BEFORE the
/// plan shapes it: each must name a kind the restore family can
/// re-translate — "span" or "daily". An entry whose kind is
/// anything else (hand-edited, corrupted) REFUSES the restore
/// naming the row, the unknown-TAG posture one entry over —
/// because the plan's `and_then(window_persist_to_spec)` would
/// otherwise swallow the unreadable window into "no window" and
/// apply the row WITHOUT its lifetime: an auto-expire promise
/// silently converted into a forever-limit, exactly the
/// inversion the design brief forbids ("a restored row must
/// never convert auto-expires into forever"). Pure; pinned in
/// persist_tests.rs.
pub(crate) fn validate_persisted_windows(doc: &SnapshotDoc) -> Result<()> {
    for e in &doc.entries {
        if let Some(form) = &e.during {
            if form.kind != "span" && form.kind != "daily" {
                bail!(
                    "state file entry '{}' carries a --during window of kind \
                     '{}' — neither 'span' nor 'daily'. Refusing the restore: an \
                     unreadable auto-expire promise must never restore as a \
                     forever-limit (fix or drop the entry, then re-run restore)",
                    e.name,
                    form.kind
                );
            }
        }
    }
    Ok(())
}

// NIGHT-private-research-4: the pure-transform pins live under the
// single test/ tree (cosmostrix Pattern C), #[path]-wired exactly
// like the census pins.
#[cfg(test)]
#[cfg(feature = "ebpf")]
#[path = "../../test/commands/persist_tests.rs"]
mod persist_tests;

// night-during-7: the WINDOW family's pins (the wall-form census
// join, the plan's window round-trip, the window-kind gate) — the
// LOC cap's split when the gate pin pushed persist_tests past 500
// (the during_map discipline, one test tree over).
#[cfg(test)]
#[cfg(feature = "ebpf")]
#[path = "../../test/commands/persist_window_tests.rs"]
mod persist_window_tests;
