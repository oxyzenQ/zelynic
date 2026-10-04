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

use anyhow::{Context, Result};
use std::path::Path;

use crate::ebpf::limiter::{Direction, Limiter, PolicyRaw, RateSpec, Target};

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
    pub(crate) fn from_rows(
        direction: Direction,
        rows: &[(u32, PolicyRaw)],
        names: &dyn Fn(u32) -> Option<String>,
        per_socket_flag: u32,
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
}

/// One solo accumulator leg: (name, dl rate, ul rate, per-socket).
type SoloLeg = (String, Option<u64>, Option<u64>, bool);

/// One group accumulator leg: (group id, member names, dl rate,
/// ul rate) — the shared-bucket key plus what it carried.
type GroupLeg = (u32, Vec<String>, Option<u64>, Option<u64>);

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
            let idx = groups.iter().position(|(gid, _, _, _)| *gid == e.group_id);
            match idx {
                Some(i) => {
                    let (_, names, g_dl, g_ul) = &mut groups[i];
                    if dl.is_some() {
                        *g_dl = dl;
                    }
                    if ul.is_some() {
                        *g_ul = ul;
                    }
                    if !names.contains(&e.name) {
                        names.push(e.name.clone());
                    }
                }
                None => groups.push((e.group_id, vec![e.name.clone()], dl, ul)),
            }
        } else {
            let idx = solos.iter().position(|(n, _, _, _)| *n == e.name);
            match idx {
                Some(i) => {
                    let (_, s_dl, s_ul, _) = &mut solos[i];
                    if dl.is_some() {
                        *s_dl = dl;
                    }
                    if ul.is_some() {
                        *s_ul = ul;
                    }
                }
                None => solos.push((e.name.clone(), dl, ul, e.per_socket)),
            }
        }
    }
    let mut plan: Vec<RestoreStep> = solos
        .into_iter()
        .map(|(name, dl, ul, per_socket)| RestoreStep {
            names: vec![name],
            rates: RateSpec {
                download: dl,
                upload: ul,
            },
            per_socket,
        })
        .collect();
    plan.extend(groups.into_iter().map(|(_, names, dl, ul)| RestoreStep {
        names,
        rates: RateSpec {
            download: dl,
            upload: ul,
        },
        per_socket: false,
    }));
    plan
}

// ── The verbs ──────────────────────────────────────────────────────

/// Handle `zelynic snapshot`: read the live census from both pinned
/// policy maps, join names through the identity walk, write the state
/// file atomically. The root gate matches the strict family (the
/// /var/lib lane is root's; the maps read fine on any uid but the
/// state file is a policy-state writer).
#[cfg(feature = "ebpf")]
pub fn handle_snapshot(json: bool) -> Result<()> {
    use crate::ebpf::identity::IdentityMap;
    use crate::ebpf::limiter::types::POLICY_FLAG_PER_SOCKET;

    if !nix::unistd::geteuid().is_root() {
        anyhow::bail!(
            "snapshot writes the policy state file ({STATE_FILE}) — run with sudo (the strict family's privilege ladder)"
        );
    }
    let _lock = crate::ebpf::lock::acquire()?;

    let limiter = Limiter::open_pinned(false)?;
    let dl = limiter.read_policies_public(Direction::Download)?;
    let ul = limiter.read_policies_public(Direction::Upload)?;

    // The identity join: one walk, both directions.
    let mut identity = IdentityMap::new();
    identity.refresh();
    let join = |id: u32| -> Option<String> {
        identity
            .all()
            .into_iter()
            .find(|e| e.cgroup_id == id)
            .map(|e| e.comm.clone())
    };

    let mut skip = Vec::new();
    let mut doc = SnapshotDoc::from_rows(
        Direction::Download,
        &dl,
        &join,
        POLICY_FLAG_PER_SOCKET,
        &mut skip,
    );
    let mut ul_skip = Vec::new();
    let ul_doc = SnapshotDoc::from_rows(
        Direction::Upload,
        &ul,
        &join,
        POLICY_FLAG_PER_SOCKET,
        &mut ul_skip,
    );
    doc.entries.extend(ul_doc.entries);
    skip.extend(ul_skip);
    doc.captured_at_unix = unix_now_secs();

    // The honest-capture report: census rows that no longer have a
    // running process are named on stderr (the partial-census note
    // pattern), never silently dropped.
    if !skip.is_empty() {
        let ids: Vec<String> = skip.iter().map(|id| format!("cg:{id}")).collect();
        eprintln_safe!(
            "{}",
            crate::output::warn_bold(&format!(
                "{} policy leg(s) skipped: cgroup id(s) {} no longer resolve to a process — they cannot be restored by name",
                skip.len(),
                ids.join(", ")
            ))
        );
    }

    write_state_file(&doc)?;

    if json {
        crate::output::print_json(&doc);
        return Ok(());
    }
    let names: std::collections::BTreeSet<&str> =
        doc.entries.iter().map(|e| e.name.as_str()).collect();
    println_safe!(
        "{}",
        crate::output::ok(&format!(
            "snapshot: {} policy leg(s) across {} name(s) -> {STATE_FILE}",
            doc.entries.len(),
            names.len()
        ))
    );
    Ok(())
}

/// Handle `zelynic restore`: read the state file, derive the plan,
/// apply it step by step, and report honestly (applied legs, names
/// not running yet — the strict-all best-effort contract, never an
/// abort for the fleet). Idempotent: re-running picks up late
/// starters without disturbing applied legs (an apply over an
/// existing limit is the documented supersede).
#[cfg(feature = "ebpf")]
pub fn handle_restore(json: bool) -> Result<()> {
    if !nix::unistd::geteuid().is_root() {
        anyhow::bail!(
            "restore re-applies policies from the state file — run with sudo (the strict family's privilege ladder)"
        );
    }
    let doc: SnapshotDoc = read_state_file()?;
    let plan = restore_plan(&doc);

    let _lock = crate::ebpf::lock::acquire()?;

    // The lifecycle ladder every strict-* rides: attach IS the
    // reuse/migration/cleanup contract (hunt-21), and a fresh boot
    // has no pins at all — this is the load that materializes them.
    Limiter::attach(false)?;

    let mut limiter = Limiter::open_pinned(false)?;
    let mut applied = 0usize;
    let mut unresolved: Vec<String> = Vec::new();
    for step in &plan {
        let targets: Vec<Target> = step
            .names
            .iter()
            .map(|n| Target::ProcessName(n.clone()))
            .collect();
        // apply's own return is the resolution verdict: zero legs
        // means nothing resolved (the name is not running) — the
        // step lands in the report, the fleet carries on.
        let n = if step.names.len() == 1 {
            limiter.apply_single(&targets[0], &step.rates, step.per_socket)?
        } else {
            limiter.apply_group(&targets, &step.rates)?
        };
        if n == 0 {
            unresolved.extend(step.names.iter().cloned());
        } else {
            applied += n;
        }
    }

    if json {
        crate::output::print_json(&RestoreReportJson {
            steps: plan.len(),
            applied,
            unresolved: unresolved.clone(),
        });
        return Ok(());
    }
    println_safe!(
        "{}",
        crate::output::ok(&format!(
            "restore: {applied} policy leg(s) applied across {} step(s)",
            plan.len()
        ))
    );
    if !unresolved.is_empty() {
        eprintln_safe!(
            "{}",
            crate::output::warn_bold(&format!(
                "{} name(s) not running yet (skipped — re-run restore after they start): {}",
                unresolved.len(),
                unresolved.join(", ")
            ))
        );
    }
    Ok(())
}

/// The `restore --print-json` document.
#[cfg(feature = "ebpf")]
#[derive(serde::Serialize)]
struct RestoreReportJson {
    steps: usize,
    applied: usize,
    unresolved: Vec<String>,
}

// ── The file lane (thin, honest errors) ────────────────────────────

/// Write the document to the state path: create the parent (first
/// run on a fresh install), then the atomic write (temp + rename, so
/// a crash mid-write never leaves a half-serialized policy fleet).
pub(crate) fn write_state_file(doc: &SnapshotDoc) -> Result<()> {
    let path = Path::new(STATE_FILE);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating state directory {}", parent.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_string_pretty(doc).context("serializing the snapshot document")?;
    std::fs::write(&tmp, body).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("installing {STATE_FILE}"))?;
    Ok(())
}

/// Read the state file and refuse schema drift loudly (the tag ride:
/// a newer zelynic's file names its own version; a best-guess parse
/// would apply the wrong shape's policies).
pub(crate) fn read_state_file() -> Result<SnapshotDoc> {
    let body =
        std::fs::read_to_string(STATE_FILE).with_context(|| format!("reading {STATE_FILE}"))?;
    let doc: SnapshotDoc = serde_json::from_str(&body).context("parsing the state file")?;
    if doc.schema != STATE_SCHEMA {
        anyhow::bail!(
            "state file schema v{} != expected v{STATE_SCHEMA} — a newer or older zelynic wrote it; re-run snapshot to refresh it",
            doc.schema
        );
    }
    Ok(doc)
}

/// Unix seconds, std only (the no-chrono discipline; the value is a
/// capture stamp, not a formatted clock).
pub(crate) fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// NIGHT-private-research-4: the pure-transform pins live under the
// single test/ tree (cosmostrix Pattern C), #[path]-wired exactly
// like the census pins.
#[cfg(test)]
#[cfg(feature = "ebpf")]
#[path = "../../test/commands/persist_tests.rs"]
mod persist_tests;
