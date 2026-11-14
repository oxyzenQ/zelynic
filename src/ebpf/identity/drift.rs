// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The identity drift alarm (night-frontier-Z3, Dive 4 -1000m) — the
//! `netns://` / `iface://` lanes' contract, verified per read.
//!
//! The container lanes resolve a URI to a cgroup id ONCE, at apply
//! time, and every downstream surface rides the resolved id — the
//! documented contract ("the resolved cgroup id is the durable
//! handle, the URI is the speller"). The contract's own blind spot:
//! nothing re-checked the handle after the apply. `ip netns del x &&
//! ip netns add x` recreates the namespace (a NEW nsfs inode, a NEW
//! workload cgroup), and the pinned policy keeps enforcing against
//! the OLD cgroup id — `status` shows a live-looking row, a fresh
//! apply with the same URI silently writes a SECOND policy, and
//! kernfs inode recycling can even point the old row at an unrelated
//! cgroup. The watch pointed at a corpse, and nothing said so.
//!
//! The alarm closes the loop with one fact per lane, pinned at
//! attach and re-verified with ONE stat() per read:
//!
//! - the netns lane's identity is the handle's nsfs inode (the same
//!   number the member pids' `ns/net` links report);
//! - the iface lane's identity is the VRF device's ifindex (a
//!   recreated VRF draws a fresh index from the kernel's monotonic
//!   counter; a device that owns no ifindex at attach — the lane's
//!   cgroup-only resolution — records 0 and reads UNVERIFIABLE, the
//!   honest absence, never a false alarm).
//!
//! Storage is `/run/zelynic/identity/` (tmpfs, root-owned): one
//! line-format file per URI, keyed by the lane and name the URI
//! grammar already guarantees (no `/`, no `:`), carrying the uri,
//! lane, name, resolved cgroup id, and the identity word. Tmpfs is
//! the right volatility: the nsfs inode churns across reboots (the
//! netns lane's own doc), so the pin is runtime state, not config —
//! the same class the BPF pins themselves own, and `unpin_all_bpf`
//! sweeps the directory beside the retired persistence pair's state
//! file.
//!
//! The alarm has three mouths, all best-effort (a warning lane never
//! fails the visit that carries it):
//!
//! 1. ATTACH (`attach_identity_pin`, the apply family): the pin is
//!    written/refreshed with the fresh resolution; an existing pin
//!    whose identity differs prints the drift line — the re-apply
//!    that heals the ghost also names it.
//! 2. READ (`status_visit`, every `zelynic status` visit): each pin
//!    gets its one stat() — the handle gone is STALE-removed, a
//!    changed inode/ifindex is STALE-recreated, the wording always
//!    names the corpse and the two honest doors (re-apply, or
//!    unstrict the ghost row). A pin whose cgroup no longer holds a
//!    policy is residue, not a watch — dropped silently, the same
//!    law the census sweeps enforce one layer down.
//! 3. TEARDOWN (`drop_identity_pin_by_uri` /
//!    `drop_identity_pins_for_cgroups`, the unstrict family; the
//!    whole-directory sweep under `unpin_all_bpf`): the pin dies
//!    with the policy it describes, whichever spelling removed it.
//!
//! Pure cores (the file-name law, the line format, the verdict
//! reduction, the warning wording) are separated from the IO
//! wrappers (the dir-parameterized family, every production wrapper
//! a thin IDENTITY_DIR call) so every decision pins rootlessly in
//! test/ebpf/identity/drift_tests.rs — the tempdir-driven IO round
//! trips included.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::ebpf::identity::container::ResolvedIdentity;

/// The identity pins' runtime home (tmpfs — the volatility class the
/// nsfs inode itself owns; created on first write, swept on teardown).
pub const IDENTITY_DIR: &str = "/run/zelynic/identity";

/// The netns lane's tag (the pin file prefix and the `lane=` word).
pub const NETNS_LANE: &str = "netns";

/// The iface lane's tag.
pub const IFACE_LANE: &str = "iface";

/// One container URI's pinned identity — the facts one stat() later
/// verifies. `identity` is lane-typed: the nsfs inode (netns) or the
/// ifindex (iface), 0 recording the honest absence (an iface whose
/// device owned no ifindex at attach).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityPin {
    /// The display URI (`netns://x`, `iface://v`) — the round-trip
    /// form `ContainerRef::display` produces.
    pub uri: String,
    /// The lane tag (`netns` / `iface`).
    pub lane: String,
    /// The lane's name (the URI's own).
    pub name: String,
    /// The cgroup id the apply resolved and pinned.
    pub cgroup_id: u32,
    /// The identity word: nsfs inode or ifindex; 0 = absent at attach.
    pub identity: u64,
}

impl IdentityPin {
    /// The attach-time constructor: the lane's resolution becomes the
    /// pin — uri/lane/name ride the resolution verbatim, the cgroup
    /// id is the resolved policy root the apply just wrote.
    pub fn from_resolution(resolved: &ResolvedIdentity, cgroup_id: u32) -> Self {
        IdentityPin {
            uri: resolved.uri.clone(),
            lane: resolved.lane.to_string(),
            name: resolved.name.clone(),
            cgroup_id,
            identity: resolved.identity,
        }
    }
}

/// Pure: the pin file's name for a lane+name pair — `<lane>_<name>.pin`.
/// The URI grammar already guarantees the name carries no `/` and no
/// `:`; the re-check is the file boundary's own defense (a name that
/// could escape the directory, carry a separator, or grow unbounded
/// names no pin, and None is the caller's silent skip). The lane tag
/// must be one of the two this module owns — a foreign lane's pin is
/// not this alarm's to write.
pub fn pin_file_name(lane: &str, name: &str) -> Option<String> {
    if lane != NETNS_LANE && lane != IFACE_LANE {
        return None;
    }
    if name.is_empty()
        || name.len() > 64
        || name.contains('/')
        || name.contains(':')
        || name.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return None;
    }
    Some(format!("{lane}_{name}.pin"))
}

/// Pure: the pin file's line form. Five `key=value` lines, fixed
/// order — the format is the parse's own contract, no serde, no
/// dependencies (the estate's hand-written wire discipline).
pub fn serialize_pin(pin: &IdentityPin) -> String {
    format!(
        "uri={}\nlane={}\nname={}\ncgroup={}\nidentity={}\n",
        pin.uri, pin.lane, pin.name, pin.cgroup_id, pin.identity
    )
}

/// Pure: parse one pin file's text — every line a `key=value`, all
/// five keys required exactly once, the numbers numeric. Anything
/// else is not a pin this module wrote (a foreign or corrupt file)
/// and parses to None — the reader skips it, never fails the visit.
pub fn parse_pin(text: &str) -> Option<IdentityPin> {
    let mut uri = None;
    let mut lane = None;
    let mut name = None;
    let mut cgroup = None;
    let mut identity = None;
    for line in text.lines() {
        let (key, value) = line.split_once('=')?;
        match key {
            "uri" if uri.is_none() => uri = Some(value.to_string()),
            "lane" if lane.is_none() => lane = Some(value.to_string()),
            "name" if name.is_none() => name = Some(value.to_string()),
            "cgroup" if cgroup.is_none() => cgroup = value.parse::<u32>().ok(),
            "identity" if identity.is_none() => identity = value.parse::<u64>().ok(),
            _ => return None,
        }
    }
    Some(IdentityPin {
        uri: uri?,
        lane: lane?,
        name: name?,
        cgroup_id: cgroup?,
        identity: identity?,
    })
}

/// The drift verdict — one stat()'s reduction, pure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriftVerdict {
    /// The identity source answers with the pinned word — the watch
    /// points where it pointed at attach.
    Live,
    /// The identity source is gone (the handle unlinked, the device
    /// removed) while the policy row stands — the corpse case.
    Removed,
    /// The source answers with a DIFFERENT word — the namespace or
    /// VRF was recreated; the policy row enforces against the old
    /// identity's cgroup.
    Recreated { current: u64 },
    /// The pin recorded no identity (an iface with no device at
    /// attach) and the source is still absent — nothing to verify,
    /// honestly silent.
    Unverifiable,
}

/// Pure: the verdict for a pinned word and the source's current
/// answer. `None` (source absent) reads Removed against a recorded
/// identity and Unverifiable against the 0 sentinel; a `Some` that
/// differs reads Recreated — including the 0-pin case, where an
/// identity APPEARING is a change the operator should see (the
/// device came back as something new).
pub fn drift_verdict(pinned: u64, current: Option<u64>) -> DriftVerdict {
    match (pinned, current) {
        (_, None) if pinned == 0 => DriftVerdict::Unverifiable,
        (_, None) => DriftVerdict::Removed,
        (0, Some(current)) => DriftVerdict::Recreated { current },
        (p, Some(c)) if p == c => DriftVerdict::Live,
        (_, Some(current)) => DriftVerdict::Recreated { current },
    }
}

/// Pure: the lane's noun in the warning wording — the thing the
/// corpse sentence names.
pub fn lane_noun(lane: &str) -> &'static str {
    if lane == NETNS_LANE {
        "namespace"
    } else {
        "VRF domain"
    }
}

/// Pure: the warning lines a drifted pin prints — the STALE finding
/// (what drifted, which policy row watches the corpse) and the tip
/// (the two honest doors: re-apply to follow the new identity, or
/// unstrict the ghost row). Live and Unverifiable print nothing.
pub fn warning_lines(pin: &IdentityPin, verdict: &DriftVerdict) -> Vec<String> {
    let noun = lane_noun(&pin.lane);
    match verdict {
        DriftVerdict::Removed => vec![
            format!(
                "STALE: {} is gone — policy cg:{} still enforces against the dead {} \
                 (the watch points at a corpse)",
                pin.uri, pin.cgroup_id, noun
            ),
            format!(
                "  tip: re-apply to pin the new {} (zelynic s {} <rate>), \
                 or remove the ghost row: zelynic u cg:{}",
                noun, pin.uri, pin.cgroup_id
            ),
        ],
        DriftVerdict::Recreated { current } => vec![
            format!(
                "STALE: {} was recreated (identity {} -> {}) — policy cg:{} enforces \
                 against the OLD {}",
                pin.uri, pin.identity, current, pin.cgroup_id, noun
            ),
            format!(
                "  tip: re-apply to follow the new workload (zelynic s {} <rate>), \
                 or remove the ghost row: zelynic u cg:{}",
                pin.uri, pin.cgroup_id
            ),
        ],
        DriftVerdict::Live | DriftVerdict::Unverifiable => Vec::new(),
    }
}

// ━━ the IO wrappers — every one dir-parameterized, the production
// wrapper a thin IDENTITY_DIR call (the unpin_dir discipline) ━━

fn identity_dir() -> PathBuf {
    PathBuf::from(IDENTITY_DIR)
}

fn pin_path_in(dir: &Path, pin: &IdentityPin) -> Option<PathBuf> {
    pin_file_name(&pin.lane, &pin.name).map(|f| dir.join(f))
}

/// The netns lane's identity source: the handle's nsfs inode, the
/// same two-path probe the resolver owns (`/run/netns` first, the
/// legacy `/var/run/netns` second). Absent everywhere is None.
pub fn current_netns_identity(name: &str) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    for base in ["/run/netns", "/var/run/netns"] {
        let handle = Path::new(base).join(name);
        if let Ok(meta) = std::fs::metadata(&handle) {
            return Some(meta.ino());
        }
    }
    None
}

/// The iface lane's identity source: the VRF device's ifindex, the
/// kernel's own word at `/sys/class/net/<name>/ifindex`. Absent
/// device or unreadable index is None.
pub fn current_iface_identity(name: &str) -> Option<u64> {
    std::fs::read_to_string(Path::new("/sys/class/net").join(name).join("ifindex"))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
}

/// The lane's current identity word — the ONE stat() (or one sysfs
/// read, its sysfs twin) the read-side contract promises.
pub fn current_identity(lane: &str, name: &str) -> Option<u64> {
    if lane == NETNS_LANE {
        current_netns_identity(name)
    } else {
        current_iface_identity(name)
    }
}

/// Write (or refresh) one pin file in `dir` — the attach half. The
/// file is the five-line form, created/truncated atomically enough
/// for a root-owned tmpfs directory the CLI alone populates.
pub fn write_identity_pin_in(dir: &Path, pin: &IdentityPin) -> Result<()> {
    let Some(path) = pin_path_in(dir, pin) else {
        return Ok(()); // the name law refused it — nothing to pin
    };
    std::fs::create_dir_all(dir)?;
    std::fs::write(&path, serialize_pin(pin))?;
    Ok(())
}

/// Read every parsable pin in `dir` — unparsable or foreign files
/// are skipped, a missing directory is the honest empty.
pub fn read_identity_pins_in(dir: &Path) -> Vec<IdentityPin> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            let text = std::fs::read_to_string(e.path()).ok()?;
            parse_pin(&text)
        })
        .collect()
}

/// Drop every pin in `dir` whose cgroup id is in `ids` — the
/// unstrict family's by-cgroup sweep (any spelling that resolves to
/// the cgroup drops the pin). Returns the files removed.
pub fn drop_identity_pins_for_cgroups_in(dir: &Path, ids: &[u32]) -> usize {
    let live: HashSet<u32> = ids.iter().copied().collect();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let Ok(text) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        if let Some(pin) = parse_pin(&text)
            && live.contains(&pin.cgroup_id)
            && std::fs::remove_file(entry.path()).is_ok()
        {
            removed += 1;
        }
    }
    removed
}

/// Drop every pin in `dir` whose uri matches — the unstrict family's
/// by-URI sweep (the recreated-namespace case: the pin's cgroup id
/// differs from the current resolution, so only the URI matches).
/// Returns the files removed.
pub fn drop_identity_pins_for_uri_in(dir: &Path, uri: &str) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let Ok(text) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        if let Some(pin) = parse_pin(&text)
            && pin.uri == uri
            && std::fs::remove_file(entry.path()).is_ok()
        {
            removed += 1;
        }
    }
    removed
}

/// Remove `dir` whole — the full-teardown sweep (`unpin_all_bpf`'s
/// law: when the BPF estate goes, every pin describing it is a
/// ghost). Returns the files removed (the directory's unlink rides
/// remove_dir_all).
pub fn sweep_identity_dir_in(dir: &Path) -> usize {
    let count = read_identity_pins_in(dir).len();
    if count > 0 {
        let _ = std::fs::remove_dir_all(dir);
    }
    count
}

// ━━ the production wrappers — IDENTITY_DIR call sites ━━

/// ATTACH mouth: write/refresh the pin for a fresh resolution, and
/// when a pin for the same URI already recorded a DIFFERENT identity,
/// print the drift line first — the re-apply that heals the ghost
/// also names it. Best-effort by contract: a warning lane never
/// fails the apply that carries it.
pub fn attach_identity_pin(pin: &IdentityPin) {
    let dir = identity_dir();
    for existing in read_identity_pins_in(&dir) {
        if existing.uri == pin.uri && existing.identity != pin.identity {
            crate::output::eprintln_warn_labeled(&format!(
                "STALE: {} changed identity since the last apply ({} -> {}) — the \
                 previous row cg:{} may watch a corpse; this apply re-pins",
                pin.uri, existing.identity, pin.identity, existing.cgroup_id
            ));
            break;
        }
    }
    if let Err(e) = write_identity_pin_in(&dir, pin) {
        crate::output::verbose::vlog!("drift", "identity pin for {} not written: {e}", pin.uri);
    }
}

/// READ mouth: one stat() per pin, the verdicts returned (the
/// printer is the caller's — the tests read the verdicts, the CLI
/// prints them). A pin whose cgroup no longer holds a policy is
/// residue, not a watch: dropped silently, the census sweeps' own
/// law. Returns the drifted pins with their verdicts, in file order.
pub fn verify_identity_pins_in(
    dir: &Path,
    live_cgroups: &HashSet<u32>,
) -> Vec<(IdentityPin, DriftVerdict)> {
    let mut drifted = Vec::new();
    for pin in read_identity_pins_in(dir) {
        if !live_cgroups.contains(&pin.cgroup_id) {
            if let Some(path) = pin_path_in(dir, &pin) {
                let _ = std::fs::remove_file(path);
            }
            continue;
        }
        let verdict = drift_verdict(pin.identity, current_identity(&pin.lane, &pin.name));
        if !matches!(verdict, DriftVerdict::Live | DriftVerdict::Unverifiable) {
            drifted.push((pin, verdict));
        }
    }
    drifted
}

/// The status visit's production wrapper — the READ mouth's print
/// half. Warnings ride stderr (the frame and the JSON contract on
/// stdout stay byte-stable; the diagnostics lane is where every
/// other warning in the estate prints).
pub fn status_visit(live_cgroups: &HashSet<u32>) {
    for (pin, verdict) in verify_identity_pins_in(&identity_dir(), live_cgroups) {
        for line in warning_lines(&pin, &verdict) {
            crate::output::eprintln_warn_labeled(&line);
        }
    }
}

/// TEARDOWN mouth, by cgroup ids — the unstrict family's sweep.
pub fn drop_identity_pins_for_cgroups(ids: &[u32]) {
    drop_identity_pins_for_cgroups_in(&identity_dir(), ids);
}

/// TEARDOWN mouth, by URI — the recreated-identity case.
pub fn drop_identity_pin_by_uri(uri: &str) {
    drop_identity_pins_for_uri_in(&identity_dir(), uri);
}

/// TEARDOWN mouth, whole-directory — `unpin_all_bpf`'s sweep.
pub fn sweep_identity_dir() {
    sweep_identity_dir_in(&identity_dir());
}

// NIGHT-hunt-17: pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the sibling lanes'.
#[cfg(test)]
#[path = "../../../test/ebpf/identity/drift_tests.rs"]
mod drift_tests;
