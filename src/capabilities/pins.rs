// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The BPF pin lattice (night-improve-64) — split from capabilities
//! mod.rs by the NIGHT-improve-44 LOC law (a pure move, gates green
//! in between): the machine verdict [`PinState`], the pure
//! [`pin_verdict`] law, the [`collect_pin_state`] collector, and the
//! human "Pins:" line both surfaces render from.

use serde::{Deserialize, Serialize};

/// The BPF pin lattice's machine verdict (night-improve-64): the
/// shape `doctor --print-json` carries under `pins`, one object for
/// the state the human report renders as its "Pins:" line.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinState {
    /// "clean" (no pins under the directory — nothing is active),
    /// "active" (the four enforcement pins all present — BPF is
    /// live), or "stale" (partial — the recovery hint applies).
    pub state: String,
    /// The file count under the pin directory (0 when clean — the
    /// figure the human line renders beside the verdict).
    pub files: usize,
}

/// The pin directory — one name, the human printer and the JSON
/// collector read the same lattice (a split constant is how the two
/// surfaces drift).
#[cfg(feature = "ebpf")]
const PIN_DIR: &str = "/sys/fs/bpf/zelynic";

/// The pin verdict vocabulary (night-improve-64): the three states
/// the JSON contract and the human line share.
#[cfg(feature = "ebpf")]
const PIN_STATE_CLEAN: &str = "clean";
#[cfg(feature = "ebpf")]
const PIN_STATE_ACTIVE: &str = "active";
#[cfg(feature = "ebpf")]
const PIN_STATE_STALE: &str = "stale";

/// The pure verdict core (night-improve-64): file count plus the
/// four-pin lattice check decide the state. Extracted so the JSON
/// contract is unit-pinnable without a real /sys/fs/bpf (the
/// hunt-22 pure-builder pattern).
#[cfg(feature = "ebpf")]
#[must_use]
fn pin_verdict(files: usize, all_valid: bool) -> &'static str {
    if files == 0 {
        PIN_STATE_CLEAN
    } else if all_valid {
        PIN_STATE_ACTIVE
    } else {
        PIN_STATE_STALE
    }
}

/// Collect the pin lattice's verdict (night-improve-64), the pure
/// core [`print_pin_state`] renders and the doctor JSON serializes.
/// `None` when the directory exists but cannot be read — the one
/// state the report refuses to fabricate (the former human path
/// mapped an unreadable directory to "clean", a verdict nothing
/// backed; both surfaces now answer honestly, JSON by absence, the
/// line by UNKNOWN).
#[cfg(feature = "ebpf")]
pub(super) fn collect_pin_state() -> Option<PinState> {
    let pin_dir = std::path::Path::new(PIN_DIR);
    if !pin_dir.exists() {
        return Some(PinState {
            state: PIN_STATE_CLEAN.to_string(),
            files: 0,
        });
    }
    let files = std::fs::read_dir(pin_dir).ok()?.count();
    let all_valid = [
        "enforce_dl",
        "enforce_ul",
        "enforce_dl_link",
        "enforce_ul_link",
    ]
    .iter()
    .all(|p| pin_dir.join(p).exists());
    Some(PinState {
        state: pin_verdict(files, all_valid).to_string(),
        files,
    })
}

/// Print BPF pin state — checks /sys/fs/bpf/zelynic/ for active/stale pins.
///
/// night-improve-64: the line renders the SAME verdict the JSON's
/// `pins` object carries ([`collect_pin_state`]) — one collector, two
/// surfaces, no drift. The previously-reachable wordings are byte-
/// identical; the one change is honesty: a directory that exists but
/// cannot be read used to print "clean (empty directory)" — a verdict
/// nothing backed — and now prints UNKNOWN.
#[cfg(feature = "ebpf")]
pub(super) fn print_pin_state() {
    use crate::output::{ok_bold, warn_bold};

    match collect_pin_state() {
        None => println_safe!(
            "  Pins:       {} (could not read {})",
            warn_bold("UNKNOWN"),
            PIN_DIR
        ),
        Some(ps) if ps.state == PIN_STATE_ACTIVE => println_safe!(
            "  Pins:       {} ({} files, BPF active)",
            ok_bold("active"),
            ps.files
        ),
        Some(ps) if ps.state == PIN_STATE_STALE => println_safe!(
            "  Pins:       {} ({} files, partial — run 'zelynic recover')",
            warn_bold("STALE"),
            ps.files
        ),
        Some(_) if std::path::Path::new(PIN_DIR).exists() => {
            println_safe!("  Pins:       {} (empty directory)", ok_bold("clean"))
        }
        Some(_) => println_safe!("  Pins:       {} (no limits active)", ok_bold("clean")),
    }
}

#[cfg(not(feature = "ebpf"))]
pub(super) fn print_pin_state() {}

#[cfg(test)]
mod tests {
    use super::super::{BUILD_FLAVOR_FULL_LIFE, CapabilityReport, SystemInfo};
    use super::*;

    /// night-improve-64: the pin verdict vocabulary — file count and
    /// the four-pin lattice decide the state, the exact law the JSON
    /// `pins` object and the human "Pins:" line share.
    #[cfg(feature = "ebpf")]
    #[test]
    fn pin_verdict_law() {
        assert_eq!(pin_verdict(0, false), PIN_STATE_CLEAN);
        assert_eq!(pin_verdict(0, true), PIN_STATE_CLEAN);
        assert_eq!(pin_verdict(4, true), PIN_STATE_ACTIVE);
        // Partial lattice (or foreign files): stale — the recover
        // hint applies, never a fabricated active.
        assert_eq!(pin_verdict(2, false), PIN_STATE_STALE);
        assert_eq!(pin_verdict(7, false), PIN_STATE_STALE);
    }

    /// night-improve-64: a populated verdict serializes under `pins`
    /// with the state/files pair, and the report round-trips through
    /// Deserialize with the additive default (old JSON without the
    /// field still parses).
    #[test]
    fn pin_state_serializes_and_defaults() {
        let report = CapabilityReport {
            system: SystemInfo {
                kernel: "6.18.0".to_string(),
                cgroup_v2: true,
                cgroup2_mount_path: Some("/sys/fs/cgroup".to_string()),
                bpf_fs_mounted: true,
                is_root: true,
            },
            ebpf_supported: true,
            build_flavor: BUILD_FLAVOR_FULL_LIFE.to_string(),
            ebpf_lane: "source-built".to_string(),
            build: Some(crate::info::BuildInfo::collect()),
            warnings: vec![],
            pins: Some(PinState {
                state: "active".to_string(),
                files: 4,
            }),
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"pins\":{\"state\":\"active\",\"files\":4}"));
        let back: CapabilityReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pins.as_ref().unwrap().files, 4);

        // The additive rule: a document from before the field parses
        // untouched, the verdict honestly absent. The same rule holds
        // for the night-improve-66 build object: a pre-improve-66
        // doctor document parses with the block honestly absent —
        // never fabricated, never a parse failure.
        let legacy = r#"{"system":{"kernel":"6.18.0","cgroup_v2":true,"cgroup2_mount_path":null,"bpf_fs_mounted":true,"is_root":false},"ebpf_supported":true,"build_flavor":"full-life","ebpf_lane":"source-built","warnings":[]}"#;
        let old: CapabilityReport = serde_json::from_str(legacy).unwrap();
        assert!(old.pins.is_none());
        assert!(old.build.is_none());
    }
}
