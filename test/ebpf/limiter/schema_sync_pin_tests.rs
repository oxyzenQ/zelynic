// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The BPF-side anchor pin (NIGHT-upgrade-charger-core-3a), split
//! out of src/ebpf/limiter/schema.rs at the 600-line owner cap (the
//! night-recvn-audit v30 entry's own hour, the display-family split
//! lineage). The v13 bump drifted this constant from its ebpf-crate
//! twin for one full schema era — harmless at runtime (userspace
//! stamps the pinned map; the BPF const is the parity ANCHOR, never
//! executed), but the anchor existed precisely so a reader of either
//! tree could trust the number, and it lied. This pin reads the
//! anchor out of the BPF source itself and fails the build on any
//! future drift — the layout-contract discipline (size pins) applied
//! to the version contract.

/// The BPF-side parity anchor, scraped from the source file that
/// declares it (it cannot be compiled into this tree — the file
/// is aya-ebpf `#![no_std]` — but its TEXT is a contract this
/// pin owns, the same way the size pins own struct offsets).
fn bpf_schema_version() -> u32 {
    // NIGHT-improve-44: the anchor moved with the 600-line split
    // (bin/limiter.rs -> schema.rs, the doc ledger's own file) —
    // the pin follows the declaration, wherever it lives. The
    // night-recvn-audit split moves this file under test/ (the
    // #[path] wiring keeps the module rooted at schema.rs, so the
    // include still climbs from the src tree: three levels to the
    // repo root).
    let src = include_str!("../../../ebpf/src/schema.rs");
    let needle = "const SCHEMA_VERSION: u32 = ";
    let start = src
        .find(needle)
        .expect("ebpf/src/schema.rs must declare SCHEMA_VERSION");
    let rest = &src[start + needle.len()..];
    let end = rest
        .find(';')
        .expect("SCHEMA_VERSION declaration must terminate");
    rest[..end]
        .trim()
        .parse()
        .expect("SCHEMA_VERSION must be a plain u32 literal")
}

#[test]
fn bpf_anchor_matches_expected() {
    assert_eq!(
        bpf_schema_version(),
        super::SCHEMA_VERSION_EXPECTED,
        "SCHEMA_VERSION (ebpf/src/schema.rs) drifted from \
         SCHEMA_VERSION_EXPECTED (src/ebpf/limiter/schema.rs) — \
         bump BOTH together, the v13 lesson"
    );
}
