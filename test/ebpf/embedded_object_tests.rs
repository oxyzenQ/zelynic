// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Unit pins for the embedded pure-Rust eBPF objects
//! (NIGHT-improve-1 phase 3). Kept in the repo's single test/ tree
//! (NIGHT-hunt-17, cosmostrix Pattern C) and #[path]-wired from
//! src/ebpf/loader.rs.
//!
//! Both objects ride inside the binary via include_bytes! from the
//! build.rs OUT_DIR staging. These pins hold the cheap-but-early
//! part of the load contract: the bytes that reach aya's
//! `Ebpf::load` / `EbpfLoader::load` at runtime are non-empty ELF
//! files at compile time — a truncated or wrong-format artifact
//! fails here (and was already failed by build.rs's ELF-magic check
//! at staging time) instead of surfacing as a mysterious load error
//! on a user host. The full parse-level contract (sections, map
//! geometry, pins, license) was verified by the phase-2 scratch
//! harness and is recorded in docs/PURE_RUST_EVALUATION.md.

use crate::ebpf::limiter::LIMITER_ELF;

use super::OBSERVER_ELF;

fn is_elf(bytes: &[u8]) -> bool {
    bytes.len() > 4 && bytes[0] == 0x7f && bytes[1] == b'E' && bytes[2] == b'L' && bytes[3] == b'F'
}

/// The observer object is a real, non-empty ELF — the exact bytes
/// `Ebpf::load` will see on every host zelynic runs on.
#[test]
fn embedded_observer_object_is_elf() {
    assert!(
        is_elf(OBSERVER_ELF),
        "embedded observer object failed the ELF magic check ({} bytes)",
        OBSERVER_ELF.len()
    );
}

/// The limiter object likewise — the exact bytes `EbpfLoader::load`
/// will see, carrying the nine PIN_BY_NAME maps the persistence
/// design rests on.
#[test]
fn embedded_limiter_object_is_elf() {
    assert!(
        is_elf(LIMITER_ELF),
        "embedded limiter object failed the ELF magic check ({} bytes)",
        LIMITER_ELF.len()
    );
}
