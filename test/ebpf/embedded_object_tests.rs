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
//!
//! NIGHT-hunt-30 added the alignment pins: the `object` crate's
//! ELF64 parser reads its structures straight out of the embedded
//! buffer and requires an 8-byte-aligned buffer ADDRESS. A plain
//! align-1 `include_bytes!` static gets that only by linker luck —
//! the owner host lost that luck on every build while the dev
//! container kept winning it (the artifact was healthy all along).
//! The pins below hold the AlignedElf embedding to its contract in
//! every binary the suite runs in.

use crate::ebpf::embedded::misalignment;
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

/// NIGHT-hunt-30: the embedded limiter bytes must sit at an
/// 8-byte-aligned address — the `object` crate's Pod casts require
/// it, and the AlignedElf wrapper (src/ebpf/embedded.rs) is the
/// guarantee under test. A failure here is a build regression in the
/// wrapper, not a test environment quirk.
#[test]
fn embedded_limiter_object_is_alignment_safe() {
    assert_eq!(
        misalignment(LIMITER_ELF),
        None,
        "the embedded limiter object address is not 8-byte aligned — the \
         ELF64 parser will reject these healthy bytes (NIGHT-hunt-30)"
    );
}

/// NIGHT-hunt-30: the observer twin of the alignment pin above.
#[test]
fn embedded_observer_object_is_alignment_safe() {
    assert_eq!(
        misalignment(OBSERVER_ELF),
        None,
        "the embedded observer object address is not 8-byte aligned — the \
         ELF64 parser will reject these healthy bytes (NIGHT-hunt-30)"
    );
}

/// NIGHT-hunt-30: the pure detector behind the load-path preflights
/// must mirror the Pod-cast alignment law exactly — `None` at every
/// 8-aligned address, `Some(ptr % 8)` one byte past each. A heap
/// `Vec<u8>` is the fixture: malloc guarantees at least the 8-byte
/// alignment the detector assumes for its base.
#[test]
fn misalignment_detector_matches_the_pod_cast_law() {
    let data = LIMITER_ELF.to_vec();
    assert_eq!(misalignment(&data), None, "heap base must be 8-aligned");
    for shift in 1..8usize {
        let shifted = &data[shift..];
        assert_eq!(
            misalignment(shifted),
            Some(shift),
            "a slice starting {shift} bytes past an 8-aligned base must report {shift}"
        );
    }
}

/// NIGHT-dinner-6's E1 rider: the observer's four maps ride the LRU
/// lane in the embedded bytes — BPF_MAP_TYPE_LRU_HASH, pinned by
/// parse. aya-obj 0.3.0 is the exact parser crate compiled into
/// aya 0.14.0 (NIGHT-depthtest moved the pairing with the loader
/// wave; the phase-2 harness lane,
/// docs/PURE_RUST_EVALUATION.md), and `Object::parse` is
/// syscall-free — the pin runs on any host, no privileges, no
/// kernel. Before the rider the two counter maps were plain HASH:
/// on a host churning past 4096 distinct cgroups in one observe
/// session the FIRST 4096 pinned their slots and later cgroups
/// counted nothing (USAGE limitation 11). The pin keeps the lane
/// contract executable: a regression back to HASH — or a socket map
/// losing its LRU — fails here, in the battery, not in the field
/// where only a dense host would ever notice.
#[test]
fn embedded_observer_maps_ride_the_lru_lane() {
    let parsed =
        aya_obj::Object::parse(OBSERVER_ELF).expect("the embedded observer object must parse");
    // BPF_MAP_TYPE_LRU_HASH (include/uapi/linux/bpf.h). The literal
    // is deliberate: aya-obj's generated enum is arch-gated while
    // the uapi value is stable ABI every arch agrees on.
    const BPF_MAP_TYPE_LRU_HASH: u32 = 9;
    // (name, key, value, capacity) — the geometry each family ships:
    // cgroup counters 4-byte key / 16-byte CgroupStats (boost-34's
    // size pin), socket counters 8/8, all at the 4096 lane.
    let lru_geometry = [
        ("cgroup_counters", 4u32, 16u32, 4096u32),
        ("cgroup_counters_ingress", 4, 16, 4096),
        ("socket_counters", 8, 8, 4096),
        ("socket_counters_ingress", 8, 8, 4096),
    ];
    for (name, key, value, entries) in lru_geometry {
        let map = parsed
            .maps
            .get(name)
            .unwrap_or_else(|| panic!("map {name} missing from the observer object"));
        assert_eq!(
            map.map_type(),
            BPF_MAP_TYPE_LRU_HASH,
            "{name} must declare BPF_MAP_TYPE_LRU_HASH"
        );
        assert_eq!(map.key_size(), key, "{name} key size");
        assert_eq!(map.value_size(), value, "{name} value size");
        assert_eq!(map.max_entries(), entries, "{name} capacity");
    }
}
