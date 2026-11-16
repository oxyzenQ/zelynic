// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! night-frontier-Z6 (D1, the proven datapath): the proof-harness
//! package's root. The pure cores compile here from their own files
//! (#[path] wirings — the fuzz harnesses' include law), and the two
//! instruments attach as cfg-gated modules:
//!
//!  * `property_tests` — #[cfg(test)]: proptest exhaustion of the
//!    cores' laws on stable (the standing lane: `cargo test`).
//!  * `kani_cores` — #[cfg(kani)]: the totality theorems, for all
//!    inputs within each harness's domain (`cargo kani --lib`).
//!
//! The loom instrument was examined and returned a signed census NO
//! (no location-backed atomics — the manifest comment carries the
//! record); the manifest and the Z6 audit hold the verdict.
//!
//! The cores are law libraries: each instrument uses the slice of
//! each core its theorem names, so dead-code silence is the honest
//! crate posture here (every unused fn is pinned by another tree).
#![allow(dead_code)]

// ── The included law files (the SAME bytes the kernel object
// builds — ebpf/src's core-only discipline, wired the fuzz-harness
// way). One inclusion per file per binary; the harness modules
// consume these, never their own copies.

#[path = "../../ebpf/src/math.rs"]
mod math_core;

#[path = "../../ebpf/src/drr.rs"]
mod drr_core;

#[path = "../../ebpf/src/mmspa.rs"]
mod mmspa_core;

#[path = "../../ebpf/src/rate_ring.rs"]
mod rate_ring_core;

#[path = "../../ebpf/src/during.rs"]
mod during_core;

#[path = "../../ebpf/src/hist.rs"]
mod hist_core;

#[path = "../../ebpf/src/quic.rs"]
mod quic_core;

// ── The instruments (each cfg-gated; see the module docs).

#[cfg(test)]
#[path = "property_tests.rs"]
mod property_tests;

#[cfg(kani)]
#[path = "kani_cores.rs"]
mod kani_cores;
