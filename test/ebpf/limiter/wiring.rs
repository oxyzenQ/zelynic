// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The rootless test-tree wiring for the limiter's pure cores,
//! split out of src/ebpf/limiter/mod.rs (NIGHT-private-research-4's
//! LOC-cap split: mod.rs rode the 500-line owner cap at exactly 500
//! and the ECN lane's sixth wiring crossed it, so the whole family
//! moved here — the parse/format LOC-cap precedent one module over,
//! and into the test tree where the gate's own discipline says
//! wiring belongs). The depth is preserved exactly: every test
//! file's `super::` and `super::super::` cross-reference resolved
//! against the limiter mod before and resolves against THIS module
//! now — the same child-of-parent distance either way, so no test
//! text moves. The paths below are same-directory relatives (the
//! wirings and the files they wire are neighbors in this tree).
//!
//! The blocks are verbatim moves — each carries its own task note,
//! and the mods stay private to this module (their `pub(super)`
//! inner views widen to exactly this tree, the same descendant
//! visibility the limiter mod gave them).

// NIGHT-depthbore-1: ebpf/src/math.rs — the same file the BPF object
// builds — #[path]-wired here, pinned by test/ebpf/limiter/math_tests.rs.
#[cfg(test)]
#[path = "math_tests.rs"]
mod math_tests;

// NIGHT-boost-38: the SMP invariants, pinned by math_smp_tests.rs.
#[cfg(test)]
#[path = "math_smp_tests.rs"]
mod math_smp_tests;

// NIGHT-private-research-2 (AMMSP): the resolution core compiles
// from ebpf/src/ammsp.rs the same way, pinned by ammsp_tests.rs.
#[cfg(test)]
#[path = "ammsp_tests.rs"]
mod ammsp_tests;

// NIGHT-upgrade-charger-core-1c: the DRR quantum core compiles from
// ebpf/src/drr.rs the same way, pinned rootlessly by
// test/ebpf/limiter/drr_tests.rs.
#[cfg(test)]
#[path = "drr_tests.rs"]
mod drr_tests;

// NIGHT-private-research-4 (ECN-first policing): the debt core
// compiles from ebpf/src/ecn.rs the same way, pinned rootlessly by
// test/ebpf/limiter/ecn_tests.rs.
#[cfg(test)]
#[path = "ecn_tests.rs"]
mod ecn_tests;
