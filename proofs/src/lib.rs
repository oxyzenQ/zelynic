// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

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

// night-frontier-Z17 (the interleaving theorem): the ECN debt core
// joins the included law files — the debt pair is one of the five
// interleaving verbs the two-CPU segment model drives, and the same
// #[path] include law holds (the bytes the kernel object builds).
#[path = "../../ebpf/src/ecn.rs"]
mod ecn_core;

// The two-CPU segment model over the dual-compiled primitives —
// three files, one implementation, both instruments below it (the
// vt_model precedent: the model is a law library, pinned by
// conformance). The state layer (the World, the invariant laws,
// the access twins), the segment layer (the five verbs' atomicity
// units), and the actor layer (the micro-step coroutine
// controllers — the honest scheduler's execution shape). The kani
// tier proves the single-step preservation theorems (the induction
// that carries every schedule length) plus the fidelity pins; the
// property tier hammers the same fidelity per-push and samples
// full coroutine-shaped schedules against the invariant.
#[path = "interleave_actors.rs"]
mod interleave_actors;
#[path = "interleave_model.rs"]
mod interleave_model;
#[path = "interleave_segments.rs"]
mod interleave_segments;

#[cfg(kani)]
#[path = "kani_interleave.rs"]
mod kani_interleave;

#[cfg(test)]
#[path = "interleave_laws.rs"]
mod interleave_laws;

#[cfg(test)]
#[path = "interleave_sampler.rs"]
mod interleave_sampler;

// ── The instruments (each cfg-gated; see the module docs).

#[cfg(test)]
#[path = "property_tests.rs"]
mod property_tests;

#[cfg(kani)]
#[path = "kani_cores.rs"]
mod kani_cores;

// ── night-frontier-Z10 rung 2 (D8, the no-corruption theorem): the
// emission law files ─────────────────────────────────────────────────
//
// PHILOSOPHY.md names terminal corruption the one bug class a
// monitoring tool cannot apologize its way out of. Z10's rung 2
// turns that fear's standing countermeasures (the layered reset
// contract, the byte-identical raw-frame capture) into a for-all
// law: for EVERY frame pair in the theorem's domain, applying the
// engine's emitted diff to the previous screen yields exactly the
// new frame.

// The probe seam the included engine's `use super::raw` resolves
// against — the piped-sink environment, byte-for-byte raw.rs's
// behavior on every piped run. The theorem harnesses drive the
// size-injectable cores directly and never touch either stub (the
// restatement rule the Z6 audit set, beside its SYSTEM_MAX_RATE
// precedent).
#[path = "raw_stub.rs"]
mod raw;

// The diff engine's own bytes — src/terminal/diff.rs included the
// fuzz-harness way: the SAME emission bytes the flagship binary
// runs, so a law these instruments verify is a law the renderer
// draws. The engine's #[cfg(test)] submodules (the diff pins, the
// guard pins, the ghost-cell soak) compile and run in this crate's
// cargo test lane too — the engine's standing evidence rides along.
#[path = "../../src/terminal/diff.rs"]
mod diff_core;

// The minimal VT state machine the emission law is checked against —
// one implementation, both instruments below (the standing soak
// model's semantics, restated as a law library).
#[path = "vt_model.rs"]
mod vt_model;

// The sampled tier: the pairwise emission conformance property over
// wide frames (up to 64 rows x 200 cols, SGR-bearing rows included,
// wild geometry churn across a three-frame session), plus the three
// structural laws in the same check: the absence of ESC[2J, the idle
// fast path's zero-byte verdict, and the one-batched-write-per-frame
// rule.
#[cfg(test)]
#[path = "terminal_laws.rs"]
mod terminal_laws;

// The for-all tier: the same conformance law over the bounded 4x16
// domain, machine-checked for EVERY frame pair in it (the small
// frames keep the solver's circuit inside its budget; the wide-frame
// domain is the sampled tier's, and the boundary both domains state
// is documented in vt_model.rs's scope note).
#[cfg(kani)]
#[path = "kani_terminal.rs"]
mod kani_terminal;
