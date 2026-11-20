// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! night-frontier-Z10 rung 2 (D8): the probe seam the proofs crate
//! provides so src/terminal/diff.rs can be included by #[path]
//! without dragging the raw-fd module in. The engine's `use
//! super::raw::{probe_size, winsize}` resolves against this module
//! when the crate root hosts the engine.
//!
//! The stubs reproduce the piped-sink environment the existing tests
//! and the benchmark harness already pin through the size-injectable
//! cores: `winsize()` answers None (not a TTY) and `probe_size()`
//! falls back to the classic 80x24 — byte-for-byte the behavior of
//! src/terminal/raw.rs on every piped CI run. The theorem harnesses
//! never touch either: they drive the deterministic `emit_at` /
//! `force_repaint_at` cores directly, exactly the discipline the
//! main crate's own pins carry. The real probes stay in the binary's
//! raw.rs — the lockstep is the include itself (the emission bytes
//! are the same bytes, the probe wrappers are environment, not
//! logic), stated here per the Z6 restatement rule (kani_cores.rs's
//! SYSTEM_MAX_RATE precedent).

/// The piped-sink answer: no terminal geometry (src/terminal/raw.rs
/// answers the same on every piped run — tests, CI, the harnesses).
pub(crate) fn winsize() -> Option<(u16, u16)> {
    None
}

/// The 80x24 fallback (raw.rs's non-TTY shape), unused by the
/// theorem harnesses (they pin sizes through the cores).
pub(crate) fn probe_size() -> (usize, usize) {
    (80, 24)
}
