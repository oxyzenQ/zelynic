// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The diagnostic trace lane — the `-v/--verbose` flag's one door
//! (night-dragon-maintenance-xenric-1, the zejtron verbose law
//! ported to zelynic's output group).
//!
//! The contract is the pipe law: stdout holds ONLY the report bytes,
//! every `[tag]` trace rides stderr through [`eprintln_safe!`], and
//! the trace tier is the grammar grey — the same tier the clap
//! surface paints its passive tips with, so a trace never reads as
//! a verdict (verdict words ride the ok/error/warn tiers).
//!
//! Design: one static AtomicBool, set once by main straight after
//! the CLI parse, read everywhere through [`enabled`]. The [`vlog`]
//! macro guards on the flag BEFORE any format machinery runs, so a
//! silent run pays one relaxed atomic load per call site and never
//! allocates — and a future call site cannot format-then-guard by
//! accident, because the guard lives inside the door instead of
//! beside it. The `-v` flag stops threading a bool through every
//! handler signature: the lane is process-global state, exactly like
//! the forced color capability it sits beside in this module group.
//!
//! Logs are factual and boring by law: one line, one bracketed tag
//! naming the subsystem, no emojis, stderr only.

use std::sync::atomic::{AtomicBool, Ordering};

/// The verbose switch. Relaxed ordering is sufficient: the flag is
/// written once at startup, before any command surface runs, and the
/// only contract is eventual visibility within one process lifetime.
static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Arm the diagnostic lane. Called exactly once, by main, straight
/// after the CLI parse — every later call site only reads.
pub fn init(enabled: bool) {
    VERBOSE.store(enabled, Ordering::Relaxed);
}

/// True when `-v/--verbose` armed the diagnostic lane. The one read
/// door for the sites whose verbose value is control flow (attaching
/// an observer before the TUI opens) rather than a trace line.
pub fn enabled() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// The one logging door: print `[tag] message` grey on stderr when
/// the lane is armed, do nothing (and format nothing) when it is
/// not. Call sites use the [`vlog`] macro, which guards on
/// [`enabled`] before evaluating its format arguments.
pub fn log(tag: &str, msg: &str) {
    if enabled() {
        eprintln_safe!("{}", crate::output::grey(&format!("[{tag}] {msg}")));
    }
}

/// The diagnostic trace macro: `vlog!("limiter", "loading {} bytes", n)`
/// prints `[limiter] loading N bytes` grey on stderr under `-v`, and
/// costs one atomic load when the lane is silent. Arguments are NOT
/// evaluated when the lane is off (the guard sits in front of the
/// format machinery), so logging never allocates on a quiet run.
// The macros ride the ebpf gate like the call sites they serve:
// every reader lives under the ebpf graph (src/ebpf/ and the
// ebpf-gated command handlers), so the dormant test flavor — the
// module compiles there for its flag pins, which read the
// functions, never the macros — would otherwise hold two defined
// but never-read macros, a hard error under CI's -D warnings
// (unused_macros). Gating the definitions keeps the documented
// law true in every build flavor: a featureless build never arms
// what it never reads.
#[cfg(feature = "ebpf")]
macro_rules! vlog {
    ($tag:expr, $($arg:tt)*) => {
        if $crate::output::verbose::enabled() {
            $crate::output::verbose::log($tag, &format!($($arg)*));
        }
    };
}

#[cfg(feature = "ebpf")]
pub(crate) use vlog;

/// The pre-rendered line door: `vlog_line!(trace::kernel_line(...))`
/// prints a line that owns its own tag (the unit-pinned `trace::`
/// shapes, the multi-line apply-tail groups) grey on stderr under
/// `-v`. Two shapes: one bare expression (the expression sits inside
/// the guard, so a silent run never builds the line), or a literal
/// template plus arguments (the format machinery also sits inside
/// the guard).
#[cfg(feature = "ebpf")]
macro_rules! vlog_line {
    ($line:expr) => {
        if $crate::output::verbose::enabled() {
            let line = $line;
            eprintln_safe!("{}", crate::output::grey(&line));
        }
    };
    ($fmt:literal, $($arg:tt)*) => {
        if $crate::output::verbose::enabled() {
            let line = format!($fmt, $($arg)*);
            eprintln_safe!("{}", crate::output::grey(&line));
        }
    };
}

#[cfg(feature = "ebpf")]
pub(crate) use vlog_line;

// The verbose pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired like every output-layer pin. The test
// process's stderr is piped, so the door's inert lane is the pinned
// behavior — the armed lane needs a terminal-adjacent probe and
// stays a live-behavior contract (the flag round-trip is the byte
// contract here).
#[cfg(test)]
#[path = "../../test/output/verbose_tests.rs"]
mod self_tests;
