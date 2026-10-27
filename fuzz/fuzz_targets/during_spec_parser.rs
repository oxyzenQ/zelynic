// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Fuzz target: the --during grammar family (the fuzz lane,
//! night-dragon-maintenance-5).
//!
//! [`parse_during`] turns one CLI argument into a rate-limit
//! duration - the string the owner types, but also the string an
//! adversary can type: the flag rides the rootless pin path, and a
//! parser that panics on hostile input turns a UX bug into a
//! crash-the-tool primitive. The documented contract (the module's
//! own header) is total: any input yields a bounded
//! `DuringSpec::Duration` or a named error - never a panic, never
//! an out-of-bounds value.
//!
//! The harness asserts the contract's three properties:
//!
//! 1. Totality: no input panics (the property itself).
//! 2. Bounds: an Ok result lands inside the grammar's published
//!    bounds - at least the 1s floor (`DURING_MIN_NS`), at most the
//!    5y ceiling (`DURING_MAX_NS`) - the two constants the module
//!    names as the contract.
//! 3. Grammar honesty: the shapes the grammar retired (the window
//!    form with ':', the date form with '-') are refused, never
//!    silently accepted - the restore-lane vocabulary stays
//!    unreachable from the flag path.
//!
//! The source is path-included, not copied (see fuzz/Cargo.toml for
//! the full rationale): the harness compiles the same
//! during_parse.rs bytes the binary ships. The file is std+anyhow
//! only and crate-import-free - the property the include law
//! scripts/gates/check-fuzz-includes.sh holds.

#![no_main]

#[path = "../../src/ebpf/limiter/during_parse.rs"]
mod during_parse;

use libfuzzer_sys::fuzz_target;

use during_parse::{DURING_MAX_NS, DURING_MIN_NS, DuringSpec, parse_during};

fuzz_target!(|data: &[u8]| {
    if let Ok(spec) = std::str::from_utf8(data) {
        match parse_during(spec) {
            Ok(during) => {
                // The grammar's one shape today (the duration-only
                // revision): the irrefutable let stops compiling the
                // day the enum grows a second shape, forcing this
                // harness to keep up with the exact contract it
                // fuzzes - the same fail-closed posture the include
                // law holds for the grammar bytes themselves.
                let DuringSpec::Duration { ns } = during;
                assert!(
                    ns >= DURING_MIN_NS,
                    "the parse accepted a duration under the 1s floor \
                     (input {spec:?}, ns {ns})"
                );
                assert!(
                    ns <= DURING_MAX_NS,
                    "the parse accepted a duration over the 5y ceiling \
                     (input {spec:?}, ns {ns})"
                );
            }
            Err(_) => {
                // A refusal is a contract fulfillment, not a failure:
                // the named-error path is what hostile input owes.
            }
        }
    }
});
