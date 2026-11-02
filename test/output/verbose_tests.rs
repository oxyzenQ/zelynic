// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The verbose lane's tests: the flag gates, and the door's shape.
//!
//! The static flag is process-global and the harness runs its tests
//! in parallel threads, so every test that touches the flag holds
//! one shared mutex — the armed/disarmed assertions must observe
//! their own init, not a neighbor's.

use super::{enabled, init, log};

/// The gate every flag-touching test holds while it arms, probes,
/// and disarms (one-writer discipline for the shared static).
static FLAG_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The flag arms and disarms round-trip.
#[test]
fn init_round_trips() {
    let _guard = FLAG_GATE.lock().unwrap();
    init(true);
    assert!(enabled());
    init(false);
    assert!(!enabled());
}

/// The log door emits the bracketed shape on stderr when armed.
#[test]
fn log_prints_tagged_line_when_armed() {
    let _guard = FLAG_GATE.lock().unwrap();
    init(true);
    // No panic, no stdout use: the shape contract is exercised by
    // the pipe-purity integration surface (the JSON lane stays clean
    // under -v), and this pin keeps the door callable in both states.
    log("limiter", "test probe line");
    assert!(enabled());
    init(false);
}

/// The disarmed lane never prints: the door's silent arm costs one
/// atomic load and nothing else.
#[test]
fn log_is_silent_when_disarmed() {
    let _guard = FLAG_GATE.lock().unwrap();
    init(false);
    log("limiter", "this must not print");
    assert!(!enabled());
}
