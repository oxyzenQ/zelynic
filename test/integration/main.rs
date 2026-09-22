// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Integration tests for zelynic (Cosmic Dragon Architecture — pure eBPF).
//!
//! One test binary, split by surface (NIGHT-docs-4) so every file
//! stays under the 500-LOC cap that `scripts/check-loc.sh` enforces
//! over `src/**` AND `test/**` (the same navigability rationale as
//! cosmostrix's `src/RULES.md` split policy). Since NIGHT-hunt-17 the
//! whole tree lives under `test/` (cosmostrix Pattern C) and is the
//! single test target declared in Cargo.toml (`autotests = false` —
//! the old `tests/` directory convention is gone for good):
//! - `smoke` — end-to-end surface checks (doctor, version, cycles)
//! - `cli_ux` — flag/error UX contract pins (suggestions, EPIPE)
//! - `help_pins` — `--help` reference drift pins
//! - `surface_pins` — command-surface wiring pins (aliases, removals)
//! - `privilege` — the unprivileged contract + validation ladder
//!
//! These tests run on any Linux system; the enforcement cases that
//! need root + eBPF are `#[ignore]`d or uid-gated inside. Run with:
//! `cargo test --test integration` (add `sudo` for the ignored ones).

use std::process::Command;

mod cli_ux;
mod help_pins;
mod privilege;
mod smoke;
mod surface_pins;

/// Test helper to run zelynic commands.
fn zelynic_cmd() -> Command {
    let binary = env!("CARGO_BIN_EXE_zelynic");
    let mut cmd = Command::new(binary);
    cmd.env("NO_COLOR", "1");
    cmd
}

/// Effective uid from /proc/self/status (no nix dependency needed in
/// the default feature build): "Uid:\t<real>\t<effective>\t...".
fn euid_is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .map(|l| l.to_string())
        })
        .and_then(|l| l.split_whitespace().nth(1).map(|u| u.to_string()))
        .and_then(|u| u.parse::<u32>().ok())
        == Some(0)
}
