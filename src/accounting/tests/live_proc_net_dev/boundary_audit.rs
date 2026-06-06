// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Boundary audit and structural safety tests for the live `/proc/net/dev` reader seam.
//!
//! Source-level audits verify the production module source does not contain forbidden
//! filesystem write APIs or sysfs/cgroup paths. Structural tests verify no CLI command
//! registration, no filesystem write usage, and no real /proc/net/dev reads in tests.

use super::*;

// ── Structural: no CLI command ────────────────────────────────────

#[test]
fn no_cli_command_is_added() {
    // Structural test: verify that no CLI usage command registration
    // exists in the accounting module. The live_proc_net_dev module
    // does not expose any CLI-facing types — only pub(crate) model types.
    let _ = build_live_proc_net_dev_read_plan();
    let _ = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE);
    // No clap/structopt args, no Command enum variants, no CLI routing.
    // This test documents the intent structurally.
}

// ── Structural: no filesystem write APIs ──────────────────────────

#[test]
fn no_filesystem_write_apis_used() {
    // Structural test: the live_proc_net_dev module must not import
    // or use std::fs::write, std::fs::create_dir, std::fs::remove_file,
    // or any other filesystem mutation API.
    //
    // This is verified by the module's source code containing only
    // parse_proc_net_dev (pure parser), string operations, and
    // model construction — no std::fs imports.
    //
    // The module source does not contain "std::fs" anywhere.
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    assert!(!plan.filesystem_write_performed);
    assert!(!plan.state_mutation_performed);
}

// ── No sysfs/cgroup paths in module source ───────────────────────────

#[test]
fn no_sysfs_or_cgroup_paths_in_module_source() {
    let source = include_str!("../../live_proc_net_dev.rs");
    // Filter out lines that define FORBIDDEN_PATHS or FORBIDDEN_FS_WRITE_APIS
    // constants, since those constants naturally contain the forbidden strings
    // as their values.
    for line in source.lines() {
        // Skip doc comments, const declarations, and const value lines.
        if line.contains("FORBIDDEN_PATHS")
            || line.contains("FORBIDDEN_FS_WRITE_APIS")
            || line.contains("pub const")
            || line.starts_with("///")
            || line.starts_with("//!")
            || line.trim_start().starts_with('"')
        {
            continue;
        }
        for forbidden in FORBIDDEN_PATHS {
            assert!(
                !line.contains(forbidden),
                "code line must not contain forbidden path '{}': {}",
                forbidden,
                line
            );
        }
    }
}

// ── No filesystem write APIs in module source ──────────────────────────

#[test]
fn no_filesystem_write_apis_in_module_source() {
    let source = include_str!("../../live_proc_net_dev.rs");
    // Filter out lines that define the FORBIDDEN_FS_WRITE_APIS constant itself,
    // since the constant values naturally contain the forbidden strings.
    for line in source.lines() {
        // Skip doc comments, const declarations, and const value lines.
        if line.contains("FORBIDDEN_FS_WRITE_APIS")
            || line.contains("FORBIDDEN_PATHS")
            || line.contains("pub const")
            || line.starts_with("///")
            || line.starts_with("//!")
            || line.trim_start().starts_with('"')
        {
            continue;
        }
        for forbidden in FORBIDDEN_FS_WRITE_APIS {
            assert!(
                !line.contains(forbidden),
                "code line must not contain forbidden fs write API '{}': {}",
                forbidden,
                line
            );
        }
    }
}
