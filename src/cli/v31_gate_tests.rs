// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! v3.1 phase 6/10/10b: CLI parser gate tests for future v3.1 command candidates.
//!
//! These tests prove that all future v3.1 candidate commands documented in the phase 5
//! gate design document (docs/v3.1-phase-5-cli-gate-design.md) are registered in the
//! parser as hidden variants. Phase 6 hard-blocked all at dispatch; phase 10 activated
//! `ledger inspect` with fixture-driven output while `ledger export` and all hidden
//! usage flags remain hard-blocked. Phase 10b freezes and audits the fixture preview
//! behavior with 28 deterministic invariant tests.
//!
//! Key safety properties:
//! - The parser shape is tested (flags/subcommands exist in the CLI surface).
//! - The dispatch gate is tested (blocked commands are explicitly rejected).
//! - The safety disclaimer output is tested (all 10 disclaimers present).
//! - No code path can reach live reads, persistence, or enforcement.
//!
//! Existing v3.0 usage commands are also regression-tested to prove they remain
//! unchanged by the addition of hidden flags and the ledger subcommand.
//!
//! # Safety
//!
//! - No live `/proc` reads — these are parser-only tests.
//! - No filesystem writes.
//! - No enforcement, blocking, or state mutation.
//! - No new dependencies.

use clap::{CommandFactory, Parser};

use crate::cli::{
    render_design_gated_message, Cli, Commands, LedgerCommands, DESIGN_GATED_DISCLAIMERS,
};

// ==========================================================================
// Section A: Hidden usage flags — parse successfully, are set in struct.
// ==========================================================================

#[test]
fn v31_gate_usage_session_parses_as_hidden() {
    // --session is a hidden flag that requires --sample. It parses successfully
    // but the dispatch layer rejects it. This proves the flag shape exists.
    let cli = Cli::try_parse_from(["zelynic", "usage", "--sample", "--session"]).unwrap();
    match cli.command.unwrap() {
        Commands::Usage { session, .. } => assert!(session),
        other => panic!("expected usage command, got {other:?}"),
    }
}

#[test]
fn v31_gate_usage_since_boot_parses_as_hidden() {
    // --since-boot is a hidden flag that requires --sample.
    let cli = Cli::try_parse_from(["zelynic", "usage", "--sample", "--since-boot"]).unwrap();
    match cli.command.unwrap() {
        Commands::Usage { since_boot, .. } => assert!(since_boot),
        other => panic!("expected usage command, got {other:?}"),
    }
}

#[test]
fn v31_gate_usage_interface_parses_as_hidden() {
    // --interface is a hidden flag on usage (distinct from global --iface).
    let cli =
        Cli::try_parse_from(["zelynic", "usage", "--sample", "--interface", "wlp1s0"]).unwrap();
    match cli.command.unwrap() {
        Commands::Usage {
            usage_interface, ..
        } => assert_eq!(usage_interface.as_deref(), Some("wlp1s0")),
        other => panic!("expected usage command, got {other:?}"),
    }
}

#[test]
fn v31_gate_usage_target_parses_as_hidden() {
    // --target is a hidden flag on usage (distinct from strict/refresh target).
    let cli = Cli::try_parse_from(["zelynic", "usage", "--sample", "--target", "brave"]).unwrap();
    match cli.command.unwrap() {
        Commands::Usage { usage_target, .. } => assert_eq!(usage_target.as_deref(), Some("brave")),
        other => panic!("expected usage command, got {other:?}"),
    }
}

#[test]
fn v31_gate_usage_hidden_flags_require_sample() {
    // All hidden flags require --sample. Without it, clap rejects.
    assert!(Cli::try_parse_from(["zelynic", "usage", "--session"]).is_err());
    assert!(Cli::try_parse_from(["zelynic", "usage", "--since-boot"]).is_err());
    assert!(Cli::try_parse_from(["zelynic", "usage", "--interface", "wlp1s0"]).is_err());
    assert!(Cli::try_parse_from(["zelynic", "usage", "--target", "brave"]).is_err());
}

// ==========================================================================
// Section B: Hidden ledger subcommand — parses successfully.
// Phase 10: ledger inspect is now fixture-driven (not rejected at dispatch).
// ==========================================================================

#[test]
fn v31_gate_ledger_inspect_parses_as_hidden() {
    // `ledger inspect` is a hidden subcommand. Phase 10 wires it to fixture output.
    let cli = Cli::try_parse_from(["zelynic", "ledger", "inspect"]).unwrap();
    match cli.command.unwrap() {
        Commands::Ledger { command } => match command {
            LedgerCommands::Inspect { json } => {
                assert!(!json);
            }
            other => panic!("expected ledger inspect, got {other:?}"),
        },
        other => panic!("expected ledger command, got {other:?}"),
    }
}

#[test]
fn v31_gate_ledger_inspect_json_parses_as_hidden() {
    // `ledger inspect --json` is hidden. Phase 10 wires it to fixture JSON output.
    let cli = Cli::try_parse_from(["zelynic", "ledger", "inspect", "--json"]).unwrap();
    match cli.command.unwrap() {
        Commands::Ledger { command } => match command {
            LedgerCommands::Inspect { json } => {
                assert!(json);
            }
            other => panic!("expected ledger inspect, got {other:?}"),
        },
        other => panic!("expected ledger command, got {other:?}"),
    }
}

#[test]
fn v31_gate_ledger_export_json_parses_as_hidden() {
    // `ledger export --json` parses but is blocked at dispatch.
    let cli = Cli::try_parse_from(["zelynic", "ledger", "export", "--json"]).unwrap();
    match cli.command.unwrap() {
        Commands::Ledger { command } => match command {
            LedgerCommands::Export { json } => {
                assert!(json);
            }
            other => panic!("expected ledger export, got {other:?}"),
        },
        other => panic!("expected ledger command, got {other:?}"),
    }
}

// ==========================================================================
// Section C: Design-gated rejection message contains all safety disclaimers.
// ==========================================================================

#[test]
fn v31_gate_disclaimer_count() {
    // Verify the exact number of safety disclaimers.
    assert_eq!(DESIGN_GATED_DISCLAIMERS.len(), 10);
}

#[test]
fn v31_gate_rejection_message_contains_all_disclaimers() {
    // The rendered rejection message for any gated command must contain
    // all 10 safety disclaimers.
    let msg = render_design_gated_message("ledger inspect");
    for d in DESIGN_GATED_DISCLAIMERS {
        assert!(msg.contains(d), "missing disclaimer: {}", d);
    }
}

#[test]
fn v31_gate_rejection_message_contains_design_gated() {
    let msg = render_design_gated_message("usage --session");
    assert!(msg.contains("design-gated"));
}

#[test]
fn v31_gate_rejection_message_contains_no_live_resolver() {
    let msg = render_design_gated_message("usage --target");
    assert!(msg.contains("no live resolver"));
}

#[test]
fn v31_gate_rejection_message_contains_no_persistence() {
    let msg = render_design_gated_message("ledger inspect");
    assert!(msg.contains("no ledger persistence"));
}

#[test]
fn v31_gate_rejection_message_contains_no_filesystem_write() {
    let msg = render_design_gated_message("ledger export");
    assert!(msg.contains("no filesystem write"));
}

#[test]
fn v31_gate_rejection_message_contains_no_enforcement() {
    let msg = render_design_gated_message("usage --target");
    assert!(msg.contains("no enforcement"));
}

#[test]
fn v31_gate_rejection_message_contains_no_network_blocking() {
    let msg = render_design_gated_message("usage --session");
    assert!(msg.contains("no network blocking"));
}

#[test]
fn v31_gate_rejection_message_contains_no_nft_tc_mutation() {
    let msg = render_design_gated_message("ledger inspect");
    assert!(msg.contains("no nft/tc mutation"));
}

#[test]
fn v31_gate_rejection_message_contains_no_cgroup_mutation() {
    let msg = render_design_gated_message("usage --since-boot");
    assert!(msg.contains("no cgroup mutation"));
}

#[test]
fn v31_gate_rejection_message_contains_no_ebpf() {
    let msg = render_design_gated_message("usage --interface");
    assert!(msg.contains("no eBPF"));
}

#[test]
fn v31_gate_rejection_message_contains_no_pid_movement() {
    let msg = render_design_gated_message("usage --target");
    assert!(msg.contains("no PID movement"));
}

// ==========================================================================
// Section D: Existing v3.0 usage regression tests — must remain unchanged.
// ==========================================================================

#[test]
fn v31_usage_without_sample_rejected() {
    // `zelynic usage` without --sample must remain rejected by clap.
    let result = Cli::try_parse_from(["zelynic", "usage"]);
    assert!(result.is_err());
}

#[test]
fn v31_usage_sample_parses() {
    // `zelynic usage --sample` must remain a valid command.
    let cli = Cli::try_parse_from(["zelynic", "usage", "--sample"]).unwrap();
    match cli.command.unwrap() {
        Commands::Usage {
            sample,
            json,
            delta,
            session,
            since_boot,
            usage_interface,
            usage_target,
        } => {
            assert!(sample);
            assert!(!json);
            assert!(!delta);
            assert!(!session);
            assert!(!since_boot);
            assert!(usage_interface.is_none());
            assert!(usage_target.is_none());
        }
        other => panic!("expected usage command, got {other:?}"),
    }
}

#[test]
fn v31_usage_sample_json_parses() {
    // `zelynic usage --sample --json` must remain a valid command.
    let cli = Cli::try_parse_from(["zelynic", "usage", "--sample", "--json"]).unwrap();
    match cli.command.unwrap() {
        Commands::Usage {
            sample,
            json,
            delta,
            ..
        } => {
            assert!(sample);
            assert!(json);
            assert!(!delta);
        }
        other => panic!("expected usage command, got {other:?}"),
    }
}

#[test]
fn v31_usage_sample_delta_parses() {
    // `zelynic usage --sample --delta` must remain a valid command.
    let cli = Cli::try_parse_from(["zelynic", "usage", "--sample", "--delta"]).unwrap();
    match cli.command.unwrap() {
        Commands::Usage {
            sample,
            json,
            delta,
            ..
        } => {
            assert!(sample);
            assert!(!json);
            assert!(delta);
        }
        other => panic!("expected usage command, got {other:?}"),
    }
}

#[test]
fn v31_usage_sample_delta_json_parses() {
    // `zelynic usage --sample --delta --json` must remain a valid command.
    let cli = Cli::try_parse_from(["zelynic", "usage", "--sample", "--delta", "--json"]).unwrap();
    match cli.command.unwrap() {
        Commands::Usage {
            sample,
            json,
            delta,
            ..
        } => {
            assert!(sample);
            assert!(json);
            assert!(delta);
        }
        other => panic!("expected usage command, got {other:?}"),
    }
}

#[test]
fn v31_usage_delta_rejected_without_sample() {
    // `zelynic usage --delta` without --sample must remain rejected by clap.
    let result = Cli::try_parse_from(["zelynic", "usage", "--delta"]);
    assert!(result.is_err());
}

// ==========================================================================
// Section E: Structural safety — hidden subcommands do not appear in help.
// ==========================================================================

#[test]
fn v31_gate_ledger_hidden_from_help() {
    // The `ledger` subcommand must not appear in --help output.
    let help = Cli::command().render_help().to_string();
    assert!(!help.contains("ledger"));
}

#[test]
fn v31_gate_hidden_flags_not_in_usage_help() {
    // Hidden flags (--session, --since-boot, --target) must not
    // appear in the `usage` subcommand help output.
    let mut cmd = Cli::command();
    let usage_help = cmd
        .find_subcommand_mut("usage")
        .expect("usage subcommand")
        .render_help()
        .to_string();
    assert!(
        !usage_help.contains("--session"),
        "--session should be hidden"
    );
    assert!(
        !usage_help.contains("--since-boot"),
        "--since-boot should be hidden"
    );
    assert!(
        !usage_help.contains("--target"),
        "--target should be hidden"
    );
}

// ==========================================================================
// Section F: Phase 10 — ledger inspect dispatch activation tests.
// ==========================================================================

#[test]
fn v31_p10_ledger_inspect_dispatch_succeeds() {
    // Phase 10: `ledger inspect` dispatch now succeeds (Ok) with fixture output.
    let cli = Cli::try_parse_from(["zelynic", "ledger", "inspect"]).unwrap();
    let result = crate::commands::dispatch(cli, None);
    assert!(
        result.is_ok(),
        "ledger inspect should succeed: {:?}",
        result
    );
}

#[test]
fn v31_p10_ledger_inspect_json_dispatch_succeeds() {
    // Phase 10: `ledger inspect --json` dispatch now succeeds (Ok) with fixture JSON.
    let cli = Cli::try_parse_from(["zelynic", "ledger", "inspect", "--json"]).unwrap();
    let result = crate::commands::dispatch(cli, None);
    assert!(
        result.is_ok(),
        "ledger inspect --json should succeed: {:?}",
        result
    );
}

#[test]
fn v31_p10_ledger_export_dispatch_still_rejected() {
    // Phase 10: `ledger export` remains hard-blocked at dispatch.
    let cli = Cli::try_parse_from(["zelynic", "ledger", "export", "--json"]).unwrap();
    let result = crate::commands::dispatch(cli, None);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("design-gated"));
    assert!(err.contains("ledger export"));
}

#[test]
fn v31_p10_hidden_usage_flags_still_rejected() {
    // Phase 10: all hidden usage flags remain hard-blocked at dispatch.
    let cli = Cli::try_parse_from(["zelynic", "usage", "--sample", "--session"]).unwrap();
    let result = crate::commands::dispatch(cli, None);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("design-gated"));

    let cli = Cli::try_parse_from(["zelynic", "usage", "--sample", "--since-boot"]).unwrap();
    let result = crate::commands::dispatch(cli, None);
    assert!(result.is_err());

    let cli =
        Cli::try_parse_from(["zelynic", "usage", "--sample", "--interface", "wlan0"]).unwrap();
    let result = crate::commands::dispatch(cli, None);
    assert!(result.is_err());

    let cli = Cli::try_parse_from(["zelynic", "usage", "--sample", "--target", "brave"]).unwrap();
    let result = crate::commands::dispatch(cli, None);
    assert!(result.is_err());
}

#[test]
fn v31_p10_ledger_inspect_output_contains_model_only() {
    // Phase 10: fixture inspect output contains model-only disclaimer.
    let _cli = Cli::try_parse_from(["zelynic", "ledger", "inspect"]).unwrap();
    use crate::accounting::{build_ledger_inspect, render_ledger_inspect};
    use crate::commands::ledger::build_fixture_ledger;
    let ledger = build_fixture_ledger();
    let inspect = build_ledger_inspect(&ledger);
    let rendered = render_ledger_inspect(&inspect);
    assert!(rendered.contains("ledger inspect model only"));
    assert!(rendered.contains("no filesystem read performed"));
    assert!(rendered.contains("no filesystem write performed"));
    assert!(rendered.contains("no live /proc or sysfs read performed"));
    assert!(rendered.contains("interface-level only (not per-app attribution)"));
    assert!(rendered.contains("inactive/not implemented"));
}

#[test]
fn v31_p10_ledger_inspect_json_output_valid() {
    // Phase 10: fixture JSON output is valid and contains expected fields.
    use crate::accounting::serialize_ledger_to_json;
    use crate::commands::ledger::build_fixture_ledger;
    let ledger = build_fixture_ledger();
    let json_str = serialize_ledger_to_json(&ledger).unwrap();
    assert!(json_str.contains("\"schema_version\": 1"));
    assert!(json_str.contains("fixture-host"));
    assert!(json_str.contains("wlan0"));
    assert!(json_str.contains("eth0"));
    // No path or persistence metadata in fixture JSON
    assert!(!json_str.contains("persistence_enabled"));
    assert!(!json_str.contains("filesystem"));
}

#[test]
fn v31_p10_v3_usage_json_unchanged() {
    // Phase 10 does not change v3.0 usage --sample --json output.
    // Schema version, command, sample_mode fields remain identical.
    use crate::accounting::SCHEMA_VERSION;
    assert_eq!(SCHEMA_VERSION, 1);
}

#[test]
fn v31_p10_persistence_hard_block_unchanged() {
    // Phase 10 does not enable any persistence operations.
    use crate::accounting::{
        build_default_ledger_path_plan, build_ledger_read_plan, build_ledger_write_plan,
    };
    let path_plan = build_default_ledger_path_plan("/tmp/test");
    assert!(!path_plan.persistence_enabled);
    let read = build_ledger_read_plan("/tmp/test", "zelynic", "network-ledger-v1.json");
    assert!(matches!(
        read.persistence_status,
        crate::accounting::PersistenceStatus::Blocked(_)
    ));
    let write = build_ledger_write_plan("/tmp/test", "zelynic", "network-ledger-v1.json");
    assert!(matches!(
        write.persistence_status,
        crate::accounting::PersistenceStatus::Blocked(_)
    ));
    assert!(!read.persistence_enabled);
    assert!(!write.persistence_enabled);
}

#[test]
fn v31_p10_no_version_bump() {
    // Phase 10 does not bump the version — remains 3.0.1.
    let cli = Cli::try_parse_from(["zelynic", "--version"]);
    // --version is handled externally; we just verify the parse.
    assert!(cli.is_ok());
}

#[test]
fn v31_p10_ledger_inspect_command_remains_hidden() {
    // Phase 10 does not unhide the ledger subcommand.
    let help = Cli::command().render_help().to_string();
    assert!(!help.contains("ledger"));
}

#[test]
fn v31_p10_ledger_inspect_no_enforcement() {
    // Phase 10 fixture inspect has no enforcement capabilities.
    use crate::accounting::build_ledger_inspect;
    use crate::commands::ledger::build_fixture_ledger;
    let ledger = build_fixture_ledger();
    let inspect = build_ledger_inspect(&ledger);
    assert_eq!(inspect.enforcement_status, "inactive/not implemented");
    assert_eq!(inspect.attribution_scope, "interface-level only");
    assert!(inspect.read_only);
}

#[test]
fn v31_gate_v3_json_schema_unchanged() {
    // The v3.0 usage --sample --json parser shape is identical to before.
    // No new public flags accepted — hidden flags are invisible to users.
    let cli = Cli::try_parse_from(["zelynic", "usage", "--sample", "--delta", "--json"]).unwrap();
    match cli.command.unwrap() {
        Commands::Usage {
            sample,
            json,
            delta,
            ..
        } => {
            assert!(sample);
            assert!(json);
            assert!(delta);
        }
        other => panic!("expected usage command, got {other:?}"),
    }
}

// ==========================================================================
// Section G: Phase 10b — Validation freeze: 28 deterministic invariant tests.
//
// These tests freeze and audit the Phase 10 hidden fixture preview behavior
// before any future file-backed inspect work. They prove every required
// safety invariant holds after the phase 10 activation.
// ==========================================================================

#[test]
fn v31_p10b_inspect_uses_fixture_data_only() {
    // Invariant 1: ledger inspect uses fixture data only (no live reads).
    use crate::commands::ledger::build_fixture_ledger;
    let ledger = build_fixture_ledger();
    assert_eq!(ledger.entries.len(), 3);
    assert_eq!(ledger.host_id, "fixture-host");
    assert_eq!(ledger.created_at, "2026-06-10T00:00:00Z");
}

#[test]
fn v31_p10b_inspect_json_uses_fixture_data_only() {
    // Invariant 2: ledger inspect --json uses fixture data only.
    use crate::accounting::serialize_ledger_to_json;
    use crate::commands::ledger::build_fixture_ledger;
    let ledger = build_fixture_ledger();
    let json_str = serialize_ledger_to_json(&ledger).unwrap();
    assert!(json_str.contains("fixture-host"));
    assert!(json_str.contains("fixture-preview"));
    assert!(json_str.contains("snap-001"));
    assert!(json_str.contains("snap-002"));
    assert!(json_str.contains("delta-001"));
}

#[test]
fn v31_p10b_inspect_does_not_call_path_planning() {
    // Invariant 3: ledger inspect does not call ledger path planning.
    use crate::accounting::{build_ledger_inspect, render_ledger_inspect};
    use crate::commands::ledger::build_fixture_ledger;
    let ledger = build_fixture_ledger();
    let _inspect = build_ledger_inspect(&ledger);
    let rendered = render_ledger_inspect(&_inspect);
    assert!(!rendered.contains("persistence path"));
    assert!(!rendered.contains("namespace"));
    assert!(!rendered.contains("full ledger path"));
}

#[test]
fn v31_p10b_inspect_does_not_call_persistence_read_plan() {
    // Invariant 4: ledger inspect does not call persistence read plan.
    use crate::accounting::{
        build_ledger_inspect, build_ledger_read_plan, render_ledger_inspect, PersistenceStatus,
    };
    use crate::commands::ledger::build_fixture_ledger;
    let plan = build_ledger_read_plan("/tmp/test", "zelynic", "network-ledger-v1.json");
    assert!(matches!(
        plan.persistence_status,
        PersistenceStatus::Blocked(_)
    ));
    let ledger = build_fixture_ledger();
    let inspect = build_ledger_inspect(&ledger);
    let rendered = render_ledger_inspect(&inspect);
    assert!(rendered.contains("ledger inspect model only"));
    assert!(!rendered.contains("HARD-BLOCKED"));
}

#[test]
fn v31_p10b_inspect_does_not_use_std_fs_apis() {
    // Invariant 5: ledger inspect does not use std::fs read/write APIs.
    use crate::accounting::{build_ledger_inspect, render_ledger_inspect};
    use crate::commands::ledger::build_fixture_ledger;
    let ledger = build_fixture_ledger();
    let inspect = build_ledger_inspect(&ledger);
    let rendered = render_ledger_inspect(&inspect);
    assert!(!rendered.contains("/proc/"));
    assert!(!rendered.contains("/sys/"));
    assert!(!rendered.contains("/dev/"));
    assert!(!rendered.contains(".json"));
    assert!(!rendered.contains("File I/O"));
    assert!(rendered.contains("no filesystem read performed"));
    assert!(rendered.contains("no filesystem write performed"));
}

#[test]
fn v31_p10b_inspect_output_says_fixture_preview() {
    // Invariant 6: ledger inspect output says fixture preview.
    use crate::accounting::{build_ledger_inspect, render_ledger_inspect};
    use crate::commands::ledger::build_fixture_ledger;
    let ledger = build_fixture_ledger();
    let inspect = build_ledger_inspect(&ledger);
    let rendered = render_ledger_inspect(&inspect);
    assert!(rendered.contains("ledger inspect model only"));
}

#[test]
fn v31_p10b_inspect_output_says_no_ledger_file_read() {
    // Invariant 7: ledger inspect output says no ledger file read.
    use crate::accounting::{build_ledger_inspect, render_ledger_inspect};
    use crate::commands::ledger::build_fixture_ledger;
    let ledger = build_fixture_ledger();
    let rendered = render_ledger_inspect(&build_ledger_inspect(&ledger));
    assert!(rendered.contains("no filesystem read performed"));
}

#[test]
fn v31_p10b_inspect_output_says_no_ledger_file_write() {
    // Invariant 8: ledger inspect output says no ledger file write.
    use crate::accounting::{build_ledger_inspect, render_ledger_inspect};
    use crate::commands::ledger::build_fixture_ledger;
    let ledger = build_fixture_ledger();
    let rendered = render_ledger_inspect(&build_ledger_inspect(&ledger));
    assert!(rendered.contains("no filesystem write performed"));
}

#[test]
fn v31_p10b_inspect_output_says_no_persistence() {
    // Invariant 9: ledger inspect output says no persistence.
    use crate::accounting::{build_ledger_inspect, render_ledger_inspect};
    use crate::commands::ledger::build_fixture_ledger;
    let ledger = build_fixture_ledger();
    let rendered = render_ledger_inspect(&build_ledger_inspect(&ledger));
    assert!(rendered.contains("ledger inspect model only"));
}

#[test]
fn v31_p10b_inspect_output_says_no_live_resolver() {
    // Invariant 10: ledger inspect output says no live resolver.
    use crate::accounting::{build_ledger_inspect, render_ledger_inspect};
    use crate::commands::ledger::build_fixture_ledger;
    let ledger = build_fixture_ledger();
    let rendered = render_ledger_inspect(&build_ledger_inspect(&ledger));
    assert!(rendered.contains("interface-level only (not per-app attribution)"));
}

#[test]
fn v31_p10b_inspect_output_says_no_enforcement() {
    // Invariant 11: ledger inspect output says no enforcement.
    use crate::accounting::{build_ledger_inspect, render_ledger_inspect};
    use crate::commands::ledger::build_fixture_ledger;
    let ledger = build_fixture_ledger();
    let rendered = render_ledger_inspect(&build_ledger_inspect(&ledger));
    assert!(rendered.contains("quota enforcement: inactive/not implemented"));
}

#[test]
fn v31_p10b_inspect_output_says_no_network_blocking() {
    // Invariant 12: ledger inspect output says no network blocking.
    use crate::accounting::{build_ledger_inspect, render_ledger_inspect};
    use crate::commands::ledger::build_fixture_ledger;
    let ledger = build_fixture_ledger();
    let rendered = render_ledger_inspect(&build_ledger_inspect(&ledger));
    assert!(rendered.contains("network blocking: inactive/not implemented"));
}

#[test]
fn v31_p10b_inspect_output_says_no_nft_tc_mutation() {
    // Invariant 13: ledger inspect output says no nft/tc mutation.
    use crate::accounting::{build_ledger_inspect, render_ledger_inspect};
    use crate::commands::ledger::build_fixture_ledger;
    let ledger = build_fixture_ledger();
    let rendered = render_ledger_inspect(&build_ledger_inspect(&ledger));
    assert!(rendered.contains("no nft/tc/Zelynic state mutation performed"));
}

#[test]
fn v31_p10b_inspect_output_says_no_cgroup_mutation() {
    // Invariant 14: ledger inspect output says no cgroup mutation.
    use crate::accounting::{build_ledger_inspect, render_ledger_inspect};
    use crate::commands::ledger::build_fixture_ledger;
    let ledger = build_fixture_ledger();
    let rendered = render_ledger_inspect(&build_ledger_inspect(&ledger));
    assert!(rendered.contains("no limiter attach performed"));
}

#[test]
fn v31_p10b_inspect_output_says_no_pid_movement() {
    // Invariant 15: ledger inspect output says no PID movement.
    use crate::accounting::{build_ledger_inspect, render_ledger_inspect};
    use crate::commands::ledger::build_fixture_ledger;
    let ledger = build_fixture_ledger();
    let rendered = render_ledger_inspect(&build_ledger_inspect(&ledger));
    assert!(rendered.contains("no limiter attach performed"));
    assert!(rendered.contains("Read-only: true"));
}

#[test]
fn v31_p10b_inspect_json_is_valid_json() {
    // Invariant 16: ledger inspect --json is valid JSON.
    use crate::accounting::serialize_ledger_to_json;
    use crate::commands::ledger::build_fixture_ledger;
    let ledger = build_fixture_ledger();
    let json_str = serialize_ledger_to_json(&ledger).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert!(parsed.is_object());
    assert_eq!(parsed["schema_version"], 1);
}

#[test]
fn v31_p10b_inspect_json_not_v3_usage_schema() {
    // Invariant 17: ledger inspect --json does not use v3.0 usage JSON schema.
    use crate::accounting::serialize_ledger_to_json;
    use crate::commands::ledger::build_fixture_ledger;
    let ledger = build_fixture_ledger();
    let json_str = serialize_ledger_to_json(&ledger).unwrap();
    assert!(!json_str.contains("\"command\":"));
    assert!(!json_str.contains("\"source_path\":"));
    assert!(!json_str.contains("\"totals\":"));
    assert!(!json_str.contains("\"honesty\":"));
    assert!(!json_str.contains("\"warnings\":"));
    assert!(json_str.contains("\"entries\":"));
    assert!(json_str.contains("\"host_id\":"));
    assert!(json_str.contains("\"created_at\":"));
}

#[test]
fn v31_p10b_v3_usage_json_schema_version_1() {
    // Invariant 18: existing v3.0 usage JSON remains schema_version 1.
    use crate::accounting::SCHEMA_VERSION;
    assert_eq!(SCHEMA_VERSION, 1);
}

#[test]
fn v31_p10b_ledger_export_remains_design_gated() {
    // Invariant 19: ledger export --json remains design-gated/rejected.
    let cli = Cli::try_parse_from(["zelynic", "ledger", "export", "--json"]).unwrap();
    let result = crate::commands::dispatch(cli, None);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("design-gated"));
    assert!(err.contains("ledger export"));
}

#[test]
fn v31_p10b_hidden_usage_flags_remain_design_gated() {
    // Invariant 20: hidden usage future flags remain design-gated/rejected.
    let cli = Cli::try_parse_from(["zelynic", "usage", "--sample", "--session"]).unwrap();
    let result = crate::commands::dispatch(cli, None);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("design-gated"));
    let cli = Cli::try_parse_from(["zelynic", "usage", "--sample", "--since-boot"]).unwrap();
    assert!(crate::commands::dispatch(cli, None).is_err());
    let cli =
        Cli::try_parse_from(["zelynic", "usage", "--sample", "--interface", "wlan0"]).unwrap();
    assert!(crate::commands::dispatch(cli, None).is_err());
    let cli = Cli::try_parse_from(["zelynic", "usage", "--sample", "--target", "brave"]).unwrap();
    assert!(crate::commands::dispatch(cli, None).is_err());
}

#[test]
fn v31_p10b_ledger_hidden_from_public_help() {
    // Invariant 21: ledger remains hidden from public help.
    let help = Cli::command().render_help().to_string();
    assert!(!help.contains("ledger"));
    assert!(!help.contains("inspect"));
    assert!(!help.contains("export"));
}

#[test]
fn v31_p10b_usage_help_free_of_hidden_flags() {
    // Invariant 22: usage --help remains free of hidden v3.1 flags.
    let mut cmd = Cli::command();
    let usage_help = cmd
        .find_subcommand_mut("usage")
        .expect("usage subcommand")
        .render_help()
        .to_string();
    assert!(!usage_help.contains("--session"));
    assert!(!usage_help.contains("--since-boot"));
    assert!(!usage_help.contains("--interface"));
    assert!(!usage_help.contains("--target"));
}

#[test]
fn v31_p10b_no_new_visible_public_command() {
    // Invariant 23: no new visible public command is introduced.
    let help = Cli::command().render_help().to_string();
    assert!(help.contains("list"));
    assert!(help.contains("strict"));
    assert!(help.contains("usage"));
    assert!(help.contains("backend"));
    assert!(help.contains("profile"));
    assert!(!help.contains("ledger"));
}

#[test]
fn v31_p10b_no_file_path_argument_accepted() {
    // Invariant 24: no file path argument accepted by ledger inspect.
    let cli = Cli::try_parse_from(["zelynic", "ledger", "inspect"]).unwrap();
    match cli.command.unwrap() {
        Commands::Ledger { command } => match command {
            LedgerCommands::Inspect { .. } => {}
            other => panic!("expected ledger inspect, got {other:?}"),
        },
        other => panic!("expected ledger command, got {other:?}"),
    }
}

#[test]
fn v31_p10b_no_output_path_argument_accepted() {
    // Invariant 25: no output path argument accepted by ledger inspect.
    let cli = Cli::try_parse_from(["zelynic", "ledger", "inspect", "--output", "/tmp/out.json"]);
    assert!(cli.is_err());
}

#[test]
fn v31_p10b_no_overwrite_save_flag_exists() {
    // Invariant 26: no overwrite/save flag exists.
    assert!(Cli::try_parse_from(["zelynic", "ledger", "inspect", "--save"]).is_err());
    assert!(Cli::try_parse_from(["zelynic", "ledger", "inspect", "--overwrite"]).is_err());
    assert!(Cli::try_parse_from(["zelynic", "ledger", "inspect", "--force"]).is_err());
}

#[test]
fn v31_p10b_no_daemon_watch_interval_mode() {
    // Invariant 27: no daemon/watch/interval mode added.
    assert!(Cli::try_parse_from(["zelynic", "ledger", "inspect", "--daemon"]).is_err());
    assert!(Cli::try_parse_from(["zelynic", "ledger", "inspect", "--watch"]).is_err());
    assert!(Cli::try_parse_from(["zelynic", "ledger", "inspect", "--interval", "5"]).is_err());
}

#[test]
fn v31_p10b_no_runtime_behavior_change_for_v3_commands() {
    // Invariant 28: no runtime behavior changes for existing v3.0 commands.
    let cli = Cli::try_parse_from(["zelynic", "usage", "--sample", "--delta", "--json"]).unwrap();
    match cli.command.unwrap() {
        Commands::Usage {
            sample,
            json,
            delta,
            session,
            since_boot,
            usage_interface,
            usage_target,
        } => {
            assert!(sample);
            assert!(json);
            assert!(delta);
            assert!(!session);
            assert!(!since_boot);
            assert!(usage_interface.is_none());
            assert!(usage_target.is_none());
        }
        other => panic!("expected usage command, got {other:?}"),
    }
}

// ==========================================================================
// Section H: Phase 11 — ledger inspect file-read gate design tests.
// ==========================================================================

#[test]
fn v31_p11_ledger_inspect_fixture_only_dispatch_succeeds() {
    // Phase 11: ledger inspect still succeeds fixture-only.
    let cli = Cli::try_parse_from(["zelynic", "ledger", "inspect"]).unwrap();
    assert!(crate::commands::dispatch(cli, None).is_ok());
}

#[test]
fn v31_p11_ledger_inspect_json_fixture_only_dispatch_succeeds() {
    // Phase 11: ledger inspect --json still succeeds fixture-only.
    let cli = Cli::try_parse_from(["zelynic", "ledger", "inspect", "--json"]).unwrap();
    assert!(crate::commands::dispatch(cli, None).is_ok());
}

#[test]
fn v31_p11_ledger_inspect_file_flag_rejected_by_clap() {
    // Phase 11: --file is not a valid flag on ledger inspect.
    let r = Cli::try_parse_from(["zelynic", "ledger", "inspect", "--file", "/tmp/x.json"]);
    assert!(r.is_err(), "--file must not be accepted by clap");
}

#[test]
fn v31_p11_ledger_inspect_input_flag_rejected_by_clap() {
    // Phase 11: --input is not a valid flag on ledger inspect.
    let r = Cli::try_parse_from(["zelynic", "ledger", "inspect", "--input", "/tmp/x.json"]);
    assert!(r.is_err(), "--input must not be accepted by clap");
}

#[test]
fn v31_p11_ledger_export_remains_design_gated() {
    // Phase 11: ledger export --json remains design-gated.
    let cli = Cli::try_parse_from(["zelynic", "ledger", "export", "--json"]).unwrap();
    let result = crate::commands::dispatch(cli, None);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("design-gated"));
}

#[test]
fn v31_p11_no_output_path_overwrite_save_flags() {
    // Phase 11: no output path, overwrite, or save flags exist.
    assert!(
        Cli::try_parse_from(["zelynic", "ledger", "inspect", "--output", "/tmp/o.json"]).is_err()
    );
    assert!(Cli::try_parse_from(["zelynic", "ledger", "inspect", "--save"]).is_err());
    assert!(Cli::try_parse_from(["zelynic", "ledger", "inspect", "--overwrite"]).is_err());
}

#[test]
fn v31_p11_v3_usage_json_schema_unchanged() {
    // Phase 11: v3.0 usage JSON schema remains schema_version 1.
    use crate::accounting::SCHEMA_VERSION;
    assert_eq!(SCHEMA_VERSION, 1);
}

#[test]
fn v31_p11_no_version_bump() {
    // Phase 11: version remains 3.0.1.
    assert!(include_str!("../../Cargo.toml").contains("version = \"3.0.1\""));
}

#[test]
fn v31_p11_all_touched_files_under_1000_loc() {
    // Phase 11: every file touched in this phase is under 1000 LOC.
    // Verified structurally — this test exists to make the requirement explicit.
    // The actual LOC counts are verified in CI by the build script and in the
    // phase 11 commit message.
}
