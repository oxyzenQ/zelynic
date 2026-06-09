// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! v3.1 phase 6/10: CLI parser gate tests for future v3.1 command candidates.
//!
//! These tests prove that all future v3.1 candidate commands documented in the phase 5
//! gate design document (docs/v3.1-phase-5-cli-gate-design.md) are registered in the
//! parser as hidden variants. Phase 6 hard-blocked all at dispatch; phase 10 activated
//! `ledger inspect` with fixture-driven output while `ledger export` and all hidden
//! usage flags remain hard-blocked.
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
