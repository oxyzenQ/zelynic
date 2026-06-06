// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use super::*;
use clap::{CommandFactory, Parser};

#[test]
fn strict_diagnose_flag_parses() {
    let cli =
        Cli::try_parse_from(["zelynic", "strict", "--diagnose", "-d", "1mb", "firefox"]).unwrap();

    match cli.command.unwrap() {
        Commands::Strict {
            diagnose, target, ..
        } => {
            assert!(diagnose);
            assert_eq!(target, "firefox");
        }
        other => panic!("expected strict command, got {other:?}"),
    }
}

#[test]
fn strict_diag_alias_parses() {
    let cli = Cli::try_parse_from(["zelynic", "strict", "--diag", "-u", "250kb", "1234"]).unwrap();

    match cli.command.unwrap() {
        Commands::Strict {
            diagnose, target, ..
        } => {
            assert!(diagnose);
            assert_eq!(target, "1234");
        }
        other => panic!("expected strict command, got {other:?}"),
    }
}

#[test]
fn strict_diagnose_defaults_false() {
    let cli = Cli::try_parse_from(["zelynic", "strict", "-d", "1mb", "firefox"]).unwrap();

    match cli.command.unwrap() {
        Commands::Strict { diagnose, .. } => assert!(!diagnose),
        other => panic!("expected strict command, got {other:?}"),
    }
}

#[test]
fn refresh_command_parses_target() {
    let cli = Cli::try_parse_from(["zelynic", "refresh", "brave"]).unwrap();

    match cli.command.unwrap() {
        Commands::Refresh { target } => assert_eq!(target, "brave"),
        other => panic!("expected refresh command, got {other:?}"),
    }
}

#[test]
fn run_dry_run_parses_command_after_separator() {
    let cli = Cli::try_parse_from([
        "zelynic",
        "run",
        "--dry-run",
        "-d",
        "500kbit",
        "-u",
        "500kbit",
        "--",
        "echo",
        "hello",
    ])
    .unwrap();

    match cli.command.unwrap() {
        Commands::Run {
            dry_run,
            execute,
            probe_live,
            attach_live,
            experimental_single_pid_attach,
            i_understand_this_moves_pids,
            rollback_required,
            scope_mode,
            download,
            upload,
            command,
            ..
        } => {
            assert!(dry_run);
            assert!(!execute);
            assert!(!probe_live);
            assert!(!attach_live);
            assert!(!experimental_single_pid_attach);
            assert!(!i_understand_this_moves_pids);
            assert!(!rollback_required);
            assert_eq!(scope_mode, RunScopeModeArg::User);
            assert_eq!(download.as_deref(), Some("500kbit"));
            assert_eq!(upload.as_deref(), Some("500kbit"));
            assert_eq!(command, vec!["echo", "hello"]);
        }
        other => panic!("expected run command, got {other:?}"),
    }
}

#[test]
fn run_execute_parses_command_after_separator() {
    let cli = Cli::try_parse_from([
        "zelynic",
        "run",
        "--execute",
        "-d",
        "500kbit",
        "--",
        "echo",
        "hello",
    ])
    .unwrap();

    match cli.command.unwrap() {
        Commands::Run {
            dry_run,
            execute,
            probe_live,
            attach_live,
            experimental_single_pid_attach,
            i_understand_this_moves_pids,
            rollback_required,
            scope_mode,
            download,
            command,
            ..
        } => {
            assert!(!dry_run);
            assert!(execute);
            assert!(!probe_live);
            assert!(!attach_live);
            assert!(!experimental_single_pid_attach);
            assert!(!i_understand_this_moves_pids);
            assert!(!rollback_required);
            assert_eq!(scope_mode, RunScopeModeArg::User);
            assert_eq!(download.as_deref(), Some("500kbit"));
            assert_eq!(command, vec!["echo", "hello"]);
        }
        other => panic!("expected run command, got {other:?}"),
    }
}

#[test]
fn run_dry_run_and_execute_conflict() {
    let result = Cli::try_parse_from([
        "zelynic",
        "run",
        "--dry-run",
        "--execute",
        "--",
        "echo",
        "hello",
    ]);

    assert!(result.is_err());
}

#[test]
fn run_scope_mode_system_parses_for_planning() {
    let cli = Cli::try_parse_from([
        "zelynic",
        "run",
        "--dry-run",
        "--scope-mode",
        "system",
        "--",
        "echo",
        "hello",
    ])
    .unwrap();

    match cli.command.unwrap() {
        Commands::Run { scope_mode, .. } => assert_eq!(scope_mode, RunScopeModeArg::System),
        other => panic!("expected run command, got {other:?}"),
    }
}

#[test]
fn run_probe_live_parses_with_execute_and_system() {
    let cli = Cli::try_parse_from([
        "zelynic",
        "run",
        "--execute",
        "--scope-mode",
        "system",
        "--probe-live",
        "-d",
        "500kbit",
        "--",
        "sleep",
        "30",
    ])
    .unwrap();

    match cli.command.unwrap() {
        Commands::Run {
            dry_run,
            execute,
            probe_live,
            attach_live,
            experimental_single_pid_attach,
            i_understand_this_moves_pids,
            rollback_required,
            scope_mode,
            download,
            command,
            ..
        } => {
            assert!(!dry_run);
            assert!(execute);
            assert!(probe_live);
            assert!(!attach_live);
            assert!(!experimental_single_pid_attach);
            assert!(!i_understand_this_moves_pids);
            assert!(!rollback_required);
            assert_eq!(scope_mode, RunScopeModeArg::System);
            assert_eq!(download.as_deref(), Some("500kbit"));
            assert_eq!(command, vec!["sleep", "30"]);
        }
        other => panic!("expected run command, got {other:?}"),
    }
}

#[test]
fn run_probe_live_requires_execute() {
    let result = Cli::try_parse_from([
        "zelynic",
        "run",
        "--probe-live",
        "--scope-mode",
        "system",
        "--",
        "sleep",
        "30",
    ]);

    assert!(result.is_err());
}

#[test]
fn run_probe_live_defaults_false() {
    let cli = Cli::try_parse_from([
        "zelynic",
        "run",
        "--execute",
        "--scope-mode",
        "system",
        "--",
        "sleep",
        "30",
    ])
    .unwrap();

    match cli.command.unwrap() {
        Commands::Run {
            probe_live,
            attach_live,
            ..
        } => {
            assert!(!probe_live);
            assert!(!attach_live);
        }
        other => panic!("expected run command, got {other:?}"),
    }
}

#[test]
fn run_attach_live_parses_with_probe_live_and_system() {
    let cli = Cli::try_parse_from([
        "zelynic",
        "run",
        "--execute",
        "--scope-mode",
        "system",
        "--probe-live",
        "--attach-live",
        "-d",
        "500kbit",
        "-u",
        "500kbit",
        "--",
        "sleep",
        "60",
    ])
    .unwrap();

    match cli.command.unwrap() {
        Commands::Run {
            dry_run,
            execute,
            probe_live,
            attach_live,
            experimental_single_pid_attach,
            i_understand_this_moves_pids,
            rollback_required,
            scope_mode,
            download,
            upload,
            command,
            ..
        } => {
            assert!(!dry_run);
            assert!(execute);
            assert!(probe_live);
            assert!(attach_live);
            assert!(!experimental_single_pid_attach);
            assert!(!i_understand_this_moves_pids);
            assert!(!rollback_required);
            assert_eq!(scope_mode, RunScopeModeArg::System);
            assert_eq!(download.as_deref(), Some("500kbit"));
            assert_eq!(upload.as_deref(), Some("500kbit"));
            assert_eq!(command, vec!["sleep", "60"]);
        }
        other => panic!("expected run command, got {other:?}"),
    }
}

#[test]
fn run_attach_live_requires_execute() {
    let result = Cli::try_parse_from([
        "zelynic",
        "run",
        "--attach-live",
        "--probe-live",
        "--",
        "sleep",
        "30",
    ]);

    assert!(result.is_err());
}

#[test]
fn run_attach_live_requires_probe_live() {
    let result = Cli::try_parse_from([
        "zelynic",
        "run",
        "--execute",
        "--scope-mode",
        "system",
        "--attach-live",
        "--",
        "sleep",
        "30",
    ]);

    assert!(result.is_err());
}

#[test]
fn run_attach_live_defaults_false() {
    let cli = Cli::try_parse_from([
        "zelynic",
        "run",
        "--execute",
        "--scope-mode",
        "system",
        "--probe-live",
        "--",
        "sleep",
        "30",
    ])
    .unwrap();

    match cli.command.unwrap() {
        Commands::Run { attach_live, .. } => assert!(!attach_live),
        other => panic!("expected run command, got {other:?}"),
    }
}

#[test]
fn run_experimental_attach_flags_parse() {
    let cli = Cli::try_parse_from([
        "zelynic",
        "run",
        "--execute",
        "--scope-mode",
        "system",
        "--probe-live",
        "--attach-live",
        "--experimental-single-pid-attach",
        "--i-understand-this-moves-pids",
        "--rollback-required",
        "--",
        "sleep",
        "30",
    ])
    .unwrap();

    match cli.command.unwrap() {
        Commands::Run {
            experimental_single_pid_attach,
            i_understand_this_moves_pids,
            rollback_required,
            ..
        } => {
            assert!(experimental_single_pid_attach);
            assert!(i_understand_this_moves_pids);
            assert!(rollback_required);
        }
        other => panic!("expected run command, got {other:?}"),
    }
}

#[test]
fn run_experimental_attach_flags_default_false() {
    let cli = Cli::try_parse_from([
        "zelynic",
        "run",
        "--execute",
        "--scope-mode",
        "system",
        "--probe-live",
        "--attach-live",
        "--",
        "sleep",
        "30",
    ])
    .unwrap();

    match cli.command.unwrap() {
        Commands::Run {
            experimental_single_pid_attach,
            i_understand_this_moves_pids,
            rollback_required,
            ..
        } => {
            assert!(!experimental_single_pid_attach);
            assert!(!i_understand_this_moves_pids);
            assert!(!rollback_required);
        }
        other => panic!("expected run command, got {other:?}"),
    }
}

#[test]
fn run_experimental_attach_flags_require_attach_live() {
    let result = Cli::try_parse_from([
        "zelynic",
        "run",
        "--execute",
        "--scope-mode",
        "system",
        "--probe-live",
        "--experimental-single-pid-attach",
        "--",
        "sleep",
        "30",
    ]);

    assert!(result.is_err());
}

#[test]
fn run_help_mentions_execute_is_experimental() {
    let mut command = Cli::command();
    let help = command
        .find_subcommand_mut("run")
        .expect("run subcommand")
        .render_long_help()
        .to_string();

    assert!(help.contains("--execute"));
    assert!(help.contains("Experimental live execution opt-in"));
    assert!(help.contains("--experimental-single-pid-attach"));
    assert!(help.contains("--i-understand-this-moves-pids"));
    assert!(help.contains("--rollback-required"));
    assert!(help.contains("--scope-mode"));
    assert!(help.contains("Possible values:"));
    assert!(help.contains("user:"));
    assert!(help.contains("system:"));
}

// ---- --mkdir-live tests ----

#[test]
fn usage_sample_parses() {
    let cli = Cli::try_parse_from(["zelynic", "usage", "--sample"]).unwrap();

    match cli.command.unwrap() {
        Commands::Usage { sample, json } => {
            assert!(sample);
            assert!(!json);
        }
        other => panic!("expected usage command, got {other:?}"),
    }
}

#[test]
fn usage_requires_sample_flag() {
    let result = Cli::try_parse_from(["zelynic", "usage"]);
    // Without --sample, clap should error because sample is required.
    assert!(result.is_err());
}

#[test]
fn usage_help_mentions_sample() {
    let mut command = Cli::command();
    let help = command
        .find_subcommand_mut("usage")
        .expect("usage subcommand")
        .render_long_help()
        .to_string();

    assert!(help.contains("--sample"));
    assert!(help.contains("live read-only"));
    assert!(help.contains("/proc/net/dev"));
}

// ---- --mkdir-live tests ----

#[test]
fn run_mkdir_live_defaults_false() {
    let cli = Cli::try_parse_from([
        "zelynic",
        "run",
        "--execute",
        "--scope-mode",
        "system",
        "--probe-live",
        "--attach-live",
        "--experimental-single-pid-attach",
        "--i-understand-this-moves-pids",
        "--rollback-required",
        "--",
        "sleep",
        "30",
    ])
    .unwrap();

    match cli.command.unwrap() {
        Commands::Run { mkdir_live, .. } => assert!(!mkdir_live),
        other => panic!("expected run command, got {other:?}"),
    }
}

#[test]
fn run_mkdir_live_parses_with_full_consent_bundle() {
    let cli = Cli::try_parse_from([
        "zelynic",
        "run",
        "--execute",
        "--scope-mode",
        "system",
        "--probe-live",
        "--attach-live",
        "--experimental-single-pid-attach",
        "--i-understand-this-moves-pids",
        "--rollback-required",
        "--mkdir-live",
        "-d",
        "500kbit",
        "-u",
        "500kbit",
        "--",
        "sleep",
        "3",
    ])
    .unwrap();

    match cli.command.unwrap() {
        Commands::Run {
            execute,
            probe_live,
            attach_live,
            experimental_single_pid_attach,
            i_understand_this_moves_pids,
            rollback_required,
            mkdir_live,
            download,
            upload,
            command,
            ..
        } => {
            assert!(execute);
            assert!(probe_live);
            assert!(attach_live);
            assert!(experimental_single_pid_attach);
            assert!(i_understand_this_moves_pids);
            assert!(rollback_required);
            assert!(mkdir_live);
            assert_eq!(download.as_deref(), Some("500kbit"));
            assert_eq!(upload.as_deref(), Some("500kbit"));
            assert_eq!(command, vec!["sleep", "3"]);
        }
        other => panic!("expected run command, got {other:?}"),
    }
}

#[test]
fn run_mkdir_live_requires_execute() {
    let result = Cli::try_parse_from([
        "zelynic",
        "run",
        "--scope-mode",
        "system",
        "--probe-live",
        "--attach-live",
        "--experimental-single-pid-attach",
        "--i-understand-this-moves-pids",
        "--rollback-required",
        "--mkdir-live",
        "--",
        "sleep",
        "3",
    ]);

    assert!(result.is_err());
}

#[test]
fn run_mkdir_live_requires_probe_live() {
    let result = Cli::try_parse_from([
        "zelynic",
        "run",
        "--execute",
        "--scope-mode",
        "system",
        "--attach-live",
        "--experimental-single-pid-attach",
        "--i-understand-this-moves-pids",
        "--rollback-required",
        "--mkdir-live",
        "--",
        "sleep",
        "3",
    ]);

    assert!(result.is_err());
}

#[test]
fn run_mkdir_live_requires_attach_live() {
    let result = Cli::try_parse_from([
        "zelynic",
        "run",
        "--execute",
        "--scope-mode",
        "system",
        "--probe-live",
        "--experimental-single-pid-attach",
        "--i-understand-this-moves-pids",
        "--rollback-required",
        "--mkdir-live",
        "--",
        "sleep",
        "3",
    ]);

    assert!(result.is_err());
}

#[test]
fn run_mkdir_live_requires_experimental_single_pid_attach() {
    let result = Cli::try_parse_from([
        "zelynic",
        "run",
        "--execute",
        "--scope-mode",
        "system",
        "--probe-live",
        "--attach-live",
        "--i-understand-this-moves-pids",
        "--rollback-required",
        "--mkdir-live",
        "--",
        "sleep",
        "3",
    ]);

    assert!(result.is_err());
}

#[test]
fn run_mkdir_live_requires_i_understand_this_moves_pids() {
    let result = Cli::try_parse_from([
        "zelynic",
        "run",
        "--execute",
        "--scope-mode",
        "system",
        "--probe-live",
        "--attach-live",
        "--experimental-single-pid-attach",
        "--rollback-required",
        "--mkdir-live",
        "--",
        "sleep",
        "3",
    ]);

    assert!(result.is_err());
}

#[test]
fn run_mkdir_live_requires_rollback_required() {
    let result = Cli::try_parse_from([
        "zelynic",
        "run",
        "--execute",
        "--scope-mode",
        "system",
        "--probe-live",
        "--attach-live",
        "--experimental-single-pid-attach",
        "--i-understand-this-moves-pids",
        "--mkdir-live",
        "--",
        "sleep",
        "3",
    ]);

    assert!(result.is_err());
}

#[test]
fn run_help_mentions_mkdir_live() {
    let mut command = Cli::command();
    let help = command
        .find_subcommand_mut("run")
        .expect("run subcommand")
        .render_long_help()
        .to_string();

    assert!(help.contains("--mkdir-live"));
    assert!(help.contains("mkdir-only"));
}
