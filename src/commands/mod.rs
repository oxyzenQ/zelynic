// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Command handlers for all zelynic CLI subcommands.
//!
//! This module provides the top-level dispatch that routes parsed CLI subcommands
//! to focused handler functions organized by domain. Each sub-file contains handlers
//! for a related set of commands.

pub(crate) mod backend;
pub(crate) mod help;
pub(crate) mod monitor;
pub(crate) mod profile;
pub(crate) mod run;
pub(crate) mod strict;

use anyhow::Result;
use clap::Parser;

use crate::cli::{BackendCommands, Cli, Commands, ProfileCommands, QosCommands};

/// Top-level CLI dispatch: match parsed subcommand and delegate to focused handlers.
pub(crate) fn dispatch(cli: Cli, iface_value: Option<&str>) -> Result<()> {
    match cli.command {
        Some(Commands::List {
            usage_all,
            high_to_low,
            json,
            live,
            interval,
            verbose,
        }) => monitor::handle_list(
            usage_all,
            high_to_low,
            json,
            live,
            interval,
            verbose,
            iface_value,
        ),

        Some(Commands::Strict {
            download,
            upload,
            preset,
            diagnose,
            target,
        }) => strict::handle_strict(download, upload, preset, diagnose, &target, iface_value),

        Some(Commands::Unstrict { target }) => strict::handle_unstrict(&target),

        Some(Commands::Refresh { target }) => strict::handle_refresh(&target),

        Some(Commands::Run {
            dry_run,
            execute,
            probe_live,
            attach_live,
            experimental_single_pid_attach,
            i_understand_this_moves_pids,
            rollback_required,
            mkdir_live,
            target,
            scope_mode,
            download,
            upload,
            command,
        }) => run::handle_run(
            dry_run,
            execute,
            probe_live,
            attach_live,
            experimental_single_pid_attach,
            i_understand_this_moves_pids,
            rollback_required,
            mkdir_live,
            target,
            scope_mode,
            download,
            upload,
            &command,
        ),

        Some(Commands::Status) => strict::handle_status(),

        Some(Commands::Clean { all }) => strict::handle_clean(all),

        Some(Commands::Log {
            snapshot,
            last,
            json,
        }) => monitor::handle_log(snapshot, last, json),

        Some(Commands::Profile { command }) => match command {
            ProfileCommands::Save {
                name,
                download,
                upload,
            } => profile::handle_profile_save(&name, download.as_deref(), upload.as_deref()),
            ProfileCommands::Apply { name, target } => {
                profile::handle_profile_apply(&name, &target, iface_value)
            }
            ProfileCommands::List => profile::handle_profile_list(),
            ProfileCommands::Delete { name } => profile::handle_profile_delete(&name),
        },

        Some(Commands::Qos { command }) => match command {
            QosCommands::High { target } => profile::handle_qos_high(&target, iface_value),
            QosCommands::Low { target } => profile::handle_qos_low(&target, iface_value),
            QosCommands::Status => profile::handle_qos_status(),
            QosCommands::Reset => profile::handle_qos_reset(iface_value),
        },

        Some(Commands::Watch {
            alert,
            target,
            interval,
            notify_cmd,
        }) => monitor::handle_watch(&target, &alert, interval, notify_cmd.as_deref()),

        Some(Commands::Auto {
            download,
            upload,
            target,
            kill,
            daemon,
            interval,
            status,
        }) => monitor::handle_auto(
            download.as_deref(),
            upload.as_deref(),
            target.as_deref(),
            kill,
            daemon,
            interval,
            iface_value,
            status,
        ),

        Some(Commands::Completions { shell }) => backend::handle_completions(&shell),

        Some(Commands::Man) => backend::generate_man_page(),

        Some(Commands::Backend { command }) => match command {
            Some(BackendCommands::Doctor(args)) => backend::handle_doctor(args.json),
            None => backend::handle_backend_info(),
        },

        None => {
            // No subcommand: print help
            Cli::parse_from(["zelynic", "--help"]);
            Ok(())
        }
    }
}
