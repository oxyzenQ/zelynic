// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
/// zelynic - Easy userspace bandwidth manager for Linux
///
/// zelynic provides a simple CLI interface for monitoring and limiting
/// per-process network bandwidth on Linux systems. It uses Linux
/// traffic control (tc) with HTB qdisc and cgroups for rate limiting,
/// and the `ss` utility for bandwidth monitoring.
mod auto;
mod capabilities;
mod cli;
mod commands;
mod ebpf;
mod info;
mod limiter;
mod log;
mod monitor;
mod profile;
mod qos;
mod systemd_wrapper;
mod tui;
mod units;
mod watch;

use anyhow::Result;
use clap::Parser;
use colored::Colorize;

use cli::Cli;

fn main() -> Result<()> {
    // Handle -v (lowercase) before clap parsing, since clap reserves -V for --version
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && (args[1] == "-v" || args[1] == "--ver") {
        info::print_version();
        return Ok(());
    }

    let cli = Cli::parse();

    // Handle --help-all before anything else
    if cli.help_all {
        commands::help::print_help_all();
        return Ok(());
    }

    // Disable colors if --no-color flag is set or NO_COLOR env var is present
    if cli.no_color || std::env::var("NO_COLOR").is_ok() {
        colored::control::set_override(false);
    }

    // Handle -i / --info flag (takes priority over subcommands)
    if cli.info {
        info::print_info();
        return Ok(());
    }

    // Handle --iface with no value -> list available interfaces and exit
    if matches!(&cli.iface, Some(None)) {
        let ifaces = limiter::list_interfaces();
        if ifaces.is_empty() {
            println!("No network interfaces found.");
        } else {
            // Show default interface if detectable
            let default = limiter::get_default_interface().ok();
            println!("{}", "Available network interfaces:".bold());
            for iface in &ifaces {
                let marker =
                    default
                        .as_ref()
                        .map_or("", |d| if *d == *iface { " (default)" } else { "" });
                println!("  {}{}", iface.cyan(), marker.dimmed());
            }
        }
        return Ok(());
    }

    // Extract iface value: Some(Some("eth0")) -> Some("eth0"), else None
    // Clone to own the string before moving cli into dispatch.
    let iface_value = cli
        .iface
        .as_ref()
        .and_then(|v| v.as_deref())
        .map(|s| s.to_string());

    // If --iface was given a value, validate it early (before subcommand match)
    // so invalid interfaces always error, regardless of what else was typed.
    if let Some(ref iface_name) = iface_value {
        limiter::validate_interface(iface_name)?;
    }

    // Dispatch to command handlers
    commands::dispatch(cli, iface_value.as_deref())
}
