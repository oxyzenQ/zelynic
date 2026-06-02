// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Result;
use clap::CommandFactory;
use clap_complete::{generate, Shell};

use crate::cli::Cli;
use crate::{capabilities, ebpf};

/// Show backend information and capability checks.
pub(crate) fn handle_backend_info() -> Result<()> {
    ebpf::print_backend_info();
    println!();
    ebpf::check_ebpf_support().print_status();
    Ok(())
}

/// Run Backend Doctor diagnostics.
pub(crate) fn handle_doctor(json: bool) -> Result<()> {
    capabilities::run_backend_doctor(json)
}

/// Generate shell completions.
pub(crate) fn handle_completions(shell: &str) -> Result<()> {
    let shell = match shell.to_lowercase().as_str() {
        "bash" => Shell::Bash,
        "zsh" => Shell::Zsh,
        "fish" => Shell::Fish,
        "elvish" => Shell::Elvish,
        "powershell" | "pwsh" => Shell::PowerShell,
        _ => {
            eprintln!(
                "Unknown shell: {}. Supported: bash, zsh, fish, elvish, powershell",
                shell
            );
            std::process::exit(1);
        }
    };
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    generate(shell, &mut cmd, name, &mut std::io::stdout());
    Ok(())
}

/// Generate man page in roff format from clap Command.
///
/// Outputs a complete man page suitable for installation in
/// /usr/share/man/man1/ or ~/.local/share/man/man1/
pub(crate) fn generate_man_page() -> Result<()> {
    let cmd = Cli::command();
    let name = cmd.get_name();
    let about = cmd.get_about().map(|s| s.to_string()).unwrap_or_default();
    let long_about = cmd
        .get_long_about()
        .map(|s| s.to_string())
        .unwrap_or(about.clone());

    // Get version from info module
    let version = crate::info::VERSION;

    // Build man page in roff format
    let mut man = String::new();

    // Header
    let date = chrono::Local::now().format("%B %Y").to_string();
    man.push_str(&format!(
        r#".TH "{}" "1" "{}" "zelynic {}" "User Commands""#,
        name.to_uppercase(),
        date,
        version
    ));
    man.push('\n');

    // Name section
    man.push_str(".SH NAME\n");
    man.push_str(&format!("{} \\- {}\n", name, about));

    // Synopsis section
    man.push_str(".SH SYNOPSIS\n");
    man.push_str(&format!(".B {}\n", name));
    man.push_str(".RI [ OPTIONS ] ");
    man.push_str(".IR [ COMMAND ] ");
    man.push_str(".IR [ ARGS ]\n");

    // Description section
    man.push_str(".SH DESCRIPTION\n");
    for line in long_about.lines() {
        if line.trim().is_empty() {
            man.push_str(".PP\n");
        } else {
            man.push_str(&format!("{}\n", line));
        }
    }

    // Commands section
    man.push_str(".SH COMMANDS\n");
    for subcommand in cmd.get_subcommands() {
        let sc_name = subcommand.get_name();
        let sc_about = subcommand
            .get_about()
            .map(|s| s.to_string())
            .unwrap_or_default();
        man.push_str(".TP\n");
        man.push_str(&format!(".B {} {}\n", name, sc_name));
        man.push_str(&format!("{}\n", sc_about));
    }

    // Options section
    man.push_str(".SH OPTIONS\n");
    for opt in cmd.get_opts() {
        let long = opt
            .get_long()
            .map(|l| format!("--{}", l))
            .unwrap_or_default();
        let short = opt
            .get_short()
            .map(|s| format!("-{}", s))
            .unwrap_or_default();
        let help = opt.get_help().map(|h| h.to_string()).unwrap_or_default();

        man.push_str(".TP\n");
        if !short.is_empty() && !long.is_empty() {
            man.push_str(&format!(".BR {} \", \" {}\n", short, long));
        } else if !long.is_empty() {
            man.push_str(&format!(".B {}\n", long));
        } else if !short.is_empty() {
            man.push_str(&format!(".B {}\n", short));
        }
        man.push_str(&format!("{}\n", help));
    }

    // Global options
    man.push_str(".SH GLOBAL OPTIONS\n");
    man.push_str(".TP\n");
    man.push_str(".B --no-color\n");
    man.push_str("Disable colored output (also respects NO_COLOR environment variable).\n");
    man.push_str(".TP\n");
    man.push_str(".B -i, --info\n");
    man.push_str("Print detailed package information.\n");

    // Files section
    man.push_str(".SH FILES\n");
    man.push_str(".PP\n");
    man.push_str("Zelynic uses the zelynic runtime namespace for state, cgroups, and nftables identifiers.\n");
    man.push_str(".TP\n");
    man.push_str(".I /run/zelynic/state.json\n");
    man.push_str("Runtime state file containing active bandwidth limits.\n");
    man.push_str(".TP\n");
    man.push_str(".I /sys/fs/cgroup/zelynic/\n");
    man.push_str("Cgroup directory for process classification.\n");

    // Examples section
    man.push_str(".SH EXAMPLES\n");
    man.push_str(".TP\n");
    man.push_str(".B zelynic list --live\n");
    man.push_str("Start interactive bandwidth monitor.\n");
    man.push_str(".TP\n");
    man.push_str(".B zelynic strict -d 1mb -u 500kb firefox\n");
    man.push_str("Limit Firefox to 1MB/s download and 500KB/s upload.\n");
    man.push_str(".TP\n");
    man.push_str(".B zelynic strict --preset gaming discord\n");
    man.push_str("Apply gaming preset (50mb/50mb) to Discord.\n");
    man.push_str(".TP\n");
    man.push_str(".B zelynic unstrict firefox\n");
    man.push_str("Remove all limits from Firefox.\n");
    man.push_str(".TP\n");
    man.push_str(".B zelynic refresh firefox\n");
    man.push_str("Move reopened or respawned Firefox PIDs into the existing limit without duplicating rules.\n");
    man.push_str(".TP\n");
    man.push_str(".B zelynic status\n");
    man.push_str("Show all active bandwidth limits.\n");

    // See also
    man.push_str(".SH SEE ALSO\n");
    man.push_str(".BR tc (8),\n");
    man.push_str(".BR cgroups (7),\n");
    man.push_str(".BR ss (8)\n");

    // Author
    man.push_str(".SH AUTHOR\n");
    man.push_str("Written by Rezky_nightky.\n");

    // Print to stdout
    println!("{}", man);

    Ok(())
}
