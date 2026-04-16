/// oxy - Easy userspace bandwidth manager for Linux
///
/// oxy provides a simple CLI interface for monitoring and limiting
/// per-process network bandwidth on Linux systems. It uses Linux
/// traffic control (tc) with HTB qdisc and cgroups for rate limiting,
/// and the `ss` utility for bandwidth monitoring.
mod auto;
mod cli;
mod info;
mod limiter;
mod log;
mod monitor;
mod profile;
mod qos;
mod tui;
mod units;
mod watch;

use anyhow::Result;
use clap::{CommandFactory, Parser};
use clap_complete::{generate, Shell};
use colored::Colorize;

use cli::{Cli, Commands, ProfileCommands, QosCommands};

fn main() -> Result<()> {
    // Handle -v (lowercase) before clap parsing, since clap reserves -V for --version
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && (args[1] == "-v" || args[1] == "--ver") {
        info::print_version();
        return Ok(());
    }

    let cli = Cli::parse();

    // Disable colors if --no-color flag is set or NO_COLOR env var is present
    if cli.no_color || std::env::var("NO_COLOR").is_ok() {
        colored::control::set_override(false);
    }

    // Handle -i / --info flag (takes priority over subcommands)
    if cli.info {
        info::print_info();
        return Ok(());
    }

    // Handle subcommands
    match cli.command {
        Some(Commands::List {
            usage_all,
            high_to_low,
            json,
            live,
            interval,
            verbose,
        }) => {
            if live {
                let interval_secs = interval.unwrap_or(1);
                monitor::display_usage_live(interval_secs)?;
            } else if json {
                monitor::display_usage_json()?;
            } else if verbose {
                monitor::display_usage_verbose()?;
            } else if !usage_all && !high_to_low {
                // Default: show usage-all if no flag specified
                monitor::display_usage_all()?;
            } else if usage_all {
                monitor::display_usage_all()?;
            } else {
                monitor::display_usage_high_to_low()?;
            }
        }

        Some(Commands::Strict {
            download,
            upload,
            preset,
            target,
        }) => {
            // Resolve preset values if specified
            let (mut dl_value, mut ul_value) = (download, upload);

            if let Some(preset_name) = preset {
                // Validate preset name
                let preset_lower = preset_name.to_lowercase();
                let (preset_dl, preset_ul) = match preset_lower.as_str() {
                    "gaming" => ("50mb", "50mb"),
                    "streaming" => ("10mb", "5mb"),
                    "background" => ("500kb", "100kb"),
                    _ => {
                        eprintln!(
                            "Unknown preset: {}. Available: gaming, streaming, background",
                            preset_name
                        );
                        std::process::exit(1);
                    }
                };

                // Check for conflicts with explicit -d/-u
                if dl_value.is_some() || ul_value.is_some() {
                    eprintln!(
                        "Error: --preset conflicts with -d/--download and -u/--upload options.\n\
                         Use either --preset OR -d/-u, not both."
                    );
                    std::process::exit(1);
                }

                dl_value = Some(preset_dl.to_string());
                ul_value = Some(preset_ul.to_string());

                println!(
                    "Using {} preset: {} down / {} up",
                    preset_lower, preset_dl, preset_ul
                );
            }

            // Check for "only" keyword in download/upload values
            let download_only = dl_value
                .as_deref()
                .is_some_and(|v| v.eq_ignore_ascii_case("only"));
            let upload_only = ul_value
                .as_deref()
                .is_some_and(|v| v.eq_ignore_ascii_case("only"));

            let dl_ref = if download_only {
                None
            } else {
                dl_value.as_deref()
            };
            let ul_ref = if upload_only {
                None
            } else {
                ul_value.as_deref()
            };

            limiter::apply_limit(&target, dl_ref, ul_ref, download_only, upload_only)?;
        }

        Some(Commands::Unstrict { target }) => {
            limiter::remove_limit(&target)?;
        }

        Some(Commands::Status) => {
            limiter::list_active_limits()?;
        }

        Some(Commands::Clean) => {
            limiter::clean_orphans()?;
        }

        Some(Commands::Log {
            snapshot,
            last,
            json,
        }) => {
            if snapshot {
                log::save_snapshot()?;
            } else {
                log::show_history(last, json)?;
            }
        }

        Some(Commands::Profile { command }) => match command {
            ProfileCommands::Save {
                name,
                download,
                upload,
            } => {
                profile::save_profile(&name, download.as_deref(), upload.as_deref())?;
            }
            ProfileCommands::Apply { name, target } => {
                profile::apply_profile(&name, &target)?;
            }
            ProfileCommands::List => {
                profile::list_profiles()?;
            }
            ProfileCommands::Delete { name } => {
                profile::delete_profile(&name)?;
            }
        },

        Some(Commands::Qos { command }) => match command {
            QosCommands::High { target } => {
                qos::set_priority(&target, qos::PriorityTier::High)?;
            }
            QosCommands::Low { target } => {
                qos::set_priority(&target, qos::PriorityTier::Low)?;
            }
            QosCommands::Status => {
                qos::show_qos_status()?;
            }
            QosCommands::Reset => {
                qos::reset_qos()?;
            }
        },

        Some(Commands::Watch {
            alert,
            target,
            interval,
            notify_cmd,
        }) => {
            watch::watch_process(&target, &alert, interval, notify_cmd.as_deref())?;
        }

        Some(Commands::Auto {
            download,
            upload,
            target,
            kill,
            daemon,
            interval,
        }) => {
            auto::run_auto(
                download.as_deref(),
                upload.as_deref(),
                target.as_deref(),
                kill,
                daemon,
                interval,
            )?;
        }

        Some(Commands::Completions { shell }) => {
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
        }

        Some(Commands::Man) => {
            generate_man_page()?;
        }

        None => {
            // No subcommand and no -i flag: print help
            print_banner();
            Cli::parse_from(["oxy", "--help"]);
        }
    }

    Ok(())
}

/// Print the oxy ASCII banner on startup (when no arguments given).
fn print_banner() {
    let banner = r#"
     ╔═╗╔═╗╦ ╦
     ║ ║╠═╝╚╦╝
     ╚═╝╩   ╩
    "#;
    println!("{}", banner.cyan());
    println!();
    println!(
        "  {} | {}",
        "Easy userspace bandwidth manager for Linux".dimmed(),
        format!("v{}", info::VERSION).dimmed()
    );
    println!();
}

/// Generate man page in roff format from clap Command.
///
/// Outputs a complete man page suitable for installation in
/// /usr/share/man/man1/ or ~/.local/share/man/man1/
fn generate_man_page() -> anyhow::Result<()> {
    let cmd = Cli::command();
    let name = cmd.get_name();
    let about = cmd.get_about().map(|s| s.to_string()).unwrap_or_default();
    let long_about = cmd
        .get_long_about()
        .map(|s| s.to_string())
        .unwrap_or(about.clone());

    // Get version from info module
    let version = info::VERSION;

    // Build man page in roff format
    let mut man = String::new();

    // Header
    let date = chrono::Local::now().format("%B %Y").to_string();
    man.push_str(&format!(
        r#".TH "{}" "1" "{}" "oxy {}" "User Commands""#,
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
    man.push_str(".TP\n");
    man.push_str(".I /run/oxy/state.json\n");
    man.push_str("Runtime state file containing active bandwidth limits.\n");
    man.push_str(".TP\n");
    man.push_str(".I /sys/fs/cgroup/oxy/\n");
    man.push_str("Cgroup directory for process classification.\n");

    // Examples section
    man.push_str(".SH EXAMPLES\n");
    man.push_str(".TP\n");
    man.push_str(".B oxy list --live\n");
    man.push_str("Start interactive bandwidth monitor.\n");
    man.push_str(".TP\n");
    man.push_str(".B oxy strict -d 1mb -u 500kb firefox\n");
    man.push_str("Limit Firefox to 1MB/s download and 500KB/s upload.\n");
    man.push_str(".TP\n");
    man.push_str(".B oxy strict --preset gaming discord\n");
    man.push_str("Apply gaming preset (50mb/50mb) to Discord.\n");
    man.push_str(".TP\n");
    man.push_str(".B oxy unstrict firefox\n");
    man.push_str("Remove all limits from Firefox.\n");
    man.push_str(".TP\n");
    man.push_str(".B oxy status\n");
    man.push_str("Show all active bandwidth limits.\n");

    // See also
    man.push_str(".SH SEE ALSO\n");
    man.push_str(".BR tc (8),\n");
    man.push_str(".BR cgroups (7),\n");
    man.push_str(".BR ss (8)\n");

    // Author
    man.push_str(".SH AUTHOR\n");
    man.push_str("Written by rezky_nightky.\n");

    // Print to stdout
    println!("{}", man);

    Ok(())
}
