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
use clap::{CommandFactory, Parser};
use clap_complete::{generate, Shell};
use colored::Colorize;

use cli::{BackendCommands, Cli, Commands, ProfileCommands, QosCommands};

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
        print_help_all();
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

    // Handle --iface with no value → list available interfaces and exit
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

    // Extract iface value: Some(Some("eth0")) → Some("eth0"), else None
    let iface_value = cli.iface.as_ref().and_then(|v| v.as_deref());

    // If --iface was given a value, validate it early (before subcommand match)
    // so invalid interfaces always error, regardless of what else was typed.
    if let Some(iface_name) = iface_value {
        limiter::validate_interface(iface_name)?;
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
            if live.is_some() {
                // --live N (shorthand) takes priority, then --interval, then default 1
                let interval_secs = live.and_then(|v| v).or(interval).unwrap_or(1);
                monitor::display_usage_live(interval_secs, iface_value)?;
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
            diagnose,
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

                dl_value = Some(preset_dl.to_string());
                ul_value = Some(preset_ul.to_string());

                println!(
                    "Using {} preset: {} down / {} up",
                    preset_lower, preset_dl, preset_ul
                );
            }

            limiter::apply_limit_with_diagnostics(
                &target,
                dl_value.as_deref(),
                ul_value.as_deref(),
                iface_value,
                diagnose,
            )?;
        }

        Some(Commands::Unstrict { target }) => {
            limiter::remove_limit(&target)?;
        }

        Some(Commands::Refresh { target }) => {
            limiter::refresh_limit(&target)?;
        }

        Some(Commands::Run {
            dry_run,
            execute,
            target,
            scope_mode,
            download,
            upload,
            command,
        }) => {
            let scope_mode = match scope_mode {
                cli::RunScopeModeArg::User => systemd_wrapper::ScopeMode::User,
                cli::RunScopeModeArg::System => systemd_wrapper::ScopeMode::System,
            };
            systemd_wrapper::run_systemd_wrapper(
                dry_run,
                execute,
                target.as_deref(),
                download.as_deref(),
                upload.as_deref(),
                scope_mode,
                &command,
            )?;
        }

        Some(Commands::Status) => {
            limiter::list_active_limits()?;
        }

        Some(Commands::Clean { all }) => {
            if all {
                limiter::emergency_cleanup()?;
            } else {
                limiter::clean_orphans()?;
            }
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
                profile::apply_profile(&name, &target, iface_value)?;
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
                qos::set_priority(&target, qos::PriorityTier::High, iface_value)?;
            }
            QosCommands::Low { target } => {
                qos::set_priority(&target, qos::PriorityTier::Low, iface_value)?;
            }
            QosCommands::Status => {
                qos::show_qos_status()?;
            }
            QosCommands::Reset => {
                qos::reset_qos(iface_value)?;
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
            status,
        }) => {
            if status {
                auto::auto_status()?;
            } else {
                auto::run_auto(
                    download.as_deref(),
                    upload.as_deref(),
                    target.as_deref(),
                    kill,
                    daemon,
                    interval,
                    iface_value,
                )?;
            }
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

        Some(Commands::Backend { command }) => match command {
            Some(BackendCommands::Doctor(args)) => {
                capabilities::run_backend_doctor(args.json)?;
            }
            None => {
                ebpf::print_backend_info();
                println!();
                ebpf::check_ebpf_support().print_status();
            }
        },

        None => {
            // No subcommand: print help
            Cli::parse_from(["zelynic", "--help"]);
        }
    }

    Ok(())
}

/// Print comprehensive help with all commands, options, and examples.
///
/// This is shown via `zelynic --help-all` and covers every subcommand with
/// practical usage examples that aren't visible in the default `-h` output.
fn print_help_all() {
    println!(
        "  {} | {}\n",
        "Easy userspace bandwidth manager for Linux".dimmed(),
        format!("v{}", info::VERSION).dimmed()
    );
    println!("{}", "USAGE".bold());
    println!("  zelynic [FLAGS] [COMMAND] [ARGS]\n");

    println!("{}", "FLAGS".bold());
    println!("  -i, --info              Print detailed package information");
    println!("  --no-color              Disable colored output");
    println!("  -v, --ver               Print version (short)");
    println!("  -V, --version           Print version (long)");
    println!("  -h, --help              Show basic help");
    println!(
        "  --help-all              {} Show this comprehensive help\n",
        "(you are here)".dimmed()
    );

    println!("{}", "COMMANDS".bold());
    println!();

    // --- list ---
    println!(
        "  {} {}",
        "list".green().bold(),
        "— List network bandwidth usage per process".dimmed()
    );
    println!(
        "    {} Track per-process bandwidth consumption (like htop for network).\n",
        "  ".dimmed()
    );
    println!("    {} Usage:", "  ".dimmed());
    println!("    {} zelynic list", "  ".dimmed());
    println!(
        "    {} zelynic list --live            # {} Real-time TUI dashboard (like iftop/bpftrace)",
        "  ".dimmed(),
        "RECOMMENDED".cyan()
    );
    println!(
        "    {} zelynic list --live 2          # Shorthand: 2s refresh interval",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic list --live --interval 2  # Explicit interval (same as above)",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic list --verbose          # Show individual socket connections",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic list --high-to-low-usage-net  # Sort by bandwidth (highest first)",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic list --usage-all        # Show all programs (default)",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic list --json             # JSON output for scripting",
        "  ".dimmed()
    );
    println!();
    println!(
        "    {} TUI keys: [q] Quit  [\u{2191}\u{2193}/j/k] Scroll  [Esc] Quit",
        "  ".dimmed()
    );
    println!();

    // --- strict ---
    println!(
        "  {} {}",
        "strict".green().bold(),
        "— Set bandwidth limits for a process".dimmed()
    );
    println!(
        "    {} Apply download/upload speed limits using tc + nftables.\n",
        "  ".dimmed()
    );
    println!("    {} Usage:", "  ".dimmed());
    println!(
        "    {} zelynic strict -d 500kb -u 500kb brave    # Limit both directions",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic strict -d 1mb firefox             # Download only limit (omit -u)",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic strict -u 250kb 1234             # Upload only limit (omit -d)",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic strict --preset gaming discord     # Use preset profile",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic strict --preset background steam",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic strict --diagnose -d 1mb firefox  # Print backend diagnostics while applying",
        "  ".dimmed()
    );
    println!();
    println!("    {} Presets:", "  ".dimmed());
    println!(
        "    {} gaming     → 50mb down / 50mb up    (low latency)",
        "  ".dimmed()
    );
    println!(
        "    {} streaming  → 10mb down / 5mb up     (video calls)",
        "  ".dimmed()
    );
    println!(
        "    {} background → 500kb down / 100kb up  (minimal)",
        "  ".dimmed()
    );
    println!();
    println!(
        "    {} Supported units: byte/bs, kb, mb, gb, kbit, mbit, gbit",
        "  ".dimmed()
    );
    println!(
        "    {} Minimum rate: 1kb (1 KB/s) | Maximum: no limit",
        "  ".dimmed()
    );
    println!();

    // --- unstrict ---
    println!(
        "  {} {}",
        "unstrict".green().bold(),
        "— Remove all bandwidth limits".dimmed()
    );
    println!(
        "    {} Removes tc classes, filters, cgroups, and nftables rules.\n",
        "  ".dimmed()
    );
    println!("    {} Usage:", "  ".dimmed());
    println!(
        "    {} zelynic unstrict brave            # By process name",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic unstrict 1234             # By PID",
        "  ".dimmed()
    );
    println!();

    // --- refresh ---
    println!(
        "  {} {}",
        "refresh".green().bold(),
        "— Move respawned target PIDs into an existing limit".dimmed()
    );
    println!(
        "    {} Reuses existing state, cgroup, nftables rules, and tc filters.\n",
        "  ".dimmed()
    );
    println!("    {} Usage:", "  ".dimmed());
    println!(
        "    {} sudo zelynic refresh brave        # Refresh reopened browser PIDs",
        "  ".dimmed()
    );
    println!(
        "    {} sudo zelynic refresh 1234         # Refresh by PID target",
        "  ".dimmed()
    );
    println!();

    // --- run ---
    println!(
        "  {} {}",
        "run".green().bold(),
        "— Experimental systemd scope wrapper planning".dimmed()
    );
    println!(
        "    {} Use --dry-run to preview. User scope is the default; --execute is gated.\n",
        "  ".dimmed()
    );
    println!("    {} Usage:", "  ".dimmed());
    println!(
        "    {} zelynic run --dry-run -d 500kbit -u 500kbit -- helium",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic run --dry-run --target helium -d 500kbit -- helium --flag",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic run --dry-run --scope-mode system -d 500kbit -- helium",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic run --execute -d 500kbit -u 500kbit -- helium  # Not implemented yet",
        "  ".dimmed()
    );
    println!();

    // --- status ---
    println!(
        "  {} {}",
        "status".green().bold(),
        "— Show active bandwidth limits".dimmed()
    );
    println!(
        "    {} Displays all currently applied limits with process info.\n",
        "  ".dimmed()
    );
    println!("    {} Usage: zelynic status", "  ".dimmed());
    println!();

    // --- clean ---
    println!(
        "  {} {}",
        "clean".green().bold(),
        "— Clean up orphaned bandwidth limits".dimmed()
    );
    println!(
        "    {} Removes tc/cgroup rules for processes that have already exited.\n",
        "  ".dimmed()
    );
    println!("    {} Usage: sudo zelynic clean", "  ".dimmed());
    println!();

    // --- profile ---
    println!(
        "  {} {}",
        "profile".green().bold(),
        "— Manage named bandwidth profiles".dimmed()
    );
    println!(
        "    {} Save/load custom profiles for quick application.\n",
        "  ".dimmed()
    );
    println!("    {} Usage:", "  ".dimmed());
    println!(
        "    {} zelynic profile save slow --dl 50kb --ul 50kb",
        "  ".dimmed()
    );
    println!("    {} zelynic profile apply slow brave", "  ".dimmed());
    println!("    {} zelynic profile list", "  ".dimmed());
    println!("    {} zelynic profile delete slow", "  ".dimmed());
    println!();

    // --- qos ---
    println!(
        "  {} {}",
        "qos".green().bold(),
        "— QoS priority-based bandwidth shaping".dimmed()
    );
    println!("    {} Assign priority tiers instead of hard limits. High priority gets\n    {} bandwidth first; idle bandwidth from low priority redistributes.\n", "  ".dimmed(), "  ".dimmed());
    println!("    {} Usage:", "  ".dimmed());
    println!(
        "    {} zelynic qos high brave             # High priority (gets bandwidth first)",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic qos low wget               # Low priority (gets leftovers)",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic qos status                 # Show QoS assignments",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic qos reset                  # Clear all QoS rules",
        "  ".dimmed()
    );
    println!();

    // --- watch ---
    println!(
        "  {} {}",
        "watch".green().bold(),
        "— Monitor and alert on bandwidth threshold".dimmed()
    );
    println!(
        "    {} Background bandwidth monitor with desktop notifications.\n",
        "  ".dimmed()
    );
    println!("    {} Usage:", "  ".dimmed());
    println!(
        "    {} zelynic watch -a 500kb wget           # Alert when wget rate > 500KB/s",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic watch -a 5mb firefox -i 30    # Alert when firefox rate > 5MB/s",
        "  ".dimmed()
    );
    println!();

    // --- auto ---
    println!(
        "  {} {}",
        "auto".green().bold(),
        "— Auto-throttle daemon mode".dimmed()
    );
    println!(
        "    {} Continuously monitor and auto-limit when thresholds exceeded.\n",
        "  ".dimmed()
    );
    println!("    {} Usage:", "  ".dimmed());
    println!(
        "    {} zelynic auto --download 100mb --upload 50mb",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic auto --download 80mb --kill firefox",
        "  ".dimmed()
    );
    println!("    {} zelynic auto --daemon", "  ".dimmed());
    println!(
        "    {} zelynic auto --status           # Check if daemon is running",
        "  ".dimmed()
    );
    println!();

    // --- log ---
    println!(
        "  {} {}",
        "log".green().bold(),
        "— Bandwidth usage history".dimmed()
    );
    println!(
        "    {} Historical snapshots and logged bandwidth data.\n",
        "  ".dimmed()
    );
    println!("    {} Usage:", "  ".dimmed());
    println!(
        "    {} zelynic log                   # Show recent history",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic log --snapshot         # Record current state",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic log --last 1h          # Show last hour",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic log --json             # JSON output",
        "  ".dimmed()
    );
    println!();

    // --- backend ---
    println!(
        "  {} {}",
        "backend".green().bold(),
        "— Show backend info and capability checks".dimmed()
    );
    println!(
        "    {} Shows active backend summary or a read-only Backend Doctor matrix.\n",
        "  ".dimmed()
    );
    println!("    {} Usage: zelynic backend", "  ".dimmed());
    println!("    {} Usage: zelynic backend doctor", "  ".dimmed());
    println!("    {} Usage: zelynic backend doctor --json", "  ".dimmed());
    println!();

    // --- completions ---
    println!(
        "  {} {}",
        "completions".green().bold(),
        "— Generate shell completions".dimmed()
    );
    println!(
        "    {} Output shell completion scripts for bash, zsh, fish, etc.\n",
        "  ".dimmed()
    );
    println!("    {} Usage:", "  ".dimmed());
    println!(
        "    {} zelynic completions bash  > /usr/share/bash-completion/completions/zelynic",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic completions zsh   > ~/.zsh/completions/_zelynic",
        "  ".dimmed()
    );
    println!(
        "    {} zelynic completions fish  > ~/.config/fish/completions/zelynic.fish",
        "  ".dimmed()
    );
    println!();

    // --- man ---
    println!(
        "  {} {}",
        "man".green().bold(),
        "— Generate man page".dimmed()
    );
    println!(
        "    {} Output roff-format man page for manual installation.\n",
        "  ".dimmed()
    );
    println!("    {} Usage:", "  ".dimmed());
    println!(
        "    {} zelynic man > /usr/share/man/man1/zelynic.1",
        "  ".dimmed()
    );
    println!();

    // --- globals ---
    println!("{}", "GLOBAL OPTIONS".bold());
    println!("  --iface <INTERFACE>      Specify network interface (default: auto-detect)");
    println!("                            Validates against available interfaces.");
    println!("                            Invalid names show available list.");
    println!("  --iface                  List available interfaces (no value)");
    println!("  --no-color               Disable colored output");
    println!();

    println!("{}", "EXAMPLES".bold());
    println!("  # List available interfaces");
    println!("  zelynic --iface");
    println!();
    println!("  # Real-time monitoring");
    println!("  zelynic list --live");
    println!();
    println!("  # Limit browser bandwidth");
    println!("  sudo zelynic strict -d 1mb -u 500kb brave");
    println!();
    println!("  # Re-limit without unstrict (auto-cleans old rules)");
    println!("  sudo zelynic strict -d 500kb brave      # apply limit");
    println!("  sudo zelynic strict -d 10mb brave       # auto-overrides to 10mb");
    println!();
    println!("  # Quick preset");
    println!("  sudo zelynic strict --preset gaming discord");
    println!();
    println!("  # Specify interface explicitly");
    println!("  sudo zelynic --iface wlan0 strict -d 1mb brave");
    println!("  sudo zelynic --iface eth0 qos high firefox");
    println!("  zelynic --iface enp3s0 list --live");
    println!();
    println!("  # Remove limits");
    println!("  sudo zelynic unstrict brave");
    println!();
    println!("  # Refresh a reopened/respawned target without duplicating rules");
    println!("  sudo zelynic refresh brave");
    println!();
    println!("  # Custom profile workflow");
    println!("  zelynic profile save slow --dl 50kb --ul 50kb");
    println!("  sudo zelynic profile apply slow steam");
    println!();
    println!("  # QoS: browser first, downloads get leftovers");
    println!("  sudo zelynic qos high brave");
    println!("  sudo zelynic qos low wget");
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
