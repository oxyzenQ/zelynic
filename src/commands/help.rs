// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use colored::Colorize;

use crate::info;

/// Print comprehensive help with all commands, options, and examples.
///
/// This is shown via `zelynic --help-all` and covers every subcommand with
/// practical usage examples that aren't visible in the default `-h` output.
pub(crate) fn print_help_all() {
    println!(
        "  {} | {}\n",
        info::DESCRIPTION.dimmed(),
        format!("v{}", info::VERSION).dimmed()
    );
    println!("{}", "USAGE".bold());
    println!("  zelynic [FLAGS] [COMMAND] [ARGS]\n");

    println!("{}", "FLAGS".bold());
    println!("  -i, --info              Print detailed package information");
    println!("  -V, --version           Print complete version and build information");
    println!("  --check-update          Check the latest upstream release");
    println!("  --no-color              Disable colored output");
    println!("  -v, --ver               Print version (short)");
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
        "\u{2014} List network bandwidth usage per process".dimmed()
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
        "\u{2014} Set bandwidth limits for a process".dimmed()
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
        "    {} gaming     \u{2192} 50mb down / 50mb up    (low latency)",
        "  ".dimmed()
    );
    println!(
        "    {} streaming  \u{2192} 10mb down / 5mb up     (video calls)",
        "  ".dimmed()
    );
    println!(
        "    {} background \u{2192} 500kb down / 100kb up  (minimal)",
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
        "\u{2014} Remove all bandwidth limits".dimmed()
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
        "\u{2014} Move respawned target PIDs into an existing limit".dimmed()
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
        "\u{2014} Experimental systemd scope wrapper planning".dimmed()
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
        "\u{2014} Show active bandwidth limits".dimmed()
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
        "\u{2014} Clean up orphaned bandwidth limits".dimmed()
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
        "\u{2014} Manage named bandwidth profiles".dimmed()
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
        "\u{2014} QoS priority-based bandwidth shaping".dimmed()
    );
    println!(
        "    {} Assign priority tiers instead of hard limits. High priority gets\n    {} bandwidth first; idle bandwidth from low priority redistributes.\n",
        "  ".dimmed(),
        "  ".dimmed()
    );
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
        "\u{2014} Monitor and alert on bandwidth threshold".dimmed()
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
        "\u{2014} Auto-throttle daemon mode".dimmed()
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
        "\u{2014} Bandwidth usage history".dimmed()
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
        "\u{2014} Show backend info and capability checks".dimmed()
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
        "\u{2014} Generate shell completions".dimmed()
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
        "\u{2014} Generate man page".dimmed()
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
