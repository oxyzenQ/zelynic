// SPDX-License-Identifier: GPL-3.0-only
use clap::{Args, Parser, Subcommand, ValueEnum};

/// zelynic - Easy userspace bandwidth manager for Linux
///
/// Manage network bandwidth per process using Linux traffic control (tc) and cgroups.
/// Requires root privileges for bandwidth limiting operations.
#[derive(Parser, Debug)]
#[command(
    name = "zelynic",
    version,
    author = "Rezky_nightky <oxyzenq>",
    about = "Easy userspace bandwidth manager for Linux",
    long_about = None,
    propagate_version = true,
    arg_required_else_help = false,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Print detailed package information
    #[arg(short = 'i', long = "info", global = false)]
    pub info: bool,

    /// Disable colored output
    ///
    /// Alternatively, set NO_COLOR=1 environment variable.
    #[arg(long, global = true, help = "Disable colored output")]
    pub no_color: bool,

    /// Show comprehensive help with all commands, options, and examples
    #[arg(
        long = "help-all",
        global = false,
        help = "Show comprehensive help with all commands and examples"
    )]
    pub help_all: bool,

    /// Network interface to use
    ///
    /// Defaults to the first non-loopback interface. Use this to explicitly
    /// specify which interface to monitor and shape (e.g., eth0, wlan0).
    /// Use without a value (--iface) to list available interfaces.
    #[arg(
        long,
        global = true,
        value_name = "INTERFACE",
        num_args = 0..=1,
        help = "Network interface to use (no value = list available)"
    )]
    pub iface: Option<Option<String>>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// List network bandwidth usage per process
    ///
    /// Displays all processes with active network connections along with
    /// their bandwidth consumption statistics.
    ///
    /// Use --live for real-time rate monitoring (like htop for bandwidth).
    /// Use --verbose to see individual socket connections per process.
    List {
        /// Show all programs/ports with bandwidth usage
        #[arg(long = "usage-all")]
        usage_all: bool,

        /// Show programs sorted by highest to lowest bandwidth usage
        #[arg(long = "high-to-low-usage-net")]
        high_to_low: bool,

        /// Output results as JSON for scripting integration
        #[arg(long = "json")]
        json: bool,

        /// Live mode: continuously refresh with real-time rates
        ///
        /// Enters TUI mode with auto-refresh. Shows per-process
        /// bandwidth rates (bytes/sec) instead of cumulative totals.
        /// Press 'q' or Ctrl+C to exit.
        ///
        /// Accepts optional interval value:
        ///   --live          # 1 second default
        ///   --live 2        # 2 second interval
        #[arg(long = "live", num_args = 0..=1, value_name = "SECONDS")]
        live: Option<Option<u64>>,

        /// Refresh interval in seconds for live mode [default: 1]
        #[arg(long = "interval", value_name = "SECONDS")]
        interval: Option<u64>,

        /// Verbose mode: show individual socket connections
        ///
        /// Displays per-connection breakdown including remote IP, port,
        /// protocol (TCP/UDP), and bytes transferred for each socket.
        #[arg(short = 'v', long = "verbose")]
        verbose: bool,
    },

    /// Set bandwidth limits (strict) for a specific process
    ///
    /// Applies download and/or upload speed limits to the target process
    /// using Linux traffic control (tc) with HTB qdisc and cgroups.
    ///
    /// Supported units: byte/bs, kb, mb, gb, kbit, mbit, gbit
    ///
    /// Use --preset for common profiles instead of manual rates:
    ///   gaming     - 50mb/50mb (prioritizes low latency)
    ///   streaming  - 10mb/5mb  (balanced for video calls)
    ///   background - 500kb/100kb (minimal, for downloads)
    ///
    /// Examples:
    ///   zelynic strict -d 500kb -u 500kb brave
    ///   zelynic strict -d 1mb firefox               # Download only
    ///   zelynic strict -u 250kb 1234                # Upload only
    ///   zelynic strict --preset gaming discord
    ///   zelynic strict --preset background steam
    #[command(verbatim_doc_comment)]
    Strict {
        /// Download speed limit (e.g., 500kb, 1mb, 2gb, 100byte)
        #[arg(short = 'd', long = "download", allow_hyphen_values = true)]
        download: Option<String>,

        /// Upload speed limit (e.g., 500kb, 1mb, 2gb, 100byte)
        #[arg(short = 'u', long = "upload", allow_hyphen_values = true)]
        upload: Option<String>,

        /// Preset bandwidth profile (conflicts with -d/-u)
        ///
        /// Available presets:
        /// - gaming:     50mb down / 50mb up  (low latency priority)
        /// - streaming:  10mb down / 5mb up   (balanced for video)
        /// - background: 500kb down / 100kb up (minimal, deprioritized)
        #[arg(long = "preset", value_name = "PROFILE", group = "preset_group")]
        preset: Option<String>,

        /// Print strict backend diagnostics while applying the limit
        ///
        /// This keeps normal strict behavior but emits cgroup v2, nftables,
        /// tc details, and selected-PID match reasons needed to debug backend
        /// failures on a real Linux host.
        #[arg(long = "diagnose", alias = "diag")]
        diagnose: bool,

        /// Target process name or PID (name matching is conservative; use PID for exact targeting)
        target: String,
    },

    /// Remove all bandwidth limits from a process
    ///
    /// Removes all tc classes, filters, and cgroup rules that were applied
    /// to the target process, restoring full bandwidth access.
    #[command(verbatim_doc_comment)]
    Unstrict {
        /// Target process name or PID to release from bandwidth limits
        target: String,
    },

    /// Refresh an existing limit after a target process respawns
    ///
    /// Discovers current PIDs for an already-limited target and moves any
    /// missing live PIDs into the existing target cgroup. This does not create
    /// a new limit and does not duplicate nftables or tc rules.
    ///
    /// Examples:
    ///   zelynic refresh brave
    ///   zelynic refresh 1234
    #[command(verbatim_doc_comment)]
    Refresh {
        /// Target process name or PID that already has an active strict limit
        target: String,
    },

    /// Experimental groundwork for launching a command in a future systemd scope
    ///
    /// This is v2.2 groundwork only. Use --dry-run for a safe preview. User
    /// scope is the default to avoid system Polkit prompts. The
    /// --execute opt-in is experimental and currently stops at a non-mutating
    /// implementation boundary.
    ///
    /// Examples:
    ///   zelynic run --dry-run -d 500kbit -u 500kbit -- helium
    ///   zelynic run --dry-run --scope-mode system -d 500kbit -- helium
    ///   zelynic run --execute -d 500kbit -u 500kbit -- helium
    ///   zelynic run --dry-run --target helium -d 500kbit -- helium --flag
    #[command(verbatim_doc_comment)]
    Run {
        /// Show the planned systemd scope wrapper without launching anything
        #[arg(long = "dry-run", conflicts_with = "execute")]
        dry_run: bool,

        /// Experimental live execution opt-in; currently parsed but not implemented
        #[arg(long = "execute", conflicts_with = "dry_run")]
        execute: bool,

        /// Optional target name for state/cgroup naming; defaults to command basename
        #[arg(long = "target", value_name = "TARGET")]
        target: Option<String>,

        /// Planning scope mode for the future systemd wrapper
        #[arg(long = "scope-mode", value_enum, default_value_t = RunScopeModeArg::User)]
        scope_mode: RunScopeModeArg,

        /// Download speed limit (e.g., 500kb, 1mb, 500kbit)
        #[arg(short = 'd', long = "download", allow_hyphen_values = true)]
        download: Option<String>,

        /// Upload speed limit (e.g., 500kb, 1mb, 500kbit)
        #[arg(short = 'u', long = "upload", allow_hyphen_values = true)]
        upload: Option<String>,

        /// Command to launch in the future wrapper mode; pass after `--`
        #[arg(
            required = true,
            num_args = 1..,
            last = true,
            allow_hyphen_values = true,
            value_name = "COMMAND"
        )]
        command: Vec<String>,
    },

    /// Show active bandwidth limits
    ///
    /// Displays all currently active bandwidth limits that were applied
    /// using the 'strict' command, showing target processes, limits,
    /// and interfaces.
    Status,

    /// Generate shell completions
    ///
    /// Outputs shell completion scripts for bash, zsh, fish, etc.
    /// Install by redirecting output to your shell's completions directory.
    ///
    /// Examples:
    ///   zelynic completions bash > /usr/share/bash-completion/completions/zelynic
    ///   zelynic completions zsh > /usr/local/share/zsh/site-functions/_zelynic
    ///   zelynic completions fish > ~/.config/fish/completions/zelynic.fish
    #[command(verbatim_doc_comment)]
    Completions {
        /// Shell to generate completions for (bash, zsh, fish, elvish, powershell)
        shell: String,
    },

    /// Generate man page
    ///
    /// Outputs a man page in roff format for zelynic.
    /// Install by redirecting output to your man page directory.
    ///
    /// Examples:
    ///   zelynic man > /usr/share/man/man1/zelynic.1
    ///   zelynic man | gzip > /usr/share/man/man1/zelynic.1.gz
    #[command(verbatim_doc_comment)]
    Man,

    /// Clean up orphaned bandwidth limits
    ///
    /// Removes tc classes, filters, and cgroups for processes that have
    /// already exited. Run this periodically or when you suspect stale
    /// rules are accumulating.
    #[command(verbatim_doc_comment)]
    Clean {
        /// Perform emergency cleanup: remove ALL state, rules, and cgroups.
        /// Use this when normal unstrict fails (e.g., target process has exited).
        #[arg(
            long,
            help = "Remove ALL state, nftables rules, tc objects, and cgroups"
        )]
        all: bool,
    },

    /// Show bandwidth usage history
    ///
    /// Displays historical bandwidth snapshots logged over time.
    /// Use with --snapshot to record current state for later analysis.
    ///
    /// Examples:
    ///   zelynic log              # Show recent history
    ///   zelynic log --snapshot     # Record current state
    ///   zelynic log --last 1h      # Show last hour
    ///   zelynic log --last 24h     # Show last 24 hours
    #[command(verbatim_doc_comment)]
    Log {
        /// Record current bandwidth snapshot
        #[arg(long = "snapshot")]
        snapshot: bool,

        /// Show history for last N hours (e.g., 1h, 24h)
        #[arg(long = "last", value_name = "HOURS")]
        last: Option<u64>,

        /// Output as JSON for analysis
        #[arg(long = "json")]
        json: bool,
    },

    /// Manage named bandwidth profiles
    ///
    /// Save and load bandwidth limit profiles for quick application.
    /// Profiles persist across sessions and can be applied with a single command.
    ///
    /// Examples:
    ///   zelynic profile save background --dl 100kb --ul 100kb
    ///   zelynic profile save streaming --dl 5mb --ul 2mb
    ///   zelynic profile list
    ///   zelynic profile apply background firefox
    ///   zelynic profile delete background
    #[command(verbatim_doc_comment)]
    Profile {
        /// Profile subcommand
        #[command(subcommand)]
        command: ProfileCommands,
    },

    /// Quality of Service (QoS) priority-based bandwidth shaping
    ///
    /// Assign processes a priority tier instead of hard limits. High priority
    /// processes get bandwidth first; idle bandwidth from low-priority processes
    /// redistributes to high-priority ones automatically.
    ///
    /// This solves the "large download + browsing" use case: set wget to low
    /// priority and browser to high — browser stays fast, wget gets leftovers.
    ///
    /// Examples:
    ///   zelynic qos high brave        # High priority for browser
    ///   zelynic qos low wget           # Low priority for download
    ///   zelynic qos status             # Show current QoS assignments
    ///   zelynic qos reset              # Clear all QoS rules
    #[command(verbatim_doc_comment)]
    Qos {
        /// QoS subcommand
        #[command(subcommand)]
        command: QosCommands,
    },

    /// Watch bandwidth and alert when thresholds are exceeded
    ///
    /// Monitor a process and send desktop notification (or stderr fallback)
    /// when bandwidth exceeds specified threshold. Useful for background
    /// download monitoring without keeping --live open.
    ///
    /// Examples:
    ///   zelynic watch --alert 500kb wget     # Alert when rate > 500KB/s
    ///   zelynic watch --alert 5mb firefox   # Alert when rate > 5MB/s
    ///   zelynic watch --alert 100mb -i 30    # Check every 30 seconds
    #[command(verbatim_doc_comment)]
    Watch {
        /// Alert threshold as bandwidth rate (e.g., 500kb, 5mb, 100mb)
        #[arg(
            short = 'a',
            long,
            value_name = "RATE",
            required = true,
            allow_hyphen_values = true
        )]
        alert: String,
        /// Process to watch (name or PID)
        #[arg(value_name = "PROCESS")]
        target: String,
        /// Check interval in seconds
        #[arg(short, long, default_value = "10")]
        interval: u64,
        /// Desktop notification command (default: notify-send)
        #[arg(long, value_name = "CMD")]
        notify_cmd: Option<String>,
    },

    /// Auto-throttle: background daemon mode
    ///
    /// Runs continuously in the background, monitoring total bandwidth usage
    /// and automatically applying limits when bandwidth exceeds thresholds.
    /// Perfect for unattended systems that need automatic bandwidth management.
    ///
    /// Examples:
    ///   zelynic auto --download 100mb --upload 50mb     # Limit when > threshold
    ///   zelynic auto --download 80mb --kill firefox    # Kill heavy users
    ///   zelynic auto --daemon                          # Run as daemon
    #[command(verbatim_doc_comment)]
    Auto {
        /// Download threshold (e.g., 100mb, 1gb)
        #[arg(short = 'd', long, value_name = "RATE", allow_hyphen_values = true)]
        download: Option<String>,
        /// Upload threshold (e.g., 50mb, 100mb)
        #[arg(short = 'u', long, value_name = "RATE", allow_hyphen_values = true)]
        upload: Option<String>,
        /// Process to auto-limit when threshold exceeded
        #[arg(short, long, value_name = "PROCESS")]
        target: Option<String>,
        /// Kill process instead of limiting (when --target specified)
        #[arg(long, requires = "target")]
        kill: bool,
        /// Run as background daemon
        #[arg(long)]
        daemon: bool,
        /// Check interval in seconds
        #[arg(short, long, default_value = "5")]
        interval: u64,
        /// Show auto-throttle daemon status
        #[arg(short, long)]
        status: bool,
    },

    /// Show backend information and capability checks
    ///
    /// Displays the active backend (tc/cgroup) and whether the system
    /// supports eBPF for future use. Use `zelynic backend doctor` for a
    /// detailed read-only capability matrix.
    Backend {
        /// Optional backend diagnostic command
        #[command(subcommand)]
        command: Option<BackendCommands>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum RunScopeModeArg {
    /// Preview a user-scoped transient systemd unit
    User,
    /// Preview a system-scoped transient systemd unit
    System,
}

/// Backend diagnostics subcommands.
#[derive(Debug, Subcommand)]
pub enum BackendCommands {
    /// Show detailed read-only host capability diagnostics and backend scoring
    Doctor(BackendDoctorArgs),
}

#[derive(Debug, Args)]
pub struct BackendDoctorArgs {
    /// Output Backend Doctor report as JSON
    #[arg(long)]
    pub json: bool,
}

/// Profile management subcommands.
#[derive(Debug, Subcommand)]
pub enum ProfileCommands {
    /// Save a new bandwidth profile
    Save {
        /// Profile name (e.g., background, streaming, gaming)
        name: String,
        /// Download limit (e.g., 100kb, 5mb, 1gb)
        #[arg(long = "dl", value_name = "RATE", allow_hyphen_values = true)]
        download: Option<String>,
        /// Upload limit (e.g., 100kb, 5mb, 1gb)
        #[arg(long = "ul", value_name = "RATE", allow_hyphen_values = true)]
        upload: Option<String>,
    },
    /// Apply a saved profile to a process
    Apply {
        /// Profile name to apply
        name: String,
        /// Target process name or PID
        target: String,
    },
    /// List all saved profiles
    List,
    /// Delete a saved profile
    Delete {
        /// Profile name to delete
        name: String,
    },
}

/// QoS priority management subcommands.
#[derive(Debug, Subcommand)]
pub enum QosCommands {
    /// Set high priority for a process
    ///
    /// High priority processes get bandwidth first.
    /// Idle bandwidth from low-priority processes redistributes here.
    High {
        /// Process name or PID to prioritize
        target: String,
    },
    /// Set low priority for a process
    ///
    /// Low priority processes get leftover bandwidth only.
    /// When bandwidth is scarce, these are throttled first.
    Low {
        /// Process name or PID to deprioritize
        target: String,
    },
    /// Show current QoS assignments
    Status,
    /// Reset all QoS rules
    Reset,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[test]
    fn strict_diagnose_flag_parses() {
        let cli = Cli::try_parse_from(["zelynic", "strict", "--diagnose", "-d", "1mb", "firefox"])
            .unwrap();

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
        let cli =
            Cli::try_parse_from(["zelynic", "strict", "--diag", "-u", "250kb", "1234"]).unwrap();

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
                scope_mode,
                download,
                upload,
                command,
                ..
            } => {
                assert!(dry_run);
                assert!(!execute);
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
                scope_mode,
                download,
                command,
                ..
            } => {
                assert!(!dry_run);
                assert!(execute);
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
    fn run_help_mentions_execute_is_experimental() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("run")
            .expect("run subcommand")
            .render_long_help()
            .to_string();

        assert!(help.contains("--execute"));
        assert!(help.contains("Experimental live execution opt-in"));
        assert!(help.contains("--scope-mode"));
        assert!(help.contains("Possible values:"));
        assert!(help.contains("user:"));
        assert!(help.contains("system:"));
    }
}
