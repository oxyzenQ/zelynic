use clap::{Parser, Subcommand};

/// oxy - Easy userspace bandwidth manager for Linux
///
/// Manage network bandwidth per process using Linux traffic control (tc) and cgroups.
/// Requires root privileges for bandwidth limiting operations.
#[derive(Parser, Debug)]
#[command(
    name = "oxy",
    version,
    author = "rezky_nightky <oxyzenq>",
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

    /// Network interface to use
    ///
    /// Defaults to the first non-loopback interface. Use this to explicitly
    /// specify which interface to monitor and shape (e.g., eth0, wlan0).
    #[arg(
        long,
        global = true,
        value_name = "INTERFACE",
        help = "Network interface to use"
    )]
    pub iface: Option<String>,
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
        #[arg(long = "live")]
        live: bool,

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
    /// Supported units: byte/bs, kb/kbps, mb/mbs, gb/gbs, kbit, mbit, gbit
    ///
    /// Use --preset for common profiles instead of manual rates:
    ///   gaming    - 50mb/50mb (prioritizes low latency)
    ///   streaming - 10mb/5mb  (balanced for video calls)
    ///   background- 500kb/100kb (minimal, for downloads)
    ///
    /// Examples:
    ///   oxy strict -d 500kb -u 500kb brave
    ///   oxy strict -d 1mb -u only firefox
    ///   oxy strict -d only -u 250kb 1234
    ///   oxy strict --preset gaming discord
    ///   oxy strict --preset background steam
    #[command(verbatim_doc_comment)]
    Strict {
        /// Download speed limit (e.g., 500kb, 1mb, 2gb, 100byte)
        #[arg(short = 'd', long = "download")]
        download: Option<String>,

        /// Upload speed limit (e.g., 500kb, 1mb, 2gb, 100byte)
        #[arg(short = 'u', long = "upload")]
        upload: Option<String>,

        /// Preset bandwidth profile (conflicts with -d/-u)
        ///
        /// Available presets:
        /// - gaming:     50mb down / 50mb up  (low latency priority)
        /// - streaming:  10mb down / 5mb up   (balanced for video)
        /// - background: 500kb down / 100kb up (minimal, deprioritized)
        #[arg(long = "preset", value_name = "PROFILE", group = "preset")]
        preset: Option<String>,

        /// Target process name or PID (e.g., brave, firefox, 1234)
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
    ///   oxy completions bash > /usr/share/bash-completion/completions/oxy
    ///   oxy completions zsh > /usr/local/share/zsh/site-functions/_oxy
    ///   oxy completions fish > ~/.config/fish/completions/oxy.fish
    #[command(verbatim_doc_comment)]
    Completions {
        /// Shell to generate completions for (bash, zsh, fish, elvish, powershell)
        shell: String,
    },

    /// Generate man page
    ///
    /// Outputs a man page in roff format for oxy.
    /// Install by redirecting output to your man page directory.
    ///
    /// Examples:
    ///   oxy man > /usr/share/man/man1/oxy.1
    ///   oxy man | gzip > /usr/share/man/man1/oxy.1.gz
    #[command(verbatim_doc_comment)]
    Man,

    /// Clean up orphaned bandwidth limits
    ///
    /// Removes tc classes, filters, and cgroups for processes that have
    /// already exited. Run this periodically or when you suspect stale
    /// rules are accumulating.
    #[command(verbatim_doc_comment)]
    Clean,

    /// Show bandwidth usage history
    ///
    /// Displays historical bandwidth snapshots logged over time.
    /// Use with --snapshot to record current state for later analysis.
    ///
    /// Examples:
    ///   oxy log              # Show recent history
    ///   oxy log --snapshot     # Record current state
    ///   oxy log --last 1h      # Show last hour
    ///   oxy log --last 24h     # Show last 24 hours
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
    ///   oxy profile save background --dl 100kb --ul 100kb
    ///   oxy profile save streaming --dl 5mb --ul 2mb
    ///   oxy profile list
    ///   oxy profile apply background firefox
    ///   oxy profile delete background
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
    ///   oxy qos high brave        # High priority for browser
    ///   oxy qos low wget           # Low priority for download
    ///   oxy qos status             # Show current QoS assignments
    ///   oxy qos reset              # Clear all QoS rules
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
    ///   oxy watch --alert 500mb wget     # Alert when wget > 500MB/s
    ///   oxy watch --alert 1gb firefox   # Alert when firefox > 1GB/s
    ///   oxy watch --alert 100mb -i 30    # Check every 30 seconds
    #[command(verbatim_doc_comment)]
    Watch {
        /// Alert threshold (e.g., 500mb, 1gb, 10mb)
        #[arg(short = 'a', long, value_name = "RATE", required = true)]
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
    ///   oxy auto --download 100mb --upload 50mb     # Limit when > threshold
    ///   oxy auto --download 80mb --kill firefox    # Kill heavy users
    ///   oxy auto --daemon                          # Run as daemon
    #[command(verbatim_doc_comment)]
    Auto {
        /// Download threshold (e.g., 100mb, 1gb)
        #[arg(short = 'd', long, value_name = "RATE")]
        download: Option<String>,
        /// Upload threshold (e.g., 50mb, 100mb)
        #[arg(short = 'u', long, value_name = "RATE")]
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
    },

    /// Show backend information and eBPF support status
    ///
    /// Displays which backend (eBPF or tc/cgroup) is being used
    /// and checks system capabilities for eBPF support.
    ///
    /// Use this to verify if your system can use the eBPF backend.
    Backend,
}

/// Profile management subcommands.
#[derive(Debug, Subcommand)]
pub enum ProfileCommands {
    /// Save a new bandwidth profile
    Save {
        /// Profile name (e.g., background, streaming, gaming)
        name: String,
        /// Download limit (e.g., 100kb, 5mb, 1gb)
        #[arg(long = "dl", value_name = "RATE")]
        download: Option<String>,
        /// Upload limit (e.g., 100kb, 5mb, 1gb)
        #[arg(long = "ul", value_name = "RATE")]
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
