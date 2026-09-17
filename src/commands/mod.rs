// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Command handlers for zelynic CLI (Dragon Architecture — pure eBPF).

#[cfg(feature = "ebpf")]
pub(crate) mod block;
// The safety blocklist is pure data (no eBPF dependency) — always
// compiled so --help-all can count it in every build. The rate and
// strict handler modules are eBPF-only surfaces.
#[cfg(feature = "ebpf")]
pub(crate) mod cleanup;
pub(crate) mod help;
#[cfg(feature = "ebpf")]
pub(crate) mod monitor;
#[cfg(feature = "ebpf")]
pub(crate) mod rates;
pub(crate) mod safety;
#[cfg(feature = "ebpf")]
pub(crate) mod strict;

#[cfg(not(feature = "ebpf"))]
use anyhow::Result;
#[cfg(feature = "ebpf")]
use anyhow::Result;
use clap::Parser;

use crate::cli::{Cli, Commands};

#[cfg(feature = "ebpf")]
use crate::ebpf::pin::unpin_all;

/// Legacy PID file (kept for cleanup of old installations).
#[cfg(feature = "ebpf")]
const PID_FILE: &str = "/tmp/zelynic.pid";

/// Top-level CLI dispatch.
pub(crate) fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Some(Commands::StrictSingle {
            target,
            rate,
            download,
            upload,
            allow_dangerous,
            force,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                strict::handle_strict_single(
                    &target,
                    rate.as_deref(),
                    download.as_deref(),
                    upload.as_deref(),
                    allow_dangerous,
                    force,
                    cli.verbose,
                )
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (
                    target,
                    rate,
                    download,
                    upload,
                    allow_dangerous,
                    force,
                    cli.verbose,
                );
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::StrictMulti {
            targets,
            rate,
            download,
            upload,
            allow_dangerous,
            force,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                strict::handle_strict_multi(
                    &targets,
                    rate.as_deref(),
                    download.as_deref(),
                    upload.as_deref(),
                    allow_dangerous,
                    force,
                    cli.verbose,
                )
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (
                    targets,
                    rate,
                    download,
                    upload,
                    allow_dangerous,
                    force,
                    cli.verbose,
                );
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::LimitAll {
            rate,
            download,
            upload,
            allow_dangerous,
            force,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                strict::handle_limit_all(
                    rate.as_deref(),
                    download.as_deref(),
                    upload.as_deref(),
                    allow_dangerous,
                    force,
                    cli.verbose,
                )
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (rate, download, upload, allow_dangerous, force, cli.verbose);
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::BlockSingle { target, force }) => {
            #[cfg(feature = "ebpf")]
            {
                block::handle_block_single(&target, force, cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (target, force, cli.verbose);
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::BlockMulti { targets, force }) => {
            #[cfg(feature = "ebpf")]
            {
                block::handle_block_multi(&targets, force, cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (targets, force, cli.verbose);
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::BlockAll { force }) => {
            #[cfg(feature = "ebpf")]
            {
                block::handle_block_all(force, cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (force, cli.verbose);
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::Unstrict { target }) => {
            #[cfg(feature = "ebpf")]
            {
                cleanup::handle_unstrict(&target, cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (target, cli.verbose);
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::UnstrictAll) => {
            #[cfg(feature = "ebpf")]
            {
                cleanup::handle_unstrict_all(cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::Recover) => {
            #[cfg(feature = "ebpf")]
            {
                cleanup::handle_recover(cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::Status) => {
            #[cfg(feature = "ebpf")]
            {
                monitor::handle_status(cli.verbose, cli.print_json)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::ListApps) => {
            #[cfg(feature = "ebpf")]
            {
                monitor::handle_list_apps(cli.print_json)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::Observe { live, cgroup }) => {
            #[cfg(feature = "ebpf")]
            {
                monitor::handle_observe(live.as_deref(), cgroup, cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (live, cgroup, cli.verbose);
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::Top {
            duration,
            limit,
            live,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                monitor::handle_top(duration.as_deref(), limit, live.as_deref(), cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (duration, limit, live, cli.verbose);
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::Doctor) => crate::capabilities::run_doctor(cli.print_json),

        None => {
            if cli.help_all {
                help::print_help_all();
                Ok(())
            } else {
                Cli::parse_from(["zelynic", "--help"]);
                Ok(())
            }
        }
    }
}

// ━━ Command handlers (ebpf feature) ━━

/// Remove ALL BPF pin files + directory. Full cleanup.
/// Delegates to `limiter::unpin_all()` which iterates the pin directory
/// and removes every file, then removes the directory. Also removes the
/// legacy PID file if present.
#[cfg(feature = "ebpf")]
pub(crate) fn unpin_all_bpf() -> Result<()> {
    unpin_all()?;
    // Remove legacy PID file if present (from old serve-child versions).
    let _ = std::fs::remove_file(PID_FILE);
    Ok(())
}
