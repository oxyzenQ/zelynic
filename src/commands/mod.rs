// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Command handlers for zelynic CLI (Cosmic Dragon Architecture — pure eBPF).

#[cfg(feature = "ebpf")]
pub(crate) mod block;
// The safety blocklist is pure data (no eBPF dependency) — always
// compiled so --help can count it in every build. The rate and
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

use crate::cli::{Cli, Commands};

#[cfg(feature = "ebpf")]
use crate::ebpf::pin::unpin_all;

/// Legacy PID file (kept for cleanup of old installations).
#[cfg(feature = "ebpf")]
const PID_FILE: &str = "/tmp/zelynic.pid";

/// Shared root guard — one clean branded error instead of the old
/// double print (a plain "requires root" line followed by a second
/// duplicated "root required" error from the anyhow path).
///
/// The tip line renders white via the line-aware error renderer.
/// ebpf-gated: every caller is an eBPF-surface command handler.
#[cfg(feature = "ebpf")]
pub(crate) fn ensure_root() -> Result<()> {
    if nix::unistd::geteuid().is_root() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "root required — eBPF operations need CAP_BPF\n  \
             tip: re-run with sudo"
        ))
    }
}

/// Shared error for commands compiled without the `ebpf` feature:
/// a single actionable message instead of the old eprintln + Err pair,
/// which printed the failure twice.
#[cfg(not(feature = "ebpf"))]
fn ebpf_disabled() -> Result<()> {
    Err(anyhow::anyhow!(
        "eBPF not compiled into this build\n  \
         tip: rebuild with 'cargo build --features ebpf'"
    ))
}

/// Top-level CLI dispatch.
pub(crate) fn dispatch(cli: Cli) -> Result<()> {
    // NIGHT-boost-24: --print-json riding a non-JSON surface is a
    // silent no-op no more — one stderr note names the surfaces that
    // honor it. Dispatch-level, so every arm (including the
    // no-subcommand help fallback) is covered exactly once; the JSON
    // surfaces themselves pass the gate silently.
    if cli.print_json && !crate::cli::command_honors_print_json(cli.command.as_ref()) {
        crate::cli::warn_print_json_ignored();
    }
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
                ebpf_disabled()
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
                ebpf_disabled()
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
                ebpf_disabled()
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
                ebpf_disabled()
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
                ebpf_disabled()
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
                ebpf_disabled()
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
                ebpf_disabled()
            }
        }

        Some(Commands::UnstrictMulti { targets }) => {
            #[cfg(feature = "ebpf")]
            {
                cleanup::handle_unstrict_multi(&targets, cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (targets, cli.verbose);
                ebpf_disabled()
            }
        }

        Some(Commands::UnstrictAll) => {
            #[cfg(feature = "ebpf")]
            {
                cleanup::handle_unstrict_all(cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                ebpf_disabled()
            }
        }

        Some(Commands::Recover) => {
            #[cfg(feature = "ebpf")]
            {
                cleanup::handle_recover(cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                ebpf_disabled()
            }
        }

        Some(Commands::Status) => {
            #[cfg(feature = "ebpf")]
            {
                monitor::handle_status(cli.verbose, cli.print_json)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                ebpf_disabled()
            }
        }

        Some(Commands::ListApps) => {
            #[cfg(feature = "ebpf")]
            {
                monitor::handle_list_apps(cli.print_json)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                ebpf_disabled()
            }
        }

        Some(Commands::EagleEyes { targets, interval }) => {
            #[cfg(feature = "ebpf")]
            {
                monitor::handle_eagle_eyes(targets.as_deref(), interval.as_deref(), cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (targets, interval, cli.verbose);
                ebpf_disabled()
            }
        }

        Some(Commands::Doctor) => crate::capabilities::run_doctor(cli.print_json),

        None => {
            // No subcommand: print the end-to-end reference — the same
            // single help surface as `zelynic --help`, written through
            // the broken-pipe-safe stdout path (exit 0).
            help::print_help();
            Ok(())
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
