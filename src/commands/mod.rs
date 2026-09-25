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
#[cfg(feature = "ebpf")]
pub(crate) mod eagle;
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

// ── The apply-verb success epilogue (NIGHT-improve-28) ──────────────
//
// The owner's verbosity audit: the apply verbs (strict-single and its
// siblings) answered with a two-line report that restated the request
// ("Limiting 'cg:48181' to 10.0 KB/s + 10.0 KB/s (2 policies, active
// in background)") before the follow-up line. The pro contract is the
// affirmative-verdict grammar: a green "OK." (the #50FA7B tier that
// affirmative verdicts already own) plus the follow-up commands in
// the runnable-example green tier — the same "this is what you type"
// color the --help examples render in (NIGHT-boost-4). The request
// echo lives in the shell history, the enforced facts (rates, policy
// counts) live in 'zelynic status', and the success surface stays
// one glance.
//
// The follow-up must ROUND-TRIP: each caller passes the exact unstrict
// form that reverses what it applied. The former shared suggestion
// was wrong advice on two shapes — 'zelynic unstrict brave:curl'
// does not split colon lists (unstrict-single takes one target), and
// 'zelynic unstrict 3 apps' is not a target at all — so the multi and
// all verbs now suggest 'unstrict-multi <list>' / 'unstrict-all'.

/// The pure line builder behind the apply-verb epilogue (pinned in
/// test/cli/apply_epilogue_tests.rs): line 1 is the affirmative
/// verdict, line 2 the follow-up with both runnable commands wrapped
/// in the green tier. Pure so the exact wording — including the
/// 'or' the owner specced — is a contract, not an accident.
#[cfg(feature = "ebpf")]
#[must_use]
pub(crate) fn apply_success_lines(unstrict_cmd: &str, action: &str) -> [String; 2] {
    [
        crate::output::ok("OK."),
        format!(
            "Run '{}' to {action}, or '{}' to check.",
            crate::output::ok(unstrict_cmd),
            crate::output::ok("zelynic status")
        ),
    ]
}

/// Print the apply-verb success epilogue (NIGHT-improve-28): green
/// "OK." on its own line, then the follow-up commands in green —
/// `action` names what the unstrict form does ("remove" for the
/// strict family, "restore access" for the block family).
#[cfg(feature = "ebpf")]
pub(crate) fn apply_success_epilogue(unstrict_cmd: &str, action: &str) {
    for line in apply_success_lines(unstrict_cmd, action) {
        eprintln_safe!("{line}");
    }
}

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
            force_this,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                strict::handle_strict_single(
                    &target,
                    rate.as_deref(),
                    download.as_deref(),
                    upload.as_deref(),
                    force_this,
                    cli.verbose,
                )
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (target, rate, download, upload, force_this, cli.verbose);
                ebpf_disabled()
            }
        }

        Some(Commands::StrictMulti {
            targets,
            rate,
            download,
            upload,
            force_this,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                strict::handle_strict_multi(
                    &targets,
                    rate.as_deref(),
                    download.as_deref(),
                    upload.as_deref(),
                    force_this,
                    cli.verbose,
                )
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (targets, rate, download, upload, force_this, cli.verbose);
                ebpf_disabled()
            }
        }

        Some(Commands::StrictAll {
            rate,
            download,
            upload,
            force_this,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                strict::handle_strict_all(
                    rate.as_deref(),
                    download.as_deref(),
                    upload.as_deref(),
                    force_this,
                    cli.verbose,
                )
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (rate, download, upload, force_this, cli.verbose);
                ebpf_disabled()
            }
        }

        Some(Commands::BlockSingle { target, force_this }) => {
            #[cfg(feature = "ebpf")]
            {
                block::handle_block_single(&target, force_this, cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (target, force_this, cli.verbose);
                ebpf_disabled()
            }
        }

        Some(Commands::BlockMulti {
            targets,
            force_this,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                block::handle_block_multi(&targets, force_this, cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (targets, force_this, cli.verbose);
                ebpf_disabled()
            }
        }

        Some(Commands::BlockAll { force_this }) => {
            #[cfg(feature = "ebpf")]
            {
                block::handle_block_all(force_this, cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (force_this, cli.verbose);
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

        Some(Commands::EagleEyes {
            targets,
            interval,
            depth,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                if depth {
                    // The one-shot mode has no refresh loop: the
                    // live-only cadence flag answers with the same
                    // honesty the --print-json ignored-note carries —
                    // one stderr line, stdout and exit codes
                    // untouched (NIGHT-master-1).
                    if interval.is_some() {
                        eprintln_safe!(
                            "{}",
                            crate::output::warn_bold(
                                "--interval ignored (--depth prints one report and exits)"
                            )
                        );
                    }
                    eagle::handle_eagle_eyes_depth(targets.as_deref(), cli.print_json, cli.verbose)
                } else {
                    monitor::handle_eagle_eyes(targets.as_deref(), interval.as_deref(), cli.verbose)
                }
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (targets, interval, depth, cli.verbose);
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

// NIGHT-improve-28: the apply-verb epilogue pins live under the single
// test/ tree (cosmostrix Pattern C), #[path]-wired exactly like the
// print-json scope pins in cli/mod.rs.
#[cfg(test)]
#[cfg(feature = "ebpf")]
#[path = "../../test/cli/apply_epilogue_tests.rs"]
mod apply_epilogue_tests;
