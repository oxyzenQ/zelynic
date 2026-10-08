// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Command handlers for zelynic CLI (the cosmic dragon architecture — pure eBPF).

#[cfg(feature = "ebpf")]
pub(crate) mod block;
// The safety blocklist is pure data (no eBPF dependency) — always
// compiled so --help can count it in every build. The rate and
// strict handler modules are eBPF-only surfaces.
#[cfg(feature = "ebpf")]
pub(crate) mod cleanup;
#[cfg(feature = "ebpf")]
pub(crate) mod eagle;
pub(crate) mod guarantee;
pub(crate) mod help;
// NIGHT-hunt-39: the flag estate (Global flags, Rate formats, Pro
// mode) split from help.rs at the 600-line no-mercy cap — every
// spelling surface one module, the flag_row tier law included.
// Pure reference rendering (no eBPF dependency), like help.
pub(crate) mod help_flags;
#[cfg(feature = "ebpf")]
pub(crate) mod list_apps;
#[cfg(feature = "ebpf")]
pub(crate) mod monitor;
#[cfg(feature = "ebpf")]
pub(crate) mod probe;
#[cfg(feature = "ebpf")]
pub(crate) mod probe_report;
#[cfg(feature = "ebpf")]
pub(crate) mod probe_role;
#[cfg(feature = "ebpf")]
pub(crate) mod rates;
// NIGHT-dinner-11: recover split from cleanup (the LOC-cap push —
// crash repair is a different concern from user-initiated removal).
#[cfg(feature = "ebpf")]
pub(crate) mod recover;
pub(crate) mod safety;
// NIGHT-improve-53: the masterclass '::' list grammar — the
// routing law (target_is_list) and the list validation the unified
// verbs (strict / block / unstrict) share. Split from safety.rs at
// the 600-line cap, the same one-theme-one-file discipline that
// gave strict_all.rs and dispatch_common.rs their own homes.
#[cfg(feature = "ebpf")]
pub(crate) mod strict;
#[cfg(feature = "ebpf")]
pub(crate) mod target_grammar;
// night-during's LOC-cap split: the strict-all handler moved out of
// strict.rs when the --during threading crossed the 500-line cap.
#[cfg(feature = "ebpf")]
pub(crate) mod strict_all;

#[cfg(not(feature = "ebpf"))]
use anyhow::Result;
#[cfg(feature = "ebpf")]
use anyhow::Result;

use crate::cli::{Cli, Commands};

// NIGHT-improve-44: the 600-line cap split — the dispatch-shared
// surfaces (apply epilogue, root gate, no-match hard error, dormant
// refusal, unpin cleanup) live in dispatch_common.rs, re-exported
// here so every super:: call site and arm resolves identically.
mod dispatch_common;
// The moved items carry their own lane gates (ebpf for the live
// surfaces, not(ebpf) for the dormant refusal) — the re-exports
// wear the same gates so both lanes resolve exactly as the
// pre-split file did.
#[cfg(not(feature = "ebpf"))]
pub(crate) use dispatch_common::ebpf_disabled;
#[cfg(feature = "ebpf")]
pub(crate) use dispatch_common::{
    apply_success_epilogue, ensure_root, target_no_match_error, unpin_all_bpf, TIP_LIST_APPS,
    TIP_STATUS,
};

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
        // NIGHT-improve-53 (the masterclass unification) +
        // NIGHT-improve-54 (the sweep merge): strict / block /
        // unstrict are ONE verb per family, and --all is the sweep
        // LANE of each — the target grammar (target_grammar) picks
        // the single/list lane, this dispatch picks target-vs-fleet.
        // The three retired -all spellings (strict-all/sa,
        // block-all/ba, unstrict-all/ua) land on the ux redirect
        // table's successor tips.
        Some(Commands::Strict {
            target,
            rate,
            download,
            upload,
            all,
            force_this,
            no_test,
            per_socket,
            floor,
            ceil,
            floor_download,
            floor_upload,
            ceil_download,
            ceil_upload,
            during,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                // NIGHT-improve-54: the sweep lane. On --all the
                // TARGET positional is absent by grammar, so clap
                // parks a lone positional in its slot — `s --all
                // 500kb` carries the RATE there. Reinterpreted here
                // (the CLI boundary owns the shape), with the
                // two-positional shape refused: a target beside
                // --all is a lane confusion, whatever the values.
                if all {
                    if let (Some(stray), Some(_)) = (target.as_deref(), rate.as_deref()) {
                        return Err(anyhow::anyhow!(
                            "--all sweeps every user app — it takes a rate, not a target\n  \
                             tip: zelynic s --all 500kb (drop '{stray}', or drop --all)"
                        ));
                    }
                    let sweep_rate = rate.as_deref().or(target.as_deref());
                    return strict_all::handle_strict_all(
                        sweep_rate,
                        download.as_deref(),
                        upload.as_deref(),
                        force_this,
                        no_test,
                        guarantee::BracketFlags {
                            floor: floor.as_deref(),
                            ceil: ceil.as_deref(),
                            floor_download: floor_download.as_deref(),
                            floor_upload: floor_upload.as_deref(),
                            ceil_download: ceil_download.as_deref(),
                            ceil_upload: ceil_upload.as_deref(),
                        },
                        during.as_deref(),
                        cli.verbose,
                    );
                }
                match target.as_deref() {
                    Some(t) => {
                        strict::handle_strict(
                            t,
                            rate.as_deref(),
                            download.as_deref(),
                            upload.as_deref(),
                            force_this,
                            no_test,
                            per_socket,
                            // improve-40-b: the six bracket flags ride one
                            // struct (the per-direction spellings included).
                            guarantee::BracketFlags {
                                floor: floor.as_deref(),
                                ceil: ceil.as_deref(),
                                floor_download: floor_download.as_deref(),
                                floor_upload: floor_upload.as_deref(),
                                ceil_download: ceil_download.as_deref(),
                                ceil_upload: ceil_upload.as_deref(),
                            },
                            during.as_deref(),
                            cli.verbose,
                        )
                    }
                    // clap's required_unless_present owns this rung;
                    // the crafted fallback is the no-panic posture
                    // if that attribute ever drifts.
                    None => Err(anyhow::anyhow!(
                        "a target is required unless --all sweeps the fleet\n  \
                         tip: zelynic s brave 100kb, or zelynic s --all 500kb"
                    )),
                }
            }
            #[cfg(not(feature = "ebpf"))]
            {
                // per_socket joins the tuple with the other payload
                // fields: the dormant-mode build destructures every
                // strict flag here so -D warnings never sees an
                // unused binding (the CI build leg's -D warnings ride
                // the no-default-features leg; the field is read only
                // on the ebpf side, so the dormant arm silences it).
                let _ = (
                    target,
                    rate,
                    download,
                    upload,
                    all,
                    force_this,
                    no_test,
                    per_socket,
                    floor,
                    ceil,
                    floor_download,
                    floor_upload,
                    ceil_download,
                    ceil_upload,
                    during,
                    cli.verbose,
                );
                ebpf_disabled()
            }
        }

        Some(Commands::Block {
            target,
            all,
            force_this,
            during,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                // NIGHT-improve-54: the block sweep lane (the former
                // block-all verb) — it takes no target at all.
                if all {
                    if let Some(stray) = target.as_deref() {
                        return Err(anyhow::anyhow!(
                            "--all blocks every user app — it takes no target\n  \
                             tip: zelynic b --all (drop '{stray}', or drop --all)"
                        ));
                    }
                    return block::handle_block_all(force_this, during.as_deref(), cli.verbose);
                }
                match target.as_deref() {
                    Some(t) => block::handle_block(t, force_this, during.as_deref(), cli.verbose),
                    None => Err(anyhow::anyhow!(
                        "a target is required unless --all sweeps the fleet\n  \
                         tip: zelynic b brave, or zelynic b --all"
                    )),
                }
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (target, all, force_this, during, cli.verbose);
                ebpf_disabled()
            }
        }

        // NIGHT-improve-53: unstrict's '::' routing lives inside
        // cleanup::handle_unstrict (the masterclass router).
        // NIGHT-improve-54: --all is the emergency-reset lane (the
        // former unstrict-all verb) — it takes no target at all.
        Some(Commands::Unstrict { target, all }) => {
            #[cfg(feature = "ebpf")]
            {
                if all {
                    if let Some(stray) = target.as_deref() {
                        return Err(anyhow::anyhow!(
                            "--all removes every limit on the machine — it takes no target\n  \
                             tip: zelynic u --all (drop '{stray}', or drop --all)"
                        ));
                    }
                    return cleanup::handle_unstrict_all(cli.verbose);
                }
                match target.as_deref() {
                    Some(t) => cleanup::handle_unstrict(t, cli.verbose),
                    None => Err(anyhow::anyhow!(
                        "a target is required unless --all resets the fleet\n  \
                         tip: zelynic u brave, or zelynic u --all"
                    )),
                }
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (target, all, cli.verbose);
                ebpf_disabled()
            }
        }

        Some(Commands::Recover) => {
            #[cfg(feature = "ebpf")]
            {
                recover::handle_recover(cli.verbose)
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
                list_apps::handle_list_apps(cli.print_json)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                ebpf_disabled()
            }
        }

        Some(Commands::EagleEyes {
            targets,
            interval,
            focus,
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
                    eagle::handle_eagle_eyes_depth(
                        targets.as_deref(),
                        focus.as_deref(),
                        cli.print_json,
                        cli.verbose,
                    )
                } else {
                    // NIGHT-private-research-3: the mirror image of
                    // the --interval note above — --focus is the
                    // one-shot report's traffic window, and the live
                    // monitor needs no window (its frames ARE one).
                    // One stderr note, stdout and exit codes
                    // untouched (the ignored-note contract).
                    if focus.is_some() {
                        eprintln_safe!(
                            "{}",
                            crate::output::warn_bold(
                                "--focus ignored (the live monitor is already continuous — it owns --depth's traffic-window job)"
                            )
                        );
                    }
                    monitor::handle_eagle_eyes(targets.as_deref(), interval.as_deref(), cli.verbose)
                }
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (targets, interval, focus, depth, cli.verbose);
                ebpf_disabled()
            }
        }

        Some(Commands::Doctor) => crate::capabilities::run_doctor(cli.print_json),

        // NIGHT-upgrade-charger-core-1-b: the enforcement probe's hidden child
        // roles — spawned by the probe orchestrator, never typed by hand.
        #[cfg(feature = "ebpf")]
        Some(Commands::ProbeServer { port, mode }) => probe_role::run_server_role(port, &mode),
        #[cfg(not(feature = "ebpf"))]
        Some(Commands::ProbeServer { .. }) => ebpf_disabled(),
        #[cfg(feature = "ebpf")]
        Some(Commands::ProbeClient { addr, mode, secs }) => {
            probe_role::run_client_role(&addr, &mode, secs)
        }
        #[cfg(not(feature = "ebpf"))]
        Some(Commands::ProbeClient { .. }) => ebpf_disabled(),

        None => {
            // No subcommand: print the end-to-end reference — the same
            // single help surface as `zelynic --help`, written through
            // the broken-pipe-safe stdout path (exit 0).
            help::print_help();
            Ok(())
        }
    }
}
