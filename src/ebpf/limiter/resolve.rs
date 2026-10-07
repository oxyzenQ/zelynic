// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Target resolution (night-during's LOC-cap split of policy.rs: the
//! --during threading pushed the parent past the 500-line owner cap;
//! the house precedent moves one cohesive concern out — the resolve
//! walk, unchanged, its callers' paths updated).
//!
//! NIGHT-hunt-28: the walk itself moved one layer down — every
//! ProcessName resolution, single or batched, walks through
//! `identity::name_walk::resolve_name_set` (one walker, one
//! matching semantics, no per-site drift class). `resolve_target`
//! keeps the single-target contract; `resolve_target_list` is the
//! multi lanes' batched twin — ONE /proc walk for the whole name
//! population of the list (hunt-27's residual #1: the per-name
//! loop was O(names x /proc), so a thousand-name multi walked
//! /proc a thousand times before the first map write — the same
//! quadratic class improve-50 closed for numeric ids).

use anyhow::Result;

use super::policy_lines::resolution_trace_line;
use super::types::Target;
use crate::ebpf::identity::name_walk::{matched_pairs_to_ids, resolve_name_set};

/// One name's matched `(pid, cgroup)` pairs through the shared
/// walker — `resolve_target`'s ProcessName arm, split so the single
/// arm and the batch read as one discipline (the pairs are the
/// trace's input; `matched_pairs_to_ids` is the reduction).
fn name_pairs(name: &str) -> Vec<(u32, u32)> {
    resolve_name_set(&[name.to_string()])
        .remove(&name.to_lowercase())
        .unwrap_or_default()
}

impl super::Limiter {
    /// Resolve a target to cgroup IDs. Process names do a DIRECT
    /// /proc walk (not the identity cache) to find all PIDs matching
    /// the name, then their cgroup IDs — the fix for aria2c sharing
    /// a cgroup with alacritty (first-pid-wins lied).
    pub(super) fn resolve_target(&mut self, target: &Target) -> Result<Vec<u32>> {
        match target {
            Target::CgroupId(id) => {
                if self.verbose {
                    eprintln_safe!("[limiter] cg:{id} targeted directly (no /proc walk)");
                }
                Ok(vec![*id])
            }
            Target::Container(c) => {
                // charger-core-2 (TIER A #5): resolve-only — the URI
                // becomes the workload's cgroup id, the rest is the
                // strict-single machinery (specific infrastructure errors,
                // never the generic no-match; the trace is resolve's own).
                crate::ebpf::identity::container::resolve(c, self.verbose)
            }
            Target::ProcessName(name) => {
                // Direct /proc walk: find all PIDs whose comm matches —
                // through the shared one-walk resolver (NIGHT-hunt-28:
                // the walk, the matching, and the pair-to-id reduction
                // are the same code the batched twin runs, so a name
                // resolves identically however it is spelled in).
                let matched = name_pairs(name);
                if self.verbose {
                    eprintln_safe!("{}", resolution_trace_line(name, &matched));
                }

                // Also refresh identity map for display purposes.
                self.identity.maybe_refresh();

                Ok(matched_pairs_to_ids(&matched))
            }
        }
    }

    /// The multi lanes' batched resolver (NIGHT-hunt-28): resolve
    /// every target of a list, walking /proc ONCE for the whole
    /// ProcessName population — the per-target `resolve_target`
    /// loop the strict/block multi lanes rode was O(names x
    /// /proc), the residual hunt-27 named and the owner has now
    /// called. Contract-identical to the loop it replaces:
    /// resolutions return in TARGET order; each name keeps
    /// `resolve_target`'s verbose trace (the matched (pid,
    /// cgroup) evidence, per name, in list order); the CgroupId
    /// arm never walked /proc and still does not; the Container
    /// arm keeps its own URI machinery at its list position; the
    /// identity refresh that rode per name rides once for the
    /// batch (the TTL gate made the per-name repeats no-ops by
    /// construction — one refresh is the same gate with the
    /// redundant checks dropped).
    pub(super) fn resolve_target_list(&mut self, targets: &[Target]) -> Result<Vec<Vec<u32>>> {
        // The name population, resolved in ONE walk before the
        // per-target loop (the walk prints nothing, so trace order
        // is the target order either way).
        let names: Vec<String> = targets
            .iter()
            .filter_map(|t| match t {
                Target::ProcessName(n) => Some(n.clone()),
                _ => None,
            })
            .collect();
        let matched_by_name = resolve_name_set(&names);

        let mut out: Vec<Vec<u32>> = Vec::with_capacity(targets.len());
        let mut walked_names = false;
        for target in targets {
            match target {
                Target::CgroupId(id) => {
                    if self.verbose {
                        eprintln_safe!("[limiter] cg:{id} targeted directly (no /proc walk)");
                    }
                    out.push(vec![*id]);
                }
                Target::Container(c) => {
                    out.push(crate::ebpf::identity::container::resolve(c, self.verbose)?);
                }
                Target::ProcessName(name) => {
                    let matched = matched_by_name
                        .get(&name.to_lowercase())
                        .cloned()
                        .unwrap_or_default();
                    if self.verbose {
                        eprintln_safe!("{}", resolution_trace_line(name, &matched));
                    }
                    out.push(matched_pairs_to_ids(&matched));
                    walked_names = true;
                }
            }
        }
        if walked_names {
            self.identity.maybe_refresh();
        }
        Ok(out)
    }
}
