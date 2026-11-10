// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The `netns://<name>` lane (night-netns-1, the five-frontier
//! review's netns half — its iface:// twin was ruled out) — a named
//! network namespace (the `ip netns add <name>` family, the handle
//! bind-mounted under `/run/netns/`) resolves to the cgroup id of
//! the workload living inside it.
//!
//! The contract is the container lanes' own, resolve-only by
//! design: the URI is just another way to NAME a cgroup, and every
//! downstream surface is the single lane's machinery unchanged. No
//! eBPF changed — the namespace is read through procfs, never
//! entered, never modified.
//!
//! Resolution, all read-only:
//!   1. the handle file `/run/netns/<name>` (the legacy
//!      `/var/run/netns/<name>` checked second, for the layouts
//!      where it is not a symlink to /run) — its absence is a
//!      specific error naming the discovery command, never the
//!      generic no-match;
//!   2. the handle's nsfs inode IS the namespace's identity — the
//!      same number every member's `readlink /proc/<pid>/ns/net`
//!      reports as `net:[<ino>]`;
//!   3. one /proc walk collects the member pids (inode match) and
//!      each member's cgroup id through the identity walk's own
//!      `pid_cgroup_id` boundary;
//!   4. the verdict ([`netns_verdict`], pure): no member — the
//!      namespace exists but nothing lives in it; one distinct
//!      member cgroup — the target; two or more — the honest
//!      ambiguity, refusing with the ids named and the direct
//!      `cg:<id>` route as the tip.
//!
//! The ambiguity refusal is a safety property, not a limitation:
//! `sudo ip netns exec` leaves the exec'd process in the caller's
//! session cgroup, so a namespace shared between a workload and an
//! operator's shell would otherwise drag a host-side cgroup into
//! the policy — the exact lockout the container lanes' doc names
//! (a URI target can starve the workload, never the host). The
//! direct `cg:<id>` route stays the honest door for shapes that
//! genuinely span cgroups.
//!
//! Volatility is stated, not hidden: namespace names are
//! host-local and the nsfs inode churns across reboots — the URI
//! resolves against LIVE state at apply time, the same contract
//! the process-name lane owns; the resolved cgroup id is the
//! durable handle, the URI is the speller.
//!
//! Pure cores (the ns-link inode parser, the verdict reduction)
//! are separated from the IO wrappers (the handle stat, the /proc
//! walk) so every decision pins rootlessly in
//! test/ebpf/identity/netns_tests.rs.

use std::path::PathBuf;

use anyhow::{Result, anyhow, bail};

/// Pure: the nsfs inode a `/proc/<pid>/ns/net` readlink reports —
/// `net:[4026532500]` → `4026532500`. Anything else is `None`: the
/// procfs format is kernel-owned, and a shape that does not parse
/// is a process we cannot vouch for, never a guess.
pub(super) fn parse_ns_ino(link: &str) -> Option<u64> {
    let rest = link.strip_prefix("net:[")?;
    let ino = rest.strip_suffix(']')?;
    if ino.is_empty() || !ino.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    ino.parse::<u64>().ok()
}

/// Pure: the member verdict — the member cgroup ids reduced to the
/// lane's outcome. No member is its own shape (the namespace
/// exists, the workload does not), one distinct cgroup is the
/// target, two or more is the honest ambiguity (sorted, so the
/// error text is deterministic).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NetnsVerdict {
    Empty,
    One(u32),
    Ambiguous(Vec<u32>),
}

pub(super) fn netns_verdict(member_cgroups: &[u32]) -> NetnsVerdict {
    let distinct: std::collections::BTreeSet<u32> = member_cgroups.iter().copied().collect();
    let ids: Vec<u32> = distinct.into_iter().collect();
    match ids.len() {
        0 => NetnsVerdict::Empty,
        1 => NetnsVerdict::One(ids[0]),
        _ => NetnsVerdict::Ambiguous(ids),
    }
}

/// The named namespace's handle paths, probed in order — the
/// modern `/run/netns` first (where `ip netns add` mounts since
/// util-linux moved runstate to /run), the legacy `/var/run/netns`
/// second for the layouts where it is not a symlink to /run.
fn handle_candidates(name: &str) -> [PathBuf; 2] {
    [
        PathBuf::from("/run/netns").join(name),
        PathBuf::from("/var/run/netns").join(name),
    ]
}

/// Resolve `netns://<name>` to the workload cgroup's id living in
/// the named namespace. Every failure is a specific, honest error
/// — the sibling lanes' law — because the input was a well-formed
/// reference whose INFRASTRUCTURE answered.
pub(super) fn resolve_netns(name: &str) -> Result<Vec<u32>> {
    let handle = handle_candidates(name)
        .into_iter()
        .find(|p| p.exists())
        .ok_or_else(|| {
            if std::fs::metadata("/run/netns").is_ok()
                || std::fs::metadata("/var/run/netns").is_ok()
            {
                anyhow!(
                    "no network namespace named '{name}' under /run/netns\n  \
                     tip: ip netns lists this host's named namespaces"
                )
            } else {
                anyhow!(
                    "no /run/netns directory — netns:// resolves named network \
                     namespaces (the 'ip netns add <name>' family), and this host \
                     has none"
                )
            }
        })?;
    use std::os::unix::fs::MetadataExt;
    // The handle's inode is the namespace identity (an nsfs inode —
    // the same number the member pids' ns links report).
    let ns_ino = std::fs::metadata(&handle)
        .map_err(|e| {
            anyhow!(
                "namespace handle {} could not be stat()ed: {e}",
                handle.display()
            )
        })?
        .ino();
    crate::output::verbose::vlog!(
        "netns",
        "handle {} (nsfs inode {ns_ino}), walking /proc for members",
        handle.display()
    );

    // One /proc walk: member pids by ns-link inode match, each
    // member's cgroup id through the identity walk's own boundary.
    let mut member_cgroups: Vec<u32> = Vec::new();
    let mut members = 0usize;
    let Ok(entries) = std::fs::read_dir("/proc") else {
        bail!(
            "no /proc — netns:// resolves member processes through procfs, \
             and this view has none"
        );
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(link) = std::fs::read_link(format!("/proc/{pid}/ns/net")) else {
            continue; // raced exit, or a view without the perm — not a member
        };
        let Some(link_ino) = link.to_str().and_then(parse_ns_ino) else {
            continue;
        };
        if link_ino != ns_ino {
            continue;
        }
        members += 1;
        if let Some(cid) = crate::ebpf::identity::pid_cgroup_id(pid) {
            member_cgroups.push(cid);
        }
    }

    match netns_verdict(&member_cgroups) {
        NetnsVerdict::One(id) => {
            crate::output::verbose::vlog!(
                "netns",
                "netns://{name} → {members} member process(es) (cgroup cg:{id})"
            );
            Ok(vec![id])
        }
        NetnsVerdict::Empty => bail!(
            "namespace '{name}' exists but no process lives in it — nothing to limit \
             (empty, or the handle is a stale unmounted leftover)\n  \
             tip: recreate it if stale: ip netns del {name} && ip netns add {name}, \
             or start a workload: ip netns exec {name} <cmd>"
        ),
        NetnsVerdict::Ambiguous(ids) => {
            let list = ids
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "namespace '{name}' spans {} member cgroups ({list}) — a netns:// \
                 target writes one policy per workload cgroup\n  \
                 tip: target the cgroup directly: zelynic list-apps, then cg:<id>",
                ids.len()
            )
        }
    }
}

// NIGHT-hunt-17: pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the docker lane's.
#[cfg(test)]
#[path = "../../../../test/ebpf/identity/netns_tests.rs"]
mod netns_tests;
