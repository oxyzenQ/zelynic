// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The `iface://<name>` lane (night-T-2, the five-frontier review's
//! iface half) — a VRF (Virtual Routing and Forwarding) domain
//! resolves to the cgroup `ip vrf exec` groups its processes into.
//!
//! The physics, stated honestly: zelynic policies cgroups, and a
//! plain interface (wg0, eth1) owns no cgroup — but a VRF DOES.
//! iproute2's `ip vrf exec <name> <cmd>` creates the cgroup
//! `<caller-path>/vrf/<name>` under the cgroup2 root (keyed by the
//! caller's cgroup path and network namespace — the exact contract
//! its own `ip vrf identify` reads back from `/proc/<pid>/cgroup`'s
//! `/vrf/<name>` segment) and moves the exec'd pid into it, so every
//! process a network engineer runs inside the VRF domain shares one
//! named cgroup — exactly the workload-shape the strict single lane
//! targets. The iface:// lane resolves that cgroup; every downstream
//! surface is the single lane's machinery unchanged, and no eBPF
//! changed (the resolver reads the cgroup tree, nothing else).
//!
//! The parent law is the iproute2 contract: the domain's cgroup is
//! the directory `<name>` whose PARENT is named `vrf` (at any depth —
//! the caller's path prefixes it). A directory named `<name>` without
//! a `vrf` parent (a slice, a scope, a depth-1 impostor) is not a VRF
//! domain, and the matcher refuses it — precision over tolerance.
//!
//! A cgroup whose `cgroup.procs` is empty is refused as dead (the
//! VRF exists but nothing runs in it — the netns lane's empty
//! verdict, one lane over). A plain interface with no same-named
//! cgroup is refused with the physics named and the honest
//! alternatives offered (`netns://` for the namespace, `cg:<id>` for
//! the cgroup directly) — never the generic no-match, because the
//! input was a well-formed reference whose INFRASTRUCTURE answered.
//!
//! Volatility is stated, not hidden: VRF names and their cgroups are
//! host-local; `ip vrf del <name>` removes the domain whole.
//! Resolution reads live state at apply time — the same contract the
//! process-name lane owns; the resolved cgroup id is the durable
//! handle, the URI is the speller.
//!
//! Pure cores (the vrf-parent matcher) are separated from the IO
//! wrappers (the walk, the cgroup.procs read) so every decision pins
//! rootlessly in test/ebpf/identity/iface_tests.rs.

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};

use super::{cgroup_id_of, find_cgroup_dir};

/// Pure: is this directory the VRF domain's cgroup? iproute2's
/// `ip vrf exec <name>` creates the domain cgroup as `<name>` under
/// a parent directory named `vrf` — the shape `ip vrf identify`
/// reads back from `/proc/<pid>/cgroup` (the `/vrf/<name>` segment).
/// The parent check is the contract; a same-named directory under a
/// slice or at the root is an impostor the matcher refuses.
pub(super) fn iface_cgroup_matches(path: &Path, name: &str) -> bool {
    path.file_name().and_then(|n| n.to_str()) == Some(name)
        && path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            == Some("vrf")
}

/// Resolve `iface://<name>` to the VRF domain's cgroup id. Every
/// failure is a specific, honest error — the sibling lanes' law —
/// because the input was a well-formed reference whose
/// INFRASTRUCTURE answered.
pub(super) fn resolve_iface(name: &str) -> Result<Vec<u32>> {
    let root = PathBuf::from("/sys/fs/cgroup");
    let dir = find_cgroup_dir(&root, &|p| iface_cgroup_matches(p, name));
    let Some(dir) = dir else {
        // No vrf/<name> cgroup carries the name. Name the physics and
        // the honest doors — the interface check only sharpens the
        // error (a VRF's device usually shares the domain's name).
        if !Path::new("/sys/class/net").join(name).exists() {
            bail!(
                "no interface '{name}' and no vrf domain '{name}' on this host — the iface:// \
                 lane resolves VRF domains ('ip vrf exec' groups its processes into the \
                 vrf/{name} cgroup)\n  \
                 tip: ip -d link lists this host's VRF devices"
            );
        }
        bail!(
            "interface '{name}' owns no cgroup — the iface:// lane resolves VRF domains \
             ('ip vrf exec' groups its processes into the vrf/{name} cgroup); a plain \
             interface carries no cgroup\n  \
             tip: target the namespace's workloads with netns://<name>, or the cgroup \
             directly: zelynic list-apps, then cg:<id>"
        );
    };

    // Liveness: the VRF domain's own cgroup.procs must name at least
    // one live process — a domain with no process has no workload to
    // limit (the netns lane's empty verdict, the same law).
    let procs = std::fs::read_to_string(dir.join("cgroup.procs")).map_err(|e| {
        anyhow!(
            "vrf cgroup {} cgroup.procs could not be read: {e}",
            dir.display()
        )
    })?;
    let members = procs.trim().lines().count();
    if members == 0 {
        bail!(
            "cgroup '{name}' exists but no process lives in it — nothing to limit\n  \
             tip: start one: ip vrf exec {name} <cmd>"
        );
    }
    let id = cgroup_id_of(&dir)
        .ok_or_else(|| anyhow!("vrf cgroup {} could not be stat()ed", dir.display()))?;
    crate::output::verbose::vlog!(
        "iface",
        "iface://{name} → {} ({members} member process(es), cgroup cg:{id})",
        dir.display()
    );
    Ok(vec![id])
}

// NIGHT-hunt-17: pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the netns lane's.
#[cfg(test)]
#[path = "../../../../test/ebpf/identity/iface_tests.rs"]
mod iface_tests;
