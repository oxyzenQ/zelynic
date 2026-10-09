// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Container-native target resolution (NIGHT-upgrade-
//! charger-core-2, TIER A #5) — `docker://<name>` and
//! `k8s://<namespace>/<pod>` resolve to the workload's cgroup id.
//!
//! The contract is resolve-only, by design: a container reference
//! becomes the same cgroup id `cg:<id>` targets, and every
//! downstream surface (policy writes, unstrict, the enforcement
//! probe) is the single lane's machinery unchanged — containers are
//! just another way to NAME a cgroup.
//!
//! Resolution sources, all read-only: the docker Engine API over
//! its unix socket plus a bounded /sys/fs/cgroup walk (docker.rs,
//! the sibling split), and the kubelet's /var/log/pods directory
//! names (`<namespace>_<pod>_<uid>`) plus the same walk for the pod
//! cgroup (`...pod<uid>.slice` for the systemd driver, `pod<uid>`
//! for cgroupfs — here).
//!
//! The dangerous-target blocklist does not apply to container
//! targets: it names HOST system processes (sshd, systemd) whose
//! throttling can lock the operator out; a container target writes
//! a policy against a workload cgroup under the host tree — it can
//! starve the workload, never the host. Direct `cg:<id>` targets
//! get the same treatment when their members resolve (the
//! NIGHT-blade-18 guard), and a container named "sshd" is a label,
//! not the host daemon.
//!
//! Pure cores (URI grammar, log-dir parsing, cgroup-name matching,
//! the walk) are separated from the IO wrappers so every decision
//! pins rootlessly in test/ebpf/identity/container_tests.rs.

mod docker;

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};

/// The cgroup-walk bounds: a hostile or enormous tree cannot wedge a
/// CLI invocation — depth 10 covers every driver layout this
/// resolver knows (root → slices → pod slice ≈ 4), and 200_000
/// entries is a large single node's whole tree.
const WALK_MAX_DEPTH: usize = 10;
const WALK_MAX_ENTRIES: usize = 200_000;

/// One container target, as typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerRef {
    /// `docker://<name-or-id-prefix>`
    Docker { name: String },
    /// `k8s://<namespace>/<pod>`
    K8s { namespace: String, pod: String },
}

impl ContainerRef {
    /// The display form — round-trips: `parse_container(display())`
    /// returns the same reference, so every surface that prints a
    /// target (the success epilogue's unstrict suggestion, status
    /// labels) produces a command that works verbatim.
    pub fn display(&self) -> String {
        match self {
            ContainerRef::Docker { name } => format!("docker://{name}"),
            ContainerRef::K8s { namespace, pod } => format!("k8s://{namespace}/{pod}"),
        }
    }
}

/// Parse a container URI — `None` means "not a container target",
/// so the caller keeps its name-target contract. Grammar (pure,
/// pinned): `docker://<name>` with a non-empty name carrying no '/'
/// or ':' (both break the target grammars that embed the string),
/// and `k8s://<namespace>/<pod>` with exactly one '/' and both
/// parts non-empty. Malformed shapes return None — they fall back
/// to the process-name lane and surface as the graceful no-match,
/// the same contract alnum-bearing garbage owns.
pub fn parse_container(s: &str) -> Option<ContainerRef> {
    if let Some(rest) = s.strip_prefix("docker://") {
        if rest.is_empty() || rest.contains('/') || rest.contains(':') {
            return None;
        }
        return Some(ContainerRef::Docker {
            name: rest.to_string(),
        });
    }
    if let Some(rest) = s.strip_prefix("k8s://") {
        let mut parts = rest.split('/');
        let namespace = parts.next()?;
        let pod = parts.next()?;
        if parts.next().is_some() {
            return None; // 'k8s://a/b/c' — more than one slash
        }
        if namespace.is_empty() || pod.is_empty() || rest.contains(':') {
            return None;
        }
        return Some(ContainerRef::K8s {
            namespace: namespace.to_string(),
            pod: pod.to_string(),
        });
    }
    None
}

/// Resolve a container target to its cgroup ids (one: a container
/// is one workload cgroup). Every failure is a specific, honest
/// error — "socket not found", "no container named X", "no cgroup
/// directory" — never the generic no-match, because the input was
/// a well-formed reference whose INFRASTRUCTURE answered.
pub fn resolve(c: &ContainerRef, verbose: bool) -> Result<Vec<u32>> {
    match c {
        ContainerRef::Docker { name } => docker::resolve_docker(name, verbose),
        ContainerRef::K8s { namespace, pod } => resolve_k8s(namespace, pod, verbose),
    }
}

// ━━ k8s ━━

/// Pure: does a uid string carry the kubelet's UUID shape (36
/// chars, hex groups 8-4-4-4-12)? The filter keeps unrelated
/// /var/log/pods entries (agent-side files) from masquerading as
/// pods.
pub(super) fn uid_looks_like_uuid(uid: &str) -> bool {
    if uid.len() != 36 {
        return false;
    }
    let b = uid.as_bytes();
    [8, 13, 18, 23].iter().all(|&i| b[i] == b'-')
        && uid.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// Pure: parse one /var/log/pods directory name into (namespace,
/// pod, uid). Kubelet names them `<namespace>_<pod>_<uid>`; both
/// namespace and pod are DNS labels/subdomains (no '_'), so exactly
/// three '_' separated parts parse, and the uid must look like a
/// UUID.
pub(super) fn parse_pod_log_dir(name: &str) -> Option<(String, String, String)> {
    let parts: Vec<&str> = name.split('_').collect();
    if parts.len() != 3 {
        return None;
    }
    let (ns, pod, uid) = (parts[0], parts[1], parts[2]);
    if ns.is_empty() || pod.is_empty() || !uid_looks_like_uuid(uid) {
        return None;
    }
    Some((ns.to_string(), pod.to_string(), uid.to_string()))
}

/// Pure: the pod uids whose log dir matches the reference.
pub(super) fn pod_uid_matches(
    dirs: &[(String, String, String)],
    namespace: &str,
    pod: &str,
) -> Vec<String> {
    dirs.iter()
        .filter(|(ns, p, _)| ns == namespace && p == pod)
        .map(|(_, _, uid)| uid.clone())
        .collect()
}

/// Resolve `k8s://<namespace>/<pod>` to the pod cgroup's id. Stale
/// log dirs (a restarted pod, the old dir not yet GC'd) are
/// disambiguated by the cgroup tree itself: only the LIVE pod owns
/// a `pod<uid>` directory, so every candidate uid is probed and a
/// single survivor wins; a tie stays an honest ambiguity.
fn resolve_k8s(namespace: &str, pod: &str, verbose: bool) -> Result<Vec<u32>> {
    let log_root = Path::new("/var/log/pods");
    let entries = std::fs::read_dir(log_root).map_err(|_| {
        anyhow!(
            "no /var/log/pods directory — k8s:// resolves pods through the \
             kubelet's pod log dirs, and this host has none (not a kubelet node?)"
        )
    })?;
    let mut dirs: Vec<(String, String, String)> = Vec::new();
    for entry in entries.flatten() {
        if let Some(parsed) = entry.file_name().to_str().and_then(parse_pod_log_dir) {
            dirs.push(parsed);
        }
    }
    let uids = pod_uid_matches(&dirs, namespace, pod);
    if uids.is_empty() {
        bail!(
            "no pod '{pod}' in namespace '{namespace}' under /var/log/pods\n  \
             tip: ls /var/log/pods lists this node's pods as namespace_podname_uid"
        );
    }

    // Stale-log-dir disambiguation: the cgroup tree is the truth.
    let live: Vec<String> = uids
        .iter()
        .filter(|uid| {
            find_cgroup_dir(&PathBuf::from("/sys/fs/cgroup"), &|p| {
                pod_cgroup_matches(p, uid)
            })
            .is_some()
        })
        .cloned()
        .collect();
    let chosen = match live.as_slice() {
        [] => bail!(
            "pod '{namespace}/{pod}' has log dirs but no live pod cgroup — \
             the pod is not running on this node"
        ),
        [one] => one.clone(),
        many => {
            bail!(
                "pod '{namespace}/{pod}' matches {} live uids ({}) — target the \
                 cgroup directly: zelynic list-apps",
                many.len(),
                many.join(", ")
            )
        }
    };
    if verbose && uids.len() > 1 {
        eprintln_safe!(
            "[container] k8s://{namespace}/{pod}: {} stale log dir(s) skipped, live uid {chosen}",
            uids.len() - 1
        );
    }

    let dir = find_cgroup_dir(&PathBuf::from("/sys/fs/cgroup"), &|p| {
        pod_cgroup_matches(p, &chosen)
    })
    .ok_or_else(|| {
        anyhow!(
            "pod '{namespace}/{pod}' (uid {chosen}) has no cgroup under \
             /sys/fs/cgroup — unrecognized cgroup driver layout"
        )
    })?;
    let id = cgroup_id_of(&dir)
        .ok_or_else(|| anyhow!("pod cgroup {} could not be stat()ed", dir.display()))?;
    if verbose {
        eprintln_safe!(
            "[container] k8s://{namespace}/{pod} → {} (cgroup cg:{id})",
            dir.display()
        );
    }
    Ok(vec![id])
}

// ━━ the cgroup tree walk ━━

/// Pure: is this directory the pod's cgroup? The systemd driver's
/// `kubepods[-<qos>]-pod<uid>.slice` (matched by suffix — the QoS
/// class prefixes vary), and the cgroupfs driver's exact `pod<uid>`.
pub(super) fn pod_cgroup_matches(path: &Path, uid: &str) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name.ends_with(&format!("pod{uid}.slice")) || name == format!("pod{uid}")
}

/// Bounded DFS for the first directory the matcher accepts — depth
/// and entry caps keep the walk terminated on any tree. Rooted at
/// an argument so the pins can drive it over a tempdir tree.
fn find_cgroup_dir(root: &Path, matcher: &dyn Fn(&Path) -> bool) -> Option<PathBuf> {
    let mut visited = 0usize;
    fn descend(
        dir: &Path,
        depth: usize,
        visited: &mut usize,
        matcher: &dyn Fn(&Path) -> bool,
    ) -> Option<PathBuf> {
        if depth > WALK_MAX_DEPTH {
            return None;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return None;
        };
        for entry in entries.flatten() {
            *visited += 1;
            if *visited > WALK_MAX_ENTRIES {
                return None;
            }
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            if matcher(&path) {
                return Some(path);
            }
            if let Some(hit) = descend(&path, depth + 1, visited, matcher) {
                return Some(hit);
            }
        }
        None
    }
    descend(root, 0, &mut visited, matcher)
}

/// The cgroup id of a cgroup directory — the kernfs inode, the same
/// resolution `pid_cgroup_id` applies to /proc paths, truncated to
/// the BPF map's u32 (the identity walk's documented contract).
fn cgroup_id_of(dir: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(dir).ok().map(|m| m.ino() as u32)
}

// NIGHT-hunt-17: pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the identity pins.
#[cfg(test)]
#[path = "../../../../test/ebpf/identity/container_tests.rs"]
mod container_tests;
