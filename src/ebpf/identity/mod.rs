// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Identity mapping — resolve cgroup IDs to process names and users.
//!
//! Walks /proc and /sys/fs/cgroup to build a reverse map:
//! cgroup_id (u32) → ProcessIdentity.
//!
//! Refreshed periodically (default 10s TTL) to handle process churn without
//! paying the /proc walk cost on every observer poll.
//!
//! # Cosmic Dragon Architecture — Layer 2: Identity Resolution
//!
//! BPF programs return raw cgroup IDs. To make output human-readable, we
//! reverse-resolve: walk /proc to find which PID lives in which cgroup, then
//! look up the cgroup's path and the process's name/uid.
//!
//! The representative name per cgroup is chosen by MAJORITY VOTE
//! (NIGHT-hunt-10): the comm hosting the most processes names the
//! cgroup. The previous first-pid-wins rule let a single
//! chrome_crashpad process label the cgroup whose other ~30 processes
//! were all brave — status then showed the browser's real traffic
//! carrier as "cg:18526 (chrome_crashpad)", and removing that
//! "helper" silently removed brave's enforcement.
//!
//! This layer is **userspace-only** and **best-effort**: if resolution fails,
//! we fall back to raw `cg:{id}` labels. The BPF program is unaffected.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

mod tally;

// NIGHT-cybersecurity-2: sanitize_comm moved up to the always-compiled
// output layer (src/output/sanitize.rs) so the update check — which
// runs in BOTH feature graphs — reuses the one canonical terminal
// sanitizer instead of a copy.
use crate::output::sanitize_comm;
use tally::{pick_representative, CommStat};

/// Default refresh interval: rebuild the identity map every 10 seconds.
const DEFAULT_REFRESH_TTL_SECS: u64 = 10;

/// Process identity information.
#[derive(Debug, Clone, Default)]
pub struct ProcessIdentity {
    pub cgroup_id: u32,
    pub uid: u32,
    pub comm: String,
}

/// Cached identity mapping: cgroup_id (u32) → ProcessIdentity.
///
/// Refreshed periodically to handle process churn. Build cost is O(nproc),
/// paid once per TTL window.
#[derive(Debug)]
pub struct IdentityMap {
    cache: HashMap<u32, ProcessIdentity>,
    last_refresh: Option<Instant>,
    refresh_ttl: Duration,
}

impl Default for IdentityMap {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityMap {
    /// Create new empty identity map with default 10s refresh TTL.
    pub fn new() -> Self {
        IdentityMap {
            cache: HashMap::new(),
            last_refresh: None,
            refresh_ttl: Duration::from_secs(DEFAULT_REFRESH_TTL_SECS),
        }
    }

    /// Create with custom refresh TTL (test seam for TTL logic).
    #[cfg(test)]
    pub fn with_ttl(ttl: Duration) -> Self {
        IdentityMap {
            cache: HashMap::new(),
            last_refresh: None,
            refresh_ttl: ttl,
        }
    }

    /// Test seam: insert a synthetic identity directly.
    ///
    /// Cross-module harnesses (the frame benchmark in `render.rs`)
    /// need realistic label sets without walking /proc. In-module tests
    /// touch `cache` directly; this seam offers the same power to
    /// sibling modules under cfg(test).
    #[cfg(test)]
    pub fn insert(&mut self, id: ProcessIdentity) {
        self.cache.insert(id.cgroup_id, id);
    }

    /// Force a full refresh: walk /proc to rebuild the reverse map.
    ///
    /// For each live PID:
    /// 1. Read `/proc/<pid>/cgroup` → cgroup path (v2 format: `0::/path`)
    /// 2. `stat()` `/sys/fs/cgroup{path}` → the kernfs inode IS the
    ///    64-bit cgroup ID
    /// 3. Truncate to u32 to match BPF map key
    /// 4. Read `/proc/<pid>/comm` → process name (tallied per cgroup)
    /// 5. Read `/proc/<pid>/status` → uid
    ///
    /// The cgroup's representative identity is the MAJORITY comm
    /// (NIGHT-hunt-10, see [`pick_representative`]) — first-pid-wins
    /// let one chrome_crashpad speak for a cgroup of 30 brave
    /// processes. Unreadable comms never outvote real ones; a cgroup
    /// whose every comm read failed keeps an empty-comm identity (the
    /// `cg:{id}` label fallback) so crash-recovery still sees it alive.
    ///
    /// Returns the number of unique cgroups discovered.
    pub fn refresh(&mut self) -> usize {
        self.cache.clear();

        // cgroup_id → comm tally. Entries exist for every resolvable
        // cgroup even when no comm was readable (empty map), so the
        // alive-cgroup set stays complete for recover().
        let mut per_cgroup: HashMap<u32, HashMap<String, CommStat>> = HashMap::new();

        let proc_entries = match fs::read_dir("/proc") {
            Ok(e) => e,
            Err(_) => {
                self.last_refresh = Some(Instant::now());
                return 0;
            }
        };

        for entry in proc_entries.flatten() {
            let name = entry.file_name();
            let name_str = match name.to_str() {
                Some(s) => s,
                None => continue,
            };

            // Only numeric directories are PIDs.
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Shared /proc boundary helpers (NIGHT-optimized-1): the
            // pid-to-cgroup resolution and the sanitized comm read now
            // live once — this walk, the connection walk, and the
            // resolve_target match walk all call the same functions, so
            // boundary fixes (like the cybersecurity-1 sanitize) apply
            // in one place, not three.
            let Some(cgroup_id) = pid_cgroup_id(pid) else {
                continue;
            };

            // Read /proc/<pid>/comm for the tally. Sanitized at the
            // boundary (NIGHT-cybersecurity-1): the label is attacker
            // controllable via prctl, and it flows to every display
            // surface — list-apps, observe/top, detail lines — as well
            // as the majority-vote tally below.
            let comm = pid_comm(pid).unwrap_or_default();

            // Unreadable comm: count the cgroup as alive but never let a
            // blank name outvote real ones.
            let comm_stats = per_cgroup.entry(cgroup_id).or_default();
            if comm.is_empty() {
                continue;
            }

            // Read /proc/<pid>/status for uid (first field after "Uid:").
            let uid = fs::read_to_string(format!("/proc/{pid}/status"))
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.starts_with("Uid:"))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|u| u.parse().ok())
                })
                .unwrap_or(0);

            match comm_stats.get_mut(&comm) {
                Some(stat) => {
                    stat.count += 1;
                    if pid < stat.min_pid {
                        stat.min_pid = pid;
                        stat.min_pid_uid = uid;
                    }
                }
                None => {
                    comm_stats.insert(
                        comm,
                        CommStat {
                            count: 1,
                            min_pid: pid,
                            min_pid_uid: uid,
                        },
                    );
                }
            }
        }

        for (cgroup_id, comm_stats) in per_cgroup {
            let (comm, uid) = pick_representative(&comm_stats).unwrap_or_default();
            self.cache.insert(
                cgroup_id,
                ProcessIdentity {
                    cgroup_id,
                    uid,
                    comm,
                },
            );
        }

        self.last_refresh = Some(Instant::now());
        self.cache.len()
    }

    /// Refresh if the TTL has elapsed. Returns true if a refresh happened.
    pub fn maybe_refresh(&mut self) -> bool {
        let needs_refresh = match self.last_refresh {
            None => true,
            Some(last) => last.elapsed() >= self.refresh_ttl,
        };

        if needs_refresh {
            self.refresh();
            true
        } else {
            false
        }
    }

    /// Look up identity for a cgroup ID. Returns None if not in cache.
    pub fn get(&self, cgroup_id: u32) -> Option<&ProcessIdentity> {
        self.cache.get(&cgroup_id)
    }

    /// Get a short display label for a cgroup ID.
    ///
    /// Format: `cg:73386 (firefox)` if resolved, else `cg:73386`.
    pub fn label(&self, cgroup_id: u32) -> String {
        match self.get(cgroup_id) {
            Some(id) if !id.comm.is_empty() => {
                format!("cg:{cgroup_id} ({})", id.comm)
            }
            _ => format!("cg:{cgroup_id}"),
        }
    }

    /// Number of cached identities.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Is the cache empty?
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// All known identities (unspecified order).
    pub fn all(&self) -> Vec<&ProcessIdentity> {
        self.cache.values().collect()
    }
}

/// Resolve the cgroup ID (u32, BPF map key width) a PID lives in
/// (NIGHT-optimized-1: the ONE canonical pid-to-cgroup boundary —
/// the identity walk, the connection walk, and the resolve_target
/// match walk all route through here; the only public door to the
/// path-based resolver below, so no caller can skip the u32
/// truncation or the v2-format parsing this function owns).
///
/// Reads `/proc/<pid>/cgroup`, parses the cgroup v2 `0::/path`
/// single-line format, and resolves the ID via
/// [`cgroup_id_from_path`]. Truncates to u32 to match the
/// BPF map key type (cgroup IDs are well under 2^32 in practice —
/// see the SAFETY_ANALYSIS audit note on ID width).
pub fn pid_cgroup_id(pid: u32) -> Option<u32> {
    let content = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let path = content.lines().next()?.split("::").nth(1)?.trim();
    if path.is_empty() {
        return None;
    }
    let id64 = cgroup_id_from_path(&format!("/sys/fs/cgroup{path}"))?;
    Some(id64 as u32)
}

/// Read and sanitize a PID's comm (NIGHT-optimized-1: the ONE
/// canonical comm boundary; sanitize semantics per
/// [`sanitize_comm`]). Callers own the fallback: the identity tally
/// treats a failed read as an empty label, the connection walk shows
/// `pid {n}`, and the match walk lowercases for case-insensitive
/// comparison.
///
/// NIGHT-engrave-7 (the owner's `WebKitNetworkPro` find): the
/// kernel hard-caps comm at 15 bytes (TASK_COMM_LEN minus NUL), so
/// `WebKitNetworkProcess` walks in as `WebKitNetworkPr` — a name
/// that looks zelynic-trimmed but is the kernel's own ceiling. When
/// the comm sits AT the cap, this boundary enriches it from
/// `/proc/<pid>/cmdline` argv[0]'s basename (the exec-time name,
/// uncapped) under two guards: the basename must START WITH the
/// capped comm (prefix continuity — same process, fuller name; a
/// 7-char `python3` never triggers this, its own name is honest),
/// and the result is capped at [`DISPLAY_NAME_MAX`] columns with an
/// ellipsis — the footer's actionable line budgets 37 + name + 7
/// columns, and a 64-char name would wrap the pinned footer off an
/// 80-column frame (the frame-harmony reason 24 is the ceiling).
pub fn pid_comm(pid: u32) -> Option<String> {
    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| sanitize_comm(s.trim()))?;
    // The common case — a comm UNDER the kernel's 15-byte cap is
    // the process's own honest name: no second read, no enrichment
    // possible, no cap needed (nothing under 15 exceeds 24).
    if comm.len() != 15 {
        return Some(comm);
    }
    // At the cap: enrich opportunistically. A vanished cmdline (the
    // process exiting between the two reads, a kernel thread's empty
    // argv) keeps the capped comm — enrichment never demotes a name
    // the walk already resolved.
    let cmdline = fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .unwrap_or_default();
    Some(display_name(&comm, &cmdline))
}

/// The display-name budget (NIGHT-engrave-7): process names cap at
/// 24 columns, ellipsis included. Real offenders fit whole —
/// `WebKitNetworkProcess` (20), `systemd-resolved` (16),
/// `google-chrome-stable` (20) — while pathological argv[0] basenames
/// (JVM classpath launchers, hashed AppImage paths) degrade to 23
/// chars plus `…` instead of exploding the label column, the footer
/// headline, or the `limit target with 'sudo zelynic ss <name> …'`
/// line the frame suggests (37 + 24 + 7 = 68 columns on the classic
/// 80 — the frame keeps its rails).
const DISPLAY_NAME_MAX: usize = 24;

/// The kernel-cap enrichment + display cap as one pure rule (split
/// out of [`pid_comm`] so the pins can drive it without a live
/// `/proc`): a comm at the 15-byte cap tries argv[0]'s basename,
/// takes it only when the prefix holds, and caps the winner at
/// [`DISPLAY_NAME_MAX`] columns with an ellipsis. A short comm
/// returns unchanged — only the cap can hide a name.
fn display_name(comm: &str, cmdline: &[u8]) -> String {
    let mut name = comm.to_string();
    if let Some(full) = argv0_basename(cmdline) {
        // Prefix continuity: argv[0]'s basename must extend the
        // capped comm — same process, fuller name. A basename that
        // does not start with the comm (a rewritten argv, a `(`
        // launcher) is a different string, and the cap's ambiguity
        // is not worth the swap.
        if full.starts_with(comm) && full.chars().count() > 15 {
            name = full;
        }
    }
    // The display cap: 24 columns, ellipsis occupying the last.
    let chars: Vec<char> = name.chars().collect();
    if chars.len() > DISPLAY_NAME_MAX {
        let mut capped: String = chars[..DISPLAY_NAME_MAX - 1].iter().collect();
        capped.push('…');
        return capped;
    }
    name
}

/// argv[0]'s basename from a raw `/proc/<pid>/cmdline` buffer
/// (NUL-separated argv): everything before the first NUL, then the
/// final path component — `WebKitNetworkProcess`. Kernel threads
/// (empty cmdline) and degenerate basenames yield None; the caller
/// keeps the capped comm.
fn argv0_basename(cmdline: &[u8]) -> Option<String> {
    let end = cmdline
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(cmdline.len());
    if end == 0 {
        return None; // kernel thread or zombie: no argv at all
    }
    let argv0 = &cmdline[..end];
    let path = std::str::from_utf8(argv0).ok()?;
    let base = path.rsplit('/').next()?;
    if base.is_empty() {
        return None;
    }
    Some(sanitize_comm(base))
}

/// Resolve a 64-bit cgroup ID from a cgroup v2 path.
///
/// The kernfs inode number IS the cgroup ID: `bpf_skb_cgroup_id()`
/// returns `cgrp->kn->id`, and kernfs publishes that same node id as
/// the directory's `st_ino` — `stat(2)` is the whole resolution, and it
/// is the numbering every kernel in the verified cross-distro matrix
/// ran on. (NIGHT-hunt-31: the "cgroup.id file" this resolver once
/// tried first never existed in any mainline kernel — the stat path
/// below was the one that always worked, so the phantom file read is
/// gone.)
fn cgroup_id_from_path(path: &str) -> Option<u64> {
    fs::metadata(path).ok().map(|meta| meta.ino())
}

// NIGHT-engrave-7: the identity pins moved to the single test/ tree
// (cosmostrix Pattern C) when the name enrichment pushed this file
// past the owner's LOC cap — #[path]-wired across trees exactly like
// the render and limiter pins.
#[cfg(test)]
#[path = "../../../test/ebpf/identity/identity_tests.rs"]
mod tests;
