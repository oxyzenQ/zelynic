// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! eBPF limiter — token-bucket rate enforcement per cgroup or per group.
//!
//! Module layout (NIGHT-hunt-3 restructure):
//! - `types.rs`   — constants + BPF map structs + high-level API types
//! - `format.rs`  — rate/duration parsing + formatting helpers
//! - `policy.rs`  — apply / resolve / write / delete policy operations
//! - `stats.rs`   — status printing + map readers + identity accessors
//! - this file    — the `Limiter` struct, lifecycle (attach / open /
//!   is_pinned / Drop), and the public re-export surface.

mod format;
mod policy;
mod stats;
mod types;

// Re-export public types/functions for external use.
pub use format::{
    find_bpf_object, format_bytes, format_rate, monotonic_ns, parse_rate, parse_time_duration,
    terminal_width, validate_rate,
};
pub use types::{Direction, LimiterStatsRaw, PolicyRaw, RateSpec, Target, MAX_RATE, MIN_RATE};

pub use crate::ebpf::pin::{
    pin_dir_has_files, read_pinned_schema_version, unpin_all, PIN_DIR, PIN_LINK_DL, PIN_LINK_UL,
    PIN_PROG_DL, PIN_PROG_UL,
};

use anyhow::{anyhow, bail, Context, Result};
use aya::{
    maps::Array as BpfArray,
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType},
    Ebpf, EbpfLoader,
};
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd};
use std::path::PathBuf;

use crate::ebpf::bpf_syscall::{
    create_and_pin_link, kernel_supports_bpf_link, BPF_CGROUP_INET_EGRESS, BPF_CGROUP_INET_INGRESS,
};
use crate::ebpf::identity::IdentityMap;
use types::SCHEMA_VERSION_EXPECTED;

// ━━ Limiter struct ━━

pub struct Limiter {
    bpf: Option<Ebpf>,
    identity: IdentityMap,
    verbose: bool,
}

impl Limiter {
    /// Load limiter BPF object and attach to cgroup v2 root (both ingress + egress).
    /// Programs AND links are pinned to /sys/fs/bpf/zelynic/ so they survive process exit.
    pub fn attach(verbose: bool) -> Result<()> {
        let cgroup_path = "/sys/fs/cgroup";
        if !PathBuf::from(cgroup_path).exists() {
            bail!("cgroup v2 not found at {cgroup_path}");
        }

        // Check if ALL pins exist (fully operational from previous run).
        let all_pinned = PathBuf::from(PIN_PROG_DL).exists() && PathBuf::from(PIN_PROG_UL).exists();

        if all_pinned {
            // Check schema version. If mismatch (e.g. upgraded from v1 to v2),
            // clean up + reload to avoid struct layout incompatibility.
            match read_pinned_schema_version() {
                Some(v) if v == SCHEMA_VERSION_EXPECTED => {
                    if verbose {
                        eprintln!(
                            "[limiter] BPF programs + links already pinned (schema v{v}) — reusing"
                        );
                    }
                    return Ok(());
                }
                Some(v) => {
                    if verbose {
                        eprintln!(
                            "[limiter] Schema version mismatch: pinned v{v} ≠ expected v{SCHEMA_VERSION_EXPECTED} — reloading"
                        );
                    }
                    unpin_all()?;
                }
                None => {
                    if verbose {
                        eprintln!("[limiter] Schema version map missing — reloading");
                    }
                    unpin_all()?;
                }
            }
        } else {
            // If SOME pins exist but not all → stale state from old version or
            // crashed run. Clean up everything before reloading.
            if pin_dir_has_files() {
                if verbose {
                    eprintln!("[limiter] Stale pin files detected — cleaning up");
                }
                unpin_all()?;
            }
        }

        let obj_path = find_bpf_object()?;
        if verbose {
            eprintln!("[limiter] Loading BPF object from {}", obj_path.display());
        }
        let obj_data = std::fs::read(&obj_path)
            .context(format!("Failed to read BPF object: {}", obj_path.display()))?;

        // Create pin directory BEFORE load so maps with LIBBPF_PIN_BY_NAME
        // can be auto-pinned by EbpfLoader.
        std::fs::create_dir_all(PIN_DIR)?;

        // Use EbpfLoader with map_pin_path so all maps declared with
        // __uint(pinning, LIBBPF_PIN_BY_NAME) in limiter.bpf.c are auto-pinned
        // to /sys/fs/bpf/zelynic/<map_name>. This is what makes policies
        // persist across zelynic invocations — without it, maps vanish when
        // the Ebpf object is dropped and open_pinned() hits ENOENT.
        let mut bpf = EbpfLoader::new()
            .map_pin_path(PIN_DIR)
            .load(&obj_data)
            .context("Failed to load BPF object")?;

        // Write schema version to the pinned schema_version map.
        // This enables future migrations: if the pinned version doesn't match
        // SCHEMA_VERSION_EXPECTED, attach() cleans up + reloads.
        {
            let mut schema_map: BpfArray<_, u32> = BpfArray::try_from(
                bpf.map_mut("schema_version")
                    .context("schema_version map not found")?,
            )
            .context("Failed to access schema_version map")?;
            schema_map
                .set(0, SCHEMA_VERSION_EXPECTED, 0)
                .map_err(|e| anyhow!("Failed to write schema version: {e}"))?;
        }

        // Load + pin download program (ingress).
        let dl_prog: &mut CgroupSkb = bpf
            .program_mut("enforce_dl")
            .context("BPF program 'enforce_dl' not found")?
            .try_into()?;
        dl_prog.load()?;
        dl_prog
            .pin(PIN_PROG_DL)
            .context("Failed to pin enforce_dl")?;

        // Check kernel version for bpf_link support BEFORE borrowing ul_prog.
        let supports_link = kernel_supports_bpf_link();

        if supports_link {
            // Kernel 5.7+: extract fd, then borrow ul_prog separately.
            let dl_prog_raw = dl_prog
                .fd()
                .context("Failed to get enforce_dl fd")?
                .as_fd()
                .as_raw_fd();

            // Load + pin upload program (egress).
            let ul_prog: &mut CgroupSkb = bpf
                .program_mut("enforce_ul")
                .context("BPF program 'enforce_ul' not found")?
                .try_into()?;
            ul_prog.load()?;
            ul_prog
                .pin(PIN_PROG_UL)
                .context("Failed to pin enforce_ul")?;
            let ul_prog_raw = ul_prog
                .fd()
                .context("Failed to get enforce_ul fd")?
                .as_fd()
                .as_raw_fd();

            // Create + pin bpf_links (fire-and-forget with pin).
            let cgroup_file =
                File::open(cgroup_path).context("Failed to open cgroup root directory")?;
            let cgroup_raw = cgroup_file.as_raw_fd();
            create_and_pin_link(
                dl_prog_raw,
                cgroup_raw,
                BPF_CGROUP_INET_INGRESS,
                PIN_LINK_DL,
            )
            .context("Failed to create + pin enforce_dl link")?;
            create_and_pin_link(ul_prog_raw, cgroup_raw, BPF_CGROUP_INET_EGRESS, PIN_LINK_UL)
                .context("Failed to create + pin enforce_ul link")?;
        } else {
            // Kernel < 5.7: use legacy bpf_prog_attach via Aya.
            // Attach + take ownership of link + forget (leak) so it doesn't
            // detach on drop. Programs are pinned, so they stay loaded.
            let cgroup_file =
                File::open(cgroup_path).context("Failed to open cgroup root directory")?;
            let dl_link = dl_prog
                .attach(
                    cgroup_file.try_clone()?,
                    CgroupSkbAttachType::Ingress,
                    CgroupAttachMode::default(),
                )
                .context("Failed to attach enforce_dl (legacy)")?;
            let dl_link = dl_prog.take_link(dl_link)?;
            std::mem::forget(dl_link);

            // Now borrow ul_prog (dl_prog no longer needed).
            let ul_prog: &mut CgroupSkb = bpf
                .program_mut("enforce_ul")
                .context("BPF program 'enforce_ul' not found")?
                .try_into()?;
            ul_prog.load()?;
            ul_prog
                .pin(PIN_PROG_UL)
                .context("Failed to pin enforce_ul")?;
            let ul_link = ul_prog
                .attach(
                    cgroup_file,
                    CgroupSkbAttachType::Egress,
                    CgroupAttachMode::default(),
                )
                .context("Failed to attach enforce_ul (legacy)")?;
            let ul_link = ul_prog.take_link(ul_link)?;
            std::mem::forget(ul_link);
        }

        if verbose {
            eprintln!("[limiter] Attached + pinned to {cgroup_path} (ingress + egress)");
        }

        // Drop Ebpf object — programs stay loaded because pinned, links stay
        // attached because pinned. Maps stay loaded because pinned via
        // LIBBPF_PIN_BY_NAME.
        drop(bpf);
        Ok(())
    }

    /// Check if BPF programs are already pinned (active from previous run).
    /// Programs are required. Links are optional (only on kernel 5.7+).
    pub fn is_pinned() -> bool {
        PathBuf::from(PIN_PROG_DL).exists() && PathBuf::from(PIN_PROG_UL).exists()
    }

    /// Open pinned maps for read/write access (no BPF program load needed).
    /// Used by parent process to access policies managed by serve child.
    ///
    /// Identity refresh is lazy — only triggered when `refresh_identity()`
    /// or `maybe_refresh_identity()` is called. This speeds up startup
    /// for write operations (strict-single etc.) that don't need identity.
    pub fn open_pinned(verbose: bool) -> Result<Self> {
        let limiter = Limiter {
            bpf: None, // No Ebpf object — using pinned maps directly
            identity: IdentityMap::new(),
            verbose,
        };

        if verbose {
            eprintln!("[limiter] Opened pinned maps (identity lazy-loaded)");
        }

        Ok(limiter)
    }
}

impl Drop for Limiter {
    fn drop(&mut self) {
        if self.bpf.is_some() {
            self.bpf = None;
        }
    }
}
