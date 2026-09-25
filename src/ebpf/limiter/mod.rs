// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! eBPF limiter — token-bucket rate enforcement per cgroup or per group.
//!
//! Module layout (NIGHT-hunt-3 restructure):
//! - `types.rs`   — constants + BPF map structs + high-level API types
//! - `format.rs`  — rate/duration parsing + formatting helpers
//! - `policy.rs`  — apply / resolve / write policy operations (the
//!   unset-direction removal rides the apply, NIGHT-improve-29)
//! - `reclaim.rs` — the remove path (unstrict) + state reclamation
//! - `stats.rs`   — status printing + map readers + identity accessors
//! - this file    — the `Limiter` struct, lifecycle (attach / open /
//!   is_pinned / Drop), and the public re-export surface.

mod format;
mod policy;
mod reclaim;
mod stats;
mod types;

// NIGHT-depthbore-1: the kernel-side enforcement arithmetic is now
// pinned rootlessly by test/ebpf/limiter/math_tests.rs, which
// compiles ebpf/src/math.rs — the same file the BPF object builds —
// into the userspace test tree via its own #[path] wiring (the
// production source stays owned by the ebpf crate; only the test
// module reaches across trees).
#[cfg(test)]
#[path = "../../../test/ebpf/limiter/math_tests.rs"]
mod math_tests;

// NIGHT-boost-38: the SMP invariants of the same arithmetic (the
// lock-free consume/refill/stats protocol that closed the
// concurrent-flow over-delivery) are pinned rootlessly by
// test/ebpf/limiter/math_smp_tests.rs — same file, same #[path]
// discipline, real threads instead of the kernel's CPUs.
#[cfg(test)]
#[path = "../../../test/ebpf/limiter/math_smp_tests.rs"]
mod math_smp_tests;

// Re-export public types/functions for external use.
pub use format::{
    format_bytes, format_bytes_wide, format_count, format_rate, monotonic_ns,
    parse_monitor_interval, parse_rate, parse_time_duration, terminal_width, validate_rate,
};
pub use types::{Direction, LimiterStatsRaw, PolicyRaw, RateSpec, Target, LIMITER_ELF};

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
    create_and_pin_link, kernel_release, kernel_supports_bpf_link, BPF_CGROUP_INET_EGRESS,
    BPF_CGROUP_INET_INGRESS,
};
use crate::ebpf::identity::IdentityMap;
use crate::ebpf::trace;
use types::SCHEMA_VERSION_EXPECTED;

/// NIGHT-hunt-19 (error-path audit): the single operational-pin
/// predicate. Pure so the partial-failure regression is unit-pinned.
///
/// Program pins alone are NOT operational on kernels with bpf_link
/// (5.7+ — the supported floor is 5.13): the attach sequence pins the
/// two programs first and creates the cgroup links second, so a
/// failure in between (bpffs full, memlimit hit, SIGKILL mid-attach)
/// leaves programs pinned with nothing attached to the cgroup — every
/// policy would be written to maps no hook ever executes. On pre-5.7
/// kernels the legacy attach path never pins links, so program pins
/// alone are the operational contract there by design.
fn pins_operational(
    supports_link: bool,
    prog_dl: bool,
    prog_ul: bool,
    link_dl: bool,
    link_ul: bool,
) -> bool {
    if !(prog_dl && prog_ul) {
        return false;
    }
    if supports_link {
        return link_dl && link_ul;
    }
    true
}

/// Verbose trace line for the attach strategy (NIGHT-hunt-9): the link
/// mode decides whether limits survive process exit via pinned bpf_links
/// or the legacy attach whose links leak by design. Pure so the wording
/// is unit-pinned in the tests below.
fn link_mode_line(supports_link: bool) -> String {
    if supports_link {
        "[limiter] bpf_link supported — programs + links pinned (survive exit)".to_string()
    } else {
        "[limiter] bpf_link unsupported (pre-5.7) — legacy attach, links leak by design".to_string()
    }
}

// ━━ Limiter struct ━━

pub struct Limiter {
    bpf: Option<Ebpf>,
    identity: IdentityMap,
    verbose: bool,
}

impl Limiter {
    /// Load limiter BPF object and attach to cgroup v2 root (both ingress + egress).
    /// Programs AND links are pinned to /sys/fs/bpf/zelynic/ so they survive process exit.
    ///
    /// NIGHT-boost-6: `-v` traces the full attach anatomy — object
    /// size, kernel release, load timing, the loaded map inventory
    /// (id / type / key / value / max_entries, the bpftool facts),
    /// and the total attach cost.
    pub fn attach(verbose: bool) -> Result<()> {
        let started = std::time::Instant::now();
        let cgroup_path = "/sys/fs/cgroup";
        if !PathBuf::from(cgroup_path).exists() {
            bail!("cgroup v2 not found at {cgroup_path}");
        }

        // Check if the pinned state is fully operational from a previous
        // run. NIGHT-hunt-19: one predicate everywhere — on bpf_link
        // kernels the link pins are load-bearing (they ARE the cgroup
        // attachment), so a half-attached state must reload, never reuse.
        let all_pinned = Self::is_pinned();

        if all_pinned {
            // Check schema version. If mismatch (e.g. upgraded from v1 to v2),
            // clean up + reload to avoid struct layout incompatibility.
            match read_pinned_schema_version() {
                Some(v) if v == SCHEMA_VERSION_EXPECTED => {
                    if verbose {
                        eprintln_safe!(
                            "[limiter] BPF programs + links already pinned (schema v{v}) — reusing"
                        );
                    }
                    return Ok(());
                }
                Some(v) => {
                    if verbose {
                        eprintln_safe!(
                            "[limiter] Schema version mismatch: pinned v{v} ≠ expected v{SCHEMA_VERSION_EXPECTED} — reloading"
                        );
                    }
                    unpin_all()?;
                }
                None => {
                    if verbose {
                        eprintln_safe!("[limiter] Schema version map missing — reloading");
                    }
                    unpin_all()?;
                }
            }
        } else {
            // If SOME pins exist but not all → stale state from old version or
            // crashed run. Clean up everything before reloading.
            if pin_dir_has_files() {
                if verbose {
                    eprintln_safe!("[limiter] Stale pin files detected — cleaning up");
                }
                unpin_all()?;
            }
        }

        let obj_data = LIMITER_ELF;
        if verbose {
            eprintln_safe!(
                "[limiter] Loading embedded BPF limiter object ({} bytes)",
                obj_data.len()
            );
            eprintln_safe!("{}", trace::kernel_line("limiter", &kernel_release()));
        }

        // NIGHT-hunt-30: alignment preflight — structurally impossible
        // with the AlignedElf embedding (src/ebpf/embedded.rs), kept
        // so a future regression fails with a one-line diagnosis
        // instead of aya's opaque "error parsing ELF data" on a
        // healthy object (the owner host's 2026-09-20..21 blocker:
        // every symptom pointed at the artifact, the artifact was
        // fine, and the address of the embedded bytes was the bug).
        if let Some(violation) = crate::ebpf::embedded::alignment_violation(obj_data, "limiter") {
            bail!("{violation}");
        }

        // NIGHT-hunt-28: preflight the pin filesystem BEFORE any pin
        // attempt. The limiter pins all nine maps by name, and a
        // /sys/fs/bpf that exists but is not a mounted bpf filesystem
        // (the kernel always creates the directory; some distros never
        // mount bpffs on it) turns every BPF_OBJ_PIN into EINVAL deep
        // inside EbpfLoader::load — a generic "Failed to load BPF
        // object" far from any hint, the exact blind spot the owner's
        // first Dragon run hit. Naming the mount fix here turns that
        // dead end into a one-command repair. (The observer is
        // deliberately NOT gated: its maps are unpinned, so observe
        // works without bpffs — which also gives a natural diagnostic
        // split: observe works + strict fails = pin filesystem.)
        if !crate::capabilities::bpffs_mounted_at("/sys/fs/bpf") {
            bail!(
                "/sys/fs/bpf is not a mounted bpf filesystem — the limiter pins \
                 its maps there so limits survive process exit, and every pin \
                 would fail (EINVAL) deep inside the object load\n  \
                 tip: sudo mount -t bpf bpf /sys/fs/bpf\n  \
                 tip: make it permanent with an fstab entry or a systemd mount \
                 unit — pins are wiped at boot unless the mount is"
            );
        }

        // Create pin directory BEFORE load so maps with LIBBPF_PIN_BY_NAME
        // can be auto-pinned by EbpfLoader.
        std::fs::create_dir_all(PIN_DIR)?;

        // Use EbpfLoader with map_pin_path so all maps declared with
        // __uint(pinning, LIBBPF_PIN_BY_NAME) in the BPF object are auto-pinned
        // to /sys/fs/bpf/zelynic/<map_name>. This is what makes policies
        // persist across zelynic invocations — without it, maps vanish when
        // the Ebpf object is dropped and open_pinned() hits ENOENT.
        // (NIGHT-improve-1 phase 3: the object bytes are the embedded
        // pure-Rust aya-ebpf build — same map contract, same pinning.)
        let load_started = std::time::Instant::now();
        let mut bpf = EbpfLoader::new()
            .map_pin_path(PIN_DIR)
            .load(obj_data)
            .context("Failed to load BPF object")?;

        // NIGHT-boost-6: the loaded map inventory — one line per map
        // in bpftool vocabulary (id, type, key/value size,
        // max_entries). This is the -v surface a hacker needs when a
        // policy map fills (max_entries 1024) or a pin disagrees with
        // the object: the object's own view, printed at the moment it
        // loaded. Scoped so the immutable `bpf.maps()` borrow ends
        // before the map_mut section below takes the object over.
        if verbose {
            eprintln_safe!(
                "{}",
                trace::load_line(
                    "limiter",
                    bpf.programs().count(),
                    bpf.maps().count(),
                    load_started.elapsed()
                )
            );
            for (name, map) in bpf.maps() {
                if let Some(info) = trace::map_info(map) {
                    let kind = info
                        .map_type()
                        .map(trace::map_type_name)
                        .unwrap_or("unknown");
                    eprintln_safe!(
                        "{}",
                        trace::map_line(
                            "limiter",
                            name,
                            info.id(),
                            kind,
                            info.key_size(),
                            info.value_size(),
                            info.max_entries()
                        )
                    );
                }
            }
        }

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
        if verbose {
            eprintln_safe!("{}", link_mode_line(supports_link));
        }

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
            eprintln_safe!(
                "[limiter] Attached + pinned to {cgroup_path} (ingress + egress) in {}ms",
                trace::ms(started.elapsed())
            );
        }

        // Drop Ebpf object — programs stay loaded because pinned, links stay
        // attached because pinned. Maps stay loaded because pinned via
        // LIBBPF_PIN_BY_NAME.
        drop(bpf);
        Ok(())
    }

    /// Check whether the limiter's pinned state is fully operational.
    ///
    /// On bpf_link kernels (5.7+; the supported floor is 5.13): both
    /// program pins AND both link pins — the links are what attach the
    /// programs to the cgroup, so a state without them enforces nothing.
    /// NIGHT-hunt-19 closed the silent-no-enforcement trap where the old
    /// program-pins-only check "reused" exactly that half-attached
    /// state. On pre-5.7 kernels the legacy attach keeps programs hooked
    /// without link pins, so program pins alone are operational there.
    pub fn is_pinned() -> bool {
        pins_operational(
            kernel_supports_bpf_link(),
            PathBuf::from(PIN_PROG_DL).exists(),
            PathBuf::from(PIN_PROG_UL).exists(),
            PathBuf::from(PIN_LINK_DL).exists(),
            PathBuf::from(PIN_LINK_UL).exists(),
        )
    }

    /// Open pinned maps for read/write access (no BPF program load needed).
    /// Used by short-lived CLI invocations to read and write the pinned
    /// policy maps directly — the maps persist because they are pinned,
    /// so no background process is required.
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
            eprintln_safe!("[limiter] Opened pinned maps (identity lazy-loaded)");
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

#[cfg(test)]
mod tests {
    use super::*;

    /// NIGHT-hunt-19 drift pins: the operational predicate must not
    /// trust program pins alone on bpf_link kernels — that is the exact
    /// partial-failure state (link create/pin failed after both programs
    /// were pinned) that the old check "reused" while nothing enforced.
    #[test]
    fn pins_operational_requires_link_pins_on_bpf_link_kernels() {
        // Fully operational.
        assert!(pins_operational(true, true, true, true, true));
        // Partial failure: programs pinned, a link missing — NOT
        // operational, must reload instead of reuse.
        assert!(!pins_operational(true, true, true, false, false));
        assert!(!pins_operational(true, true, true, true, false));
        assert!(!pins_operational(true, true, true, false, true));
        // Missing program pins: never operational.
        assert!(!pins_operational(true, false, true, true, true));
        assert!(!pins_operational(true, true, false, true, true));
        assert!(!pins_operational(false, false, false, false, false));
        // Pre-5.7 kernels: the legacy attach never pins links, so
        // program pins alone are the operational contract there.
        assert!(pins_operational(false, true, true, false, false));
    }

    /// NIGHT-hunt-9 drift pin: the attach-strategy trace wording is part
    /// of the verbose diagnostic contract — exact strings, pinned.
    #[test]
    fn link_mode_line_pins_both_strategies() {
        assert_eq!(
            link_mode_line(true),
            "[limiter] bpf_link supported — programs + links pinned (survive exit)"
        );
        assert_eq!(
            link_mode_line(false),
            "[limiter] bpf_link unsupported (pre-5.7) — legacy attach, links leak by design"
        );
    }
}
