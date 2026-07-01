// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! eBPF loader — load, attach, and detach the observer BPF program.
//!
//! Uses aya-rs to load the pre-compiled BPF object file and attach
//! it to the cgroup v2 hierarchy.

use anyhow::{bail, Context, Result};
use aya::{
    include_bytes_aligned,
    maps::RingBuf,
    programs::{CgroupSkb, CgroupSkbAttachOptions},
    Bpf,
};
use std::path::Path;

/// Pre-compiled BPF object file (embedded at compile time).
/// Build with: clang -O2 -g -target bpf -c bpf/observer.bpf.c -o bpf/observer.bpf.o
static BPF_OBJECT: &[u8] = include_bytes_aligned!("../../bpf/observer.bpf.o");

/// Active eBPF observer session.
pub struct Observer {
    bpf: Bpf,
    /// cgroup path we attached to.
    cgroup_path: String,
}

impl Observer {
    /// Load the BPF program and attach to cgroup v2 hierarchy.
    ///
    /// Requires:
    /// - CAP_BPF or root
    /// - /sys/fs/cgroup exists (cgroup v2)
    /// - BPF object compiled (bpf/observer.bpf.o)
    pub fn attach() -> Result<Self> {
        // Verify cgroup v2
        let cgroup_path = "/sys/fs/cgroup";
        if !Path::new(cgroup_path).exists() {
            bail!("cgroup v2 not found at {cgroup_path} — eBPF observer requires cgroup v2");
        }

        // Load BPF object
        let mut bpf = Bpf::load(BPF_OBJECT)
            .context("Failed to load BPF object — ensure bpf/observer.bpf.o is compiled")?;

        // Get the cgroup_skb/egress program
        let program: &mut CgroupSkb = bpf
            .program_mut("observe_egress")
            .context("BPF program 'observe_egress' not found in object file")?
            .try_into()?;

        // Load the program into kernel
        program.load()?;

        // Attach to cgroup v2 root (observes all egress traffic)
        program
            .attach(cgroup_path, CgroupSkbAttachOptions::default())
            .context("Failed to attach BPF program to cgroup")?;

        eprintln!("[ebpf] Observer attached to {cgroup_path}");
        eprintln!("[ebpf] Monitoring egress traffic for all processes");

        Ok(Observer {
            bpf,
            cgroup_path: cgroup_path.to_string(),
        })
    }

    /// Get the ring buffer for reading events.
    pub fn ring_buffer(&mut self) -> Result<RingBuf> {
        self.bpf
            .take_map("events")
            .context("BPF map 'events' not found")
            .and_then(|m| RingBuf::try_from(m).context("Failed to create ring buffer from map"))
    }

    /// Detach and clean up.
    pub fn detach(self) {
        // Bpf drop automatically detaches all programs
        eprintln!("[ebpf] Observer detached from {}", self.cgroup_path);
        drop(self.bpf);
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        eprintln!("[ebpf] Cleaning up BPF programs");
    }
}
