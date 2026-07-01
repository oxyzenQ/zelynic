// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! eBPF loader — load, attach, and detach the observer BPF program.
//!
//! Uses aya-rs to load the BPF object file and attach
//! it to the cgroup v2 hierarchy.
//!
//! The BPF object is loaded from a file path at runtime (not embedded),
//! so it can be updated without recompiling zelynic.

use anyhow::{bail, Context, Result};
use aya::{
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType},
    Ebpf,
};
use std::fs::File;
use std::path::PathBuf;

/// Default path to the compiled BPF object file.
const BPF_OBJECT_PATH: &str = "bpf/observer.bpf.o";

/// Active eBPF observer session.
pub struct Observer {
    bpf: Option<Ebpf>,
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
        if !PathBuf::from(cgroup_path).exists() {
            bail!("cgroup v2 not found at {cgroup_path}");
        }

        // Find BPF object file
        let obj_path = find_bpf_object()?;
        eprintln!("[ebpf] Loading BPF object from {}", obj_path.display());

        // Read BPF object
        let obj_data = std::fs::read(&obj_path)
            .context(format!("Failed to read BPF object: {}", obj_path.display()))?;

        // Load BPF object
        let mut bpf = Ebpf::load(&obj_data).context("Failed to load BPF object")?;

        // Get the cgroup_skb/egress program
        let program: &mut CgroupSkb = bpf
            .program_mut("observe_egress")
            .context("BPF program 'observe_egress' not found")?
            .try_into()?;

        // Load the program into kernel
        program.load()?;

        // Open cgroup v2 root directory as fd (aya requires AsFd)
        let cgroup_file =
            File::open(cgroup_path).context("Failed to open cgroup root directory")?;

        // Attach to cgroup v2 root
        program
            .attach(
                cgroup_file,
                CgroupSkbAttachType::Egress,
                CgroupAttachMode::default(),
            )
            .context("Failed to attach BPF program to cgroup")?;

        eprintln!("[ebpf] Observer attached to {cgroup_path}");
        eprintln!("[ebpf] Monitoring egress traffic for all processes");

        Ok(Observer {
            bpf: Some(bpf),
            cgroup_path: cgroup_path.to_string(),
        })
    }

    /// Poll ring buffer and process events inline via callback.
    /// Returns number of events processed. Zero-allocation.
    pub fn poll_events<F>(&mut self, mut handler: F) -> Result<usize>
    where
        F: FnMut(&[u8]),
    {
        let bpf = self.bpf.as_mut().context("BPF program not loaded")?;
        let events_map = bpf
            .map_mut("events")
            .context("BPF map 'events' not found")?;
        let mut ringbuf =
            aya::maps::RingBuf::try_from(events_map).context("Failed to create ring buffer")?;

        let mut count = 0;
        while let Some(item) = ringbuf.next() {
            handler(&item);
            count += 1;
        }
        Ok(count)
    }

    /// Detach and clean up.
    pub fn detach(&mut self) {
        // Just drop the Ebpf — it auto-detaches
        self.bpf = None;
        eprintln!("[ebpf] Observer detached from {}", self.cgroup_path);
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        if self.bpf.is_some() {
            eprintln!("[ebpf] Cleaning up BPF programs");
            self.bpf = None;
        }
    }
}

/// Find the BPF object file — checks multiple locations.
fn find_bpf_object() -> Result<PathBuf> {
    let candidates = [
        PathBuf::from(BPF_OBJECT_PATH),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(BPF_OBJECT_PATH),
        PathBuf::from("/usr/lib/zelynic/observer.bpf.o"),
        PathBuf::from("/usr/local/lib/zelynic/observer.bpf.o"),
    ];

    for path in &candidates {
        if path.exists() {
            return Ok(path.clone());
        }
    }

    bail!(
        "BPF object file not found. Compile with:\n  \
         clang -O2 -g -target bpf -c bpf/observer.bpf.c -o bpf/observer.bpf.o\n  \
         Searched: {:?}",
        candidates
    )
}
