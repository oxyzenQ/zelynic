// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! eBPF observer engine — real kernel-level traffic observation.
//!
//! This module provides the userspace side of zelynic's eBPF observer:
//! - Load BPF program (cgroup_skb/egress observer)
//! - Attach to cgroup v2 hierarchy
//! - Read events from ring buffer
//! - Map events to process/cgroup identity
//! - Feed into zelynic's accounting ledger
//!
//! # Safety
//!
//! Observer only — no packet drop, no enforcement, no mutation.
//! Always returns 1 (allow) from BPF program.
//!
//! # Requirements
//!
//! - Linux 5.8+ (cgroup_skb + ring buffer)
//! - CAP_BPF or root
//! - /sys/fs/bpf mounted
//! - Compiled with `--features ebpf`

#[cfg(feature = "ebpf")]
pub mod events;
#[cfg(feature = "ebpf")]
pub mod identity;
#[cfg(feature = "ebpf")]
pub mod loader;

// Re-export capability detection (always available, even without ebpf feature)
pub use crate::ebpf_legacy::*;

/// Print eBPF observer status.
#[cfg(feature = "ebpf")]
pub fn print_observer_status() {
    let support = check_ebpf_support();
    support.print_status();

    if support.supported {
        println!("  Observer: {}", "READY".green().bold());
        println!("  Usage: sudo zelynic ebpf observe");
    } else {
        println!("  Observer: {}", "NOT AVAILABLE".red().bold());
        println!("  Install: clang, libbpf-dev, then rebuild with --features ebpf");
    }
}

#[cfg(not(feature = "ebpf"))]
pub fn print_observer_status() {
    println!("  eBPF: not compiled (rebuild with --features ebpf)");
}
