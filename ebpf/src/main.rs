// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// zelynic eBPF observer, pure-Rust prototype (NIGHT-improve-1).
//
// Stage-2 skeleton: proves the toolchain wiring end to end (nightly
// + build-std core + bpf-linker via the target's default linker
// flavor) with the smallest compilable cgroup_skb program. The full
// observer port from bpf/observer.bpf.c lands in stage 3 on this
// same file. Build contract lives in ebpf/.cargo/config.toml and
// docs/PURE_RUST_EVALUATION.md.

#![no_std]
#![no_main]

use aya_ebpf::{macros::cgroup_skb, programs::SkBuffContext};

/// Stub entry for the skeleton build. Stage 3 replaces this with the
/// line-for-line port of observe_egress from bpf/observer.bpf.c
/// (cgroup id resolution, counter update, 1-in-100 event throttle,
/// IPv4/TCP/UDP header parse, ring buffer emission).
#[cgroup_skb(egress)]
fn observe_egress(_ctx: SkBuffContext) -> i32 {
    1
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// The license section must stay GPL: bpf_skb_cgroup_id (used by the
// stage-3 port) is a GPL-only helper, and the C twin declares GPL.
#[unsafe(no_mangle)]
#[unsafe(link_section = "license")]
static LICENSE: [u8; 4] = *b"GPL\0";
