// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! eBPF observer + limiter engine — real kernel-level traffic observation and enforcement.
//!
//! Dragon Architecture: pure eBPF, no userspace backend fallback. The
//! legacy tc/cgroup/nftables backend was removed in v4; every command
//! under this module compiles only with the `ebpf` feature enabled.

#[cfg(feature = "ebpf")]
pub mod bpf_syscall;
#[cfg(feature = "ebpf")]
pub mod display;
#[cfg(feature = "ebpf")]
pub mod identity;
#[cfg(feature = "ebpf")]
pub mod limiter;
#[cfg(feature = "ebpf")]
pub mod loader;
#[cfg(feature = "ebpf")]
pub mod lock;
#[cfg(feature = "ebpf")]
pub mod pin;
