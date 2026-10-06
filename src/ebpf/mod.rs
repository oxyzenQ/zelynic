// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! eBPF observer + limiter engine — real kernel-level traffic observation and enforcement.
//!
//! The cosmic dragon architecture: pure eBPF, no userspace backend fallback.
//! Every command under this module compiles only with the `ebpf`
//! feature enabled.

#[cfg(feature = "ebpf")]
pub mod bpf_syscall;
#[cfg(feature = "ebpf")]
pub mod bypass;
#[cfg(feature = "ebpf")]
pub mod connections;
#[cfg(feature = "ebpf")]
pub mod display;
#[cfg(feature = "ebpf")]
pub mod display_json;
#[cfg(feature = "ebpf")]
mod display_lines;
#[cfg(feature = "ebpf")]
pub mod embedded;
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
#[cfg(feature = "ebpf")]
pub mod render;
#[cfg(feature = "ebpf")]
pub mod trace;
