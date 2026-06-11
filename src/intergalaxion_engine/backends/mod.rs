// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Backend abstraction for the Intergalaxion Engine.
//!
//! In I-0 only the eBPF backend model exists. No nft/tc backend or
//! procfs fallback is present in this branch.

pub mod ebpf;
