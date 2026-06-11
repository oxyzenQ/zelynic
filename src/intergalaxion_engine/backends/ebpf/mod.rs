// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! eBPF backend model for the Intergalaxion Engine.
//!
//! This module provides compile-safe model structs and enums for the
//! future eBPF backend. In I-0:
//! * No real eBPF programs are loaded or attached.
//! * No `aya` dependency is used at runtime.
//! * Backend status defaults to unavailable.
//! * Observer state defaults to inactive.
//! * All mutation flags default to false.

pub mod capability;
pub mod detector;
pub mod events;
pub mod maps;
pub mod observer;
pub mod probe;
pub mod probe_plan;

#[allow(unused_imports)]
pub use capability::*;
#[allow(unused_imports)]
pub use detector::*;
#[allow(unused_imports)]
pub use events::*;
#[allow(unused_imports)]
pub use maps::*;
#[allow(unused_imports)]
pub use observer::*;
#[allow(unused_imports)]
pub use probe::*;
#[allow(unused_imports)]
pub use probe_plan::*;
