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

pub mod attach_plan;
pub mod capability;
pub mod decoder;
pub mod detector;
pub mod event_schema;
pub mod event_stream_plan;
pub mod event_stream_reader;
pub mod events;
pub mod live_attach_artifact;
pub mod live_attach_executor;
pub mod live_attach_gate;
pub mod live_attach_lab;
pub mod live_attach_lab_result;
pub mod loader_boundary;
pub mod maps;
pub mod observer;
pub mod probe;
pub mod probe_plan;
pub mod program_skeleton;
pub mod ringbuf;

#[allow(unused_imports)]
pub use attach_plan::*;
#[allow(unused_imports)]
pub use capability::*;
#[allow(unused_imports)]
pub use decoder::*;
#[allow(unused_imports)]
pub use detector::*;
#[allow(unused_imports)]
pub use event_schema::*;
#[allow(unused_imports)]
pub use event_stream_plan::*;
#[allow(unused_imports)]
pub use event_stream_reader::*;
#[allow(unused_imports)]
pub use events::*;
#[allow(unused_imports)]
pub use live_attach_artifact::*;
#[allow(unused_imports)]
pub use live_attach_executor::*;
#[allow(unused_imports)]
pub use live_attach_gate::*;
#[allow(unused_imports)]
pub use live_attach_lab::*;
#[allow(unused_imports)]
pub use live_attach_lab_result::*;
#[allow(unused_imports)]
pub use loader_boundary::*;
#[allow(unused_imports)]
pub use maps::*;
#[allow(unused_imports)]
pub use observer::*;
#[allow(unused_imports)]
pub use probe::*;
#[allow(unused_imports)]
pub use probe_plan::*;
#[allow(unused_imports)]
pub use program_skeleton::*;
#[allow(unused_imports)]
pub use ringbuf::*;
