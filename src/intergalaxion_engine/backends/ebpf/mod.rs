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
pub mod brave_identity_scope_proof;
pub mod brave_limit_lab_plan;
pub mod capability;
pub mod decoder;
pub mod detector;
pub mod event_schema;
pub mod event_stream_dry_run;
pub mod event_stream_evidence_audit;
pub mod event_stream_fixture;
pub mod event_stream_plan;
pub mod event_stream_reader;
pub mod event_stream_reader_lab_completion_review_pack;
pub mod event_stream_reader_lab_milestone_freeze;
pub mod event_stream_reader_lab_next_arc_entry_gate;
pub mod event_stream_reader_lab_next_arc_final_gate;
pub mod event_stream_reader_lab_next_arc_freeze_review_pack;
pub mod event_stream_reader_lab_next_arc_plan;
pub mod event_stream_reader_lab_next_arc_review_pack;
pub mod event_stream_reader_lab_next_arc_static_freeze;
pub mod event_stream_reader_lab_policy_completion_gate;
pub mod event_stream_reader_lab_static_policy_freeze;
pub mod event_stream_reader_lab_static_policy_hardening;
pub mod event_stream_reader_lab_static_policy_review_pack;
pub mod event_stream_reader_spike_executor;
pub mod event_stream_reader_spike_executor_audit;
pub mod event_stream_reader_spike_prep;
pub mod event_stream_reader_spike_release_gate;
pub mod event_stream_reader_spike_result;
pub mod event_stream_reader_spike_review_pack;
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
pub use brave_identity_scope_proof::*;
#[allow(unused_imports)]
pub use brave_limit_lab_plan::*;
#[allow(unused_imports)]
pub use capability::*;
#[allow(unused_imports)]
pub use decoder::*;
#[allow(unused_imports)]
pub use detector::*;
#[allow(unused_imports)]
pub use event_schema::*;
#[allow(unused_imports)]
pub use event_stream_dry_run::*;
#[allow(unused_imports)]
pub use event_stream_evidence_audit::*;
#[allow(unused_imports)]
pub use event_stream_fixture::*;
#[allow(unused_imports)]
pub use event_stream_plan::*;
#[allow(unused_imports)]
pub use event_stream_reader::*;
#[allow(unused_imports)]
pub use event_stream_reader_lab_completion_review_pack::*;
#[allow(unused_imports)]
pub use event_stream_reader_lab_milestone_freeze::*;
#[allow(unused_imports)]
pub use event_stream_reader_lab_next_arc_entry_gate::*;
#[allow(unused_imports)]
pub use event_stream_reader_lab_next_arc_final_gate::*;
#[allow(unused_imports)]
pub use event_stream_reader_lab_next_arc_freeze_review_pack::*;
#[allow(unused_imports)]
pub use event_stream_reader_lab_next_arc_plan::*;
#[allow(unused_imports)]
pub use event_stream_reader_lab_next_arc_review_pack::*;
#[allow(unused_imports)]
pub use event_stream_reader_lab_next_arc_static_freeze::*;
#[allow(unused_imports)]
pub use event_stream_reader_lab_policy_completion_gate::*;
#[allow(unused_imports)]
pub use event_stream_reader_lab_static_policy_freeze::*;
#[allow(unused_imports)]
pub use event_stream_reader_lab_static_policy_hardening::*;
#[allow(unused_imports)]
pub use event_stream_reader_lab_static_policy_review_pack::*;
#[allow(unused_imports)]
pub use event_stream_reader_spike_executor::*;
#[allow(unused_imports)]
pub use event_stream_reader_spike_executor_audit::*;
#[allow(unused_imports)]
pub use event_stream_reader_spike_prep::*;
#[allow(unused_imports)]
pub use event_stream_reader_spike_release_gate::*;
#[allow(unused_imports)]
pub use event_stream_reader_spike_result::*;
#[allow(unused_imports)]
pub use event_stream_reader_spike_review_pack::*;
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
