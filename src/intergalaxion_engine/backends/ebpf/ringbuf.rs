// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! eBPF ring buffer delivery model for the Intergalaxion Engine.
//!
//! Phase I-3 adds a pure model for ring-buffer planning and consumer
//! state. No ring buffers are created, opened, or pinned. No eBPF maps
//! are created. No kernel state is mutated. This module defines the
//! *plan* only.

/// Plan for a ring buffer used to deliver observer events from kernel
/// to userspace.
///
/// In I-3 the ring buffer is model-only. Every boolean field that
/// controls live kernel operations defaults to `false`. The validator
/// rejects any plan that enables those operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfRingBufferPlan {
    /// Name of the BPF map backing the ring buffer.
    pub map_name: String,
    /// Maximum number of entries (bytes) in the ring buffer.
    pub max_entries: u32,
    /// Whether the userspace consumer is active (default: false).
    pub consumer_enabled: bool,
    /// Whether opening the ring buffer from kernel is enabled (default: false).
    pub kernel_open_enabled: bool,
    /// Whether creating the ring buffer map in kernel is enabled (default: false).
    pub map_create_enabled: bool,
    /// Whether pinning the ring buffer map to bpffs is enabled (default: false).
    pub map_pin_enabled: bool,
    /// Whether attaching a program to produce events is required (default: false).
    pub attach_required: bool,
    /// Whether root is required for tests (default: false).
    pub root_required_for_tests: bool,
    /// Whether any kernel state mutation is enabled (default: false).
    pub mutation_enabled: bool,
}

impl Default for EbpfRingBufferPlan {
    fn default() -> Self {
        Self {
            map_name: String::from("observer_events"),
            max_entries: 256 * 1024, // 256 KiB default model size.
            consumer_enabled: false,
            kernel_open_enabled: false,
            map_create_enabled: false,
            map_pin_enabled: false,
            attach_required: false,
            root_required_for_tests: false,
            mutation_enabled: false,
        }
    }
}

/// State of a ring buffer consumer (model-only in I-3).
///
/// In a live system this tracks the consumer's position, event
/// counts, and drop statistics. In I-3 the consumer is never active.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EbpfRingBufferConsumerState {
    /// Whether the consumer is active (default: false).
    pub active: bool,
    /// Total events received by the consumer.
    pub events_received: u64,
    /// Events dropped by the consumer (e.g., slow processing).
    pub events_dropped_by_consumer: u64,
    /// ID of the last event successfully processed.
    pub last_event_id: Option<u64>,
}

// ── Helper functions ──────────────────────────────────────────────────

/// Create a default ring buffer plan (model-only, all operation flags false).
///
/// The default plan is safe: no kernel operations are enabled.
pub fn default_ring_buffer_plan() -> EbpfRingBufferPlan {
    EbpfRingBufferPlan::default()
}

/// Validate that a ring buffer plan does not enable any live kernel operations.
///
/// Returns `Ok(())` if the plan is safe (all operation flags are false).
/// Returns `Err(description)` if any unsafe flag is set.
///
/// # Rejected flags
///
/// * `consumer_enabled`
/// * `kernel_open_enabled`
/// * `map_create_enabled`
/// * `map_pin_enabled`
/// * `attach_required`
/// * `root_required_for_tests`
/// * `mutation_enabled`
pub fn validate_ring_buffer_plan(plan: &EbpfRingBufferPlan) -> Result<(), String> {
    if plan.consumer_enabled {
        return Err("consumer_enabled must be false".to_string());
    }
    if plan.kernel_open_enabled {
        return Err("kernel_open_enabled must be false".to_string());
    }
    if plan.map_create_enabled {
        return Err("map_create_enabled must be false".to_string());
    }
    if plan.map_pin_enabled {
        return Err("map_pin_enabled must be false".to_string());
    }
    if plan.attach_required {
        return Err("attach_required must be false".to_string());
    }
    if plan.root_required_for_tests {
        return Err("root_required_for_tests must be false".to_string());
    }
    if plan.mutation_enabled {
        return Err("mutation_enabled must be false".to_string());
    }
    Ok(())
}
