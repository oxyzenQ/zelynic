// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Minimal eBPF observer probe design model for the Intergalaxion Engine.
//!
//! Phase I-2 adds compile-safe probe design models only. No eBPF programs
//! are loaded, attached, or created. No maps are pinned. No kernel state
//! is mutated. This module defines the *plan* for a future observer probe,
//! along with a strict validator that rejects any plan enabling live
//! kernel operations.

/// The kind of eBPF probe being designed.
///
/// Each variant represents a different attachment strategy for the future
/// observer. In I-2 all variants are model-only — no programs are loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EbpfProbeKind {
    /// No-op placeholder probe (default, safest).
    #[default]
    Noop,
    /// Socket filter observer — passive packet inspection.
    SocketObserver,
    /// cgroup skb observer — reads traffic at a cgroup boundary.
    CgroupSkbObserver,
    /// Tracepoint observer — hooks into kernel tracepoints.
    TracepointObserver,
}

/// Safety mode that governs what the probe plan is allowed to do.
///
/// All modes in I-2 are restricted to design/compile time. No runtime
/// kernel operations are permitted in any mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EbpfProbeSafetyMode {
    /// Plan exists only as a data model — no compile or runtime effect.
    #[default]
    ModelOnly,
    /// Plan is compile-safe but must not execute at runtime.
    CompileOnly,
    /// Attach is explicitly disabled regardless of other settings.
    AttachDisabled,
}

/// A probe plan that describes a future eBPF observer configuration.
///
/// Every boolean field defaults to `false`. The validator rejects any
/// plan that enables live kernel operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfProbePlan {
    /// The kind of probe this plan describes.
    pub kind: EbpfProbeKind,
    /// The safety mode governing this plan.
    pub safety_mode: EbpfProbeSafetyMode,
    /// Whether the plan requires the BPF filesystem to be mounted.
    pub requires_bpf_fs: bool,
    /// Whether the plan requires BTF (BPF Type Format) support.
    pub requires_btf: bool,
    /// Whether the plan requires CAP_BPF or CAP_SYS_ADMIN.
    pub requires_cap_bpf_or_sys_admin: bool,
    /// Whether the plan permits loading an eBPF program into the kernel.
    pub program_load_enabled: bool,
    /// Whether the plan permits attaching a program to a kernel hook.
    pub attach_enabled: bool,
    /// Whether the plan permits creating BPF maps in the kernel.
    pub map_create_enabled: bool,
    /// Whether the plan permits pinning BPF maps to the filesystem.
    pub map_pin_enabled: bool,
    /// Whether the plan permits dropping packets (always false).
    pub packet_drop_enabled: bool,
    /// Whether the plan permits enforcement actions (always false).
    pub enforcement_enabled: bool,
    /// Whether the plan permits any kernel state mutation (always false).
    pub mutation_enabled: bool,
    /// Free-form notes attached to the plan for documentation.
    pub notes: Vec<String>,
}

impl Default for EbpfProbePlan {
    fn default() -> Self {
        Self {
            kind: EbpfProbeKind::Noop,
            safety_mode: EbpfProbeSafetyMode::ModelOnly,
            requires_bpf_fs: false,
            requires_btf: false,
            requires_cap_bpf_or_sys_admin: false,
            program_load_enabled: false,
            attach_enabled: false,
            map_create_enabled: false,
            map_pin_enabled: false,
            packet_drop_enabled: false,
            enforcement_enabled: false,
            mutation_enabled: false,
            notes: Vec::new(),
        }
    }
}

/// Composite design that brings together a probe plan with its associated
/// event kind, map plan, and observer state. This is the top-level design
/// object for a single observer probe.
#[derive(Debug, Clone, Default)]
pub struct EbpfObserverProbeDesign {
    /// The probe plan describing what the probe would do.
    pub plan: EbpfProbePlan,
    /// The kind of events this probe would produce.
    pub event_kind: crate::intergalaxion_engine::backends::ebpf::EbpfEventKind,
    /// The planned BPF maps for this probe.
    pub map_plan: crate::intergalaxion_engine::backends::ebpf::EbpfMapPlan,
    /// Current observer state (always inactive in I-2).
    pub observer_state: crate::intergalaxion_engine::backends::ebpf::EbpfObserverState,
}

// ── Helper functions ──────────────────────────────────────────────────

/// Create a minimal socket observer probe plan (model-only, all flags false).
///
/// The socket observer is the lightest-weight observer design: it uses a
/// BPF socket filter to passively count bytes without attaching to cgroups
/// or tracepoints.
pub fn minimal_socket_observer_probe_plan() -> EbpfProbePlan {
    EbpfProbePlan {
        kind: EbpfProbeKind::SocketObserver,
        safety_mode: EbpfProbeSafetyMode::ModelOnly,
        requires_bpf_fs: false,
        requires_btf: false,
        requires_cap_bpf_or_sys_admin: false,
        program_load_enabled: false,
        attach_enabled: false,
        map_create_enabled: false,
        map_pin_enabled: false,
        packet_drop_enabled: false,
        enforcement_enabled: false,
        mutation_enabled: false,
        notes: vec![String::from(
            "Minimal socket observer: model-only, no kernel operations.",
        )],
    }
}

/// Create a minimal cgroup skb observer probe plan (model-only, all flags false).
///
/// The cgroup skb observer attaches (in future phases) at a cgroup boundary
/// to count traffic per cgroup. In I-2 this is a design model only —
/// cgroup is used as an identity concept, never mutated.
pub fn minimal_cgroup_skb_observer_probe_plan() -> EbpfProbePlan {
    EbpfProbePlan {
        kind: EbpfProbeKind::CgroupSkbObserver,
        safety_mode: EbpfProbeSafetyMode::ModelOnly,
        requires_bpf_fs: true,
        requires_btf: true,
        requires_cap_bpf_or_sys_admin: true,
        program_load_enabled: false,
        attach_enabled: false,
        map_create_enabled: false,
        map_pin_enabled: false,
        packet_drop_enabled: false,
        enforcement_enabled: false,
        mutation_enabled: false,
        notes: vec![String::from(
            "Minimal cgroup skb observer: model-only, cgroup as identity anchor only.",
        )],
    }
}

/// Create a minimal tracepoint observer probe plan (model-only, all flags false).
///
/// The tracepoint observer hooks into kernel tracepoints (e.g., sched,
/// net) for process-level telemetry. In I-2 this is a design model only.
pub fn minimal_tracepoint_observer_probe_plan() -> EbpfProbePlan {
    EbpfProbePlan {
        kind: EbpfProbeKind::TracepointObserver,
        safety_mode: EbpfProbeSafetyMode::ModelOnly,
        requires_bpf_fs: false,
        requires_btf: true,
        requires_cap_bpf_or_sys_admin: false,
        program_load_enabled: false,
        attach_enabled: false,
        map_create_enabled: false,
        map_pin_enabled: false,
        packet_drop_enabled: false,
        enforcement_enabled: false,
        mutation_enabled: false,
        notes: vec![String::from(
            "Minimal tracepoint observer: model-only, no kernel operations.",
        )],
    }
}

// ── Validator ──────────────────────────────────────────────────────────

/// Validate that a probe plan does not enable any live kernel operations.
///
/// Returns `Ok(())` if the plan is safe (all operation flags are false).
/// Returns `Err(description)` if any unsafe flag is set.
///
/// # Rejected flags
///
/// * `program_load_enabled`
/// * `attach_enabled`
/// * `map_create_enabled`
/// * `map_pin_enabled`
/// * `packet_drop_enabled`
/// * `enforcement_enabled`
/// * `mutation_enabled`
pub fn validate_probe_plan_safety(plan: &EbpfProbePlan) -> Result<(), String> {
    if plan.program_load_enabled {
        return Err("program_load_enabled must be false".to_string());
    }
    if plan.attach_enabled {
        return Err("attach_enabled must be false".to_string());
    }
    if plan.map_create_enabled {
        return Err("map_create_enabled must be false".to_string());
    }
    if plan.map_pin_enabled {
        return Err("map_pin_enabled must be false".to_string());
    }
    if plan.packet_drop_enabled {
        return Err("packet_drop_enabled must be false".to_string());
    }
    if plan.enforcement_enabled {
        return Err("enforcement_enabled must be false".to_string());
    }
    if plan.mutation_enabled {
        return Err("mutation_enabled must be false".to_string());
    }
    Ok(())
}
