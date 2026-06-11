// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! eBPF program skeleton model for the Intergalaxion Engine.
//!
//! Phase I-6 adds a compile-only, source-only eBPF program skeleton
//! shape. No programs are loaded, attached, or created. No maps are
//! pinned. No ring buffers are opened. No kernel events are read. No
//! root is required. This module defines the *skeleton layout* only.

use super::events::EbpfEventKind;

/// The kind of eBPF program described by a skeleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EbpfProgramSkeletonKind {
    /// Socket filter observer (passive packet byte counting).
    #[default]
    SocketFilter,
    /// cgroup skb observer (reads traffic at a cgroup boundary).
    CgroupSkb,
    /// Tracepoint observer (hooks into kernel tracepoints).
    Tracepoint,
}

impl EbpfProgramSkeletonKind {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SocketFilter => "socket_filter",
            Self::CgroupSkb => "cgroup_skb",
            Self::Tracepoint => "tracepoint",
        }
    }
}

/// Compilation and loading status of a program skeleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EbpfProgramSkeletonStatus {
    /// Source-only representation (default for I-6).
    #[default]
    SourceOnly,
    /// Cross-compilation is planned but not yet implemented.
    CompilePlanned,
    /// Skeleton is ready for BPF target compilation.
    CompileReady,
    /// Kernel loading is not supported in this phase.
    KernelLoadUnsupported,
}

impl EbpfProgramSkeletonStatus {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceOnly => "source_only",
            Self::CompilePlanned => "compile_planned",
            Self::CompileReady => "compile_ready",
            Self::KernelLoadUnsupported => "kernel_load_unsupported",
        }
    }
}

/// A single eBPF program skeleton describing the intended shape of a
/// future observer program.
///
/// All boolean flags controlling live kernel operations default to
/// `false`. The validator rejects any skeleton that enables those
/// operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfProgramSkeleton {
    /// Human-readable name for this skeleton.
    pub name: String,
    /// The kind of program this skeleton describes.
    pub kind: EbpfProgramSkeletonKind,
    /// Current compilation status.
    pub status: EbpfProgramSkeletonStatus,
    /// ELF section name for the program entry point.
    pub section_name: String,
    /// The event kind this program would produce.
    pub expected_event_kind: EbpfEventKind,
    /// Whether this skeleton is source-only (must be true in I-6).
    pub source_only: bool,
    /// Whether this skeleton is compile-only (must be true in I-6).
    pub compile_only: bool,
    /// Whether a userspace loader is implemented (always false).
    pub loader_implemented: bool,
    /// Whether attach logic is implemented (always false).
    pub attach_implemented: bool,
    /// Whether map creation logic is implemented (always false).
    pub map_create_implemented: bool,
    /// Whether ring buffer open logic is implemented (always false).
    pub ring_buffer_open_implemented: bool,
    /// Whether live kernel read logic is implemented (always false).
    pub live_kernel_read_implemented: bool,
    /// Whether map pinning logic is implemented (always false).
    pub map_pin_implemented: bool,
    /// Whether enforcement logic is implemented (always false).
    pub enforcement_implemented: bool,
    /// Whether kernel mutation logic is implemented (always false).
    pub mutation_implemented: bool,
    /// Free-form notes attached to the skeleton.
    pub notes: Vec<String>,
}

impl Default for EbpfProgramSkeleton {
    fn default() -> Self {
        Self {
            name: String::from("default_observer"),
            kind: EbpfProgramSkeletonKind::SocketFilter,
            status: EbpfProgramSkeletonStatus::SourceOnly,
            section_name: String::from("socket/observer"),
            expected_event_kind: EbpfEventKind::default(),
            source_only: true,
            compile_only: true,
            loader_implemented: false,
            attach_implemented: false,
            map_create_implemented: false,
            ring_buffer_open_implemented: false,
            live_kernel_read_implemented: false,
            map_pin_implemented: false,
            enforcement_implemented: false,
            mutation_implemented: false,
            notes: Vec::new(),
        }
    }
}

/// A set of program skeletons representing the full observer suite.
///
/// All availability flags default to false. The validator rejects any
/// set that enables live operations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EbpfProgramSkeletonSet {
    /// The individual program skeletons in this set.
    pub skeletons: Vec<EbpfProgramSkeleton>,
    /// Whether all skeletons are source-only.
    pub source_only: bool,
    /// Whether all skeletons are compile-only.
    pub compile_only: bool,
    /// Whether a userspace loader is available (always false).
    pub loader_available: bool,
    /// Whether attach is available (always false).
    pub attach_available: bool,
    /// Whether full runtime is available (always false).
    pub runtime_available: bool,
    /// Whether enforcement is available (always false).
    pub enforcement_available: bool,
    /// Whether kernel mutation is available (always false).
    pub mutation_available: bool,
}

// ── Helper functions ──────────────────────────────────────────────────

/// Create a default program skeleton (source-only, compile-only).
///
/// The default skeleton is the safest configuration: no loader, no
/// attach, no map creation, no ring buffer, no live reads, no pinning,
/// no enforcement, no mutation.
pub fn default_program_skeleton() -> EbpfProgramSkeleton {
    EbpfProgramSkeleton::default()
}

/// Create a socket filter observer skeleton (source-only).
///
/// The socket filter observer is the lightest-weight design: it uses a
/// BPF socket filter to passively count bytes without attaching to
/// cgroups or tracepoints.
pub fn socket_filter_observer_skeleton() -> EbpfProgramSkeleton {
    EbpfProgramSkeleton {
        name: String::from("socket_filter_observer"),
        kind: EbpfProgramSkeletonKind::SocketFilter,
        status: EbpfProgramSkeletonStatus::SourceOnly,
        section_name: String::from("socket/observer"),
        expected_event_kind: EbpfEventKind::TelemetrySample,
        source_only: true,
        compile_only: true,
        loader_implemented: false,
        attach_implemented: false,
        map_create_implemented: false,
        ring_buffer_open_implemented: false,
        live_kernel_read_implemented: false,
        map_pin_implemented: false,
        enforcement_implemented: false,
        mutation_implemented: false,
        notes: vec![String::from(
            "Socket filter observer skeleton: source-only, compile-only.",
        )],
    }
}

/// Create a cgroup skb observer skeleton (source-only).
///
/// The cgroup skb observer attaches (in future phases) at a cgroup
/// boundary to count traffic per cgroup. In I-6 this is a design
/// model only — cgroup is used as an identity concept, never mutated.
pub fn cgroup_skb_observer_skeleton() -> EbpfProgramSkeleton {
    EbpfProgramSkeleton {
        name: String::from("cgroup_skb_observer"),
        kind: EbpfProgramSkeletonKind::CgroupSkb,
        status: EbpfProgramSkeletonStatus::SourceOnly,
        section_name: String::from("cgroup/skb/observer"),
        expected_event_kind: EbpfEventKind::TelemetrySample,
        source_only: true,
        compile_only: true,
        loader_implemented: false,
        attach_implemented: false,
        map_create_implemented: false,
        ring_buffer_open_implemented: false,
        live_kernel_read_implemented: false,
        map_pin_implemented: false,
        enforcement_implemented: false,
        mutation_implemented: false,
        notes: vec![String::from(
            "cgroup skb observer skeleton: source-only, compile-only.",
        )],
    }
}

/// Create a tracepoint observer skeleton (source-only).
///
/// The tracepoint observer hooks into kernel tracepoints (e.g., sched,
/// net) for process-level telemetry. In I-6 this is a design model only.
pub fn tracepoint_observer_skeleton() -> EbpfProgramSkeleton {
    EbpfProgramSkeleton {
        name: String::from("tracepoint_observer"),
        kind: EbpfProgramSkeletonKind::Tracepoint,
        status: EbpfProgramSkeletonStatus::SourceOnly,
        section_name: String::from("tracepoint/observer"),
        expected_event_kind: EbpfEventKind::TelemetrySample,
        source_only: true,
        compile_only: true,
        loader_implemented: false,
        attach_implemented: false,
        map_create_implemented: false,
        ring_buffer_open_implemented: false,
        live_kernel_read_implemented: false,
        map_pin_implemented: false,
        enforcement_implemented: false,
        mutation_implemented: false,
        notes: vec![String::from(
            "Tracepoint observer skeleton: source-only, compile-only.",
        )],
    }
}

/// Create a default program skeleton set containing all three observer
/// skeletons.
///
/// The default set is source-only and compile-only. No loader, attach,
/// runtime, enforcement, or mutation is available.
pub fn default_program_skeleton_set() -> EbpfProgramSkeletonSet {
    EbpfProgramSkeletonSet {
        skeletons: vec![
            socket_filter_observer_skeleton(),
            cgroup_skb_observer_skeleton(),
            tracepoint_observer_skeleton(),
        ],
        source_only: true,
        compile_only: true,
        loader_available: false,
        attach_available: false,
        runtime_available: false,
        enforcement_available: false,
        mutation_available: false,
    }
}

/// Validate that a program skeleton does not enable any live kernel
/// operations.
///
/// Returns `Ok(())` if the skeleton is safe. Returns `Err(description)`
/// if any unsafe condition is detected.
///
/// # Rejected conditions
///
/// * `source_only` is not `true`
/// * `compile_only` is not `true`
/// * `loader_implemented` is `true`
/// * `attach_implemented` is `true`
/// * `map_create_implemented` is `true`
/// * `ring_buffer_open_implemented` is `true`
/// * `live_kernel_read_implemented` is `true`
/// * `map_pin_implemented` is `true`
/// * `enforcement_implemented` is `true`
/// * `mutation_implemented` is `true`
pub fn validate_program_skeleton(skeleton: &EbpfProgramSkeleton) -> Result<(), String> {
    if !skeleton.source_only {
        return Err("source_only must be true".to_string());
    }
    if !skeleton.compile_only {
        return Err("compile_only must be true".to_string());
    }
    if skeleton.loader_implemented {
        return Err("loader_implemented must be false".to_string());
    }
    if skeleton.attach_implemented {
        return Err("attach_implemented must be false".to_string());
    }
    if skeleton.map_create_implemented {
        return Err("map_create_implemented must be false".to_string());
    }
    if skeleton.ring_buffer_open_implemented {
        return Err("ring_buffer_open_implemented must be false".to_string());
    }
    if skeleton.live_kernel_read_implemented {
        return Err("live_kernel_read_implemented must be false".to_string());
    }
    if skeleton.map_pin_implemented {
        return Err("map_pin_implemented must be false".to_string());
    }
    if skeleton.enforcement_implemented {
        return Err("enforcement_implemented must be false".to_string());
    }
    if skeleton.mutation_implemented {
        return Err("mutation_implemented must be false".to_string());
    }
    Ok(())
}

/// Validate that a program skeleton set does not enable any live
/// kernel operations.
///
/// Returns `Ok(())` if the set is safe. Returns `Err(description)`
/// if any unsafe condition is detected.
///
/// # Rejected conditions
///
/// * `loader_available` is `true`
/// * `attach_available` is `true`
/// * `runtime_available` is `true`
/// * `enforcement_available` is `true`
/// * `mutation_available` is `true`
/// * Any individual skeleton in the set fails validation
pub fn validate_program_skeleton_set(set: &EbpfProgramSkeletonSet) -> Result<(), String> {
    if set.loader_available {
        return Err("loader_available must be false".to_string());
    }
    if set.attach_available {
        return Err("attach_available must be false".to_string());
    }
    if set.runtime_available {
        return Err("runtime_available must be false".to_string());
    }
    if set.enforcement_available {
        return Err("enforcement_available must be false".to_string());
    }
    if set.mutation_available {
        return Err("mutation_available must be false".to_string());
    }
    for skeleton in &set.skeletons {
        validate_program_skeleton(skeleton)?;
    }
    Ok(())
}

/// Map a skeleton kind to a stable human-readable label.
pub fn program_skeleton_kind_label(kind: EbpfProgramSkeletonKind) -> &'static str {
    kind.as_str()
}

/// Map a skeleton status to a stable human-readable label.
pub fn program_skeleton_status_label(status: EbpfProgramSkeletonStatus) -> &'static str {
    status.as_str()
}
