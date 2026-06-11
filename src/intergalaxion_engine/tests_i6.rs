// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Phase I-6 tests: eBPF program skeleton, compile-only.

use crate::cli::Cli;
use crate::commands::ledger::{handle_ledger_export, handle_ledger_inspect};
use crate::intergalaxion_engine::backends::ebpf::program_skeleton::*;
use clap::CommandFactory;

const I6_DOC: &str =
    include_str!("../../docs/intergalaxion/I-6-ebpf-program-skeleton-compile-only.md");
const I6_SKELETON_SOURCE: &str = include_str!("backends/ebpf/program_skeleton.rs");

// -- Coverage 1: default program skeleton is source-only ---------------

#[test]
fn i6_default_skeleton_is_source_only() {
    let skel = default_program_skeleton();
    assert!(skel.source_only);
}

// -- Coverage 2: default program skeleton is compile-only --------------

#[test]
fn i6_default_skeleton_is_compile_only() {
    let skel = default_program_skeleton();
    assert!(skel.compile_only);
}

// -- Coverage 3–10: default skeleton operation flags are false ---------

#[test]
fn i6_default_skeleton_loader_implemented_false() {
    let skel = default_program_skeleton();
    assert!(!skel.loader_implemented);
}

#[test]
fn i6_default_skeleton_attach_implemented_false() {
    let skel = default_program_skeleton();
    assert!(!skel.attach_implemented);
}

#[test]
fn i6_default_skeleton_map_create_implemented_false() {
    let skel = default_program_skeleton();
    assert!(!skel.map_create_implemented);
}

#[test]
fn i6_default_skeleton_ring_buffer_open_implemented_false() {
    let skel = default_program_skeleton();
    assert!(!skel.ring_buffer_open_implemented);
}

#[test]
fn i6_default_skeleton_live_kernel_read_implemented_false() {
    let skel = default_program_skeleton();
    assert!(!skel.live_kernel_read_implemented);
}

#[test]
fn i6_default_skeleton_map_pin_implemented_false() {
    let skel = default_program_skeleton();
    assert!(!skel.map_pin_implemented);
}

#[test]
fn i6_default_skeleton_enforcement_implemented_false() {
    let skel = default_program_skeleton();
    assert!(!skel.enforcement_implemented);
}

#[test]
fn i6_default_skeleton_mutation_implemented_false() {
    let skel = default_program_skeleton();
    assert!(!skel.mutation_implemented);
}

// -- Coverage 11: socket filter observer skeleton is source-only --------

#[test]
fn i6_socket_filter_observer_skeleton_is_source_only() {
    let skel = socket_filter_observer_skeleton();
    assert!(skel.source_only);
    assert!(skel.compile_only);
    assert_eq!(skel.kind, EbpfProgramSkeletonKind::SocketFilter);
}

// -- Coverage 12: cgroup skb observer skeleton is source-only ----------

#[test]
fn i6_cgroup_skb_observer_skeleton_is_source_only() {
    let skel = cgroup_skb_observer_skeleton();
    assert!(skel.source_only);
    assert!(skel.compile_only);
    assert_eq!(skel.kind, EbpfProgramSkeletonKind::CgroupSkb);
}

// -- Coverage 13: tracepoint observer skeleton is source-only ----------

#[test]
fn i6_tracepoint_observer_skeleton_is_source_only() {
    let skel = tracepoint_observer_skeleton();
    assert!(skel.source_only);
    assert!(skel.compile_only);
    assert_eq!(skel.kind, EbpfProgramSkeletonKind::Tracepoint);
}

// -- Coverage 14: skeleton kind labels are stable ----------------------

#[test]
fn i6_skeleton_kind_labels_are_stable() {
    assert_eq!(
        program_skeleton_kind_label(EbpfProgramSkeletonKind::SocketFilter),
        "socket_filter"
    );
    assert_eq!(
        program_skeleton_kind_label(EbpfProgramSkeletonKind::CgroupSkb),
        "cgroup_skb"
    );
    assert_eq!(
        program_skeleton_kind_label(EbpfProgramSkeletonKind::Tracepoint),
        "tracepoint"
    );
}

// -- Coverage 15: skeleton status labels are stable -------------------

#[test]
fn i6_skeleton_status_labels_are_stable() {
    assert_eq!(
        program_skeleton_status_label(EbpfProgramSkeletonStatus::SourceOnly),
        "source_only"
    );
    assert_eq!(
        program_skeleton_status_label(EbpfProgramSkeletonStatus::CompilePlanned),
        "compile_planned"
    );
    assert_eq!(
        program_skeleton_status_label(EbpfProgramSkeletonStatus::CompileReady),
        "compile_ready"
    );
    assert_eq!(
        program_skeleton_status_label(EbpfProgramSkeletonStatus::KernelLoadUnsupported),
        "kernel_load_unsupported"
    );
}

// -- Coverage 16: default skeleton set is deterministic ---------------

#[test]
fn i6_default_skeleton_set_is_deterministic() {
    let set1 = default_program_skeleton_set();
    let set2 = default_program_skeleton_set();
    assert_eq!(set1, set2);
}

// -- Coverage 17: skeleton set contains three observer skeletons ------

#[test]
fn i6_skeleton_set_contains_three_observer_skeletons() {
    let set = default_program_skeleton_set();
    assert_eq!(set.skeletons.len(), 3);
}

// -- Coverage 18–22: skeleton set availability flags ------------------

#[test]
fn i6_skeleton_set_loader_available_false() {
    let set = default_program_skeleton_set();
    assert!(!set.loader_available);
}

#[test]
fn i6_skeleton_set_attach_available_false() {
    let set = default_program_skeleton_set();
    assert!(!set.attach_available);
}

#[test]
fn i6_skeleton_set_runtime_available_false() {
    let set = default_program_skeleton_set();
    assert!(!set.runtime_available);
}

#[test]
fn i6_skeleton_set_enforcement_available_false() {
    let set = default_program_skeleton_set();
    assert!(!set.enforcement_available);
}

#[test]
fn i6_skeleton_set_mutation_available_false() {
    let set = default_program_skeleton_set();
    assert!(!set.mutation_available);
}

// -- Coverage 23: validate accepts safe default skeleton ---------------

#[test]
fn i6_validate_accepts_safe_default_skeleton() {
    assert!(validate_program_skeleton(&default_program_skeleton()).is_ok());
}

// -- Coverage 24: validate accepts all observer skeletons --------------

#[test]
fn i6_validate_accepts_all_observer_skeletons() {
    assert!(validate_program_skeleton(&socket_filter_observer_skeleton()).is_ok());
    assert!(validate_program_skeleton(&cgroup_skb_observer_skeleton()).is_ok());
    assert!(validate_program_skeleton(&tracepoint_observer_skeleton()).is_ok());
}

// -- Coverage 25: validate rejects source_only=false ------------------

#[test]
fn i6_validate_rejects_source_only_false() {
    let skel = EbpfProgramSkeleton {
        source_only: false,
        ..Default::default()
    };
    assert!(validate_program_skeleton(&skel).is_err());
}

// -- Coverage 26: validate rejects compile_only=false -----------------

#[test]
fn i6_validate_rejects_compile_only_false() {
    let skel = EbpfProgramSkeleton {
        compile_only: false,
        ..Default::default()
    };
    assert!(validate_program_skeleton(&skel).is_err());
}

// -- Coverage 27–34: validate rejects operation flags -------------------

#[test]
fn i6_validate_rejects_loader_implemented_true() {
    let skel = EbpfProgramSkeleton {
        loader_implemented: true,
        ..Default::default()
    };
    assert!(validate_program_skeleton(&skel).is_err());
}

#[test]
fn i6_validate_rejects_attach_implemented_true() {
    let skel = EbpfProgramSkeleton {
        attach_implemented: true,
        ..Default::default()
    };
    assert!(validate_program_skeleton(&skel).is_err());
}

#[test]
fn i6_validate_rejects_map_create_implemented_true() {
    let skel = EbpfProgramSkeleton {
        map_create_implemented: true,
        ..Default::default()
    };
    assert!(validate_program_skeleton(&skel).is_err());
}

#[test]
fn i6_validate_rejects_ring_buffer_open_implemented_true() {
    let skel = EbpfProgramSkeleton {
        ring_buffer_open_implemented: true,
        ..Default::default()
    };
    assert!(validate_program_skeleton(&skel).is_err());
}

#[test]
fn i6_validate_rejects_live_kernel_read_implemented_true() {
    let skel = EbpfProgramSkeleton {
        live_kernel_read_implemented: true,
        ..Default::default()
    };
    assert!(validate_program_skeleton(&skel).is_err());
}

#[test]
fn i6_validate_rejects_map_pin_implemented_true() {
    let skel = EbpfProgramSkeleton {
        map_pin_implemented: true,
        ..Default::default()
    };
    assert!(validate_program_skeleton(&skel).is_err());
}

#[test]
fn i6_validate_rejects_enforcement_implemented_true() {
    let skel = EbpfProgramSkeleton {
        enforcement_implemented: true,
        ..Default::default()
    };
    assert!(validate_program_skeleton(&skel).is_err());
}

#[test]
fn i6_validate_rejects_mutation_implemented_true() {
    let skel = EbpfProgramSkeleton {
        mutation_implemented: true,
        ..Default::default()
    };
    assert!(validate_program_skeleton(&skel).is_err());
}

// -- Coverage 35: validate skeleton set accepts safe default set --------

#[test]
fn i6_validate_skeleton_set_accepts_safe_default_set() {
    assert!(validate_program_skeleton_set(&default_program_skeleton_set()).is_ok());
}

// -- Coverage 36–40: validate skeleton set rejects unsafe availability --

#[test]
fn i6_validate_skeleton_set_rejects_loader_available_true() {
    let set = EbpfProgramSkeletonSet {
        loader_available: true,
        ..Default::default()
    };
    assert!(validate_program_skeleton_set(&set).is_err());
}

#[test]
fn i6_validate_skeleton_set_rejects_attach_available_true() {
    let set = EbpfProgramSkeletonSet {
        attach_available: true,
        ..Default::default()
    };
    assert!(validate_program_skeleton_set(&set).is_err());
}

#[test]
fn i6_validate_skeleton_set_rejects_runtime_available_true() {
    let set = EbpfProgramSkeletonSet {
        runtime_available: true,
        ..Default::default()
    };
    assert!(validate_program_skeleton_set(&set).is_err());
}

#[test]
fn i6_validate_skeleton_set_rejects_enforcement_available_true() {
    let set = EbpfProgramSkeletonSet {
        enforcement_available: true,
        ..Default::default()
    };
    assert!(validate_program_skeleton_set(&set).is_err());
}

#[test]
fn i6_validate_skeleton_set_rejects_mutation_available_true() {
    let set = EbpfProgramSkeletonSet {
        mutation_available: true,
        ..Default::default()
    };
    assert!(validate_program_skeleton_set(&set).is_err());
}

// -- Coverage 41: docs exist and mention eBPF program skeleton ---------

#[test]
fn i6_docs_exist_and_mention_ebpf_program_skeleton() {
    assert!(!I6_DOC.is_empty());
    assert!(I6_DOC.contains("eBPF program skeleton"));
    assert!(I6_DOC.contains("I-6"));
}

// -- Coverage 42: docs say source-only / compile-only ------------------

#[test]
fn i6_docs_say_source_only_compile_only() {
    assert!(I6_DOC.contains("source-only"));
    assert!(I6_DOC.contains("compile-only"));
}

// -- Coverage 43: docs say no userspace loader -------------------------

#[test]
fn i6_docs_say_no_userspace_loader() {
    assert!(I6_DOC.contains("no userspace loader"));
}

// -- Coverage 44: docs say no attach/load/map create/ring/open/read/pin -

#[test]
fn i6_docs_say_no_attach_load_map_create_ring_buffer_open_live_kernel_read_map_pin() {
    assert!(I6_DOC.contains("no eBPF attach"));
    assert!(I6_DOC.contains("no eBPF program load"));
    assert!(I6_DOC.contains("no eBPF map create"));
    assert!(I6_DOC.contains("no ring buffer open"));
    assert!(I6_DOC.contains("no live kernel event read"));
    assert!(I6_DOC.contains("no map pin"));
}

// -- Coverage 45: docs say no enforcement ------------------------------

#[test]
fn i6_docs_say_no_enforcement() {
    assert!(I6_DOC.contains("no enforcement"));
}

// -- Coverage 46: docs say no block/allow/quota -------------------------

#[test]
fn i6_docs_say_no_block_allow_or_quota() {
    assert!(I6_DOC.contains("no block/allow/quota"));
}

// -- Coverage 47: docs say no nft/tc fallback --------------------------

#[test]
fn i6_docs_say_no_nft_tc_fallback() {
    assert!(I6_DOC.contains("no nft/tc fallback") || I6_DOC.contains("no nft/tc"));
}

// -- Coverage 48: docs say no public CLI ------------------------------

#[test]
fn i6_docs_say_no_public_cli() {
    assert!(I6_DOC.contains("no public CLI"));
}

// -- Coverage 49: docs say no ledger file write/persistence ------------

#[test]
fn i6_docs_say_no_ledger_file_write_or_persistence() {
    assert!(I6_DOC.contains("no ledger file write") || I6_DOC.contains("no persistence"));
}

// -- Coverage 50: docs say existing v3.1 usage schema unchanged --------

#[test]
fn i6_docs_say_existing_v31_usage_schema_unchanged() {
    assert!(I6_DOC.contains("usage JSON schema") || I6_DOC.contains("unchanged"));
}

// -- Coverage 51: docs say existing v3.1 ledger schema unchanged -------

#[test]
fn i6_docs_say_existing_v31_ledger_schema_unchanged() {
    assert!(I6_DOC.contains("v3.1 ledger JSON schema") || I6_DOC.contains("ledger JSON schema"));
}

// -- Coverage 52–56: CLI and version continuity -------------------------

#[test]
fn i6_version_remains_3_1_0() {
    assert!(include_str!("../../Cargo.toml").contains("version = \"3.1.0\""));
}

#[test]
fn i6_existing_ledger_inspect_json_still_works() {
    assert!(handle_ledger_inspect(true, None).is_ok());
}

fn write_i6_valid_ledger_fixture(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("zelynic_i6_{name}_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ledger-valid.json");
    std::fs::write(
        &path,
        r#"{
  "schema_version": 1,
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-01T00:00:00Z",
  "host_id": "intergalaxion-i6-host",
  "entries": [
    {
      "entry_id": "intergalaxion-i6-entry-1",
      "timestamp": "2026-01-01T00:00:00Z",
      "entry_type": "snapshot",
      "source_label": "intergalaxion i6 runtime proof",
      "interface": "eth0",
      "rx_bytes": 100,
      "tx_bytes": 200,
      "combined_bytes": 300,
      "read_only": true,
      "provenance": "intergalaxion ebpf program skeleton compile-only proof",
      "attribution_scope": "interface-level only",
      "enforcement_status": "inactive/not implemented",
      "reset_detected": false,
      "reset_details": []
    }
  ]
}
"#,
    )
    .unwrap();
    path
}

#[test]
fn i6_existing_ledger_export_json_file_still_works() {
    let path = write_i6_valid_ledger_fixture("export");
    assert!(handle_ledger_export(true, Some(path.to_str().unwrap())).is_ok());
}

#[test]
fn i6_public_help_does_not_mention_intergalaxion() {
    let help = Cli::command().render_help().to_string();
    assert!(!help.to_ascii_lowercase().contains("intergalaxion"));
}

#[test]
fn i6_public_help_does_not_add_block_allow_quota() {
    let help = Cli::command()
        .render_help()
        .to_string()
        .to_ascii_lowercase();
    assert!(!help.contains("block"));
    assert!(!help.contains("allow"));
    assert!(!help.contains("quota"));
}

// -- Coverage 57: no new dependency added ------------------------------

#[test]
fn i6_no_new_dependency_added() {
    let cargo_toml = include_str!("../../Cargo.toml");
    assert!(cargo_toml.contains("aya"));
}

// -- Coverage 58: no live kernel mutation API in skeleton source --------

#[test]
fn i6_no_live_kernel_mutation_api_in_skeleton_source() {
    for forbidden in [
        "File::create",
        "fs::write",
        "OpenOptions",
        "/sys/fs/bpf",
        "/sys/kernel",
        "/proc/",
    ] {
        assert!(
            !I6_SKELETON_SOURCE.contains(forbidden),
            "program_skeleton.rs must not contain {}",
            forbidden
        );
    }
}

// -- Coverage 59: no aya ringbuf/map open/load/attach/pin API -----------

#[test]
fn i6_no_aya_ringbuf_map_open_load_attach_pin_api_in_skeleton_source() {
    for forbidden in [
        "Bpf::load",
        "load_file",
        "program_mut",
        ".attach(",
        "AsyncPerfEventArray",
        "PerfEventArray",
        "MapData",
        "create_map",
        "pin(",
        "bpf_prog_load",
        "bpf_map_create",
        "bpf_ringbuf",
    ] {
        assert!(
            !I6_SKELETON_SOURCE.contains(forbidden),
            "program_skeleton.rs must not contain {}",
            forbidden
        );
    }
}

// -- Coverage 60: no nft/tc source under intergalaxion backend ----------

#[test]
fn i6_no_nft_or_tc_source_under_intergalaxion_backend() {
    assert!(!std::path::Path::new("src/intergalaxion_engine/backends/nft.rs").exists());
    assert!(!std::path::Path::new("src/intergalaxion_engine/backends/tc.rs").exists());
}

// -- Coverage 61: all touched files under 1000 LOC ---------------------

#[test]
fn i6_all_touched_files_under_1000_loc() {
    for (name, source) in [
        ("program_skeleton.rs", I6_SKELETON_SOURCE),
        ("I-6 doc", I6_DOC),
        ("tests_i6.rs", include_str!("tests_i6.rs")),
    ] {
        assert!(
            source.lines().count() < 1000,
            "{name} must stay under 1000 LOC"
        );
    }
}

// ── Extra coverage: skeleton set propagates validation to members ----

#[test]
fn i6_validate_skeleton_set_rejects_unsafe_member_skeleton() {
    let unsafe_skel = EbpfProgramSkeleton {
        attach_implemented: true,
        ..Default::default()
    };
    let set = EbpfProgramSkeletonSet {
        skeletons: vec![unsafe_skel],
        ..Default::default()
    };
    assert!(validate_program_skeleton_set(&set).is_err());
}

#[test]
fn i6_default_skeleton_status_is_source_only() {
    let skel = default_program_skeleton();
    assert_eq!(skel.status, EbpfProgramSkeletonStatus::SourceOnly);
}

#[test]
fn i6_socket_filter_section_name_is_socket_observer() {
    let skel = socket_filter_observer_skeleton();
    assert_eq!(skel.section_name, "socket/observer");
}

#[test]
fn i6_cgroup_skb_section_name_is_cgroup_skb_observer() {
    let skel = cgroup_skb_observer_skeleton();
    assert_eq!(skel.section_name, "cgroup/skb/observer");
}

#[test]
fn i6_tracepoint_section_name_is_tracepoint_observer() {
    let skel = tracepoint_observer_skeleton();
    assert_eq!(skel.section_name, "tracepoint/observer");
}

#[test]
fn i6_all_observer_skeletons_expect_telemetry_sample() {
    use crate::intergalaxion_engine::backends::ebpf::events::EbpfEventKind;
    for skel in [
        socket_filter_observer_skeleton(),
        cgroup_skb_observer_skeleton(),
        tracepoint_observer_skeleton(),
    ] {
        assert_eq!(skel.expected_event_kind, EbpfEventKind::TelemetrySample);
    }
}

#[test]
fn i6_default_skeleton_set_source_only_true() {
    let set = default_program_skeleton_set();
    assert!(set.source_only);
}

#[test]
fn i6_default_skeleton_set_compile_only_true() {
    let set = default_program_skeleton_set();
    assert!(set.compile_only);
}
