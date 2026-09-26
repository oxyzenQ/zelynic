// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the per-pid deep facts layer (NIGHT-master-1) — the pure
//! helpers (magic predicates, time math, /proc parsers, the passwd
//! lookup, the shebang classification) plus the never-panic contract
//! of the /proc walk itself.

use super::*;

/// The passwd lookup resolves by uid and misses cleanly — the depth
/// report's "run from user" line degrades to "unknown", never a
/// fabricated name.
#[test]
fn passwd_lookup_finds_uid_and_misses_cleanly() {
    let passwd = "root:x:0:0:root:/root:/bin/bash\n\
                  cat:x:1000:1000:Cat User,,,:/home/cat:/bin/bash\n";
    assert_eq!(user_name_from(passwd, 0).as_deref(), Some("root"));
    assert_eq!(user_name_from(passwd, 1000).as_deref(), Some("cat"));
    assert_eq!(user_name_from(passwd, 12345), None);
    assert_eq!(user_name_from("", 0), None);
}

/// The magic predicates split ELF, shebang, and everything else —
/// the owner's "binary/scripts" field is decided by these bytes.
#[test]
fn magic_predicates_split_elf_script_and_unknown() {
    assert!(is_elf(&[0x7f, b'E', b'L', b'F']));
    assert!(!is_elf(b"#!"));
    assert!(is_shebang(b"#!/bin/bash"));
    assert!(!is_shebang(&[0x7f, b'E', b'L']));
    assert!(!is_elf(b"MZ\x00\x00"));
}

/// Time math: tick conversion, the uptime-skew clamp, and the
/// refused zero tick rate (a declined sysconf never divides).
#[test]
fn time_math_converts_clamps_and_refuses_zero_hz() {
    assert_eq!(elapsed_secs(1000, 100.0, 100.0), Some(90));
    // A process younger than the uptime read's skew clamps at zero.
    assert_eq!(elapsed_secs(10_000, 100.0, 100.0), Some(0));
    assert_eq!(elapsed_secs(1, 100.0, 0.0), None);
    assert_eq!(started_epoch(1_000_000, 200, 100.0), Some(1_000_002));
    assert_eq!(started_epoch(1_000_000, 200, 0.0), None);
}

/// The stat parser counts fields AFTER the last closing paren — the
/// classic hazard is a comm carrying spaces and its own parens
/// ("(cat (test))"), which a naive split miscounts.
#[test]
fn stat_parse_survives_parens_and_spaces_in_comm() {
    // Fields between ppid (index 1) and starttime (index 19).
    let filler = " 0".repeat(17);
    let plain = format!("1234 (cat) S 1{filler} 4242");
    assert_eq!(parse_proc_stat(&plain), Some((1, 4242)));
    let hostile = format!("5678 (weird ) name) R 2{filler} 7");
    assert_eq!(parse_proc_stat(&hostile), Some((2, 7)));
    assert_eq!(parse_proc_stat("no parens at all"), None);
    assert_eq!(parse_proc_stat("1 (x) S"), None);
}

/// argv splits on NULs and SANITIZES — argv is attacker-controlled
/// exactly the way comm is (NIGHT-cybersecurity-1), and the newline
/// here is the forged-output-line family the sanitizer exists to
/// break. Kernel threads (empty cmdline) carry no argv at all.
#[test]
fn cmdline_argv_splits_nuls_and_sanitizes() {
    let raw = b"./cat-test\0--serve\0-n\0evil\nroot\0";
    let argv = cmdline_argv(raw);
    assert_eq!(argv, vec!["./cat-test", "--serve", "-n", "evil?root"]);
    assert_eq!(
        cmdline_string(&argv).as_deref(),
        Some("./cat-test --serve -n evil?root")
    );
    assert!(cmdline_argv(b"").is_empty());
    assert_eq!(cmdline_string(&[]), None, "kernel thread: no argv");
}

/// The status parser reads the four fields the report shows from one
/// parse of one read — uid (real, the first number), the state words,
/// thread count, resident memory.
#[test]
fn status_parse_reads_uid_state_threads_rss() {
    let status = "Name:\tcat\n\
                  State:\tS (sleeping)\n\
                  Uid:\t1000\t1000\t1000\t1000\n\
                  Threads:\t4\n\
                  VmRSS:\t   1234 kB\n";
    let (uid, state, threads, rss_kb) = parse_status(status);
    assert_eq!(uid, Some(1000));
    assert_eq!(state.as_deref(), Some("S (sleeping)"));
    assert_eq!(threads, Some(4));
    assert_eq!(rss_kb, Some(1234));
    // A missing field stays None — partial status, partial facts.
    let (uid, _, _, rss_kb) = parse_status("Name:\tcat\n");
    assert_eq!(uid, None);
    assert_eq!(rss_kb, None);
}

/// The /proc walk never panics on a cgroup nothing lives in (an
/// absent id yields the empty report, the honest shape).
#[test]
fn deep_collect_never_panics_on_absent_cgroup() {
    let out = deep_collect(u32::MAX);
    assert!(out.procs.is_empty());
    assert!(out.rel_path.is_none());
}

/// The binary/script classification (the owner's field): an ELF exe
/// stays "binary" until one of the first argv arguments after argv[0]
/// resolves to a file that itself starts with `#!` — the
/// shebang-rides-the-interpreter truth (NIGHT-master-1). Relative
/// script paths resolve against the process's own cwd.
#[test]
fn classify_exe_detects_scripts_riding_interpreters() {
    let dir = std::env::temp_dir().join(format!("zelynic-depth-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp fixture dir");
    let script = dir.join("deploy.sh");
    std::fs::write(&script, "#!/bin/bash\necho hi\n").expect("script fixture");
    let plain = dir.join("notes.txt");
    std::fs::write(&plain, "no shebang here\n").expect("plain fixture");

    // A guaranteed-ELF exe: the test binary itself.
    let exe = std::env::current_exe()
        .expect("test binary")
        .to_string_lossy()
        .to_string();
    let cwd = dir.to_string_lossy().to_string();
    let script_str = script.to_string_lossy().to_string();
    let plain_str = plain.to_string_lossy().to_string();

    let (kind, path) = classify_exe(
        Some(&exe),
        Some(&cwd),
        &["runner".into(), script_str.clone()],
    );
    assert_eq!(kind, Some("script"), "the shebang argument classifies");
    assert_eq!(path.as_deref(), Some(script_str.as_str()));

    let (kind, path) = classify_exe(Some(&exe), Some(&cwd), &["runner".into(), plain_str]);
    assert_eq!(
        kind,
        Some("binary"),
        "a non-shebang argument never misclassifies"
    );
    assert_eq!(path, None);

    // Relative path resolution rides the process cwd.
    let (kind, _) = classify_exe(
        Some(&exe),
        Some(&cwd),
        &["runner".into(), "deploy.sh".into()],
    );
    assert_eq!(kind, Some("script"));

    // A missing exe stays honestly unknown.
    assert_eq!(classify_exe(None, None, &[]), (None, None));

    std::fs::remove_dir_all(&dir).ok();
}

/// NIGHT-blade-5: the cgroup controller's resource parsers — the
/// exact payloads `memory.current` and `cpu.stat` carry, plus the
/// shapes that must degrade to None (the honest absence, never a
/// fabricated zero).
#[test]
fn controller_resource_parsers_take_the_exact_payloads() {
    assert_eq!(parse_memory_current("251658240\n"), Some(251_658_240));
    assert_eq!(parse_memory_current("0"), Some(0));
    assert_eq!(parse_memory_current(""), None);
    assert_eq!(parse_memory_current("not-a-number\n"), None);

    // cpu.stat: the usage_usec line wins regardless of what follows
    // (user_usec/system_usec/nr_periods ride along on some kernels).
    let full = "usage_usec 62000000\nuser_usec 31000000\nsystem_usec 31000000\n";
    assert_eq!(parse_cpu_usage_usec(full), Some(62_000_000));
    assert_eq!(parse_cpu_usage_usec("usage_usec 42\n"), Some(42));
    assert_eq!(parse_cpu_usage_usec("nr_periods 0\n"), None);
    assert_eq!(parse_cpu_usage_usec("usage_usec junk\n"), None);
    // A prefix twin must not match: user_usec is NOT usage_usec.
    assert_eq!(parse_cpu_usage_usec("user_usec 7\n"), None);
}

/// NIGHT-blade-5: the resource layer needs a resolved path — no
/// path, no reads, all None (a cgroup whose members all exited
/// mid-walk still reports its census, just without the controller
/// view).
#[test]
fn controller_resources_without_a_path_are_all_none() {
    let r = cgroup_resources(None);
    assert_eq!(r.memory_current_bytes, None);
    assert_eq!(r.cpu_usage_usec, None);
}
