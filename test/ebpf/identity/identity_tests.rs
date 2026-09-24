// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Identity walk pins (NIGHT-engrave-7 split, cosmostrix Pattern C):
//! the inline `mod tests` moved out to the repo's single test/ tree
//! when the kernel-cap name enrichment (display_name/argv0_basename
//! and their pins) pushed identity/mod.rs past the owner's LOC cap —
//! one file per contract, the same #[path] discipline the render and
//! limiter trees already carry. `use super::*` still reaches the
//! module's private items: the #[path] wiring keeps this a child
//! module of identity/, exactly where the inline block sat.

use super::*;
use std::time::Duration;

#[test]
fn test_identity_map_new_is_empty() {
    let map = IdentityMap::new();
    assert!(map.is_empty());
    assert_eq!(map.len(), 0);
}

#[test]
fn test_label_for_unknown_cgroup() {
    let map = IdentityMap::new();
    // No refresh — cache is empty.
    assert_eq!(map.label(99999), "cg:99999");
}

#[test]
fn test_get_returns_none_when_empty() {
    let map = IdentityMap::new();
    assert!(map.get(1).is_none());
}

#[test]
fn test_with_ttl_constructor() {
    let map = IdentityMap::with_ttl(Duration::from_millis(1));
    assert!(map.is_empty());
    assert_eq!(map.refresh_ttl, Duration::from_millis(1));
}

#[test]
fn test_maybe_refresh_when_no_last_refresh() {
    // When last_refresh is None, maybe_refresh should trigger.
    // We can't easily test the actual refresh without /proc access,
    // but we can verify the contract: maybe_refresh returns true and
    // sets last_refresh.
    let mut map = IdentityMap::with_ttl(Duration::from_secs(60));
    let refreshed = map.maybe_refresh();
    assert!(refreshed);
    assert!(map.last_refresh.is_some());
}

#[test]
fn test_maybe_refresh_skips_when_within_ttl() {
    let mut map = IdentityMap::with_ttl(Duration::from_secs(60));
    // Prime the cache.
    let _ = map.maybe_refresh();
    let first_refresh = map.last_refresh.unwrap();

    // Second call should NOT refresh (within TTL).
    let refreshed = map.maybe_refresh();
    assert!(!refreshed);
    assert_eq!(map.last_refresh.unwrap(), first_refresh);
}

#[test]
fn test_label_with_manually_inserted_identity() {
    // Test the label() formatting directly by inserting a fake entry.
    let mut map = IdentityMap::new();
    map.cache.insert(
        12345,
        ProcessIdentity {
            cgroup_id: 12345,
            uid: 1000,
            comm: "firefox".to_string(),
        },
    );

    assert_eq!(map.label(12345), "cg:12345 (firefox)");
}

#[test]
fn test_label_with_empty_comm_falls_back() {
    let mut map = IdentityMap::new();
    map.cache.insert(
        12345,
        ProcessIdentity {
            cgroup_id: 12345,
            uid: 1000,
            comm: String::new(),
        },
    );

    // Empty comm → fall back to raw label.
    assert_eq!(map.label(12345), "cg:12345");
}

#[test]
fn test_refresh_runs_without_panic() {
    // Refresh should always succeed (even if /proc has 0 entries or
    // permissions block some reads). Must not panic.
    let mut map = IdentityMap::new();
    let _count = map.refresh();
    // last_refresh must be set after a refresh.
    assert!(map.last_refresh.is_some());
}

#[test]
fn test_all_returns_cached_values() {
    let mut map = IdentityMap::new();
    map.cache.insert(
        1,
        ProcessIdentity {
            cgroup_id: 1,
            uid: 0,
            comm: "init".to_string(),
        },
    );
    map.cache.insert(
        2,
        ProcessIdentity {
            cgroup_id: 2,
            uid: 1000,
            comm: "shell".to_string(),
        },
    );

    let all = map.all();
    assert_eq!(all.len(), 2);
}

#[test]
fn test_cgroup_id_from_path_is_the_inode() {
    // NIGHT-hunt-31: the resolver is stat(2), nothing else.
    let dir = std::env::temp_dir().join("zelynic-h31-inode");
    fs::create_dir_all(&dir).unwrap();
    let ino = fs::metadata(&dir).unwrap().ino();
    assert_eq!(cgroup_id_from_path(dir.to_str().unwrap()), Some(ino));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_cgroup_id_from_path_ignores_decoy_cgroup_id_file() {
    // NIGHT-hunt-31 pin: a decoy cgroup.id file must never override
    // the kernel's numbering — the file does not exist in mainline.
    let dir = std::env::temp_dir().join("zelynic-h31-decoy");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("cgroup.id"), "999999999\n").unwrap();
    let ino = fs::metadata(&dir).unwrap().ino();
    assert_eq!(cgroup_id_from_path(dir.to_str().unwrap()), Some(ino));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_cgroup_id_from_path_missing_dir_is_none() {
    assert_eq!(cgroup_id_from_path("/nonexistent-zelynic-h31"), None);
}

#[test]
fn test_display_name_enriches_the_kernel_cap() {
    // NIGHT-engrave-7 (the owner's WebKitNetworkPro find): the
    // kernel caps comm at 15 bytes, so the 20-char
    // `WebKitNetworkProcess` walks in as `WebKitNetworkPr`;
    // argv[0]'s basename restores the full name under the
    // prefix-continuity guard.
    let cmdline = b"/usr/libexec/WebKitNetworkProcess\0--child\0";
    assert_eq!(
        display_name("WebKitNetworkPr", cmdline),
        "WebKitNetworkProcess"
    );
    // A bare argv[0] (no path) enriches the same way.
    assert_eq!(
        display_name("WebKitNetworkPr", b"WebKitNetworkProcess\0"),
        "WebKitNetworkProcess"
    );
}

#[test]
fn test_display_name_keeps_short_comms_honest() {
    // Under the cap: the comm is the process's own name, and no
    // enrichment may swap it (python3 running a script keeps
    // "python3" — the script path is a different string, not a
    // fuller spelling of the same one).
    assert_eq!(
        display_name("python3", b"/usr/bin/python3\0script.py\0"),
        "python3"
    );
    assert_eq!(display_name("alacritty", b"alacritty\0"), "alacritty");
}

#[test]
fn test_display_name_rejects_non_prefix_basenames() {
    // At the cap but argv[0] tells a different story (a rewritten
    // argv, a launcher): the capped comm stays — the enrichment
    // only ever EXTENDS a name, never replaces it.
    assert_eq!(
        display_name("xxxxxxxxxxxxxxx", b"/opt/weird/launcher\0"),
        "xxxxxxxxxxxxxxx"
    );
    // Empty cmdline (kernel threads, zombies): the comm stays —
    // a 15-char kworker thread name is the kernel's own, and the
    // empty argv offers nothing fuller.
    assert_eq!(display_name("kworker/u16:2-A", b""), "kworker/u16:2-A");
}

#[test]
fn test_display_name_caps_at_24_columns() {
    // The footer's frame-harmony budget: 37 + name + 7 = 68
    // columns on the classic 80 — a longer name would wrap the
    // pinned footer. Pathological basenames degrade to 23 chars
    // plus the ellipsis, never explode the line.
    let long = b"/opt/app/some-very-long-launcher-name-v2.bin\0";
    let got = display_name("some-very-long-", long);
    assert_eq!(
        got.chars().count(),
        24,
        "the cap is 24 columns, ellipsis included"
    );
    assert!(
        got.ends_with('\u{2026}'),
        "the cap truncates with an ellipsis, got {got:?}"
    );
    // Real offenders fit whole: 20, 16, 20 chars.
    assert_eq!(
        display_name("WebKitNetworkPr", b"WebKitNetworkProcess\0")
            .chars()
            .count(),
        20
    );
}

#[test]
fn test_argv0_basename_extracts_and_sanitizes() {
    assert_eq!(
        argv0_basename(b"/usr/libexec/WebKitNetworkProcess\0arg\0"),
        Some("WebKitNetworkProcess".to_string())
    );
    // No NUL terminator (truncated read): the whole buffer is argv[0].
    assert_eq!(argv0_basename(b"/bin/tool"), Some("tool".to_string()));
    // Kernel thread: empty cmdline.
    assert_eq!(argv0_basename(b""), None);
    // Degenerate: argv[0] is just the separator.
    assert_eq!(argv0_basename(b"/\0"), None);
    // Control bytes sanitize at the boundary (the OSC injection
    // family dies here, same as comm).
    assert_eq!(argv0_basename(b"\x1bevil\0"), Some("?evil".to_string()));
}
