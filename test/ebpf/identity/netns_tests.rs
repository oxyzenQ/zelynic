// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! Pins for the netns:// lane (night-netns-1) — the pure cores: the
//! URI grammar arm (shared with the container lanes' parse, and its
//! round-trip through Target::parse), the ns-link inode parser, and
//! the member verdict reduction. The IO wrappers (the handle stat,
//! the /proc walk) stay the root-machine lane — every decision they
//! make is one of these pinned cores.

use super::*;
use crate::ebpf::identity::container::{ContainerRef, parse_container};

// ── the URI grammar ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn parse_netns_uri() {
    let Some(ContainerRef::Netns { name }) = parse_container("netns://sandbox") else {
        panic!("netns://sandbox must parse");
    };
    assert_eq!(name, "sandbox");
}

/// The display form round-trips — every surface that prints the
/// target produces a command that works verbatim.
#[test]
fn display_round_trips() {
    let c = ContainerRef::Netns {
        name: "sandbox".to_string(),
    };
    assert_eq!(c.display(), "netns://sandbox");
    assert_eq!(parse_container("netns://sandbox"), Some(c));
}

/// Malformed shapes return None — they fall back to the
/// process-name lane (the graceful no-match), never a half-parsed
/// reference. The name law is the docker lane's verbatim:
/// non-empty, no '/', no ':'.
#[test]
fn parse_rejects_malformed_netns_uris() {
    for bad in [
        "netns://",     // empty name
        "netns://a/b",  // '/' in name
        "netns://a:b",  // ':' in name (breaks the embedded grammars)
        "netns://a::b", // the list separator can never ride the name
    ] {
        assert_eq!(parse_container(bad), None, "{bad} must not parse");
    }
}

/// The parse rides Target::parse first — a netns URI is a Container
/// target, not a process name (the sibling lanes' ride).
#[test]
fn target_parse_rides_netns() {
    use crate::ebpf::limiter::Target;
    let Some(Target::Container(ContainerRef::Netns { name })) = Target::parse("netns://sandbox")
    else {
        panic!("netns://sandbox must parse as a container target");
    };
    assert_eq!(name, "sandbox");
}

// ── the ns-link inode parser ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn parse_ns_ino_links() {
    assert_eq!(parse_ns_ino("net:[4026532500]"), Some(4026532500));
    assert_eq!(parse_ns_ino("net:[1]"), Some(1));
}

#[test]
fn parse_ns_ino_rejects_odd_shapes() {
    for odd in [
        "",                  // nothing at all
        "net:",              // no bracket group
        "net:[]",            // empty inode
        "net:[abc]",         // not numeric
        "net:[4026532500]x", // trailing junk — not the kernel's shape
        "link:[3]",          // another namespace class
    ] {
        assert_eq!(parse_ns_ino(odd), None, "{odd} must not parse");
    }
}

// ── the member verdict ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn verdict_empty_when_no_members() {
    assert_eq!(netns_verdict(&[]), NetnsVerdict::Empty);
}

#[test]
fn verdict_one_distinct_cgroup() {
    assert_eq!(netns_verdict(&[73386]), NetnsVerdict::One(73386));
}

/// Duplicate members collapse — several pids of one workload
/// cgroup are ONE target (the resolve contract's shape).
#[test]
fn verdict_collapses_duplicates() {
    assert_eq!(netns_verdict(&[9, 9, 9]), NetnsVerdict::One(9));
}

/// Two or more distinct member cgroups are the honest ambiguity —
/// sorted, so the error text is deterministic.
#[test]
fn verdict_ambiguous_names_all_sorted() {
    assert_eq!(
        netns_verdict(&[99, 5, 42]),
        NetnsVerdict::Ambiguous(vec![5, 42, 99])
    );
}
