// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! private-research-4 candidate, schema v22: rootless pins for the
//! QUIC-aware attribution core (ebpf/src/quic.rs, the same file the
//! BPF object builds, wired below with #[path]). Every pin maps to
//! a documented contract in that module:
//!
//!  * the strict-shape law — only v1/v2 long headers and fixed-bit
//!    short headers parse; version 0 (Version Negotiation), junk
//!    versions, CID lengths above the RFC 9000 bound of 20, a clear
//!    fixed bit, non-UDP protocols, IPv6 extension headers, and
//!    every truncation refuse to the COOKIE lane (today's verdict,
//!    never a guess);
//!  * the hint state machine — the confirmation gate: a length must
//!    survive a second sighting before any short header keys on it,
//!    a changed length restarts unconfirmed, zero never confirms;
//!  * the direction symmetry — the mirrored egress/ingress views of
//!    one conversation agree on the SAME hint key (both hooks write
//!    the hint entry that names their conversation);
//!  * THE LIFECYCLE — a full handshake walkthrough with THREE
//!    distinct CID lengths (the throwaway Initial DCID, the client
//!    CID, the server CID): the transients never activate, the
//!    post-switch long headers confirm the correct geometry, and
//!    the 1-RTT data keys per connection exactly;
//!  * THE ISOLATION PROPERTY — the feature's whole point: N QUIC
//!    connections multiplexed over ONE socket cookie split into N
//!    distinct, stable per-connection keys (the shape the CAKE
//!    flow lane and the --per-socket budget lane key on), while
//!    the unconfirmed fallback keeps every early packet on the
//!    shared cookie key (exactly the v20/v15 behavior).

// The production attribution core, compiled into this test module:
// the SAME file the BPF object builds. Only the test tree reaches
// across trees (the gate-tree discipline, the math_tests precedent).
#[path = "../../../ebpf/src/quic.rs"]
pub(super) mod ebpf_quic;

use self::ebpf_quic::{
    classify, flow_key, hint_confirmed, hint_key, hint_learn, hint_len, hint_word, Classify,
};

/// The socket cookie the sims multiplex over (the kernel assigns
/// dense small integers; the mixer's whole job is to keep them from
/// colliding once CIDs mix in).
const COOKIE: u64 = 0x1234;

/// One UDP-over-IPv4 packet: src/dst address pair, src/dst port
/// pair, payload bytes. Header fields not under test are benign
/// defaults (ttl 64, checksum 0).
fn udp4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    // [0] ver/IHL, [1] ToS, [2-3] len, [4-5] id, [6-7] frag, [8] TTL,
    // [9] protocol 17, [10-11] csum, [12-15] src, [16-19] dst.
    let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 64, 0, 17, 0, 0];
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&(8u16 + payload.len() as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    p
}

/// One UDP-over-IPv6 packet (fixed 40-byte header, next header 17).
fn udp6(src: [u8; 16], dst: [u8; 16], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    // [0] ver, [1-3] traffic/flow, [4-5] len, [6] next header 17,
    // [7] hop limit, [8-23] src, [24-39] dst.
    let mut p = vec![0x60, 0, 0, 0, 0, 0, 17, 64];
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&(8u16 + payload.len() as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    p
}

/// A QUIC v1 long header (fixed bit + long bit set, version 1)
/// carrying explicit-length DCID and SCID.
fn quic_long(dcid: &[u8], scid: &[u8]) -> Vec<u8> {
    let mut b = vec![0xC3];
    b.extend_from_slice(&1u32.to_be_bytes());
    b.push(dcid.len() as u8);
    b.extend_from_slice(dcid);
    b.push(scid.len() as u8);
    b.extend_from_slice(scid);
    b
}

/// A QUIC v1 short header (fixed bit set, long bit clear) carrying
/// the peer's connection ID (its length is the learned hint).
fn quic_short(dcid: &[u8]) -> Vec<u8> {
    let mut b = vec![0x43];
    b.extend_from_slice(dcid);
    b
}

/// The conversation endpoints the sims use: the local socket talks
/// to one remote server, so egress sees (cli -> srv) and ingress
/// the mirror (srv -> cli).
const CLI: [u8; 4] = [192, 168, 1, 10];
const SRV: [u8; 4] = [142, 250, 185, 78];
const CLI_PORT: u16 = 55_555;
const SRV_PORT: u16 = 443;

#[test]
fn long_header_parses_exact_cid_spans() {
    let dcid = [9u8; 8];
    let scid = [7u8; 5];
    let pkt = udp4(CLI, SRV, CLI_PORT, SRV_PORT, &quic_long(&dcid, &scid));
    match classify(COOKIE, &pkt, false, 0) {
        Classify::Long {
            key,
            learn_this,
            learn_other,
            ..
        } => {
            assert_eq!(
                key,
                flow_key(COOKIE, &dcid),
                "the long header keys by its exact DCID"
            );
            assert_eq!(
                learn_this, 8,
                "this direction's hint learns the DCID length"
            );
            assert_eq!(
                learn_other, 5,
                "the opposite direction's hint learns the SCID length"
            );
        }
        other => panic!("a well-formed v1 long header must classify Long, got {other:?}"),
    }
}

#[test]
fn conversation_hint_key_is_direction_symmetric() {
    // The same conversation seen from both hooks: egress carries
    // (cli -> srv), ingress the mirror (srv -> cli). The remote
    // endpoint is the server either way, so both views must agree
    // on the hint entry — the property that lets the two programs
    // write the one conversation's hints without a shared registry.
    let dcid = [9u8; 8];
    let egress = udp4(CLI, SRV, CLI_PORT, SRV_PORT, &quic_long(&dcid, &dcid));
    let ingress = udp4(SRV, CLI, SRV_PORT, CLI_PORT, &quic_long(&dcid, &dcid));
    let (hk_out, hk_in) = match (
        classify(COOKIE, &egress, false, 0),
        classify(COOKIE, &ingress, true, 0),
    ) {
        (Classify::Long { hkey: a, .. }, Classify::Long { hkey: b, .. }) => (a, b),
        other => panic!("both directions must classify Long, got {other:?}"),
    };
    assert_eq!(
        hk_out, hk_in,
        "the mirrored views of one conversation share one hint key"
    );
    assert_ne!(hk_out, COOKIE, "the hint key mixes remote identity in");
}

#[test]
fn short_header_rides_cookie_until_confirmed() {
    let cid = [0xAB; 8];
    let pkt = udp4(CLI, SRV, CLI_PORT, SRV_PORT, &quic_short(&cid));
    assert_eq!(
        classify(COOKIE, &pkt, false, 0),
        Classify::Short { key: None },
        "no hint: the cookie lane, exactly today's behavior"
    );
    let once = hint_learn(hint_word(0), 8);
    assert!(!hint_confirmed(once));
    assert_eq!(
        classify(COOKIE, &pkt, false, once),
        Classify::Short { key: None },
        "one sighting is not enough — the confirm gate holds"
    );
}

#[test]
fn short_header_keys_by_the_confirmed_cid_prefix() {
    let cid = [0xAB; 8];
    let pkt = udp4(CLI, SRV, CLI_PORT, SRV_PORT, &quic_short(&cid));
    let confirmed = hint_learn(hint_learn(hint_word(0), 8), 8);
    assert!(hint_confirmed(confirmed));
    assert_eq!(
        classify(COOKIE, &pkt, false, confirmed),
        Classify::Short {
            key: Some(flow_key(COOKIE, &cid))
        },
        "a confirmed hint keys the short header by its DCID"
    );
    // A four-byte CID under a confirmed four-byte hint: the same
    // law, the shorter span.
    let cid4 = [0xCD; 4];
    let pkt4 = udp4(CLI, SRV, CLI_PORT, SRV_PORT, &quic_short(&cid4));
    let hint4 = hint_learn(hint_learn(hint_word(0), 4), 4);
    assert_eq!(
        classify(COOKIE, &pkt4, false, hint4),
        Classify::Short {
            key: Some(flow_key(COOKIE, &cid4))
        }
    );
}

#[test]
fn strict_shape_refusals_all_ride_the_cookie() {
    let quicish = quic_long(&[9u8; 8], &[7u8; 8]);
    // TCP protocol byte (6), QUIC payload: not UDP, not attributed.
    let mut tcp = udp4(CLI, SRV, CLI_PORT, SRV_PORT, &quicish);
    tcp[9] = 6;
    assert_eq!(classify(COOKIE, &tcp, false, 0), Classify::Cookie);
    // Version Negotiation (version 0): not a data-carrying QUIC
    // packet, refused.
    let mut vn = quic_long(&[9u8; 8], &[7u8; 8]);
    vn[1..5].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(
        classify(COOKIE, &udp4(CLI, SRV, CLI_PORT, SRV_PORT, &vn), false, 0),
        Classify::Cookie
    );
    // A junk version: same refusal.
    let mut junk = quic_long(&[9u8; 8], &[7u8; 8]);
    junk[1..5].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    assert_eq!(
        classify(COOKIE, &udp4(CLI, SRV, CLI_PORT, SRV_PORT, &junk), false, 0),
        Classify::Cookie
    );
    // DCID length above the RFC 9000 bound of 20: malformed, refused.
    let mut over = quic_long(&[9u8; 8], &[7u8; 8]);
    over[5] = 21;
    assert_eq!(
        classify(COOKIE, &udp4(CLI, SRV, CLI_PORT, SRV_PORT, &over), false, 0),
        Classify::Cookie
    );
    // Fixed bit clear (neither a valid long nor short header).
    let mut nofix = quic_long(&[9u8; 8], &[7u8; 8]);
    nofix[0] = 0x80;
    assert_eq!(
        classify(
            COOKIE,
            &udp4(CLI, SRV, CLI_PORT, SRV_PORT, &nofix),
            false,
            0
        ),
        Classify::Cookie
    );
    // Truncated mid-CID: the bounds check refuses, not panics.
    let mut cut = quic_long(&[9u8; 20], &[7u8; 20]);
    cut.truncate(6);
    assert_eq!(
        classify(COOKIE, &udp4(CLI, SRV, CLI_PORT, SRV_PORT, &cut), false, 0),
        Classify::Cookie
    );
    // IPv6 with a non-UDP next header (ICMPv6): the outer parse
    // refuses before QUIC is ever consulted.
    let mut v6_icmp = udp6([0; 16], [0; 16], CLI_PORT, SRV_PORT, &quic_short(&[1u8; 8]));
    v6_icmp[6] = 58;
    assert_eq!(classify(COOKIE, &v6_icmp, true, 0), Classify::Cookie);
    // A buffer too short to even hold UDP: refused.
    assert_eq!(classify(COOKIE, &[0x45, 0, 0], true, 0), Classify::Cookie);
}

#[test]
fn hint_state_machine_gates_on_the_second_sighting() {
    // Fresh length: unconfirmed.
    let once = hint_learn(hint_word(0), 8);
    assert_eq!(hint_len(once), 8);
    assert!(!hint_confirmed(once));
    // The same length again: confirmed.
    let twice = hint_learn(once, 8);
    assert!(hint_confirmed(twice));
    assert_eq!(hint_len(twice), 8, "confirmation never mutates the length");
    // A changed length restarts unconfirmed — the transient the
    // gate exists to absorb.
    let changed = hint_learn(twice, 12);
    assert_eq!(hint_len(changed), 12);
    assert!(!hint_confirmed(changed));
    // Zero-length never confirms: nothing to key on.
    let zero = hint_learn(hint_learn(hint_word(0), 0), 0);
    assert_eq!(hint_len(zero), 0);
    assert!(!hint_confirmed(zero));
    // The upper bound confirms like any other length.
    let max = hint_learn(hint_learn(hint_word(0), 20), 20);
    assert!(hint_confirmed(max));
    assert_eq!(hint_len(max), 20);
}

#[test]
fn ipv6_and_ip_option_packets_parse() {
    // IPv6: the fixed header, remote = the /48-prefix + port seed.
    let dcid = [5u8; 8];
    let pkt = udp6(
        [0x20; 16],
        [0x30; 16],
        CLI_PORT,
        SRV_PORT,
        &quic_long(&dcid, &dcid),
    );
    match classify(COOKIE, &pkt, true, 0) {
        Classify::Long { key, .. } => assert_eq!(key, flow_key(COOKIE, &dcid)),
        other => panic!("a well-formed v6 long header must classify Long, got {other:?}"),
    }
    // IPv4 with options (IHL 6): four option bytes pad the header
    // to 24, the UDP header shifts, and the parse follows it.
    let mut opts = udp4(CLI, SRV, CLI_PORT, SRV_PORT, &quic_long(&dcid, &dcid));
    opts[0] = 0x46;
    for _ in 0..4 {
        opts.insert(20, 0);
    }
    match classify(COOKIE, &opts, false, 0) {
        Classify::Long { key, .. } => assert_eq!(key, flow_key(COOKIE, &dcid)),
        other => panic!("an IHL-6 long header must classify Long, got {other:?}"),
    }
}

/// THE LIFECYCLE: one QUIC connection over one socket cookie, three
/// DISTINCT CID lengths — the throwaway Initial DCID (16), the
/// client CID (8), the server CID (12) — exactly the geometry that
/// separates a correct learner from a poisoned one. The transients
/// (the throwaway class the peer replaces after its Server Initial)
/// never activate a hint; the post-switch handshake flight confirms
/// the correct geometry; the 1-RTT data then keys per connection.
#[test]
fn quic_conversation_lifecycle_end_to_end() {
    let x = [0x11; 16]; // the throwaway Initial DCID
    let y = [0x22; 8]; // the client CID (egress Initial SCID)
    let z = [0x33; 12]; // the server CID (Server Initial SCID)

    // 1. Client Initial, egress: teaches ul <- |X| (transient), dl
    //    <- |Y| (correct class, unconfirmed).
    let init = udp4(CLI, SRV, CLI_PORT, SRV_PORT, &quic_long(&x, &y));
    let (mut ul, mut dl) = match classify(COOKIE, &init, false, 0) {
        Classify::Long {
            learn_this,
            learn_other,
            ..
        } => (
            hint_learn(hint_word(0), learn_this),
            hint_learn(hint_word(0), learn_other),
        ),
        other => panic!("the Initial must classify Long, got {other:?}"),
    };
    assert_eq!((hint_len(ul), hint_len(dl)), (16, 8));
    assert!(!hint_confirmed(ul) && !hint_confirmed(dl));

    // 2. Server Initial, ingress: its DCID is the throwaway echo
    //    (dl restarts at 16, the documented transient), its SCID is
    //    the server CID (ul <- |Z|, the correct egress class).
    let srv_init = udp4(SRV, CLI, SRV_PORT, CLI_PORT, &quic_long(&x, &z));
    match classify(COOKIE, &srv_init, true, dl) {
        Classify::Long {
            learn_this,
            learn_other,
            ..
        } => {
            dl = hint_learn(dl, learn_this);
            ul = hint_learn(ul, learn_other);
        }
        other => panic!("the Server Initial must classify Long, got {other:?}"),
    }
    assert_eq!(
        (hint_len(ul), hint_len(dl)),
        (12, 16),
        "both transients landed unconfirmed"
    );
    assert!(!hint_confirmed(ul) && !hint_confirmed(dl));

    // 3. The client's Handshake flight, egress (DCID = Z now — the
    //    switch the Server Initial caused): the server CID class was
    //    already learned from the Server Initial's SCID, so this
    //    sighting CONFIRMS ul; dl's correct class (8) only restarts
    //    its word (the 16-transient is overwritten), still gated.
    let hs = udp4(CLI, SRV, CLI_PORT, SRV_PORT, &quic_long(&z, &y));
    match classify(COOKIE, &hs, false, ul) {
        Classify::Long {
            learn_this,
            learn_other,
            ..
        } => {
            ul = hint_learn(ul, learn_this);
            dl = hint_learn(dl, learn_other);
        }
        other => panic!("the Handshake must classify Long, got {other:?}"),
    }
    assert_eq!((hint_len(ul), hint_len(dl)), (12, 8));
    assert!(
        hint_confirmed(ul),
        "the server CID class confirmed on its second sighting"
    );
    assert!(
        !hint_confirmed(dl),
        "the client CID class is still one sighting short"
    );

    // 4. The flight's second packet (CRYPTO retransmits are the
    //    norm): both hints confirm the CORRECT geometry.
    match classify(COOKIE, &hs, false, ul) {
        Classify::Long {
            learn_this,
            learn_other,
            ..
        } => {
            ul = hint_learn(ul, learn_this);
            dl = hint_learn(dl, learn_other);
        }
        other => panic!("the retransmit must classify Long, got {other:?}"),
    }
    assert_eq!((hint_len(ul), hint_len(dl)), (12, 8));
    assert!(hint_confirmed(ul) && hint_confirmed(dl));

    // 5. 1-RTT data: egress shorts carry the server CID, ingress
    //    shorts the client CID — the per-connection keys.
    let up = udp4(CLI, SRV, CLI_PORT, SRV_PORT, &quic_short(&z));
    let down = udp4(SRV, CLI, SRV_PORT, CLI_PORT, &quic_short(&y));
    assert_eq!(
        classify(COOKIE, &up, false, ul),
        Classify::Short {
            key: Some(flow_key(COOKIE, &z))
        }
    );
    assert_eq!(
        classify(COOKIE, &down, true, dl),
        Classify::Short {
            key: Some(flow_key(COOKIE, &y))
        }
    );
}

/// THE ISOLATION PROPERTY: N connections multiplexed over ONE
/// socket cookie split into N distinct, stable keys — the shape the
/// CAKE flow lane isolates and the --per-socket lane budgets, which
/// a raw cookie key collapses into one (the browser HTTP/3 shape
/// the feature exists for). Every key also stays distinct from the
/// cookie itself and from every other socket's key on the same CID.
#[test]
fn n_connections_one_cookie_split_into_n_keys() {
    let cids: [Vec<u8>; 4] = [vec![0xA1; 8], vec![0xB1; 8], vec![0xC1; 8], vec![0xD1; 8]];
    let hint = hint_learn(hint_learn(hint_word(0), 8), 8);
    let mut keys = Vec::new();
    for cid in &cids {
        // A connection's stream: several short-header packets, each
        // classified independently — every packet of one connection
        // must land on the SAME key.
        let stream = [
            udp4(CLI, SRV, CLI_PORT, SRV_PORT, &quic_short(cid)),
            udp4(CLI, SRV, CLI_PORT, SRV_PORT, &quic_short(cid)),
            udp4(CLI, SRV, CLI_PORT, SRV_PORT, &quic_short(cid)),
        ];
        let mut conn_key = None;
        for (i, pkt) in stream.iter().enumerate() {
            match classify(COOKIE, pkt, false, hint) {
                Classify::Short { key: Some(k) } => match conn_key {
                    None => conn_key = Some(k),
                    Some(prev) => assert_eq!(prev, k, "packet {i} of one connection moved keys"),
                },
                other => panic!("a confirmed short header must key, got {other:?}"),
            }
        }
        keys.push(conn_key.expect("every stream keyed"));
    }
    let distinct: std::collections::HashSet<u64> = keys.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        cids.len(),
        "N connections must hold N distinct keys"
    );
    for k in &keys {
        assert_ne!(
            *k, COOKIE,
            "a flow key must never collapse onto the raw cookie"
        );
        assert_ne!(
            *k,
            flow_key(COOKIE + 1, &cids[0]),
            "another socket's flow on the same CID stays distinct"
        );
    }
}

#[test]
fn cid_prefix_beyond_eight_bytes_keys_by_prefix() {
    // CIDs longer than the 8-byte key: the first 8 bytes decide.
    let long_a = [0x42u8; 20];
    let mut long_b = [0x42u8; 20];
    long_b[9] = 0x99;
    assert_eq!(flow_key(COOKIE, &long_a), flow_key(COOKIE, &long_b));
    // A difference inside the first 8 splits them.
    let mut long_c = [0x42u8; 20];
    long_c[3] = 0x99;
    assert_ne!(flow_key(COOKIE, &long_a), flow_key(COOKIE, &long_c));
    // The hint key: distinct remotes hold distinct entries.
    assert_ne!(
        hint_key(COOKIE, 0xAAAA_BBBB_CCCC_D001),
        hint_key(COOKIE, 0xAAAA_BBBB_CCCC_D002)
    );
    assert_eq!(hint_key(COOKIE, 7), hint_key(COOKIE, 7));
}
