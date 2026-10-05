// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// The QUIC-aware datapath wiring (NIGHT-private-research-4
// candidate, schema v22): the aya-touching half of the per-
// connection attribution lane — the two learned-hint maps and the
// one call that turns a socket cookie into a per-CONNECTION key
// when the packet's QUIC connection ID attributes it finer.
// Everything decidable lives in the pure core (../quic.rs, pinned
// rootlessly by test/ebpf/limiter/quic_tests.rs); everything here
// is what only the kernel side can touch:
//
//   * the learned-hint maps (conversation key -> the packed hint
//     word), one per direction, LRU 4096 so dead conversations age
//     out — the leaf-bucket posture every internal lane in this
//     object carries. The maps are shared across the two programs
//     by object construction (both hooks see the same pinned
//     maps): a long header seen on direction D folds its DCID
//     length into D's own map (D's short headers carry that CID
//     class) and its SCID length into the opposite direction's —
//     the cross-direction learn the pure core's lifecycle test
//     walks. No generation belt, on purpose: a hint is a TRANSPORT
//     fact (which CID geometry this conversation speaks), not
//     budget state — a policy mutation changes nothing a hint
//     ever saw, the buckets the hints feed keep their own belts,
//     and the LRU ages stale conversations out the way every lane
//     here documents;
//   * the learn step: read the current word, fold the sighting
//     through the pure hint_learn, CAS the word if it changed (two
//     attempts, the note_share discipline — written out, never a
//     loop for the verifier). A lost race only delays the learn to
//     the next long-header packet, and the confirmation gate means
//     a delayed learn can never key a packet against an
//     unconfirmed length — the safe direction twice over.
//
// The call runs ONLY on policed packets (try_enforce's unlimited
// fast path returns before any attribution work), and its every
// refusal is the raw cookie: the per-socket lane and the v20 flow
// lane key exactly as they did before, so the feature refines
// attribution — never invents it, never degrades it.
//
// Kernel requirement: bpf_skb_load_bytes (helper 26), exposed to
// cgroup_skb programs since before the 5.13 verified floor —
// aya-ebpf 0.2.1 wraps it as SkBuffContext::load_bytes. One fixed
// 96-byte stack read covers the worst header window (IPv4 with
// options 60 + UDP 8 + the long-header prefix 28); a short packet
// reads its own length and the pure core's bounds checks refuse
// whatever does not fit. The read is data-relative (skb->data = the
// network header at both cgroup_skb hooks); a kernel that ever
// disagreed would fail the IP version check and fall back to the
// cookie — the parse is self-protecting by shape.

use aya_ebpf::{macros::map, maps::LruHashMap, programs::SkBuffContext};
use core::sync::atomic::{AtomicU64, Ordering};

// The pure attribution core (core-only, the same file the userspace
// test tree compiles — ONE copy per crate, the math.rs
// duplicate-mod discipline).
use super::quic::{self, Classify};

/// The learned-hint map, download direction: conversation key ->
/// the packed hint word for the CID class the DOWNLOAD short
/// headers carry (the client's CID on the policed-client shape).
/// LRU + pinned (the leaf-bucket posture); datapath-internal
/// (userspace never opens it — the leaf_bucket family's contract).
#[allow(non_upper_case_globals)]
#[map]
pub(super) static quic_cid_hint_dl: LruHashMap<u64, u64> = LruHashMap::pinned(4096, 0);

/// The learned-hint map, upload direction — the download twin's
/// lane (the CID class the UPLOAD short headers carry: the
/// server's).
#[allow(non_upper_case_globals)]
#[map]
pub(super) static quic_cid_hint_ul: LruHashMap<u64, u64> = LruHashMap::pinned(4096, 0);

/// `bpf_map_update_elem` flag: fail the insert if the key already
/// exists (kernel uapi; the limiter's own BPF_NOEXIST note carries
/// the race contract — the loser re-looks-up and rides the
/// winner's entry, never clobbers it).
const BPF_NOEXIST: u64 = 1;

/// The maximum header window one attribution read covers: IPv4
/// with options (60) + UDP (8) + the QUIC long-header prefix
/// (1 + 4 + 1 + 20 + 1). Shorter packets read their own length;
/// the pure core refuses whatever does not fit.
const PARSE_BYTES: usize = 96;

/// READ_ONCE for one hint word (the math.rs access discipline,
/// applied to a bare word: BPF has RMW atomics but no atomic
/// load/store, so reads ride volatile).
#[inline(always)]
fn word_read(p: *const u64) -> u64 {
    // SAFETY: the caller hands a pointer to a live, 8-aligned u64
    // map value (the same contract math.rs's field views carry).
    unsafe { p.read_volatile() }
}

/// Fold one long-header sighting into a hint word: the pure learn
/// step, landed through a CAS when the word actually changed (two
/// attempts, the note_share discipline — written out, never a
/// loop). Relaxed ordering, the drr_flow reasoning verbatim: these
/// words are attribution SHAPING (which geometry a conversation
/// speaks), never the token-conservation bound — a lost race or a
/// delayed learn only postpones confirmation, and the gate keeps
/// every packet keyed on the cookie until the geometry is certain.
#[inline(always)]
fn learn_hint(map: &LruHashMap<u64, u64>, key: &u64, len: u8) {
    let ptr = match map.get_ptr_mut(key) {
        Some(p) => p,
        None => {
            // Cold entry: seed it with the fresh (unconfirmed)
            // learned word — the same value hint_learn folds a
            // zero word into. BPF_NOEXIST, the v11 discipline: a
            // racing first learner's entry is never clobbered; the
            // loser re-looks-up and folds against the winner's
            // word. A genuinely full LRU (4096+ concurrent
            // conversations on one policed lane) leaves the
            // relookup empty and the learn simply does not land —
            // the hint stays absent and the shorts ride the
            // cookie, the honest miss every internal lane here
            // documents.
            let init = quic::hint_word(len);
            let _ = map.insert(key, &init, BPF_NOEXIST);
            return;
        }
    };
    macro_rules! learn_attempt {
        () => {
            let observed = word_read(ptr);
            let next = quic::hint_learn(observed, len);
            if next != observed {
                // SAFETY: same 8-aligned map-value contract as
                // word_read; AtomicU64::from_ptr lowers to the
                // BPF_ATOMIC ISA the 5.13 floor carries.
                if unsafe { AtomicU64::from_ptr(ptr) }
                    .compare_exchange(observed, next, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    return;
                }
            } else {
                return;
            }
        };
    }
    learn_attempt!();
    learn_attempt!();
}

/// The per-packet attribution: the socket cookie, refined into a
/// per-CONNECTION key when the packet's QUIC connection ID carries
/// finer truth. `is_ingress` selects the direction's own hint map
/// (the one this hook's short headers read) and the remote side of
/// the conversation identity. Every refusal — non-UDP, non-QUIC,
/// unparseable, unconfirmed — hands the raw cookie back, which is
/// exactly the key the lanes keyed on before this lane existed:
/// the call can refine attribution, never degrade it.
#[inline(always)]
pub(super) fn quic_flow_key(ctx: &SkBuffContext, cookie: u64, is_ingress: bool) -> u64 {
    // One bounded read of the header window. A read failure
    // (truncated head area, a nonlinear skb the helper refuses) is
    // the cookie — never a guess.
    let mut buf = [0u8; PARSE_BYTES];
    let want = core::cmp::min(PARSE_BYTES, ctx.len() as usize);
    if want == 0 || ctx.load_bytes(0, &mut buf[..want]).is_err() {
        return cookie;
    }
    // Step one (pure): name the conversation. None is the cookie.
    let conv = match quic::conversation(cookie, &buf[..want], is_ingress) {
        Some(c) => c,
        None => return cookie,
    };
    // This direction's current hint word at the conversation's key
    // (an absent entry reads 0 — the packed "no hint" verdict).
    let hint_this = this_dir_map(is_ingress)
        .get_ptr(&conv.hkey)
        .map(|p| word_read(p))
        .unwrap_or(0);
    // Step two (pure): the QUIC decision.
    match quic::decide(cookie, &buf[..want], &conv, hint_this) {
        Classify::Cookie => cookie,
        Classify::Short { key } => match key {
            Some(k) => k,
            None => cookie,
        },
        Classify::Long {
            key,
            hkey,
            learn_this,
            learn_other,
        } => {
            // The handshake teaches both directions' maps at the
            // conversation's key, then the packet rides its OWN
            // exact DCID — stateless for long headers, no hint
            // needed.
            learn_hint(this_dir_map(is_ingress), &hkey, learn_this);
            learn_hint(other_dir_map(is_ingress), &hkey, learn_other);
            key
        }
    }
}

/// This hook's own hint map (the ingress hook reads the download
/// map: its short headers carry the peer CID the download lane
/// keys on).
#[inline(always)]
fn this_dir_map(is_ingress: bool) -> &'static LruHashMap<u64, u64> {
    if is_ingress {
        &quic_cid_hint_dl
    } else {
        &quic_cid_hint_ul
    }
}

/// The opposite hook's map — the twin the cross-direction learn
/// writes.
#[inline(always)]
fn other_dir_map(is_ingress: bool) -> &'static LruHashMap<u64, u64> {
    if is_ingress {
        &quic_cid_hint_ul
    } else {
        &quic_cid_hint_dl
    }
}
