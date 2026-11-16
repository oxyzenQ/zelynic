// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! night-frontier-Z6 (D1, the proven datapath): the bounded-model-
//! checking instrument. Each #[kani::proof] harness turns a named
//! law into a machine-checked theorem over FOR ALL INPUTS within
//! the harness's stated domain — the for-all tier above the
//! property sampler's thousands-of-cases tier. The kernel's own
//! doc claims this module proves: the fill-detect overflow guard
//! ("the exact branch only runs while elapsed < fill_ns, and the
//! product is bounded by construction"), the clamp family's
//! totality over hostile pre-states, the ladder bounds, and the
//! memo/cache decision table. The domain assumptions (the burst
//! representability contract, the hostile-state reachability) are
//! stated in the harness, never hidden.

use crate::drr_core as drr;
use crate::during_core as during;
use crate::hist_core as hist;
use crate::math_core::{self, Bucket, MAX_ENFORCABLE_BURST, NS_PER_SEC, Policy};
use crate::mmspa_core as mmspa;
use crate::quic_core as quic;
use crate::rate_ring_core as rate_ring;

/// The system's policy-rate ceiling: src/ebpf/limiter/types.rs's
/// MAX_RATE (1e12 bytes per second), the value the parse family's
/// u128 exact math refuses to exceed (parse.rs's own ceiling check).
/// The enforcement theorems quantify over the REACHABLE policy
/// domain — no CLI path can write a rate above this ceiling, so the
/// for-all proofs carry the same bound the system itself enforces.
/// (Types.rs is not #[path]-includeable standalone — its crate
/// paths — so the constant is restated here beside its source; the
/// userspace parse pins hold the two in lockstep.)
const SYSTEM_MAX_RATE: u64 = 1_000_000_000_000;

fn pol(rate: u64, burst: u64) -> Policy {
    Policy {
        rate_bps: rate,
        burst_bytes: burst,
        floor_bps: 0,
        ceil_bps: 0,
        group_id: 0,
        flags: 0,
    }
}

/// THE overflow-guard theorem: for EVERY (rate, burst, elapsed,
/// frac) in the refill contract's domain, refill_credits performs
/// no overflowing arithmetic (kani's overflow checks are the
/// verdict) and keeps its two output laws — the fraction under
/// NS_PER_SEC, the credit under rate + burst. The fill-detect branch
/// is the proof: the exact multiply only runs while
/// elapsed x rate < 2 x burst x NS_PER_SEC, representable by the
/// burst domain assumption.
#[kani::proof]
fn refill_credits_is_total_and_bounded_for_all_inputs() {
    let rate: u64 = kani::any();
    kani::assume(rate <= SYSTEM_MAX_RATE);
    let burst: u64 = kani::any();
    kani::assume(burst <= MAX_ENFORCABLE_BURST);
    let elapsed: u64 = kani::any();
    let frac: u64 = kani::any();
    let (whole, new_frac) = math_core::refill_credits(rate, burst, elapsed, frac);
    assert!(new_frac < NS_PER_SEC, "fraction escaped its domain");
    assert!(
        whole <= rate.saturating_add(burst),
        "credit exceeded rate + burst"
    );
    if rate == 0 || elapsed == 0 {
        let healthy = if frac < NS_PER_SEC { frac } else { 0 };
        assert_eq!((whole, new_frac), (0, healthy), "zero-window credit");
    }
}

/// THE clamp-family theorem: for EVERY hostile pre-state the
/// persistent maps can carry (tokens/frac/stamp arbitrary, burst
/// inside its representability contract, now forward, backward, or
/// absurd) the full enforce path performs no overflowing arithmetic,
/// answers a boolean verdict, leaves the stock at or under burst
/// (the seed clamp and the post-add cap, single-threaded), and keeps
/// the sanitized fraction in its domain.
#[kani::proof]
fn enforce_is_total_and_clamped_for_all_hostile_states() {
    let rate: u64 = kani::any();
    let burst: u64 = kani::any();
    kani::assume(burst <= MAX_ENFORCABLE_BURST);
    let tokens: u64 = kani::any();
    let frac: u64 = kani::any();
    let last: u64 = kani::any();
    let now: u64 = kani::any();
    let pkt: u32 = kani::any();
    let policy = pol(rate, burst);
    let mut b = Bucket {
        tokens,
        last_refill_ns: last,
        frac_rem: frac,
    };
    let verdict = math_core::enforce(&policy, &mut b, pkt, now, None);
    assert!(verdict == 0 || verdict == 1, "verdict escaped boolean");
    assert!(b.tokens <= burst, "stock escaped the burst cap");
    // The v6 sanitize law is ON READ: an owned window stores a
    // healthy fraction; an unowned one leaves the stored word
    // untouched (hostile stored values are re-sanitized at every
    // read, never trusted).
    if now > last && rate > 0 {
        assert!(
            b.frac_rem < NS_PER_SEC,
            "an owned window stored an unhealthy fraction"
        );
    } else {
        assert_eq!(
            b.frac_rem, frac,
            "an unowned window moved the stored fraction"
        );
    }
}

/// THE sufficiency theorem: one consume attempt against any state
/// deducts exactly the packet iff the stock covered it — the
/// never-over-allow / never-resurrect pair, for all inputs.
#[kani::proof]
fn consume_sufficiency_is_decisive_for_all_inputs() {
    let tokens: u64 = kani::any();
    let pkt: u32 = kani::any();
    let mut b = Bucket {
        tokens,
        last_refill_ns: 0,
        frac_rem: 0,
    };
    let allowed = math_core::try_consume(&mut b, pkt);
    let want = u64::from(pkt);
    assert_eq!(allowed, tokens >= want, "sufficiency verdict wrong");
    if allowed {
        assert_eq!(b.tokens, tokens - want, "consume deducted the wrong amount");
    } else {
        assert_eq!(b.tokens, tokens, "a dropped packet moved the stock");
    }
}

/// THE ladder theorem: for EVERY u64 both log2 ladders answer inside
/// [0, 31] — the bounds the AND-mask verifier proof rides — and the
/// ladder boundaries land exactly on the powers of two.
#[kani::proof]
fn bucket_ladders_are_bounded_and_exact_for_all_inputs() {
    let a: u64 = kani::any();
    assert!(hist::size_bucket(a) <= 31, "size ladder escaped");
    assert!(hist::srtt_bucket(a) <= 31, "srtt ladder escaped");
    let k: u64 = kani::any();
    kani::assume(k >= 1 && k <= 31);
    let power = 1u64 << k;
    assert_eq!(hist::size_bucket(power) as u64, k, "power-of-two boundary");
    assert_eq!(
        hist::size_bucket(power - 1) as u64,
        k - 1,
        "pre-boundary value"
    );
    assert_eq!(hist::srtt_bucket(power) as u64, k, "srtt power boundary");
}

/// THE day-domain theorem: any u64 wall instant reduces into
/// [0, NS_PER_DAY), and the window verdict is total for any row
/// bytes (unknown kinds enforce, spans compare their own pair).
#[kani::proof]
fn window_domain_is_total_for_all_inputs() {
    let wall: u64 = kani::any();
    assert!(
        during::wall_of_day_ns(wall) < during::NS_PER_DAY,
        "day domain escaped"
    );
    let kind: u32 = kani::any();
    let start_mono: u64 = kani::any();
    let end_mono: u64 = kani::any();
    let start_s: u32 = kani::any();
    let end_s: u32 = kani::any();
    let now: u64 = kani::any();
    let offset: u64 = kani::any();
    let win = during::PolicyWindow {
        kind,
        reserved: 0,
        start_mono_ns: start_mono,
        end_mono_ns: end_mono,
        start_s,
        end_s,
    };
    let active = during::window_active(&win, now, offset);
    if kind != during::WINDOW_KIND_SPAN && kind != during::WINDOW_KIND_DAILY {
        assert!(active, "an unknown kind must enforce");
    }
    if kind == during::WINDOW_KIND_SPAN {
        assert_eq!(
            active,
            now >= start_mono && now < end_mono,
            "span verdict left its law"
        );
    }
}

/// THE margin theorem: the fire-early margin erodes BOTH edges
/// toward less enforcement, so a wider margin can only shrink the
/// active set, never grow it — for every (position, window, margin)
/// triple in the u64 domain.
///
/// Wired out of both CI lanes by signed census verdict: the
/// constant-modulo circuit was measured undecided under every
/// backend, so the sampled tier carries this law until one does.
/// The harness never runs in proofs.yml or proofs-night.yml (the
/// lane headers hold the record); it executes only on a direct
/// `cargo kani --lib --harness` call. A hunt that flags its absence
/// from the lanes is re-reading a decision, not finding a gap.
#[kani::proof]
fn daily_margin_erodes_monotonically_for_all_inputs() {
    let secs: u64 = kani::any();
    let start_s: u32 = kani::any();
    let end_s: u32 = kani::any();
    let margin: u64 = kani::any();
    let wider = margin.saturating_add(1);
    if during::daily_active(secs, start_s, end_s, wider) {
        assert!(
            during::daily_active(secs, start_s, end_s, margin),
            "a wider margin grew the active set"
        );
    }
}

/// THE memo theorem: the packed memo word round-trips both halves
/// losslessly for EVERY (generation, root) pair, and the cache
/// decision table answers exactly the documented verdict for every
/// (memo, generation, aliveness) shape.
#[kani::proof]
fn memo_and_cache_table_hold_for_all_inputs() {
    let generation: u32 = kani::any();
    let root: u32 = kani::any();
    let word = mmspa::memo_value(generation, root);
    assert_eq!(mmspa::memo_gen(word), generation, "generation half");
    assert_eq!(mmspa::memo_root(word), root, "root half");

    let memo: u64 = kani::any();
    let cur: u32 = kani::any();
    let alive: bool = kani::any();
    assert!(
        matches!(
            mmspa::cache_verdict(None, cur, alive),
            mmspa::CacheVerdict::Walk
        ),
        "an absent memo must walk"
    );
    let verdict = mmspa::cache_verdict(Some(memo), cur, alive);
    if mmspa::memo_gen(memo) != cur {
        assert!(
            matches!(verdict, mmspa::CacheVerdict::Walk),
            "stale memo must walk"
        );
    } else {
        match mmspa::memo_root(memo) {
            0 => assert!(
                matches!(verdict, mmspa::CacheVerdict::Allow),
                "zero root must allow"
            ),
            r => match verdict {
                mmspa::CacheVerdict::Enforce(e) => {
                    assert_eq!(e, r, "enforce named a different root");
                    assert!(alive, "enforced a dead root's policy");
                }
                mmspa::CacheVerdict::Walk => assert!(!alive, "a live root must enforce"),
                mmspa::CacheVerdict::Allow => panic!("nonzero root allowed"),
            },
        }
    }
}

/// THE ring theorem: ring_book is total over any pre-state and any
/// clock, and single-threaded the current window's stamp lands
/// exactly on w whenever the pre-state was at or behind the clock
/// (the boundary CAS cannot lose uncontended); a future stamp is
/// left untouched.
#[kani::proof]
fn ring_book_is_total_and_stamps_lawfully() {
    let mut ring = rate_ring::RateRing::default();
    let w0: u64 = kani::any();
    let b0: u64 = kani::any();
    ring.slots[0] = rate_ring::RateSlot {
        window: w0,
        bytes: b0,
    };
    let now: u64 = kani::any();
    let len: u32 = kani::any();
    rate_ring::ring_book(&mut ring, now, len);
    let w = now / rate_ring::RING_WINDOW_NS;
    // The modulo in usize space with the bound stated: the ring's own
    // index law (w % 8 < 8) is part of the theorem, stated here so a
    // backend that proves it answers the whole harness.
    let idx = (w % rate_ring::RING_SLOTS) as usize;
    assert!(idx < rate_ring::RING_SLOTS as usize, "the modulo bound");
    let slot = &ring.slots[idx];
    if slot.window <= w {
        assert_eq!(slot.window, w, "a behind-or-current stamp must land on w");
    }
}

/// THE share-state theorem: the note step keeps the packed word's
/// laws for every input — the epoch truncation, the running
/// increment discipline, and the peak ratchet that never sits below
/// the running count.
#[kani::proof]
fn share_note_keeps_its_word_laws_for_all_inputs() {
    let word: u64 = kani::any();
    let now_epoch: u32 = kani::any();
    let drew: bool = kani::any();
    let stored = drr::pool_share_epoch(word);
    let old_running = drr::pool_share_running(word);
    let after = drr::pool_share_note(word, now_epoch, drew);
    let running_out = drr::pool_share_running(after);
    assert!(
        drr::pool_share_peak(after) >= running_out,
        "peak below running"
    );
    if stored != now_epoch {
        assert_eq!(
            drr::pool_share_epoch(after),
            now_epoch & 0x0FFF_FFFF,
            "rollover epoch law"
        );
        assert_eq!(
            drr::pool_share_last(after),
            old_running,
            "retired running into last"
        );
    }
    if !drew && stored == now_epoch {
        let expected = old_running.saturating_add(1).min(0xFFF);
        assert_eq!(
            running_out, expected,
            "the running count only moves on a fresh ask"
        );
    }
}

/// THE hint theorem: the learn step confirms exactly a repeated
/// nonzero sighting, restarts on a change, and never confirms zero —
/// for every (old, new) length in the RFC 9000 v1 range.
#[kani::proof]
fn hint_learn_holds_its_state_machine_for_all_sightings() {
    let old_len: u8 = kani::any();
    kani::assume(old_len <= quic::QUIC_MAX_CID_LEN);
    let len: u8 = kani::any();
    kani::assume(len <= quic::QUIC_MAX_CID_LEN);
    let old = quic::hint_word(old_len);
    let after = quic::hint_learn(old, len);
    if len == old_len && len != 0 {
        assert!(
            quic::hint_confirmed(after),
            "a repeat sighting must confirm"
        );
    } else {
        assert!(
            !quic::hint_confirmed(after),
            "a changed or zero sighting must not confirm"
        );
        assert_eq!(quic::hint_len(after), len, "the learned length must land");
    }
}

/// THE bounded-key theorem: the flow key is total over any window
/// shape in its real domain — a 16-byte L4 window, any offset, any
/// CID length at or under the RFC 9000 v1 bound — the 5.13 floor
/// law's bounded collector, for all (bytes, offset, length). The
/// determinism half (the same window mixes twice to the same key)
/// rides the property sampler: the for-all encoding's duplicated
/// splitmix64 circuits do not decide on this solver generation, and
/// a pure fn called twice on identical inputs is structurally one
/// circuit — the sampled tier carries it honestly.
#[kani::proof]
fn flow_key_bounded_is_total_for_all_window_shapes() {
    let buf: [u8; 16] = kani::any();
    let off: usize = kani::any();
    kani::assume(off < 32);
    let len: usize = kani::any();
    kani::assume(len <= quic::QUIC_MAX_CID_LEN as usize);
    let cookie: u64 = kani::any();
    let _key = quic::flow_key_bounded(cookie, &buf, off, len);
}
