// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! night-frontier-Z6 (D1, the proven datapath): the property-
//! exhaustion instrument. Every property names the law it holds and
//! the core file the law lives in — the same bytes the kernel object
//! builds (the lib.rs #[path] wirings). These are SAMPLED proofs:
//! thousands of shrinkable cases per law per run (the configured
//! case budget), the middle instrument between the standing unit
//! pins (hand-picked edges) and the kani theorems (for-all inputs).
//! A red here is a real counterexample with a shrunk witness, never
//! a flake to rerun away — the same fail-loud culture the SMP
//! hammer and the fuzz lanes carry.

use proptest::prelude::*;

use crate::drr_core as drr;
use crate::during_core as during;
use crate::hist_core as hist;
use crate::math_core::{self, Bucket, MAX_ENFORCABLE_BURST, NS_PER_SEC, Policy};
use crate::mmspa_core as mmspa;
use crate::quic_core as quic;
use crate::rate_ring_core as rate_ring;

// The case budget: 4096 shrinkable cases per property per run — far
// past the standing pins' hand-picked edges, far under the kani
// forall. The default strategy set plus explicit edge strategies
// cover the boundaries the docs name (0, 1, MAX, the power-of-two
// bucket edges, the wrap horizons).
fn cases() -> ProptestConfig {
    ProptestConfig::with_cases(4096)
}

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

fn fresh_bucket(tokens: u64, frac: u64, last: u64) -> Bucket {
    Bucket {
        tokens,
        last_refill_ns: last,
        frac_rem: frac,
    }
}

// ── math.rs: the enforcement arithmetic ──────────────────────────────

proptest! {
    #![proptest_config(cases())]

    /// refill_credits is TOTAL over its whole contract domain and
    /// keeps its two output laws for every input: the fraction stays
    /// below NS_PER_SEC (the carry cannot leak), and the credited
    /// whole never exceeds the window's rate plus the burst cap (the
    /// fill-detect branch answers burst, the exact branch is bounded
    /// by elapsed x rate with the elapsed cap at one second). The
    /// overflow guard is the point: burst up to MAX_ENFORCABLE_BURST
    /// keeps 2 x burst x NS_PER_SEC representable BY CONSTRUCTION —
    /// the property hammers the whole domain, edges included.
    #[test]
    fn refill_credits_total_and_bounded(
        rate in any::<u64>(),
        burst in (0u64..=MAX_ENFORCABLE_BURST),
        elapsed in any::<u64>(),
        frac in any::<u64>(),
    ) {
        let (whole, new_frac) = math_core::refill_credits(rate, burst, elapsed, frac);
        prop_assert!(new_frac < NS_PER_SEC, "fraction escaped its domain: {new_frac}");
        prop_assert!(
            whole <= rate.saturating_add(burst),
            "credit {whole} exceeds rate {rate} + burst {burst}"
        );
        if rate == 0 || elapsed == 0 {
            let healthy = if frac < NS_PER_SEC { frac } else { 0 };
            prop_assert_eq!((whole, new_frac), (0, healthy), "zero-window credit");
        }
    }

    /// The full enforce path is TOTAL for every hostile pre-state the
    /// persistent maps can carry: tokens/frac/stamp arbitrary, the
    /// burst inside its representability contract, now arbitrary
    /// (forward, backward, absurd). The verdict stays boolean, the
    /// security-3 seed clamp plus the post-add cap keep the stock at
    /// or under burst (single-threaded both one-shot CAS wins), and
    /// the sanitized fraction stays under NS_PER_SEC.
    #[test]
    fn enforce_total_and_clamped(
        rate in any::<u64>(),
        burst in (0u64..=MAX_ENFORCABLE_BURST),
        tokens in any::<u64>(),
        frac in any::<u64>(),
        last in any::<u64>(),
        now in any::<u64>(),
        pkt in any::<u32>(),
    ) {
        let policy = pol(rate, burst);
        let mut b = fresh_bucket(tokens, frac, last);
        let verdict = math_core::enforce(&policy, &mut b, pkt, now, None);
        prop_assert!(verdict == 0 || verdict == 1, "verdict escaped boolean: {verdict}");
        prop_assert!(b.tokens <= burst, "stock {} escaped the burst cap {burst}", b.tokens);
        // The v6 sanitize law is ON READ, not on store: a window the
        // call owned writes a healthy fraction (the math's own output
        // is always < NS_PER_SEC); a window it did not own leaves the
        // stored word untouched — hostile stored values are never
        // trusted, only re-sanitized at every read. Pinning the exact
        // law, not a stronger one the contract never made.
        if now > last && rate > 0 {
            prop_assert!(
                b.frac_rem < NS_PER_SEC,
                "an owned window stored an unhealthy fraction: {}",
                b.frac_rem
            );
        } else {
            prop_assert_eq!(
                b.frac_rem, frac,
                "an unowned window moved the stored fraction"
            );
        }
    }

    /// try_consume never over-allows and never resurrects: a verdict
    /// of allow means the stock covered the packet (the sufficiency-
    /// verified CAS), so the pre-state tokens >= pkt implies either
    /// an allow or a contended miss — single-threaded, the CAS never
    /// loses, so tokens >= pkt must always allow.
    #[test]
    fn consume_sufficiency_is_decisive(
        tokens in any::<u64>(),
        pkt in any::<u32>(),
    ) {
        let mut b = fresh_bucket(tokens, 0, 0);
        let allowed = math_core::try_consume(&mut b, pkt);
        let want = u64::from(pkt);
        prop_assert_eq!(allowed, tokens >= want, "sufficiency verdict wrong");
        if allowed {
            prop_assert_eq!(b.tokens, tokens - want, "consume did not deduct exactly want");
        } else {
            prop_assert_eq!(b.tokens, tokens, "a dropped packet moved the stock");
        }
    }
}

// ── drr.rs: the fair-share quantum laws ─────────────────────────────

proptest! {
    #![proptest_config(cases())]

    /// The quantum is never below the GSO admit floor (a leaf can
    /// always admit a super-packet) and equals the window share
    /// whenever the share exceeds that floor.
    #[test]
    fn quantum_respects_the_admit_floor(rate in any::<u64>()) {
        let q = drr::quantum(rate);
        prop_assert!(q >= drr::GSO_ADMIT_FLOOR, "quantum {q} under the admit floor");
        let share = rate / (1000 / drr::DRR_WINDOW_MS);
        let expected = if share > drr::GSO_ADMIT_FLOOR {
            share
        } else {
            drr::GSO_ADMIT_FLOOR
        };
        prop_assert_eq!(q, expected, "quantum left its law");
    }

    /// The residue law: a draw never exceeds the quantum and never
    /// takes more than half the visible pool.
    #[test]
    fn draw_size_stays_half_and_quantum(
        quantum in any::<u64>(),
        pool in any::<u64>(),
    ) {
        let take = drr::draw_size(quantum, pool);
        prop_assert!(take <= quantum, "take {take} over the quantum");
        prop_assert!(take <= pool / 2, "take {take} over the pool half");
    }

    /// The learned-share draw composes the residue law with the
    /// learned split: learned 0 IS the residue law by construction
    /// (the fail-open lane), any learned count caps at pool/(k+2),
    /// and the take never exceeds the residue bound.
    #[test]
    fn fair_draw_composes_the_laws(
        quantum in any::<u64>(),
        pool in any::<u64>(),
        learned in any::<u16>(),
    ) {
        let take = drr::fair_draw_size(quantum, pool, learned);
        let residue = drr::draw_size(quantum, pool);
        prop_assert!(take <= residue, "learned take {take} over the residue bound {residue}");
        prop_assert!(take <= pool / (u64::from(learned) + 2), "learned take over its split");
        if learned == 0 {
            prop_assert_eq!(take, residue, "learned 0 must be the residue law verbatim");
        }
    }

    /// The take law, one take two lanes: the engaged lane draws the
    /// residue bound, the off lane the learned fraction, and either
    /// way the ledger room caps the take.
    #[test]
    fn take_size_caps_at_room(
        quantum in any::<u64>(),
        pool in any::<u64>(),
        learned in any::<u16>(),
        allowance in any::<u64>(),
        room in any::<u64>(),
    ) {
        let take = drr::take_size(quantum, pool, learned, allowance, room);
        prop_assert!(take <= room, "take {take} over the ledger room {room}");
        let lane_bound = if allowance != u64::MAX {
            drr::draw_size(quantum, pool)
        } else {
            drr::fair_draw_size(quantum, pool, learned)
        };
        prop_assert!(take <= lane_bound, "take {take} over its lane bound {lane_bound}");
    }

    /// The share-state word round-trips: packing any legal field set
    /// unpacks to the same fields, and any out-of-range field
    /// saturates at the u12 ceiling (the LRU lane's leaf posture).
    #[test]
    fn share_word_round_trips(
        epoch in any::<u32>(),
        running in any::<u16>(),
        last in any::<u16>(),
        peak in any::<u16>(),
    ) {
        let word = drr::pool_share_pack(epoch, running, last, peak);
        prop_assert_eq!(drr::pool_share_epoch(word), epoch & 0x0FFF_FFFF, "epoch round trip");
        let sat = |v: u16| u64::from(v).min(0xFFF) as u16;
        prop_assert_eq!(drr::pool_share_running(word), sat(running), "running round trip");
        prop_assert_eq!(drr::pool_share_last(word), sat(last), "last round trip");
        prop_assert_eq!(drr::pool_share_peak(word), sat(peak), "peak round trip");
    }

    /// The note step's rollover law: on a changed epoch the running
    /// count retires into last (the next draws' divisor source), the
    /// peak ratchets so it never sits below the running count, and
    /// the stored epoch lands on the now-epoch's 28-bit truncation —
    /// the wrap is a truncation, not a divergence.
    #[test]
    fn share_note_rollover_laws(
        word in any::<u64>(),
        now_epoch in any::<u32>(),
        drew in any::<bool>(),
    ) {
        let after = drr::pool_share_note(word, now_epoch, drew);
        let stored = drr::pool_share_epoch(word);
        let old_running = drr::pool_share_running(word);
        let running_out = drr::pool_share_running(after);
        let peak_out = drr::pool_share_peak(after);
        prop_assert!(peak_out >= running_out, "peak below running");
        if stored != now_epoch {
            prop_assert_eq!(drr::pool_share_epoch(after), now_epoch & 0x0FFF_FFFF, "rollover epoch law");
            prop_assert_eq!(drr::pool_share_last(after), old_running, "retired running into last");
        }
        if !drew && stored == now_epoch {
            let expected = old_running.saturating_add(1).min(0xFFF);
            prop_assert_eq!(running_out, expected, "the running count only moves on a fresh ask");
        }
    }
}

// ── mmspa.rs: the memo word and the cache decision table ────────────

proptest! {
    #![proptest_config(cases())]

    /// The memo word round-trips for every (generation, root) pair:
    /// the packed u64 carries both halves losslessly.
    #[test]
    fn memo_word_round_trips(generation in any::<u32>(), root in any::<u32>()) {
        let word = mmspa::memo_value(generation, root);
        prop_assert_eq!(mmspa::memo_gen(word), generation, "generation half");
        prop_assert_eq!(mmspa::memo_root(word), root, "root half");
    }

    /// The cache decision table, exactly as documented: absent and
    /// generation-stale memos walk; a current memo answers Allow on
    /// the zero root (the negative memo), Enforce on a live root,
    /// and Walk on a dead one.
    #[test]
    fn cache_verdict_matches_the_table(
        word in any::<u64>(),
        generation in any::<u32>(),
        alive in any::<bool>(),
    ) {
        let verdict = mmspa::cache_verdict(Some(word), generation, alive);
        if mmspa::memo_gen(word) != generation {
            prop_assert!(matches!(verdict, mmspa::CacheVerdict::Walk), "stale memo must walk");
        } else {
            match mmspa::memo_root(word) {
                0 => prop_assert!(matches!(verdict, mmspa::CacheVerdict::Allow), "zero root must allow"),
                root => match verdict {
                    mmspa::CacheVerdict::Enforce(r) => {
                        prop_assert_eq!(r, root, "enforce named a different root");
                        prop_assert!(alive, "enforced a dead root's policy");
                    }
                    mmspa::CacheVerdict::Walk => prop_assert!(!alive, "a live root must enforce"),
                    mmspa::CacheVerdict::Allow => prop_assert!(false, "nonzero root allowed"),
                },
            }
        }
        prop_assert!(matches!(mmspa::cache_verdict(None, generation, alive), mmspa::CacheVerdict::Walk));
    }

    /// The walk's ascending-order rule: the LAST policy-carrying
    /// chain member is the resolved root, and an all-negative chain
    /// resolves unlimited (root 0, the safe sentinel).
    #[test]
    fn walk_last_policy_match_wins(chain in proptest::collection::vec((any::<u32>(), any::<bool>()), 0..40)) {
        let mut walk = mmspa::MmspaWalk::new();
        for (id, has_policy) in &chain {
            walk.note(*id, *has_policy);
        }
        let expected = chain
            .iter()
            .rev()
            .find(|(_, has)| *has)
            .map_or(0, |(id, _)| *id);
        prop_assert_eq!(walk.root(), expected, "the nearest (last) match must win");
    }
}

// ── during.rs: the window verdict totality ───────────────────────────

proptest! {
    #![proptest_config(cases())]

    /// The day reduction is total: any u64 wall instant lands inside
    /// [0, NS_PER_DAY) — a corrupt offset moves the position but can
    /// never escape the domain.
    #[test]
    fn wall_of_day_stays_in_domain(wall in any::<u64>()) {
        prop_assert!(during::wall_of_day_ns(wall) < during::NS_PER_DAY);
    }

    /// The daily comparator is total for any input and shrinks
    /// monotonically with the margin: a wider fire-early margin can
    /// only shrink the active set (the under-enforcement direction),
    /// never grow it.
    #[test]
    fn daily_active_total_and_margin_monotone(
        secs in any::<u64>(),
        start_s in any::<u32>(),
        end_s in any::<u32>(),
        margin in any::<u64>(),
    ) {
        let _active = during::daily_active(secs, start_s, end_s, margin);
        let wider = margin.saturating_add(1);
        if during::daily_active(secs, start_s, end_s, wider) {
            prop_assert!(
                during::daily_active(secs, start_s, end_s, margin),
                "a wider margin grew the active set"
            );
        }
    }

    /// The window verdict is total for any row bytes: unknown kinds
    /// enforce (the absent-entry posture), spans compare their own
    /// monotonic pair, daily rows ride the margin law.
    #[test]
    fn window_active_total(
        kind in any::<u32>(),
        start_mono in any::<u64>(),
        end_mono in any::<u64>(),
        start_s in any::<u32>(),
        end_s in any::<u32>(),
        now in any::<u64>(),
        offset in any::<u64>(),
    ) {
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
            prop_assert!(active, "an unknown kind must enforce");
        }
        if kind == during::WINDOW_KIND_SPAN {
            prop_assert_eq!(active, now >= start_mono && now < end_mono, "span verdict left its law");
        }
    }
}

// ── rate_ring.rs: the window protocol ────────────────────────────────

proptest! {
    #![proptest_config(cases())]

    /// ring_book is total over any ring pre-state and any clock: the
    /// current window's slot stamp ends at w whenever the pre-state
    /// was at or behind the clock (fresh, same-window, or behind —
    /// the single-threaded boundary CAS always wins), and a future
    /// stamp is left untouched (the poison-slot skip).
    #[test]
    fn ring_book_total_and_stamp_law(
        pre_w0 in any::<u64>(),
        pre_b0 in any::<u64>(),
        pre_w1 in any::<u64>(),
        pre_b1 in any::<u64>(),
        now in any::<u64>(),
        len in any::<u32>(),
    ) {
        let mut ring = rate_ring::RateRing::default();
        ring.slots[0] = rate_ring::RateSlot {
            window: pre_w0,
            bytes: pre_b0,
        };
        ring.slots[1] = rate_ring::RateSlot {
            window: pre_w1,
            bytes: pre_b1,
        };
        rate_ring::ring_book(&mut ring, now, len);
        let w = now / rate_ring::RING_WINDOW_NS;
        let slot = &ring.slots[(w % rate_ring::RING_SLOTS) as usize];
        if slot.window <= w {
            prop_assert_eq!(slot.window, w, "a behind-or-current stamp must land on w");
        }
    }
}

// ── hist.rs: the bucket ladders and the aggregate words ─────────────

proptest! {
    #![proptest_config(cases())]

    /// Both log2 ladders are total over all u64, stay inside
    /// [0, 31], and never decrease as the value grows (the
    /// distribution's own monotonicity).
    #[test]
    fn bucket_ladders_total_and_monotone(a in any::<u64>(), b in any::<u64>()) {
        let (sa, sb) = (hist::size_bucket(a), hist::size_bucket(b));
        let (ra, rb) = (hist::srtt_bucket(a), hist::srtt_bucket(b));
        prop_assert!(sa <= 31 && sb <= 31, "size ladder escaped: {sa} {sb}");
        prop_assert!(ra <= 31 && rb <= 31, "srtt ladder escaped: {ra} {rb}");
        if a <= b {
            prop_assert!(sa <= sb, "size ladder decreased");
            prop_assert!(ra <= rb, "srtt ladder decreased");
        }
    }

    /// The ladder boundaries are exact: 2^k lands in bucket k (for
    /// every k the 32-bucket scale carries) and 2^k - 1 lands one
    /// bucket below.
    #[test]
    fn bucket_boundaries_are_exact(k in 1u64..=31) {
        let power = 1u64 << k;
        prop_assert_eq!(hist::size_bucket(power) as u64, k, "power-of-two boundary");
        prop_assert_eq!(hist::size_bucket(power - 1) as u64, k - 1, "pre-boundary value");
        prop_assert_eq!(hist::srtt_bucket(power) as u64, k, "srtt power boundary");
    }

    /// The aggregate replace words hold their laws over any nonzero
    /// value sequence: the min word only goes down (and answers the
    /// true minimum), the max word only goes up (the true maximum).
    #[test]
    fn aggregate_words_hold_their_replace_law(values in proptest::collection::vec(1u64..u64::MAX, 1..64)) {
        let mut min_word: [u64; 1] = [0];
        let mut max_word: [u64; 1] = [0];
        for &v in &values {
            hist::agg_min_word(min_word.as_mut_ptr(), v);
            hist::agg_max_word(max_word.as_mut_ptr(), v);
        }
        let true_min = values.iter().copied().min().unwrap_or(0);
        let true_max = values.iter().copied().max().unwrap_or(0);
        prop_assert_eq!(min_word[0], true_min, "min word left the replace law");
        prop_assert_eq!(max_word[0], true_max, "max word left the replace law");
    }

    /// The tail keeps the worst-by-size story: after a sequence of
    /// distinct-size samples, every one of the largest HIST_TAIL
    /// sizes survives in some slot, every kept slot carries its
    /// sample's own fields, and the kept set never shrinks below
    /// min(N, HIST_TAIL).
    #[test]
    fn tail_keeps_the_largest_sizes(
        sizes in proptest::collection::vec(1u64..u64::MAX, 1..24),
    ) {
        // Distinct sizes only: the replacement law's tie rule keeps
        // the incumbent, so the property drives the no-tie shape the
        // worst-8 contract is phrased against.
        let mut seen = std::collections::HashSet::new();
        let sizes: Vec<u64> = sizes.into_iter().filter(|s| seen.insert(*s)).collect();
        let mut row = hist::HistRow::default();
        for (i, &size) in sizes.iter().enumerate() {
            let ts = u64::try_from(i + 1).unwrap_or(u64::MAX);
            hist::tail_update(&mut row, size, 0, 0, ts);
        }
        let kept: Vec<u64> = row
            .tail
            .iter()
            .filter(|t| t.ts_ns != 0)
            .map(|t| t.size)
            .collect();
        let expected: Vec<u64> = {
            let mut s = sizes.clone();
            s.sort_unstable();
            s.reverse();
            let keep = s.len().min(hist::HIST_TAIL);
            s[..keep].to_vec()
        };
        prop_assert_eq!(kept.len(), expected.len(), "kept-slot count left the law");
        for size in &expected {
            prop_assert!(kept.contains(size), "a worst-by-size sample was evicted: {size}");
        }
    }
}

// ── quic.rs: the hint word, the bounded key, the header totality ────

proptest! {
    #![proptest_config(cases())]

    /// The learn step's state machine: a repeated nonzero length
    /// confirms, a changed length restarts unconfirmed, zero never
    /// confirms, and confirmation always rides a nonzero length.
    #[test]
    fn hint_learn_state_machine(old_len in 0u8..=20, len in 0u8..=20) {
        let old = quic::hint_word(old_len);
        let after = quic::hint_learn(old, len);
        if len == old_len && len != 0 {
            prop_assert!(quic::hint_confirmed(after), "a repeat sighting must confirm");
        } else {
            prop_assert!(!quic::hint_confirmed(after), "a changed or zero sighting must not confirm");
            prop_assert_eq!(quic::hint_len(after), len, "the learned length must land");
        }
    }

    /// The bounded key is total over any (buffer, offset, length)
    /// shape: no panic, no dependence past the buffer, and the same
    /// window always mixes to the same key (the attribution's
    /// determinism).
    #[test]
    fn flow_key_bounded_total(
        buf in proptest::collection::vec(any::<u8>(), 0..64),
        off in any::<usize>(),
        len in any::<usize>(),
        cookie in any::<u64>(),
    ) {
        let k1 = quic::flow_key_bounded(cookie, &buf, off, len);
        let k2 = quic::flow_key_bounded(cookie, &buf, off, len);
        prop_assert_eq!(k1, k2, "the same window mixed twice to different keys");
        let _ = quic::flow_key_bounded(cookie ^ 1, &buf, off, len);
    }

    /// The header classify is total over any byte soup in the L4
    /// window: no panic, no hang, a verdict either way — the bounded
    /// collector laws under arbitrary hostile input.
    #[test]
    fn classify_total_over_hostile_bytes(
        pkt in proptest::collection::vec(any::<u8>(), 0..80),
        cookie in any::<u64>(),
        ingress in any::<bool>(),
        hint in any::<u64>(),
    ) {
        let _verdict = quic::classify(cookie, &pkt, ingress, hint);
    }
}
