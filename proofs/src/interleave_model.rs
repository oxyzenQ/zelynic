// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! night-frontier-Z17 (the interleaving theorem): the two-CPU
//! segment model's STATE layer — the World (the shared words the
//! kernel runs, plus the proof-side shadow ledger), the invariant
//! laws P (the "no corrupt state" the theorem names), and the two
//! restated access twins the segment layer rides. The full design
//! record lives in this module's siblings: interleave_segments.rs
//! (the five verbs' segment machines), interleave_actors.rs (the
//! micro-step coroutine controllers), and the two instrument
//! files (kani_interleave.rs, interleave_laws.rs).
//!
//! THE PHYSICS, stated honestly. The kernel runs the five verbs —
//! the CAS draw, the refill, the debt pair, the generation belt,
//! the NOEXIST init — on words the map layer hands out as plain
//! shared memory; the concurrency protocol IS the RMW discipline
//! math_atomics.rs / ecn.rs carry. Every scheduling unit (the
//! SEGMENT) is one observation phase plus at most one RMW/write,
//! the granularity at which the kernel's verbs are actually
//! preemptible: a volatile read feeding a later CAS is its own
//! scheduling point, because the stale-observation window between
//! that read and its CAS is exactly the race the boost-38
//! discipline exists to survive. Segments call the ACTUAL
//! dual-compiled primitives (tokens_cas, tokens_fetch_add,
//! draw_stamp_take, gen_stamp_read / gen_stamp_write,
//! refill_credits) — the same bytes the kernel object builds. Two
//! restatements exist and are pinned, never hidden: ecn.rs's
//! private word_cas twin is restated here verbatim in shape, and
//! refill_window's inline RMWs ride the named primitives (the
//! window CAS is draw_stamp_take's compare_exchange on the same
//! field; ordering flags differ from the kernel's Relaxed
//! seed/cap CASes — value semantics in the sequentialized model,
//! no memory model is checked). The fidelity theorems prove the
//! machines reproduce the kernel functions' final state for ALL
//! inputs single-threaded; the property sampler hammers the same
//! equivalence per-push. The draw and belt machines' program
//! order mirrors drr_flow_draw.rs and drr_flow.rs — the
//! aya-touching halves, not includeable by this package's
//! core-only law, so their sequencing is pinned by the segment
//! bytes themselves plus the sampler, stated in the docs.
//!
//! THE THEOREM SHAPE (the Z12 lesson applied one tier up): "for
//! every CPU interleaving of the verbs on the same words" is
//! proved by INDUCTION over the schedule — a violation is a first
//! P-failing segment, so it suffices to machine-check that EVERY
//! segment preserves P from EVERY P-state. The single-step tier
//! quantifies over segments against arbitrary P-states — a
//! conservative over-approximation of the reachable schedule class
//! (it admits orders no verb's program order produces), so a
//! green single-step theorem covers the real coroutine schedules
//! a priori; the sampler exercises the coroutine-shaped schedules
//! directly, defense in depth.
//!
//! THE INVARIANT P, the "no corrupt state" the task names, six
//! laws over the World (the ledger is the exact conservation move):
//!
//!  * P1 (the ledger — no mint, no vanish): the token stock is
//!    accounted to the byte — every landed credit, every clamp or
//!    belt burn, every consume spend, every debt pay, and every
//!    draw half in flight sums back to the genesis stock. This is
//!    drr.rs's own headline ("DRR redistributes the budget, it
//!    cannot create one") as a machine-checked law, and it is the
//!    no-lost-refill / no-debt-double-pay lemma pair the budget
//!    core never had at the for-all tier.
//!  * P2 (the debt cap): the debt word never leaves
//!    [0, ECN_DEBT_CAP], under any charge or pay race.
//!  * P3 (the taint coherence): the leaf's tokens split exactly
//!    into live (credited while stamped current) and dead
//!    (credited or born while stamped stale).
//!  * P4 (the belt's dead law): a leaf stamped with the live
//!    generation holds zero dead tokens — the stale-quantum
//!    belt's own promise. Carried outright by the QUIET belt
//!    machine (the re-observing close, certified and unshippable —
//!    the live e2e lane priced its convergence); carried by the
//!    shipped GATED machine at the conservative tier with one
//!    NAMED residual (a racing draw's in-flight take inside the
//!    belt's write window, quantum-bounded — the two-word
//!    atomicity floor itself); the pre-patch ungated write's
//!    falsification is the finding the instrument filed, and the
//!    property tier's witnesses plus the ungated family's sampler
//!    statistic remain as its record.
//!  * P5 (the stamp bound): the leaf's generation stamp never
//!    exceeds max(hostile-genesis, live generation) — no
//!    inversion: belt writes only ever land a READING of the
//!    monotone live generation.
//!  * P6 (the fraction domain): the pool's fraction stays in its
//!    domain or untouched from hostile genesis — the v6
//!    sanitize-on-read law's write-side twin.

use crate::math_core::{Bucket, NS_PER_SEC, gen_stamp_read, tokens_read};

/// The model's frac-write twin (math.rs's private write_once,
/// restated verbatim in shape for the pool's fraction writes).
#[inline(always)]
pub fn word_write(word: &mut u64, v: u64) {
    let ptr = word as *mut u64;
    // SAFETY: the caller hands the model's own live, 8-aligned u64.
    unsafe { ptr.write_volatile(v) };
}

// THE DEBT WORD'S CAS DISCIPLINE: the model rides the math core's
// own tokens_cas over a Bucket-shaped view of the debt word —
// the identical compare_exchange (AcqRel / Acquire, the same
// arguments ecn.rs's private word_cas carries), through the SAME
// included bytes the kernel object builds for its bucket fields.
// The location-backed from_ptr form stays confined to the kernel
// crate's access primitives, the loom census's own law: the
// proofs tree keeps the census's zero-stray posture, and the
// fidelity theorems pin the debt pair's semantics to ecn.rs's
// own bytes on the same word.

// ── The World: the shared words plus the proof-side shadows ────────

/// The two-CPU world. The pool is the root-keyed bucket the refill
/// credits and the draws debit; the leaf is one leaf bucket under
/// it (draw stamps ride `last_refill_ns`, the generation belt
/// rides `frac_rem` — the field roles the kernel pins); the debt
/// word is the budget's ECN debt entry; `g_live` is the MMSPA
/// generation the policy mutations bump forward only. An unborn
/// leaf slot is the absent map entry — modeled as a zero bucket
/// the leaf-targeting segments fail open over (the kernel's own
/// get-or-create miss posture: no state change at all).
///
/// The shadow words are the MODEL's proof-side accounting — the
/// ledger P1 is an equation between the kernel-visible stock and
/// these counters, and every segment updates the pair atomically
/// together (one segment, one transition). The ledger shadows are
/// u128 on purpose: the accounting is exact over every schedule
/// length the induction covers, and the representability of the
/// REAL words is the stated domain of the theorem that needs it
/// (the kernel's own MAX_ENFORCABLE_BURST philosophy), never a
/// silent wrap inside the checker itself.
#[derive(Clone)]
pub struct World {
    pub pool: Bucket,
    pub leaf: Bucket,
    /// The budget's ECN debt word, in a Bucket view (the tokens
    /// field IS the word; the CAS rides math's own tokens_cas).
    pub debt: Bucket,
    pub g_live: u64,
    /// The leaf slot's map presence (the NOEXIST init verb's flag).
    pub born: bool,
    // ── the ledger shadows (u128: exact over unbounded schedules) ──
    /// Genesis pool stock (the P1 equation's anchor).
    pub pool0: u128,
    /// Genesis leaf stock, counted only once the slot is born.
    pub leaf0: u128,
    /// Sum of every landed refill credit (won-window fetch_adds).
    pub entered: u128,
    /// Sum of every clamp/cap/belt burn (tokens leaving the stock
    /// without a delivery or a pay).
    pub burned: u128,
    /// Sum of every successful consume deduction.
    pub spent: u128,
    /// Sum of every successful debt-pay token deduction.
    pub paid: u128,
    /// Draw halves debited from the pool but not yet credited to
    /// the leaf (the real in-flight window between the pool CAS
    /// and the leaf fetch_add).
    pub inflight: u128,
    // ── the belt-taint shadows (u64: bounded by the leaf's stock) ──
    /// Leaf tokens whose credit landed while the leaf was stamped
    /// with a generation other than the live one (plus the hostile
    /// genesis stock on a stale-stamped leaf) — the stale quanta.
    pub dead: u64,
    /// Leaf tokens credited while stamped current — the live pair.
    pub live: u64,
    /// Genesis leaf stamp (P5's anchor against hostile state).
    pub stamp0: u64,
    /// Genesis pool fraction (P6's anchor against hostile state).
    pub frac0: u64,
    /// Genesis debt word (P2's anchor against hostile state — a
    /// hostile stored word persists unread, never worsens).
    pub debt0: u64,
}

impl World {
    /// The debt word's plain read.
    pub fn debt_word(&self) -> u64 {
        self.debt.tokens
    }
}

impl World {
    /// A genesis world over arbitrary (hostile) kernel-visible
    /// state, with the shadows initialized coherently: the ledger
    /// anchors at the observed stock, the taint splits the leaf by
    /// its stamp against the live generation (a mismatched hostile
    /// stamp taints the whole stock dead — the conservative split
    /// the belt's law deserves), and an absent slot is the zero
    /// bucket it is.
    pub fn genesis(pool: Bucket, leaf: Bucket, debt: u64, g_live: u64, born: bool) -> World {
        let debt_bucket = Bucket {
            tokens: debt,
            last_refill_ns: 0,
            frac_rem: 0,
        };
        let leaf = if born {
            leaf
        } else {
            Bucket {
                tokens: 0,
                last_refill_ns: 0,
                frac_rem: 0,
            }
        };
        let stamp0 = gen_stamp_read(&leaf);
        let stock = tokens_read(&leaf);
        let (dead, live) = if stamp0 == g_live {
            (0, stock)
        } else {
            (stock, 0)
        };
        World {
            pool0: u128::from(tokens_read(&pool)),
            leaf0: u128::from(stock),
            entered: 0,
            burned: 0,
            spent: 0,
            paid: 0,
            inflight: 0,
            pool,
            leaf,
            debt: debt_bucket,
            g_live,
            born,
            dead,
            live,
            stamp0,
            frac0: pool.frac_rem,
            debt0: debt,
        }
    }

    /// P1: the exact conservation ledger. Every token is in the
    /// stock, in flight inside a draw, or accounted as spent, paid,
    /// or burned — and the total equals genesis plus every credit.
    pub fn ledger_ok(&self) -> bool {
        u128::from(self.pool.tokens)
            + u128::from(self.leaf.tokens)
            + self.inflight
            + self.spent
            + self.paid
            + self.burned
            == self.pool0 + self.leaf0 + self.entered
    }

    /// P2: the debt word inside its cap — or untouched from a
    /// hostile genesis (the v6 sanitize family's own posture one
    /// word over: a hostile stored value is never trusted into
    /// the arithmetic, and the guard keeps every written value
    /// under the cap).
    pub fn debt_capped(&self) -> bool {
        self.debt.tokens <= self.debt0.max(crate::ecn_core::ECN_DEBT_CAP)
    }

    /// P3: the taint split is exactly the leaf's stock.
    pub fn taint_coherent(&self) -> bool {
        self.dead + self.live == tokens_read(&self.leaf)
    }

    /// P4: the belt's dead law — a currently-stamped leaf holds no
    /// stale-budget tokens. The GENESIS CARVE-OUT, stated: a leaf
    /// whose stamp is still its hostile GENESIS value (no belt has
    /// fired since the map carried that state) is not certified —
    /// the belt's first firing on any packet while the stamp
    /// mismatches heals it (the standing clamp-convergence
    /// doctrine), and the mutation's catch-up corner (the live
    /// generation landing exactly on a hostile stored stamp while
    /// the leaf sat idle, no packet in between) is the carve-out's
    /// own class, named here instead of hidden. Every belt-touched
    /// state carries the full law.
    pub fn belt_dead_ok(&self) -> bool {
        let stamp = gen_stamp_read(&self.leaf);
        stamp != self.g_live || stamp == self.stamp0 || self.dead == 0
    }

    /// P5: the stamp bound — no inversion past the live generation
    /// or the hostile genesis value.
    pub fn stamp_bounded(&self) -> bool {
        gen_stamp_read(&self.leaf) <= self.stamp0.max(self.g_live)
    }

    /// P8: the stamp provenance — a stamp that ever MOVED is a belt
    /// write, and a belt write is a READING of the live generation
    /// (the mutation's catch-up corner closed at the law level:
    /// the live generation can only catch up to a stamp it could
    /// never have written, which is the genesis residue the belt
    /// has not healed yet — the carve-out P4 names). The law keeps
    /// the single-step tier's over-approximated pre-state space
    /// inside the stamp semantics the model's own verbs carry.
    pub fn stamp_provenance_ok(&self) -> bool {
        let stamp = gen_stamp_read(&self.leaf);
        stamp == self.stamp0 || stamp <= self.g_live
    }

    /// P6: the pool's fraction stays in domain or hostile-untouched.
    pub fn frac_ok(&self) -> bool {
        self.pool.frac_rem == self.frac0 || self.pool.frac_rem < NS_PER_SEC
    }

    /// P7: the absent leaf slot carries nothing — an unborn slot is
    /// the zero bucket it models (the map entry does not exist; the
    /// value the model's leaf field holds for it is the artifact,
    /// and this law keeps the artifact honest). The init's birth
    /// then moves no stock, by construction.
    pub fn absent_slot_ok(&self) -> bool {
        self.born || tokens_read(&self.leaf) == 0
    }

    /// The full invariant P minus P4 (the PRE-PATCH (ungated) belt's
    /// family — the falsification the finding filed rides the
    /// research doc and the property tier's witness record).
    pub fn laws_ok_except_dead(&self) -> bool {
        self.ledger_ok()
            && self.debt_capped()
            && self.taint_coherent()
            && self.stamp_bounded()
            && self.stamp_provenance_ok()
            && self.frac_ok()
            && self.absent_slot_ok()
    }

    /// The full invariant P including P4 (the shipped, gated belt's
    /// family since the gated landing).
    pub fn laws_ok(&self) -> bool {
        self.laws_ok_except_dead() && self.belt_dead_ok()
    }
}

/// Which bucket a leaf-side verb targets (the legacy lane spends
/// the pool-keyed bucket; the DRR lane spends the leaf).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Pool,
    Leaf,
}

/// The leaf slot's live borrow, fail-open on absence (the kernel's
/// own get-or-create miss posture: the packet allows, no state
/// change at all).
pub(super) fn leaf_or_fail(w: &mut World) -> Option<&mut Bucket> {
    match w.born {
        true => Some(&mut w.leaf),
        false => None,
    }
}

// ── The refill verb's segments (math.rs refill_window) ────────────

/// The window segment's outcome, carried by the verb's controller
/// (the credit segment consumes the armed pair).
#[derive(Clone, Copy)]
pub struct WindowOutcome {
    /// The window CAS landed: this actor owns [last, now].
    pub won: bool,
    /// The elapsed the winner will credit (the capped difference),
    /// valid when `won` and the forward branch held.
    pub elapsed: u64,
}

/// The credit segment's outcome, carried to the cap and frac
/// segments (the kernel's post-credit branch decision).
#[derive(Clone, Copy)]
pub struct CreditOutcome {
    /// The fetched-before-plus-credit exceeded the burst: the cap
    /// branch is armed (the kernel's saturating compare).
    pub cap_branch: bool,
    /// The new fraction the else-branch writes.
    pub new_frac: u64,
}
