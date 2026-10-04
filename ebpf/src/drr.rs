// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// The DRR (Deficit Round Robin) fair-share core,
// NIGHT-upgrade-charger-core-1-c: the pure arithmetic of the
// fair-shared bucket — the quantum sizing and the invariants the
// datapath (drr_flow.rs) and the userspace pins share. Extracted
// core-only (the math.rs / ammsp.rs discipline): zero aya/eBPF
// dependencies, so the SAME file compiles into the kernel object
// (ebpf/src/bin/limiter.rs wires it with #[path]) AND into the
// userspace test tree, where test/ebpf/limiter/drr_tests.rs pins it
// rootlessly.
//
// THE PROBLEM (the owner's starvation find): AMMSP gives a policy's
// whole subtree ONE shared budget — and a shared bucket is
// first-come-first-served at token granularity. One greedy leaf
// (a subprocess of the limited app) whose packets keep arriving can
// consume every token the instant it refills, starving its siblings
// indefinitely: cgroup /A at 100kb with subprocess #1 greedy means
// subprocesses #2..#100 get ~nothing, forever. No configuration,
// daemon, or enumeration can fix FCFS inside the hot path — the fix
// has to live in the datapath itself.
//
// THE DESIGN (quantum-fair sharing, DRR-shaped): the shared bucket
// becomes a POOL (refills at the policy rate, exactly as before),
// and every LEAF cgroup under the root gets its own small bucket
// that spends only tokens it DREW from the pool, in quanta:
//
//   * a packet is admitted from the LEAF's bucket, never the pool;
//   * an empty leaf draws min(quantum, HALF the pool) — the residue
//     law below — under a one-drawer-per-timestamp lock (the
//     window-ownership trick, applied to draws);
//   * the draw is a bounded CAS sequence — a lost race retries
//     against a fresh read, and a lost pool draw DROPS (the safe
//     verdict), never over-allows;
//   * the stamp is a DRAW LOCK, not pacing — paced draws (a quantum
//     per window) proved TCP-hostile on the CI daemon row (the
//     silent windows read as congestion and collapse the flow to
//     46% of configured), so the anti-hog cap is the holding bound
//     alone and a leaf re-draws the moment it empties;
//   * the pool never hands out what it does not have, so the
//     subtree's aggregate stays exactly the policy it had — DRR
//     redistributes the budget, it cannot create one.
//
// WHY THIS IS FAIR: a leaf holding a quantum stops touching the pool
// (its packets spend its own tokens), so the pool's next refills go
// to whichever leaf is empty and asking. Over any window, a greedy
// leaf's consumption is bounded by roughly one quantum plus its
// share of the refill — the starvation shape (one leaf at ~100%,
// the rest at ~0%) becomes a bounded-share shape. It is
// statistical, not a formal DRR guarantee: the formal version needs
// iteration over leaves (impossible in a cgroup_skb hot path), and
// the quantized version is the strongest fairness that fits the
// verifier's straight-line budget. The bound is honest and
// documented: any leaf can hold at most one quantum at a time (the
// draw-ownership stamp enforces it), so K equal-demand leaves share
// the refill within one quantum of slop.
//
// dinner-28, THE ORDER DEEPER (the live fair-share battery's find,
// every CI leg): the residue law above splits a TWO-asker pool
// evenly, but at K > 2 drawers the takes decay geometrically per
// position (50%/25%/12.5%... of the pool per ask), and the position
// is stable across epochs on a real hook — the worst leaf read
// 3.35x its fair share while the quietest starved below one admit,
// the aggregate staying exactly the policy the whole time. The
// close is the learned-share draw (below, v16): the take further
// capped by pool/(learned+2), the learned count kept per pool in
// the drr_pool_state maps. The v13 claims stand for K <= 2; the
// K > 2 claim is the learned law's, and the simulation battery
// (drr_share_tests) pins both sides of it.
//
// THE TRICKLE TRADEOFF (the GSO admit floor, on purpose): the
// quantum is floored at the 64 KiB super-packet floor
// (BURST_FLOOR_BYTES, NIGHT-lts-8's law) because a quantum below it
// could never admit the GSO/GRO super-packets the kernel hands the
// hooks — a leaf waiting to accumulate 64 KiB in 64-byte quanta
// would bar its own packets forever, the exact class the burst floor
// closed. At rates below ~640 KB/s the floor dominates the window's
// share (a 100kb policy's 100ms share is 10 KB, but the quantum
// stays 64 KiB), so fairness at trickle rates is coarse — leaves
// alternate on quantum boundaries (~0.64s at 100kb) instead of
// never at all. Coarse fairness beats starvation; the numbers are
// pinned so the tradeoff is a decision, not drift.
//
// This module must stay `core`-only: no std, no alloc, no aya — any
// dependency added here reaches both trees at once.

/// The GSO admit floor (the math.rs BURST_FLOOR_BYTES value, named
/// locally so this core stays standalone): the largest super-packet
/// the kernel hands a cgroup_skb hook by default.
pub const GSO_ADMIT_FLOOR: u64 = 65_536;

/// The fair-share window, in milliseconds: one quantum equals the
/// policy's rate over this window — the share a single leaf may draw
/// from the pool per draw. 100 ms is the owner's specced shape
/// ("sisa token leaf balik ke pool root setelah 1 window (misal
/// 100ms)"), reinterpreted as the quantum horizon: a leaf may hold
/// at most one window's share in flight, which bounds the greedy
/// advantage to one window plus whatever the starved siblings leave.
pub const DRR_WINDOW_MS: u64 = 100;

/// The fair-share window, in nanoseconds — the unit the pins hold
/// the window constant in (the datapath itself never converts: the
/// pacing that consumed it was removed, the CI ebpf-clippy lane
/// caught the orphan, and the const stays test-facing — the
/// walk_queries precedent).
#[cfg(test)]
pub const DRR_WINDOW_NS: u64 = DRR_WINDOW_MS * 1_000_000;

/// The draw admission (pure): the leaf's stamp holds its last draw
/// time — a reached-or-later clock admits. The stamp is the DRAW LOCK
/// (one drawer per leaf per timestamp, the window-ownership trick),
/// not a pacing mechanism: the CI daemon row proved paced draws hurt
/// TCP (a quantum staircase with silent windows reads as congestion
/// and collapses the flow — 46% of configured on the leg that
/// caught it), so the fairness work belongs to the residue law and
/// the holding cap alone, and a leaf re-draws the moment it empties
/// (the single-flow shape stays the legacy trickle).
#[inline(always)]
pub const fn draw_admitted(now: u64, last_draw: u64) -> bool {
    now >= last_draw
}

/// The per-draw quantum for a policy: the window's share of the
/// rate, floored at the GSO admit floor. Pure — the datapath calls
/// it per draw, the pins hold it to its bounds.
///
/// The floor is the correctness half (see the module header): a
/// quantum below the largest super-packet the hook ever sees could
/// never admit that packet class, barring a leaf's own data forever.
/// The `rate / 10` shape is `rate x WINDOW / 1000` in integer math.
#[inline(always)]
pub const fn quantum(rate_bps: u64) -> u64 {
    let share = rate_bps / (1000 / DRR_WINDOW_MS);
    if share > GSO_ADMIT_FLOOR {
        share
    } else {
        GSO_ADMIT_FLOOR
    }
}

/// The residue law (the starved regime's fairness): a draw takes at
/// most HALF the visible pool — never all of it. Without the half,
/// the first asker at each instant captures everything that
/// accumulated and the second starves (the simulation pinned the
/// shape at 95/4 before this law); with it, an interleaved asker
/// pair splits the continuous refill stream ~evenly, because every
/// draw leaves the other half for whoever asks next. The quantum cap
/// still binds (the stockpile bound), and a single active leaf is
/// untouched in throughput: its half-draws pace at the refill rate,
/// one step of latency apart.
#[inline(always)]
pub const fn draw_size(quantum: u64, pool_tokens: u64) -> u64 {
    let pool_half = pool_tokens / 2;
    if quantum < pool_half {
        quantum
    } else {
        pool_half
    }
}

/// The worst in-flight over-allow one leaf can hold: one quantum
/// (the draw-ownership stamp makes a second concurrent draw for the
/// same leaf wait for the clock) plus the packet that triggered it —
/// the bound the fairness guarantee is phrased against, and the
/// number a stale-quantum zeroing is bounded by on the other side.
/// Test-facing by design (the walk_queries precedent): the datapath
/// needs no bound, the documentation and the pins do — cfg(test)
/// keeps the ebpf release build free of the dead symbol a clippy
/// -D warnings run rejects.
#[cfg(test)]
#[inline(always)]
pub const fn leaf_inflight_bound(rate_bps: u64) -> u64 {
    quantum(rate_bps).saturating_add(GSO_ADMIT_FLOOR)
}

// ── The learned-share draw (dinner-28) ────────────────────────────────
//
// THE FIND the live battery filed (supermassive fair-share, all four
// CI legs): the residue law splits a TWO-asker pool evenly — every
// draw leaves half for whoever asks next — but across K > 2
// successive drawers the takes decay geometrically: the first asker
// of each epoch takes half the pool, the second half of the rest
// (25%), the third 12.5% ... the K-th (1/2)^K of the pool. The
// measured CI shape at 6 leaves / 1mb: the worst leaf read 2.13 MB
// over 4s (the first-drawer's 500 KB/s share, 3.35x the fair share)
// while the quietest accumulated ~60 KB in 40 epochs — one GRO admit
// short of 64 KiB — and never admitted a single packet (78 B). The
// pool law held exactly (0.95x of policy — the aggregate was always
// right); only the DISTRIBUTION was broken. The v13 pins simulated
// K=2 only (the alternating pair), so the decay class was never
// covered: the pins' own precedent — the 95/4 FCFS shape was found
// by simulation, and this class is one order deeper.
//
// THE LAW: the draw take is the residue law's bound FURTHER capped
// by the quantum's fair split across a LEARNED drawee count — the
// number of distinct leaves that drew in the last completed 100ms
// epoch, kept per (pool, direction) in a packed state word (the
// repair-4 packing — the askers' PEAK joined the word):
//
//   bits  0..11 : last     — the distinct-drawee count of the last
//                           COMPLETED epoch (the take divisor source)
//   bits 12..23 : running  — the distinct-drawee count of the
//                           CURRENT epoch
//   bits 24..35 : peak     — the decaying HIGH-WATER of drawees (the
//                           allowance divisor source, repair-4)
//   bits 36..63 : epoch    — now / DRR_WINDOW_MS, 28 bits (an 8.5
//                           year horizon; the wrap fires one benign
//                           rollover)
//
// A learned count of 0 (a cold pool, the first 100ms) keeps the
// exact v13 shape — fair_draw_size(q, pool, 0) is draw_size by
// construction — and from the first rollover on, the first asker of
// an epoch is capped at quantum/(K+1) like every other drawer: the
// monopoly position itself stops paying. The count is an ESTIMATE
// (concurrent notes may lose one increment, a failed-draw epoch
// under-counts its starved askers): the divisor's slack absorbs it —
// the bounds the battery judges (1.75x fair + one quantum, and
// fair/4 for the quietest) are met with margin in the simulation
// pin, which reproduces the CI decay first and the close second.
//
// repair-4, THE PEAK (the divisor that does not kneel to silence):
// the live battery's second find — the worst leaf read 4.7x fair on
// the many24 leg with the anti-monopoly bound blown wide — because
// the starved leaves back off to retransmit timers and STOP ASKING,
// so `last` (the asker count) collapses toward the few survivors
// and an allowance split across the ASKERS inflates fourfold for
// exactly the leaves already winning. The peak field is the close:
// a high-water of drawees that ratchets on every count and decays
// one step every PEAK_DECAY_EPOCHS rollovers (a dead leaf's share
// releases in seconds; a starved leaf's protection outlives its
// retransmit timers), so the allowance divisor tracks the pool's
// DEMAND, not its momentary silence. The u12 fields cap at 4095 —
// the LRU lane's own leaf ceiling — and every cap is saturating.

/// The epoch length in ns for the share state (the DRR window).
#[inline(always)]
pub const fn share_epoch_ns() -> u64 {
    DRR_WINDOW_MS * 1_000_000
}

/// The peak's decay period (epochs per decay step): a starved
/// leaf's retransmit cadence spans up to four epochs, so a decay
/// this slow protects it through its silence while a dead leaf's
/// share still releases inside ~8 x peak epochs.
pub const PEAK_DECAY_EPOCHS: u32 = 8;

/// The u12 field ceiling (the LRU lane's 4096-leaf posture).
const SHARE_FIELD_MAX: u16 = 0xFFF;

/// Unpack the state word's epoch (bits 36..63, 28 bits).
#[inline(always)]
pub const fn pool_share_epoch(word: u64) -> u32 {
    ((word >> 36) & 0x0FFF_FFFF) as u32
}

/// Unpack the running distinct-drawee count (bits 12..23).
#[inline(always)]
pub const fn pool_share_running(word: u64) -> u16 {
    ((word >> 12) & 0xFFF) as u16
}

/// Unpack the learned divisor source: the last completed epoch's
/// distinct-drawee count (bits 0..11).
#[inline(always)]
pub const fn pool_share_last(word: u64) -> u16 {
    (word & 0xFFF) as u16
}

/// Unpack the demand high-water (bits 24..35): the decaying peak of
/// drawees the epoch allowance splits across (repair-4).
#[inline(always)]
pub const fn pool_share_peak(word: u64) -> u16 {
    ((word >> 24) & 0xFFF) as u16
}

/// Pack the state word (all fields saturating at the u12 ceiling).
#[inline(always)]
pub const fn pool_share_pack(epoch: u32, running: u16, last: u16, peak: u16) -> u64 {
    let epoch_bits = (epoch & 0x0FFF_FFFF) as u64;
    let peak_bits = if peak > SHARE_FIELD_MAX {
        SHARE_FIELD_MAX as u64
    } else {
        peak as u64
    };
    let running_bits = if running > SHARE_FIELD_MAX {
        SHARE_FIELD_MAX as u64
    } else {
        running as u64
    };
    let last_bits = if last > SHARE_FIELD_MAX {
        SHARE_FIELD_MAX as u64
    } else {
        last as u64
    };
    (epoch_bits << 36) | (peak_bits << 24) | (running_bits << 12) | last_bits
}

/// The rollover + count step (pure, the same math the datapath's
/// atomics and the simulation's plain stores run): given the current
/// word, the now-epoch, and whether THIS leaf already drew in the
/// current epoch, return the updated word. A rollover at an epoch
/// boundary retires the epoch's running count into `last` — the
/// divisor the next epoch's draws read — ratchets the running count
/// into `peak`, then decays the peak one step on the decay cadence
/// (the LIVE ratchet below keeps a mid-epoch surge counted too).
#[inline(always)]
pub const fn pool_share_note(word: u64, now_epoch: u32, leaf_drew_this_epoch: bool) -> u64 {
    let mut epoch = pool_share_epoch(word);
    let mut running = pool_share_running(word);
    let mut last = pool_share_last(word);
    let mut peak = pool_share_peak(word);
    if epoch != now_epoch {
        last = running;
        if running > peak {
            peak = running;
        }
        if peak > 1 && now_epoch.is_multiple_of(PEAK_DECAY_EPOCHS) {
            peak -= 1;
        }
        running = 0;
        epoch = now_epoch & 0x0FFF_FFFF;
    }
    if !leaf_drew_this_epoch {
        running = running.saturating_add(1);
    }
    if running > peak {
        peak = running;
    }
    pool_share_pack(epoch, running, last, peak)
}

/// The learned-share draw (the new law, dinner-28): the residue
/// law's bound further capped by the POOL's fair split across the
/// learned drawee count — pool/(learned+2), not quantum/(learned+1):
/// the cap must bind at the micro scale, where the pool holds only
/// the refill since the last drain (hundreds of bytes at a 200us
/// offer cadence — a quantum-scaled cap sits forty times above the
/// binding constraint there and never engages; the simulation pin
/// caught that too). At learned+2 the arithmetic keeps every case
/// honest: learned 0 (a cold pool, a missed state lookup) is
/// pool/2 — the EXACT v13 residue law by construction, the fail-open
/// lane; learned 1 (a single active leaf) is pool/3 — smaller takes,
/// the same throughput (the lone leaf re-draws freely); learned K is
/// pool/(K+2) — a flat split whose position ratio is
/// (1-1/(K+2))^(K-1), 1.34 at K=6 and 1.18 at K=24, both far inside
/// the battery's 1.75x bound. The order-dependence the residue law
/// owned at K>2 (geometric decay across positions) is gone by
/// construction: every drawer takes the same fraction of a pool the
/// previous drawers barely dented.
#[inline(always)]
pub const fn fair_draw_size(quantum: u64, pool_tokens: u64, learned: u16) -> u64 {
    // The naming is load-bearing, not decoration: the file is
    // formatted by BOTH trees' rustfmt (the root reaches it through
    // the test tree's #[path] includes, the ebpf crate formats it
    // natively), and the two toolchains disagree on collapsing a
    // short if-else into one line — the nightly collapses under its
    // single-line width cap, the stable expands. draw_size stayed
    // stable through the whole DRR era because its statement runs
    // past the cap; these names put this statement past it too (the
    // compact one-liner and the trait method — Ord::min is not const
    // on the ebpf toolchain, E0658 — each fail a gate on one side).
    let residue_law_take = draw_size(quantum, pool_tokens);
    let learned_share_take = pool_tokens / (learned as u64 + 2);
    if residue_law_take < learned_share_take {
        residue_law_take
    } else {
        learned_share_take
    }
}

/// The draw take law, one take two lanes (repair-7, the catch-up
/// drawer's close): the ENGAGED lane (allowance != u64::MAX — the
/// drawee peak >= 2) draws the residue law bounded by its ledger
/// ROOM; the OFF lane (a lone drawer, a cold pool, a missed state
/// lookup) keeps the v16 learned-share fraction verbatim.
///
/// WHY THE FRACTION RETIRES FROM THE ENGAGED LANE: it splits the
/// current refill per take — a bound the ledger's per-EPOCH room
/// already owns — and its arithmetic starves exactly the catch-up
/// drawer. A leaf asking after N silent epochs faces a pool holding
/// the UNCLAIMED residue (the fast drawers are room-blocked), yet
/// its take is pool/(K+2), a fraction that reaches the 64 KiB GSO
/// admit floor only when the pool holds (K+2) x 64 KiB — 1.7 MB at
/// K=24, against a residue that accumulates at refill/K per epoch
/// (under 0.7 MB across a 4 s window). The starved leaf banks under
/// one admit forever: the live battery's 78 B quietest (best-specs,
/// every v17 run) is this arithmetic. Under the repair-7 law the
/// same draw takes pool/2 bounded by the room — the leaf's OWN
/// earned right (the carry plus the elapsed allowances, capped at
/// the quantum) — banks the admit, and its TCP heals on it. The
/// monopoly bound never moves: a hot drawer's take is the room
/// (its per-epoch allowance), the same edge v17 held; the pool
/// keeps half for the next asker; the pool CAS keeps the budget.
#[inline(always)]
pub const fn take_size(
    quantum: u64,
    pool_tokens: u64,
    learned: u16,
    allowance: u64,
    room: u64,
) -> u64 {
    // The tail-statement naming is the fair_draw_size lesson's own
    // discipline, once more: this if-else in tail position is the
    // exact shape the two trees' rustfmt disagree on when its
    // one-line form fits the nightly's single-line cap (the stable
    // expands, the nightly collapses) — these names run the
    // one-line form past the cap, so both trees keep it expanded
    // (and clippy's let_and_return stays quiet: the direct return).
    let take_under_the_lane_law = if allowance != u64::MAX {
        draw_size(quantum, pool_tokens)
    } else {
        fair_draw_size(quantum, pool_tokens, learned)
    };
    if take_under_the_lane_law < room {
        take_under_the_lane_law
    } else {
        room
    }
}

// ── The epoch ledger (repair-3/4, v17) ────────────────────────────────
//
// THE FIND, live on every CI leg (the improve-1b battery's red era):
// the learned-share cap above bounds each DRAW's take — but a leaf's
// draw frequency is its packet rate, and that rate is TCP feedback.
// The flow that admits grows its window and offers more packets
// (every one a draw); the starved flows back off to retransmit
// timers. The battery's measured shape at 6 leaves / 1mb / 4s: the
// worst leaf read 4.7x its fair share while the quietest measured
// ONE admit (65536 + 78 B over the whole window) — the pool's credit
// stream went to the only drawer still fast enough to ask. Three
// compounding defects, each reproduced by the feedback simulation
// in drr_ledger_tests.rs before the law that closed it was written:
//
//  1. the share-state NOTE raced: a plain read plus a BPF_ANY insert
//     means concurrent notes clobber each other's increments, the
//     learned count converged to 1-3, and the cap weakened back to
//     the v13 residue shape (the sim with a racy count reproduces the
//     quietest leaf's single admit exactly);
//  2. even with a PERFECT count, a per-take cap cannot bound a
//     per-EPOCH share: one drawer drawing on every packet drains the
//     pool through (K+2)-sized bites — the geometric decay the residue
//     law owned at take granularity, back at stream granularity;
//  3. an allowance split across the ASKERS inflates for the
//     survivors the moment the starved go quiet (the asker count IS
//     the silence): the many24 leg read worst 4.7x fair with the
//     count at ~6 of 24 — the peak field above is this close.
//
// THE LAW (the epoch ledger, the carry form): each leaf banks an
// ALLOWANCE of the pool's per-epoch refill split across the drawee
// peak — earned at `epoch_refill / drawees` per 100ms epoch, held as
// a CARRY in one packed u64 per leaf (the drr_leaf_state maps, the
// leaf_bucket posture), spent only by draws, and capped at one
// QUANTUM of unspent credit:
//
//   bits 32..63 : epoch  — the epoch the carry was last credited at
//   bits  0..31 : carry  — the banked, unspent allowance (bytes)
//
// The quantum cap is the v13 doc's own stockpile sentence made real
// ("a leaf may hold at most one quantum at a time"): a starved leaf
// banks several epochs' allowance for ONE fat admit — the 64 KiB GSO
// admit floor demands it, its TCP heals on the admit, its cadence
// recovers, and the aggregate floor (the battery's 65% band, which
// the blocking form of this ledger sagged under) comes back with
// it. The worst leaf's windowed total stays inside the battery's
// 1.75x-fair-plus-one-quantum bound by construction: the earn rate
// IS the fair split, and the stockpile IS the quantum. The lone
// drawer keeps the whole budget (drawees < 2 leaves the ledger OFF
// — the single-active row's own lo bound); a state-map miss or a
// cold pool fails open onto the v16 law exactly as dinner-28 did.

/// The pool's refill over one fair-share epoch (pure): the rate's
/// 100ms share — the budget the epoch ledger splits. The quantum's
/// share term before the GSO floor applies (quantum floors at the
/// admit packet size; the refill never does).
#[inline(always)]
pub const fn epoch_refill(rate_bps: u64) -> u64 {
    rate_bps / (1000 / DRR_WINDOW_MS)
}

/// The epoch ledger's earn rate (the v17 law, pure): the pool's
/// per-epoch refill split across the drawee count — the PEAK (the
/// decaying high-water), never the momentary asker count, so the
/// allowance does not inflate when starved siblings go quiet. A
/// drawee count of 0 or 1 keeps the ledger OFF — a cold pool or a
/// missed state lookup fails open onto the v16 law (never throttles
/// a packet the laws below permit), and a lone leaf must see the
/// whole budget: the battery's single-active row measures >= 80% of
/// policy, and an allowance of refill/1 never binds a leaf whose
/// takes are already pool-fraction bounded.
#[inline(always)]
pub const fn epoch_allowance(rate_bps: u64, drawees: u16) -> u64 {
    if drawees < 2 {
        return u64::MAX;
    }
    epoch_refill(rate_bps) / drawees as u64
}

/// Pack the leaf-ledger word (epoch high, carry low).
#[inline(always)]
pub const fn ledger_pack(epoch: u32, carry: u32) -> u64 {
    ((epoch as u64) << 32) | carry as u64
}

/// Unpack the ledger word's epoch (bits 32..63): the epoch the
/// carry was last credited at.
#[inline(always)]
pub const fn ledger_epoch(word: u64) -> u32 {
    (word >> 32) as u32
}

/// Unpack the ledger word's banked carry (bits 0..31): the leaf's
/// unspent allowance, already capped at the quantum by the credit.
#[inline(always)]
pub const fn ledger_carry(word: u64) -> u32 {
    (word & 0xFFFF_FFFF) as u32
}

/// The elapsed-epoch ceiling for the carry's earning step: beyond it
/// the product below could only come from the u32 epoch wrap (13.7
/// years of 100ms epochs), and the credit saturates at the full
/// stockpile cap instead — one epoch's worth of coarseness per
/// decade, in the safe direction. The value keeps the plain multiply
/// overflow-free by construction (see ledger_room).
pub const ELAPSED_CEILING: u32 = 1 << 24;

/// The carry's earning step (pure): credit the epochs elapsed since
/// the word's epoch at the allowance, capped at the stockpile cap
/// (the quantum — the v13 stockpile bound). The multiply is PLAIN,
/// overflow-safe by construction the math.rs fill_ns way: bounds,
/// not libcall checks — saturating_mul lowers to the 128-bit
/// __multi3 libcall, which the BPF ISA does not carry and the aya
/// loader refuses to relocate (the repair-4 CI find: "function
/// 0x2190 not found while relocating enforce_dl", ten dead sites
/// from one inlined call). The bound: the allowance is at most half
/// the 1tb ladder's refill (5e10), 2^24 epochs of it stays two
/// orders under u64's ceiling, and the carry is at most one quantum
/// (1e8) — the sum cannot wrap. The stockpile naming is the
/// fair_draw_size lesson: a short if-else here collapses under the
/// ebpf nightly's single-line cap and expands under stable — these
/// names run past it, both greens.
#[inline(always)]
pub const fn ledger_room(word: u64, now_epoch: u32, allowance: u64, stockpile_cap: u64) -> u64 {
    let elapsed_epochs = now_epoch.wrapping_sub(ledger_epoch(word));
    let earned_stockpile = if elapsed_epochs > ELAPSED_CEILING {
        stockpile_cap
    } else {
        allowance * elapsed_epochs as u64 + ledger_carry(word) as u64
    };
    if earned_stockpile > stockpile_cap {
        stockpile_cap
    } else {
        earned_stockpile
    }
}

/// The carry's credit-then-spend step (pure): the room above minus
/// the take (never below zero — a take larger than the room is a
/// caller bug the saturating form forgives once), re-anchored at
/// the now-epoch. The datapath computes the room, sizes the take
/// inside it, and writes this word through one CAS — the credit and
/// the spend land together or not at all.
#[inline(always)]
pub const fn ledger_note(
    word: u64,
    now_epoch: u32,
    allowance: u64,
    stockpile_cap: u64,
    take: u64,
) -> u64 {
    let room = ledger_room(word, now_epoch, allowance, stockpile_cap);
    let spent = if take > room { room } else { take };
    ledger_pack(now_epoch, (room - spent) as u32)
}

// ── The flow lane (schema v20, CAKE-shaped isolation) ────────────────
//
// THE FIND (the owner's private-research-4 close of the DRR arc,
// measured rootlessly before any kernel saw the lane): the
// v13/v16/v17 laws made the LEAF fair — no cgroup under a policy can
// starve its siblings — but the leaf bucket itself is still shared by
// every socket the cgroup holds, and a shared bucket is FCFS at
// packet granularity. The rootless isolation battery (cake_isolation_
// tests.rs) reproduced the race's honest shape: the victims are the
// WEAKER DEMANDERS — a second download measured 524 KB of its 1.5 MB
// fair share under the shared leaf (2.9:1 against the first, and the
// three-flow shape breaks the battery's own anti-monopoly bound,
// 2.1x fair) — while the truly quiet flows (a DNS-shaped 200-byte
// query per epoch) ride the GRO-granularity banking's leftover
// crumbs and admit either way. The monopoly the pool arc closed at
// the leaf, alive inside it, one level deeper — the aggregate
// exactly the policy the whole time.
//
// THE DESIGN (CAKE-shaped, one level down — the deficit idiom the
// cake qdisc made standard, carried into a policer that cannot
// queue): the leaf becomes a small POOL for its own sockets, and
// every attributed packet spends from a per-FLOW bucket keyed by
// the socket cookie the hook already names (bpf_get_socket_cookie,
// the observer's own join, no new helper). A flow that empties
// draws from the leaf under the DRR laws mirrored one level down —
// the learned flow count, the drawee PEAK, the epoch ledger with
// its quantum-capped carry — so the bulk flow blocks at its fair
// share of the leaf's own throughput, the refills accumulate behind
// the block, and the quiet flow's rare draws find a rich leaf: the
// repair-3 story, told again at the scale the starved actually live.
//
// THE SPARSE/DENSE DISTINCTION (the CAKE signature, in the only
// form a policer can carry): a queue's scheduler serves sparse
// flows FIRST; a policer's only lever is the take law, so the
// distinction lands there — a flow whose last draw sits in a PAST
// epoch (measured on the flow bucket's own draw stamp, the word
// every draw CASes whether the ledger is on or off) is sparse, and
// its draw takes its packet's own bytes (the reserved small
// quantum: the interactive flow's 200-byte query draws exactly 200,
// admits on the first offer, and never strands a 64 KiB stockpile
// in a bucket the LRU may age out before it spends); a flow that
// already drew this epoch is dense, and its draw takes the full
// quantum (the bulk cadence amortizes the draw cost — a draw per
// packet would CAS the share word per packet). The stamp is
// SELF-CORRECTING on the shapes a ledger-anchored test would miss:
// a lone bulk flow of small packets (the ledger is off, the word
// never anchors) still reads dense the moment its draws cluster
// inside an epoch — its own frequency classifies it — and a
// starved flow's recovery draw rides the dense take it needs for
// the fat admit its TCP heals on (the repair-4 banking story, one
// level down). Both lanes cap by ROOM (the dense flow's remaining
// allowance; the sparse flow's banked carry) and by what the leaf
// HOLDS (the conservation edge — the flow lane moves what the leaf
// has, never more), and both stay under one quantum: the stockpile
// bound holds for sparse and dense alike.
//
// The residue law's halving deliberately does NOT recur at this
// level: at the pool the half-split keeps a share of the REFILL
// stream for the next asker because takes are quantum-sized against
// a stream that trickles; at the leaf the room law owns the split
// (each flow's take is its own allowance remainder) and the leaf's
// own content is itself ledger-bounded — the halving would only
// bind in the allowance-OFF lane, where a lone flow has no sibling
// to protect. The cascade keeps its conservation anyway: pool ->
// leaf -> flow moves bytes only through sufficiency-verified CAS,
// so the aggregate stays exactly the policy, one level deeper.
//
// The flow ledger rides the RAW cookie (a u64 the generation
// prefix cannot carry without collisions — the repair-6 keying
// assumes 32-bit ids), so a mutated budget's successor inherits at
// most one quantum of carry, availability-capped by the fresh
// leaf's own tokens: the bounded residue the repair-6 re-key exists
// to avoid at the DIVISOR scale, where the damage compounds across
// epochs. The flow SHARE word (per-leaf, leaf ids fit) keeps the
// full generation prefix — a fresh budget learns a fresh flow
// count. The flow BUCKET wears the generation belt on frac_rem,
// the leaf bucket's own trick.

/// The flow-level epoch budget (pure): the throughput share the LEAF
/// itself earns at the pool, that its flows split among themselves.
/// The lone leaf (drawees < 2 at the pool) earns the WHOLE refill —
/// its whole-budget row; an engaged leaf earns the refill split
/// across its drawee peak — the allowance law's own divisor, one
/// level up from where the flow lane reads it.
#[inline(always)]
pub const fn flow_leaf_budget(rate_bps: u64, leaf_drawees: u16) -> u64 {
    if leaf_drawees < 2 {
        epoch_refill(rate_bps)
    } else {
        epoch_refill(rate_bps) / leaf_drawees as u64
    }
}

/// The flow allowance (the epoch_allowance law one level down,
/// pure): the leaf's budget split across the flow drawee PEAK. A
/// count of 0 or 1 keeps the ledger OFF — a cold leaf's first flows
/// fail open onto the availability-capped take, and a lone flow
/// must see the leaf's whole content (the single-active row's own
/// lo bound, mirrored).
#[inline(always)]
pub const fn flow_allowance(leaf_budget: u64, flow_drawees: u16) -> u64 {
    if flow_drawees < 2 {
        u64::MAX
    } else {
        leaf_budget / flow_drawees as u64
    }
}

/// The sparse test (pure): a flow whose last draw sits in a PAST
/// epoch — the stamp every draw CASes (success or rollback) is the
/// evidence, at zero extra state, and it classifies by the flow's
/// own draw FREQUENCY: a flow that draws faster than an epoch is
/// dense by its own cadence, whatever its ledger state, and a flow
/// quiet for an epoch is sparse however fat its banked carry. The
/// share note consumes the same fact as drew-this-epoch.
#[inline(always)]
pub const fn flow_is_sparse(last_draw_ns: u64, now_ns: u64) -> bool {
    (last_draw_ns / share_epoch_ns()) as u32 != (now_ns / share_epoch_ns()) as u32
}

/// The flow take (the v20 law, pure — take_size's structure, one
/// level down): what one flow draw may move leaf -> flow. The LANE
/// LAW sizes the take's shape: SPARSE draws its packet's own bytes
/// (the reserved small quantum — demand-sized, admitting on the
/// first offer); DENSE draws the quantum (amortizing the draw over
/// the bulk cadence). The TWO-LANE BOUND is take_size's own, mirrored:
/// the ENGAGED lane (allowance != MAX) bounds the take by its ledger
/// ROOM (the carry law: the dense flow's remaining allowance, the
/// sparse flow's banked stockpile); the OFF lane (a lone flow, a
/// cold count, the share word's decay transient) bounds it by the
/// learned-share FRACTION of the leaf — leaf/(learned+2), never the
/// whole leaf. The fraction bound is load-bearing, not decoration:
/// the share word's PEAK decays a step every eight quiet epochs, and
/// for the epochs between the decay and the next re-ratchet the
/// allowance reads MAX — a take bound only by the lane law there
/// would drain the leaf whole, once per transient epoch, and the
/// isolation would leak its own divisor's decay (the rootless sim's
/// second catch: the bulk rode the transient to half again its
/// allowance). The fraction keeps the OFF lane exactly as honest as
/// the pool's own OFF lane, and a lone flow keeps its throughput —
/// its fraction draws pace at the leaf's refill, one step of latency
/// apart, the v13/v16 lone-drawer row verbatim. Both lanes cap by
/// the leaf's tokens (availability — the conservation edge), and the
/// GSO admit floor keeps the quantum at or above every packet the
/// hook ever sees, so a dense take can always admit the packet that
/// triggered it whenever room and leaf allow — and a sparse take IS
/// the packet.
///
/// The naming is load-bearing, the fair_draw_size lesson once more:
/// this statement must survive BOTH trees' rustfmt without a
/// one-line/expanded disagreement — the named locals run the
/// collapsed form past the nightly's single-line cap.
#[inline(always)]
pub const fn flow_take(
    sparse: bool,
    pkt_len: u32,
    quantum: u64,
    learned: u16,
    allowance: u64,
    room: u64,
    leaf_tokens: u64,
) -> u64 {
    let demand_sized_take = pkt_len as u64;
    let bulk_sized_take = quantum;
    let take_under_the_lane_law = if sparse {
        demand_sized_take
    } else {
        bulk_sized_take
    };
    let take_within_the_room = if take_under_the_lane_law < room {
        take_under_the_lane_law
    } else {
        room
    };
    let learned_share_fraction = leaf_tokens / (learned as u64 + 2);
    let take_within_the_off_lane = if take_under_the_lane_law < learned_share_fraction {
        take_under_the_lane_law
    } else {
        learned_share_fraction
    };
    let take_under_the_bound_law = if allowance != u64::MAX {
        take_within_the_room
    } else {
        take_within_the_off_lane
    };
    // THE SOURCE BUFFER LAW (the CI battery's catch, the third
    // design lesson this lane paid for): a dense take never drains
    // the leaf WHOLE — its availability cap is HALF the leaf, the
    // residue law mirrored at the scale it was always meant for.
    // At the pool the half-split keeps a share of the refill
    // stream for the next asker; at the leaf it keeps something
    // subtler and just as load-bearing: the leaf's BUFFER. The
    // leaf bucket was designed to ride HIGH — its spends are
    // packet-sized, its draws are quantum-sized, so it accumulates
    // between draws and the pool's micro-credit oscillation never
    // reaches an admit decision. A whole-leaf dense take breaks
    // that: the leaf rides at ~0, every packet's admit rides the
    // pool's instantaneous credit, and the oscillation's troughs
    // read as drops — the live battery measured 1411 packets
    // dropped under a NON-BINDING 12 GB/s policy (zero before the
    // lane, zero is the row's own law) and the 100kb trickle row
    // sagging to 64.8% under the same shape. With the half-split
    // the leaf keeps its buffer, the troughs never reach the
    // admit, and the flow bucket banks toward its admit across
    // draws exactly the way the leaf itself always banked toward
    // the GSO floor at trickle rates. A SPARSE take keeps the
    // whole-leaf right: its demand IS the packet (200 bytes may
    // take the leaf's last 200 — the bulk sibling's cascade
    // refills behind it), and the bulk discipline is the one the
    // buffer law binds.
    // THE BUFFER THRESHOLD (the second battery run's refinement of
    // the source buffer law): the half-split engages only when the
    // leaf holds two packets' worth or more — below that there is
    // nothing worth buffering, the take is whole, and the admit is
    // DETERMINISTIC again: the take covers the packet whenever the
    // leaf does, the old single-bucket lane's own property. The
    // plain half-split left the take at the packet's own order at
    // the micro-credit steady state — the admit a coin flip at the
    // boundary, 1122 drops under a policy that must drop nothing
    // (the live battery's second measurement).
    let take_within_the_source_buffer = if sparse || leaf_tokens < pkt_len as u64 * 2 {
        // A sparse demand (its packet IS the take) or a leaf below
        // two packets' worth (nothing left worth buffering): the
        // take is whole, and the admit deterministic — the old
        // single-bucket lane's own property, restored.
        leaf_tokens
    } else {
        leaf_tokens / 2
    };
    if take_under_the_bound_law < take_within_the_source_buffer {
        take_under_the_bound_law
    } else {
        take_within_the_source_buffer
    }
}
