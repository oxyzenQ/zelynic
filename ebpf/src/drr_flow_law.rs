// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// NIGHT-improve-44: the flow lane's pure law (schema v20,
// CAKE-shaped isolation — the budget/allowance/sparse/take
// math) moved out of drr.rs at the 600-line cap — nested
// #[path], re-exported through drr (the runtime half stays
// drr_flow.rs, the map-touching sibling it always was).
//
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
use super::epoch_refill;
use super::share_epoch_ns;
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
    // THE PACKET FLOOR (the third battery run's law, the lane's
    // fourth lesson — CAKE's own MTU-floor discipline, one level
    // down): the OFF lane's take never sits below the packet it
    // serves when the leaf covers it. The lone flow's fraction
    // (leaf/(learned+2)) under-sized takes at low binding rates —
    // at 2 MB/s the leaf rides near its quantum and leaf/3 sits
    // AT the packet's own order — and the under-sized take turned
    // every boundary cycle into a drop-with-bank: the flow bucket
    // accumulated across DROPPED packets while TCP collapsed to
    // 37% of a policy it should have ridden. The floor is bounded
    // by the leaf and by the lane law (a sparse demand is its own
    // floor), and the transient the fraction exists to bound
    // stays bounded: a floored take moves at most one packet, and
    // the share word re-ratchets its peak within the epoch.
    let packet_bytes = pkt_len as u64;
    let packet_cover = if packet_bytes < leaf_tokens {
        packet_bytes
    } else {
        leaf_tokens
    };
    // The floor carries the LONE/COLD shape only (learned < 2 —
    // no sibling evidence in the word's last completed epoch): a
    // decayed PEAK with learned >= 2 is a TRANSIENT, not a lone
    // flow — its fairness is engaged, its divisor merely decayed,
    // and the fraction stays its bound (the trickle regime
    // measured the floor lifting transient takes to the full
    // quantum — four epochs of allowance per draw at the rates
    // where quantum equals one packet).
    let lone_cold_floor = if learned < 2 { packet_cover } else { 0 };
    let off_lane_floor = if learned_share_fraction > lone_cold_floor {
        learned_share_fraction
    } else {
        lone_cold_floor
    };
    let take_within_the_off_lane = if take_under_the_lane_law < off_lane_floor {
        take_under_the_lane_law
    } else {
        off_lane_floor
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
    let take_within_the_source_buffer = if sparse || leaf_tokens < packet_bytes * 2 {
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
