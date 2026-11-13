// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
// NIGHT-improve-44: the schema-version ledger (the v1..v24
// contract history) and the SCHEMA_VERSION const it documents,
// moved out of limiter.rs at the 600-line cap. Same file the
// userspace loader contract names; the doc text is verbatim.
//
// ---------------------------------------------------------------------------
// Shared layout contract with the userspace loader (src/ebpf/limiter/
// types.rs: PolicyRaw, BucketRaw, LimiterStatsRaw) and the C twin. The
// compile-time size pins guarantee the layouts can never drift
// silently; the C side relies on kernel headers for the same
// invariants, the userspace tests assert the third copy.
// (NIGHT-depthbore-1: the struct definitions, the size pins,
// NS_PER_SEC, MAX_ENFORCABLE_BURST, and the enforce math moved to
// math.rs — this block keeps the contract statement.)
// ---------------------------------------------------------------------------

/// Current schema version. Increment when struct layouts or
/// semantics change. Kept in sync with SCHEMA_VERSION_EXPECTED in
/// src/ebpf/limiter/types.rs (the v3..v30 history ledger moved
/// verbatim to schema_ledger.rs — the 600-line cap's split,
/// night-T-3's v31 hour); v31 and onward append here, beside the
/// anchor.
/// v31 (night-T-3, the measured-RTT RECWN retune — the honest
///     clamp): the recwn_socket_hint row's VALUE semantics change —
///     socket cookie -> the policy's DOWNLOAD RATE in bytes per
///     second (was: the derived receive window). The sock_ops
///     program derives the window at every owned callback as
///     window = rate x max(measured srtt, 200 ms), the srtt read
///     straight from the sock_ops context (uapi bpf_sock_ops
///     .srtt_us, microseconds << 3, populated whenever is_fullsock
///     holds — v4.16+, so the 5.13 floor carries it; no new helper,
///     no new map, no userspace involvement). The 200 ms constant
///     re-frames from RTT guess to the receiver's window-update
///     CADENCE floor (the band the v25 evidence measured at
///     145-160 ms topping at 200 ms): every short link and every
///     unmeasured socket answers the exact v25 window byte for
///     byte, a link LONGER than the band derives the pipe the
///     fixed floor under-admitted, and the [2 x MSS, 1 MiB] band
///     plus the plain-multiply sanitize cap carry unchanged (the
///     product bound holds: rate <= 2^32, srtt <= u32). The status
///     derivation stays the v25 shape exactly (the cadence-floor
///     FLOOR shape — the number the runtime can only extend above).
///     The bump is REQUIRED, not polite: a pinned v30 hint row
///     holds WINDOW bytes, which a v31 reader would misread as a
///     RATE — the forced reload wipes the stale rows (active limits
///     are dropped once, re-apply after upgrade, the same one-time
///     contract as every bump before it).
/// v32 (night-T-4, the sk-storage migration — architectural
///     deepening): recwn_socket_hint and pace_socket_hint leave the
///     cookie-keyed LRU-4096 world for BPF_MAP_TYPE_SK_STORAGE —
///     the row hangs off the kernel's own struct sock
///     (bpf_sk_storage_get, BPF_F_NO_PREALLOC, max_entries 0; the
///     BTF map rides the #[btf_map] .maps section). The value
///     pairs the policy rate with the MMSPA GENERATION the prime
///     ran under, and every callback compares it against the live
///     generation (the mmspa_generation word every policy mutation
///     already bumps) — the generation belt replaces the whole-map
///     removal sweeps (limiter/recwn.rs and limiter/pace.rs's
///     flush lanes RETIRED with this bump; userspace never opens
///     either map again, the PIN_MAP_*_HINT constants are gone).
///     The kernel floor carries it: cg_skb_func_proto and
///     sock_ops_func_proto both list bpf_sk_storage_get/delete
///     since v5.9 (verified v5.13 + v5.15 net/core/filter.c),
///     arg2 is ARG_PTR_TO_BTF_ID_SOCK_COMMON, the helper's own
///     sk_fullsock guard answers NULL on request/timewait socks —
///     the same miss posture the cookie-0 skip was. What moved and
///     why ONLY these two: a sock_ops hint row is genuine
///     socket-identity state (the setsockopt lands on THE socket
///     the row hangs off), while the other cookie-keyed maps key
///     finer or coarser identities — quic_cid_hint keys the
///     per-CONVERSATION CID geometry (a QUIC connection migrates
///     across sockets; sk_storage would break the multiplexing
///     budget the v22 promise restored), the ecn_debt words key
///     the per-BUDGET generation-prefixed identity, and the
///     cake/drr flow maps key the scheduler's own flow identities
///     — each stays a hash map with its own aging law. The gains:
///     no hash to pay at the callback (one list walk on the
///     socket's local-storage chain), no LRU cap to fake-evict a
///     live connection under, no cookie-reuse ambiguity, rows die
///     with the socket (kernel GC), and a policy removal heals on
///     the very first callback — the v25 removal blind spot is
///     closed, not swept. The bump is REQUIRED, not polite: the
///     pinned v31 rows are LRU-map bytes a v32 loader would open
///     as sk_storage (a different map TYPE entirely) — the forced
///     reload wipes the stale pins (active limits are dropped
///     once, re-apply after upgrade, the same one-time contract
///     as every bump before it).
/// v33 (night-verify-final, the measured-srtt telemetry — the v31
///     retune made readable): LimiterStats grows one u64 tail word,
///     measured_srtt_us (offset 64) — the per-policy high-water of
///     the download sockets' own measured srtt, written by the
///     ingress prime site from the recwn hint row's harvest (the
///     RTT callback stores the socket's latest live sample into the
///     hint row's tail word — the repr(C) pad the 5.15 verifier
///     lesson made a real field, repurposed; the 16-byte hint row
///     size holds), read by the status surfaces as recwn_limits
///     .measured_srtt_us and folded into the binding-window
///     derivation the v31 law computes kernel-side (window = rate x
///     max(measured srtt, 200 ms) — the status now reports the
///     measured extension instead of the bare floor; the JSON field
///     is additive and honestly absent while no policed socket has
///     sampled). The policy rows are untouched — the config family
///     stays userspace-written; the ratchet rides the stats row the
///     kernel already owns and the status readers already open, so
///     the hot path pays one volatile store at the RTT callback and
///     one check-then-store at the prime site, no new map, no new
///     lookup. The bump is REQUIRED, not polite: a pinned v32 stats
///     row is 64 bytes, a v33 reader would map the 72-byte tail
///     onto nothing — the forced reload wipes the stale pins (active
///     limits are dropped once, re-apply after upgrade, the same
///     one-time contract as every bump before it).
/// v34 (night-frontier-2B, the depth histogram): two additive LRU
///     rows, depth_hist_dl/ul (LruHashMap<u32, HistRow>, keyed at
///     the leaf, 512-byte rows of two 32-bucket log2 halves — size
///     in bytes, srtt in microseconds), plus the per-CPU sampler
///     tick and the zero-row staging entry the first insert copies
///     from (a 512-byte init can never touch the BPF stack). The
///     recording rides the 1-in-1024 per-CPU sampler and the srtt
///     half fills from the RTT lane's own harvest (the read-only
///     sk-storage peek). The existing rows are byte-identical to
///     v33 — the bump is REQUIRED, not polite: a pinned v33 object
///     lacks the hist maps entirely, and the version is the one
///     gate distinguishing "no samples yet" from "no such lane";
///     the forced reload (once, re-apply after upgrade) re-pins the
///     full v34 map set.
/// v35 (night-frontier-Z1, the histogram depth pack): the HistRow
///     grows IN PLACE — the two 32-bucket halves stay byte-identical
///     to v34, then eight exact-aggregate words (count/sum/min/max
///     for size and srtt: count/sum are RMW adds, min/max the
///     volatile check-then-store replace law (the measured_srtt
///     ratchet's own discipline — the BPF ISA has no plain-atomic
///     load for a CAS shape), the 0-sentinel "no min yet") and
///     eight 32-byte tail story slots (ts_ns/size/srtt_us/cookie —
///     the worst-by-size samples, the socket cookie the skb helper
///     names — the same identity userspace's walk already maps to an
///     endpoint, so the kernel never parses the wire and never reads
///     a kernel-struct offset; ts written LAST so an empty slot never
///     reads half-filled). 512 → 832 bytes. No new map, no new
///     lookup: the sampler's get-or-create still pays once, the
///     aggregates ride the same sampled write, the tail scan is an
///     8-slot linear pass the verifier unrolls. The bump is
///     REQUIRED, not polite: a pinned v34 row is 512 bytes and a v35
///     reader would map the 320-byte extension onto nothing — the
///     forced reload (once, re-apply after upgrade) re-pins the full
///     v35 map set.
#[allow(dead_code)]
pub(crate) const SCHEMA_VERSION: u32 = 35;

// ---------------------------------------------------------------------------
// Maps. The static names ARE the userspace contract (limiter/mod.rs
// and pin.rs open each map by name or by pin path), so they stay
// lowercase exactly like the C object's symbols; the allow attribute
// suppresses the non-upper-case globals lint for that reason. Every
// map is pinned by name: policies must survive process exit, which
// is the whole point of the /sys/fs/bpf/zelynic directory.
// ---------------------------------------------------------------------------

// ─ Download (ingress) maps ─
