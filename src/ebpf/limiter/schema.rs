// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The limiter's BPF schema-version contract.
//!
//! Split from types.rs at the NIGHT-private-research-2 bump (the
//! version-history doc block grows one entry per schema bump — the
//! 500-LOC owner cap was already full at v9, and this constant's
//! history is the one piece of types.rs that grows by design).
//! Re-exported through types.rs so every existing
//! `use types::SCHEMA_VERSION_EXPECTED` import resolves unchanged —
//! the parse.rs precedent (NIGHT-private-research-3) applied to the
//! schema anchor.

/// BPF schema version. Must match `SCHEMA_VERSION` in
/// `ebpf/src/bin/limiter.rs`.
/// Increment both when BPF struct layouts or semantics change. Userspace checks
/// the pinned schema_version map on attach — if mismatch, cleans up + reloads.
/// The v1..v30 history ledger moved verbatim to schema_ledger.rs
/// (the 600-line cap's split — night-T-3's v31 hour); v31 and
/// onward append here, beside the anchor.
/// v31 (night-T-3, the measured-RTT RECWN retune — the honest
///     clamp): the recwn_socket_hint row's VALUE semantics change —
///     socket cookie -> the policy's DOWNLOAD RATE in bytes per
///     second (was: the derived receive window). The runtime law
///     the sock_ops program applies at every owned callback is now
///     window = rate x max(measured srtt, 200 ms), the srtt read
///     straight from the sock_ops context (uapi bpf_sock_ops
///     .srtt_us, microseconds << 3, v4.16+ — no new helper, no new
///     map, no userspace involvement: the zero-daemon posture
///     holds). The 200 ms constant re-frames from RTT guess to the
///     receiver's window-update CADENCE floor — the band the v25
///     evidence measured at 145-160 ms topping at 200 ms — so every
///     short link and every unmeasured socket answers the exact v25
///     window byte for byte (the retune can only extend the pipe,
///     never shrink it), while a link LONGER than the band (the
///     satellite class the fixed floor under-admitted at rate x
///     200 ms) now derives its true pipe. The [2 x MSS, 1 MiB] band
///     and the plain-multiply sanitize cap carry unchanged (measured
///     srtt maxes at u32, the product bound holds by construction).
///     The status surfaces stay the v25 shape exactly (additive
///     contract: recwn_limits.enabled / window_bytes /
///     rtt_estimate_us — the derivation is now the cadence-floor
///     FLOOR shape, the number the runtime can only extend above).
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
///     retune made readable): LimiterStatsRaw grows one u64 tail
///     word, measured_srtt_us (offset 64) — the per-policy
///     high-water of the download sockets' own measured srtt,
///     kernel-written (the ingress prime site ratchets the recwn
///     hint row's harvest word — the RTT callback's latest live
///     sample stored in the hint row's repurposed tail pad, the
///     16-byte row size holding) and read here: the status surfaces
///     report it as recwn_limits.measured_srtt_us and fold it into
///     the binding-window derivation the v31 law computes
///     kernel-side (window = rate x max(measured srtt, 200 ms) —
///     the status now reports the measured extension instead of the
///     bare floor; the JSON field is additive and honestly absent
///     while no policed socket has sampled). The policy rows are
///     untouched — the config family stays userspace-written; the
///     ratchet rides the stats row the kernel already owns and
///     read_stats already opens. The bump is REQUIRED, not polite:
///     a pinned v32 stats row is 64 bytes, a v33 reader would map
///     the 72-byte tail onto nothing — the forced reload wipes the
///     stale pins (active limits are dropped once, re-apply after
///     upgrade, the same one-time contract as every bump before it).
/// v34 (night-frontier-2B, the depth histogram — the contained
///     innovation): TWO additive LRU maps, depth_hist_dl/ul, one
///     row per cgroup per direction keyed at the LEAF (the ee
///     --depth target's identity, not the policy root the stats/
///     ring family keys), each row hist::HistRow — 512 bytes, two
///     32-bucket log2 halves (size in bytes, srtt in microseconds).
///     Recording rides a per-CPU sampler (hist::HIST_SAMPLE_SHIFT,
///     1-in-1024 per CPU: the unlimited majority pays one per-CPU
///     tick, the sampled packet the row — the NIGHT-lts-2 law's
///     measured frontier-2B amendment), and the srtt half only
///     fills from the RTT lane's own harvest (recwn_peek_srtt, the
///     read-only sk-storage peek — no new helper, no CO-RE, the
///     sock_ops uapi chain the v31/v33 entries already pin). The
///     userspace mirror (src/ebpf/limiter/hist.rs HistRowRaw) and
///     the pure core (ebpf/src/hist.rs, rootless-pinned) carry the
///     layout contract; ee --depth's new histogram section is
///     additive and honestly absent while the maps hold no row for
///     the focused cgroup (or no limiter session ever pinned them).
///     The existing rows are untouched — policy/stats/ring layouts
///     are byte-identical to v33 — but the bump is REQUIRED, not
///     polite: a pinned v33 object lacks the hist maps entirely,
///     and the version is the one gate that tells a v34 reader the
///     difference between "no samples yet" and "no such lane" —
///     the forced reload (once, re-apply after upgrade) re-pins the
///     full v34 map set.
pub const SCHEMA_VERSION_EXPECTED: u32 = 34;

#[cfg(test)]
#[path = "../../../test/ebpf/limiter/schema_sync_pin_tests.rs"]
mod sync_pin;
