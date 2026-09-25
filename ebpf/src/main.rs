// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// zelynic eBPF observer, the pure-Rust BPF source (NIGHT-improve-1,
// stage 3 port of the former bpf/observer.bpf.c; phase 3 deleted
// the C side — the port is now the production source).
//
// Line-for-line translation of the C twin onto aya-ebpf 0.2.1. The
// ELF contract with src/ebpf/loader.rs is identical (names, sections,
// map types, struct layouts, GPL license) -- the verification
// harness output and the full contract table live in
// docs/PURE_RUST_EVALUATION.md. Three deliberate behavioral deltas
// are documented there: ctx.load (bpf_skb_load_bytes) parses
// non-linear skbs the C direct-access path silently skips, the
// ingress insert result is ignored exactly like the C twin (commented
// here so a swallow audit finds the rationale in place), and the
// counter map capacity is 1024 entries instead of the C twin's 256
// (NIGHT-improve-8: server LTS — see COUNTER_MAP_MAX_ENTRIES below).
// A fourth addition (NIGHT-boost-26, no C twin ever had it): the two
// per-socket cookie maps below — per-endpoint byte attribution, the
// 2.4 frontier item. bpf_get_socket_cookie is legal in cgroup_skb
// programs (cg_skb_func_proto falls through to sk_filter_func_proto,
// which owns the helper) and the kernel sets skb->sk to the OWNING
// socket before running both hooks (egress: the sender, via the cgroup
// egress run in the output path; ingress: the receiver — the
// CGROUP_INET_INGRESS attach fires per-socket from sk_filter_trim_cap,
// and __cgroup_bpf_run_filter_skb assigns skb->sk = sk before the
// program runs), so a cookie read in either hook names exactly the
// socket the traffic belongs to. Verified against torvalds/linux
// net/core/filter.c + kernel/bpf/cgroup.c at implementation time.
// A fifth delta (NIGHT-boost-34), and the one that breaks with the C
// twin: the events ringbuf is GONE. Kernel 6.8 removed
// bpf_get_current_pid_tgid / bpf_get_current_uid_gid /
// bpf_get_current_comm from bpf_base_func_proto, and cgroup_skb's
// dispatch never reaches the new cgroup_current_func_proto, so the
// old 1-in-100 event branch's helper calls failed program load with
// EINVAL on every 6.8 host (an LTS inside the promised 5.13+ span;
// 6.17 quietly restored the helpers, but the span must hold). The
// event payload fed a ringbuf no zelynic code ever read — the
// phase-2 hunt finding recorded in docs/PURE_RUST_EVALUATION.md
// ("phase 2 should decide whether both objects drop the dead ringbuf
// or a consumer arrives"); no consumer ever arrived, and kernel 6.8
// cast the deciding vote. The egress program is now the ingress
// shape: cgroup counters + per-socket attribution, no event branch,
// no helper wall, and CgroupStats drops the throttle's
// last_event_packet leg (userspace CgroupStatsRaw synced).
//
// A sixth delta (NIGHT-improve-29, the owner-approved observer race
// hunt): the counter updates are ATOMIC. The C twin's plain
// `s.packets += 1; s.bytes += pkt_len` on the shared map value was
// the exact lost-update shape NIGHT-boost-38 closed in the limiter —
// aya hands every CPU the same unlocked value, two CPUs enforcing
// one cgroup each loaded the same counter and stored their own +1,
// and the eagle-eyes rates read LOW under exactly the concurrent
// traffic the monitor exists to measure. Every update now rides
// 64-bit BPF_ATOMIC fetch-add (Linux 5.12+, under the verified 5.13
// floor — the same ISA the v7 token bucket already requires), and
// first-packet inserts use BPF_NOEXIST so a concurrent initializer
// is never clobbered by a BPF_ANY overwrite (the loser re-looks-up
// and books its packet onto the winner's entry — one packet counted
// exactly once on every interleaving). The booking primitives and
// the stats layout live in stats.rs (the NIGHT-depthbore-1 math.rs
// precedent), pinned rootlessly by test/ebpf/stats_smp_tests.rs
// under real thread contention.
//
// Build: cd ebpf && cargo +nightly build --release

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_socket_cookie, helpers::bpf_skb_cgroup_id, macros::cgroup_skb, macros::map,
    maps::HashMap, maps::LruHashMap, programs::SkBuffContext,
};

// The observer's pure stats core (NIGHT-improve-29): the layout +
// the atomic booking primitives, pure `core`, #[path]-pinned into
// the userspace test tree the same way math.rs is (see stats.rs).
mod stats;

use stats::{CgroupStats, book_packet, bump_socket_bytes};

// ---------------------------------------------------------------------------
// Maps. The static names ARE the userspace contract (loader.rs opens each
// map by name), so they stay lowercase exactly like the C object's symbols;
// the allow attribute suppresses the non-upper-case globals lint for that
// reason.
// ---------------------------------------------------------------------------

/// Counter map capacity, shared by both directions' maps.
///
/// NIGHT-improve-8 (server LTS): raised from the C twin's 256 to
/// 1024, the limiter's policy-map capacity class. On hosts with more
/// than 256 live cgroups — Kubernetes nodes, systemd-heavy servers,
/// container hosts — the 256-entry maps filled silently and every
/// further cgroup's traffic went UNCOUNTED (the monitor showed
/// nothing for it; the insert failure path returns allow-and-skip).
/// The owner rule is "desktop Linux, even server use": a monitor
/// that quietly under-reports on exactly the hosts with the most
/// cgroups is a stability hole, not a footnote. These maps are
/// unpinned and session-scoped (created fresh at every eagle-eyes
/// run), so the raise carries no pin or schema migration; kernel
/// memory cost is 2 x 1024 x 24 B = 48 KiB for a session.
const COUNTER_MAP_MAX_ENTRIES: u32 = 1024;

#[allow(non_upper_case_globals)]
#[map]
static cgroup_counters: HashMap<u32, CgroupStats> =
    HashMap::with_max_entries(COUNTER_MAP_MAX_ENTRIES, 0);

#[allow(non_upper_case_globals)]
#[map]
static cgroup_counters_ingress: HashMap<u32, CgroupStats> =
    HashMap::with_max_entries(COUNTER_MAP_MAX_ENTRIES, 0);

/// Per-socket map capacity (NIGHT-boost-26). Sockets churn far faster
/// than cgroups — a browsing session can cycle hundreds of
/// connections an hour — and socket cookies are NEVER reused (a
/// kernel-global generation counter), so a plain hash map would
/// monotonically fill with dead sockets' stale entries and silently
/// kill attribution mid-session. The maps are therefore LRU: a cold
/// entry (a socket whose traffic stopped, usually because the socket
/// died) ages out on its own, and a new socket always finds room.
/// The honest trade, documented: under EXTREME churn (4096+ warm
/// sockets at once) an evicted-then-resumed socket restarts its
/// accumulator — endpoint figures are best-effort per-socket session
/// totals, the "map sizing bounded like the existing counters"
/// promise of the 2.4 design
/// (docs/RESEARCH_TOOLCHAIN_AND_MONITORING.md). Kernel memory: two
/// LRU hashes of 4096 entries at 8-byte key + 8-byte value payload
/// (plus the per-entry node overhead the kernel charges) — bounded,
/// session-scoped, freed at detach.
const SOCKET_MAP_MAX_ENTRIES: u32 = 4096;

/// Per-socket egress (upload) bytes, keyed by socket cookie
/// (NIGHT-boost-26): the sender's cookie, read in the egress hook
/// where skb->sk is the sending socket. Userspace joins this with the
/// ConnectionMap's /proc endpoint table via pidfd_getfd + SO_COOKIE
/// (src/ebpf/connections.rs — the identity plumbing the 2.4 design
/// said already exists).
#[allow(non_upper_case_globals)]
#[map]
static socket_counters: LruHashMap<u64, u64> =
    LruHashMap::with_max_entries(SOCKET_MAP_MAX_ENTRIES, 0);

/// Per-socket ingress (download) bytes, keyed by the RECEIVING
/// socket's cookie (NIGHT-boost-26): at the CGROUP_INET_INGRESS
/// attach the kernel has already demuxed the packet to its socket
/// (the hook fires per-socket from sk_filter_trim_cap), so the cookie
/// names the receiver — the download's true owner.
#[allow(non_upper_case_globals)]
#[map]
static socket_counters_ingress: LruHashMap<u64, u64> =
    LruHashMap::with_max_entries(SOCKET_MAP_MAX_ENTRIES, 0);

/// `bpf_map_update_elem` flag: fail the insert if the key already
/// exists (kernel uapi: BPF_ANY = 0, BPF_NOEXIST = 1, BPF_EXIST = 2).
/// NIGHT-improve-29: the first-packet inserts use NOEXIST so a
/// concurrent initializer's entry is never clobbered — the loser of
/// the insert race re-looks-up and books its packet onto the
/// winner's entry instead of overwriting it.
const BPF_NOEXIST: u64 = 1;

// ---------------------------------------------------------------------------
// Egress observer: per-cgroup and per-socket counter updates. Ported
// from observe_egress, with the 1-in-100 event branch and the events
// ringbuf retired at NIGHT-boost-34 (the kernel-6.8 cgroup_skb
// helper wall — see the file header).
// ---------------------------------------------------------------------------

/// Bump one per-socket cookie accumulator (NIGHT-boost-26; atomic
/// since NIGHT-improve-29). Cookie 0 means the kernel had no owning
/// socket on the skb (packet-level traffic not demuxed to a socket,
/// e.g. some early loopback shapes) — nothing to attribute, skip
/// honestly. The update is a Relaxed fetch_add on the shared value —
/// two CPUs attributing the same socket (multi-queue NIC steering,
/// loopback) each land their bytes, no lost update. Overflow wraps
/// at the unreachable u64::MAX session horizon (~18.4 EB through one
/// socket) — the same position the cgroup counters hold; the old
/// saturating form was a plain RMW whose race lost real bytes far
/// below any horizon (see stats.rs, bump_socket_bytes).
fn bump_socket_counter(map: &LruHashMap<u64, u64>, cookie: u64, pkt_len: u64) {
    if cookie == 0 {
        return;
    }
    match map.get_ptr_mut(&cookie) {
        Some(ptr) => bump_socket_bytes(ptr, pkt_len),
        None => {
            // First packet for this socket: NOEXIST so a concurrent
            // first-packet on another CPU is never clobbered; the
            // loser re-looks-up and books onto the winner's entry
            // (NIGHT-improve-29). Any failure beyond the race (a
            // full-LRU miss is an honest "not attributed" — the map
            // evicts cold entries to make room, so this only fails
            // transiently under extreme churn; a NOEXIST loser whose
            // entry was LRU-evicted between insert and re-lookup)
            // loses this one packet's ATTRIBUTION, never the packet —
            // the same allow-and-skip contract the cgroup counter
            // maps carry.
            if map.insert(&cookie, &pkt_len, BPF_NOEXIST).is_err() {
                if let Some(ptr) = map.get_ptr_mut(&cookie) {
                    bump_socket_bytes(ptr, pkt_len);
                }
            }
        }
    }
}

#[cgroup_skb(egress)]
fn observe_egress(ctx: SkBuffContext) -> i32 {
    let cgroup_id = unsafe { bpf_skb_cgroup_id(ctx.skb.skb) } as u32;
    let pkt_len = ctx.len();

    // Per-socket attribution (NIGHT-boost-26): the cookie of the
    // SENDING socket — per-packet accounting, never a dropped
    // packet's worth of bookkeeping.
    let cookie = unsafe { bpf_get_socket_cookie(ctx.skb.skb.cast()) };
    bump_socket_counter(&socket_counters, cookie, u64::from(pkt_len));

    // Counter update: atomic in-place booking on an existing entry
    // (NIGHT-improve-29: the old `+=` on the shared value lost
    // updates whenever two CPUs carried the same cgroup's traffic —
    // the boost-38 limiter race's observer twin), or a first-packet
    // NOEXIST insert whose loser re-looks-up and books onto the
    // winner's entry (one packet counted exactly once on every
    // interleaving; a full-map miss loses this one packet's COUNT,
    // never the packet itself).
    match cgroup_counters.get_ptr_mut(&cgroup_id) {
        Some(ptr) => book_packet(ptr, u64::from(pkt_len)),
        None => {
            let init = CgroupStats {
                packets: 1,
                bytes: pkt_len as u64,
            };
            if cgroup_counters
                .insert(&cgroup_id, &init, BPF_NOEXIST)
                .is_err()
            {
                if let Some(ptr) = cgroup_counters.get_ptr_mut(&cgroup_id) {
                    book_packet(ptr, u64::from(pkt_len));
                }
            }
        }
    }

    1
}

// ---------------------------------------------------------------------------
// Ingress observer: counter update only. Ported from observe_ingress.
// ---------------------------------------------------------------------------

#[cgroup_skb(ingress)]
fn observe_ingress(ctx: SkBuffContext) -> i32 {
    let cgroup_id = unsafe { bpf_skb_cgroup_id(ctx.skb.skb) } as u32;
    let pkt_len = ctx.len() as u64;

    // Per-socket attribution (NIGHT-boost-26): the cookie of the
    // RECEIVING socket — at this attach the kernel has already
    // demuxed the packet (the hook fires per-socket), so the cookie
    // names the download's true owner.
    let cookie = unsafe { bpf_get_socket_cookie(ctx.skb.skb.cast()) };
    bump_socket_counter(&socket_counters_ingress, cookie, pkt_len);

    match cgroup_counters_ingress.get_ptr_mut(&cgroup_id) {
        Some(ptr) => book_packet(ptr, pkt_len),
        None => {
            let init = CgroupStats {
                packets: 1,
                bytes: pkt_len,
            };
            // NOEXIST + loser re-lookup (NIGHT-improve-29, the
            // egress twin's contract): a concurrent initializer is
            // never clobbered, and one packet is counted exactly
            // once on every interleaving. A failure beyond the race
            // (full map) loses this one packet's count, never the
            // packet itself — the C twin's allow-and-skip contract.
            if cgroup_counters_ingress
                .insert(&cgroup_id, &init, BPF_NOEXIST)
                .is_err()
            {
                if let Some(ptr) = cgroup_counters_ingress.get_ptr_mut(&cgroup_id) {
                    book_packet(ptr, pkt_len);
                }
            }
        }
    }

    1
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// The license section must stay GPL: bpf_skb_cgroup_id is a GPL-only
// helper, and the C twin declares GPL. A mismatch here would fail the
// verifier at program load time on a real host.
#[unsafe(no_mangle)]
#[unsafe(link_section = "license")]
static LICENSE: [u8; 4] = *b"GPL\0";
