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
// A fifth delta (NIGHT-perf-1, call timing not values): the egress
// event payload's tgid/uid helper calls moved from the per-packet
// function top into the 1-in-100 throttled event branch -- the C
// twin paid two BPF helper calls on every packet for values only
// the hundredth packet's event reads. Same current task, same
// invocation: byte-identical events, a cheaper hot path.
//
// Build: cd ebpf && cargo +nightly build --release

#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext as _, helpers::bpf_get_socket_cookie, helpers::bpf_skb_cgroup_id,
    macros::cgroup_skb, macros::map, maps::HashMap, maps::LruHashMap, maps::RingBuf,
    programs::SkBuffContext,
};

// ---------------------------------------------------------------------------
// Shared layout contract with the userspace loader (src/ebpf/loader.rs,
// CgroupStatsRaw) and the C twin. The compile-time size pins guarantee the
// layouts can never drift silently; the C side carries the same shapes.
// ---------------------------------------------------------------------------

/// Event type tag for packet events (mirrors EVENT_PACKET).
const EVENT_PACKET: u32 = 1;
/// Ethernet protocol number for IPv4 (mirrors ETH_P_IP).
const ETH_P_IP: u16 = 0x0800;
/// IP protocol number for TCP (mirrors IPPROTO_TCP).
const IPPROTO_TCP: u8 = 6;
/// IP protocol number for UDP (mirrors IPPROTO_UDP).
const IPPROTO_UDP: u8 = 17;

/// The BPF-side stats layout; the userspace mirror is
/// `CgroupStatsRaw` in src/ebpf/loader.rs (layout contract).
#[repr(C)]
#[derive(Clone, Copy)]
struct CgroupStats {
    packets: u64,
    bytes: u64,
    last_event_packet: u64,
}

/// The packet-event layout (throttled to 1 per 100 packets per
/// cgroup; written to the events ringbuf — the dead-ringbuf
/// question is documented in docs/PURE_RUST_EVALUATION.md).
#[repr(C)]
struct Event {
    event_type: u32,
    cgroup_id: u32,
    pid: u32,
    uid: u32,
    protocol: u16,
    direction: u16,
    pkt_len: u32,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    comm: [u8; 16],
}

/// Minimal IPv4 header read model (20 fixed bytes; options are not
/// decoded, exactly like the C twin's sizeof(struct iphdr) arithmetic).
#[repr(C)]
struct Ipv4Header {
    _version_ihl: u8,
    _tos: u8,
    _tot_len: u16,
    _id: u16,
    _frag_off: u16,
    _ttl: u8,
    protocol: u8,
    _check: u16,
    saddr: u32,
    daddr: u32,
}

/// First four bytes of a TCP or UDP header (source and dest sit at the
/// same offsets in both).
#[repr(C)]
struct PortsHeader {
    source: u16,
    dest: u16,
}

const _: () = assert!(core::mem::size_of::<CgroupStats>() == 24);
const _: () = assert!(core::mem::size_of::<Event>() == 52);
const _: () = assert!(core::mem::size_of::<Ipv4Header>() == 20);
const _: () = assert!(core::mem::size_of::<PortsHeader>() == 4);

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

/// Ring buffer, 2 MB for high traffic bursts. Written by this program,
/// never read by zelynic userspace (see the hunt finding in
/// docs/PURE_RUST_EVALUATION.md); kept for exact parity with the C twin.
#[allow(non_upper_case_globals)]
#[map]
static events: RingBuf = RingBuf::with_byte_size(2 * 1024 * 1024, 0);

// ---------------------------------------------------------------------------
// Egress observer: counter update, 1-in-100 event throttle, IPv4/TCP/UDP
// header parse, ring buffer emission. Ported from observe_egress.
// ---------------------------------------------------------------------------

/// Bump one per-socket cookie accumulator (NIGHT-boost-26). Cookie 0
/// means the kernel had no owning socket on the skb (packet-level
/// traffic not demuxed to a socket, e.g. some early loopback shapes)
/// — nothing to attribute, skip honestly. Saturating add: a u64 byte
/// accumulator's honest ceiling is u64::MAX, never a wrap — the same
/// discipline the userspace session ledger guarantees (NIGHT-boost-16).
/// The cgroup counters below deliberately keep the C twin's plain
/// adds instead: their wrap horizon is the same unreachable 18.4 EB
/// (years of line-rate traffic through ONE cgroup in ONE
/// session-scoped map), and the saturating form would charge the
/// per-packet hot path extra instructions to guard a state no real
/// link can produce. The honest saturation contract users SEE is the
/// userspace one — STABILITY.md's "the accumulator saturates" scoped
/// to the session path. (NIGHT-ultimate-1 comment-truth fix: the
/// previous wording claimed saturation parity with the cgroup
/// counters that the code below never had.)
fn bump_socket_counter(map: &LruHashMap<u64, u64>, cookie: u64, pkt_len: u64) {
    if cookie == 0 {
        return;
    }
    match map.get_ptr_mut(&cookie) {
        Some(ptr) => {
            // SAFETY: the pointer comes from the map's own lookup and
            // lives until the map is freed (kernel map memory); the
            // write is a plain u64 store, the same access pattern the
            // cgroup counter updates below use.
            let cur = unsafe { *ptr };
            unsafe { *ptr = cur.saturating_add(pkt_len) };
        }
        None => {
            // Insert result ignored: a full-LRU miss is an honest
            // "not attributed" (the map evicts cold entries to make
            // room, so this only fails transiently under extreme
            // churn), never a dropped packet — the same
            // allow-and-skip contract the cgroup counter maps carry.
            let _ = map.insert(&cookie, pkt_len, 0);
        }
    }
}

#[cgroup_skb(egress)]
fn observe_egress(ctx: SkBuffContext) -> i32 {
    match try_observe_egress(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_observe_egress(ctx: SkBuffContext) -> Result<i32, i32> {
    let cgroup_id = unsafe { bpf_skb_cgroup_id(ctx.skb.skb) } as u32;
    let pkt_len = ctx.len();

    // Per-socket attribution (NIGHT-boost-26): the cookie of the
    // SENDING socket, bumped before any early return below — this is
    // per-packet accounting, not throttled event plumbing.
    let cookie = unsafe { bpf_get_socket_cookie(ctx.skb.skb.cast()) };
    bump_socket_counter(&socket_counters, cookie, u64::from(pkt_len));

    // Counter update: in-place increment on an existing entry, or
    // init-then-relookup exactly like the C twin (BPF_ANY insert; the
    // fresh pointer is required for the throttle bookkeeping below).
    let stats = match cgroup_counters.get_ptr_mut(&cgroup_id) {
        Some(ptr) => {
            let s = unsafe { &mut *ptr };
            s.packets += 1;
            s.bytes += pkt_len as u64;
            s
        }
        None => {
            let init = CgroupStats {
                packets: 1,
                bytes: pkt_len as u64,
                last_event_packet: 0,
            };
            if cgroup_counters.insert(&cgroup_id, &init, 0).is_err() {
                return Ok(1);
            }
            match cgroup_counters.get_ptr_mut(&cgroup_id) {
                Some(ptr) => unsafe { &mut *ptr },
                None => return Ok(1),
            }
        }
    };

    // Throttle: emit one event per 100 packets per cgroup, tracked via
    // the packet count at the last emission.
    if stats.packets - stats.last_event_packet < 100 {
        return Ok(1);
    }
    stats.last_event_packet = stats.packets;

    // The event payload's per-task facts resolve HERE, on the 1-in-100
    // path only (NIGHT-perf-1): the C twin computed tgid/uid per
    // packet at the function top, paying two BPF helper calls on
    // every packet for an event the throttle emits once per hundred —
    // 99% of the hot path funded a value nobody read. The helpers
    // read the CURRENT task, which cannot change between the function
    // top and this point in the same invocation, so the event carries
    // byte-identical fields; only WHEN the calls happen moved. This
    // is the lazy pattern ctx.command() two blocks below already
    // established. At line rate the saving is one full helper-call
    // pair per packet off the observer's egress hot path.
    let pid = ctx.tgid();
    let uid = ctx.uid();

    // Parse the IP header. cgroup_skb frames carry no Ethernet header.
    // The C twin uses direct data/data_end access; ctx.load performs
    // the verifier-safe copy through bpf_skb_load_bytes instead (see
    // the behavioral-delta note in the file header).
    let mut protocol = 0u16;
    let mut src_ip = 0u32;
    let mut dst_ip = 0u32;
    let mut src_port = 0u16;
    let mut dst_port = 0u16;

    if ctx.skb.protocol() == u32::from(ETH_P_IP.swap_bytes()) {
        let iph = match ctx.load::<Ipv4Header>(0) {
            Ok(h) => h,
            Err(_) => return Ok(1),
        };
        protocol = u16::from(iph.protocol);
        src_ip = iph.saddr;
        dst_ip = iph.daddr;

        if iph.protocol == IPPROTO_TCP || iph.protocol == IPPROTO_UDP {
            // Fixed +20 offset (sizeof(struct iphdr)) like the C twin;
            // IP options are not accounted for. A failed read leaves the
            // ports at zero and still emits the event, matching the C
            // bounds-check-skip behavior.
            if let Ok(ports) = ctx.load::<PortsHeader>(20) {
                src_port = u16::from_be(ports.source);
                dst_port = u16::from_be(ports.dest);
            }
        }
    }

    // Emit the event. A failed reserve (ring buffer full) drops the
    // event but never the packet, like the C twin.
    let mut entry = match events.reserve::<Event>(0) {
        Some(e) => e,
        None => return Ok(1),
    };
    entry.write(Event {
        event_type: EVENT_PACKET,
        cgroup_id,
        pid,
        uid,
        protocol,
        direction: 0, // egress (upload)
        pkt_len,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        comm: ctx.command().unwrap_or([0u8; 16]),
    });
    entry.submit(0);

    Ok(1)
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
        Some(ptr) => {
            let s = unsafe { &mut *ptr };
            s.packets += 1;
            s.bytes += pkt_len;
        }
        None => {
            let init = CgroupStats {
                packets: 1,
                bytes: pkt_len,
                last_event_packet: 0,
            };
            // Insert result ignored by design: the C twin does not check
            // the return value either; a failed insert loses this one
            // packet's count, never the packet itself.
            let _ = cgroup_counters_ingress.insert(&cgroup_id, &init, 0);
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
