// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// zelynic eBPF observer, pure-Rust port of bpf/observer.bpf.c
// (NIGHT-improve-1, stage 3).
//
// Line-for-line translation of the C twin onto aya-ebpf 0.2.1. The
// ELF contract with src/ebpf/loader.rs is identical (names, sections,
// map types, struct layouts, GPL license) -- the verification
// harness output and the full contract table live in
// docs/PURE_RUST_EVALUATION.md. Two deliberate behavioral deltas are
// documented there: ctx.load (bpf_skb_load_bytes) parses non-linear
// skbs the C direct-access path silently skips, and the ingress
// insert result is ignored exactly like the C twin (commented here
// so a swallow audit finds the rationale in place).
//
// Build: cd ebpf && cargo +nightly build --release

#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext as _, helpers::bpf_skb_cgroup_id, macros::cgroup_skb, macros::map, maps::HashMap,
    maps::RingBuf, programs::SkBuffContext,
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

/// Mirrors `struct cgroup_stats` in bpf/observer.bpf.c.
#[repr(C)]
#[derive(Clone, Copy)]
struct CgroupStats {
    packets: u64,
    bytes: u64,
    last_event_packet: u64,
}

/// Mirrors `struct event` in bpf/observer.bpf.c.
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

#[allow(non_upper_case_globals)]
#[map]
static cgroup_counters: HashMap<u32, CgroupStats> = HashMap::with_max_entries(256, 0);

#[allow(non_upper_case_globals)]
#[map]
static cgroup_counters_ingress: HashMap<u32, CgroupStats> = HashMap::with_max_entries(256, 0);

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

#[cgroup_skb(egress)]
fn observe_egress(ctx: SkBuffContext) -> i32 {
    match try_observe_egress(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_observe_egress(ctx: SkBuffContext) -> Result<i32, i32> {
    let cgroup_id = unsafe { bpf_skb_cgroup_id(ctx.skb.skb) } as u32;
    let pid = ctx.tgid();
    let uid = ctx.uid();
    let pkt_len = ctx.len();

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
