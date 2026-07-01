// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// zelynic eBPF observer — cgroup_skb egress traffic counter
//
// This BPF program attaches to cgroup_skb/egress and counts packets + bytes
// per cgroup. Events are sent to a ring buffer for userspace consumption.
//
// Build: clang -O2 -g -target bpf -c bpf/observer.bpf.c -o bpf/observer.bpf.o
//   (or use: cargo build --features ebpf with build.rs)

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ─── Event types ────────────────────────────────────────────────

#define EVENT_PACKET 1

// ─── Event structure (must match Rust side) ─────────────────────

struct event {
    __u32 event_type;      // EVENT_PACKET
    __u32 cgroup_id;       // cgroup v2 ID
    __u32 pid;             // process ID (from bpf_get_current_pid_tgid)
    __u32 uid;             // user ID
    __u16 protocol;        // IP protocol (TCP=6, UDP=17)
    __u16 direction;       // 0=egress, 1=ingress
    __u32 pkt_len;         // packet length in bytes
    __u32 src_ip;          // source IPv4 address (network byte order)
    __u32 dst_ip;          // destination IPv4 address
    __u16 src_port;        // source port
    __u16 dst_port;        // destination port
    char comm[16];         // process name (task comm)
};

// ─── Ring buffer for events ─────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB ring buffer
} events SEC(".maps");

// ─── Per-cgroup packet/byte counters ────────────────────────────

struct cgroup_stats {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);    // cgroup_id
    __type(value, struct cgroup_stats);
} cgroup_counters SEC(".maps");

// ─── Main eBPF program: cgroup_skb/egress ──────────────────────

SEC("cgroup_skb/egress")
int observe_egress(struct __sk_buff *skb) {
    // Get cgroup ID
    __u64 cgid = bpf_get_cgroup_id();
    __u32 cgroup_id = (__u32)cgid;

    // Get process info
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 uid = bpf_get_current_uid_gid();

    // Get packet length
    __u32 pkt_len = skb->len;

    // Update per-cgroup counters
    struct cgroup_stats *stats = bpf_map_lookup_elem(&cgroup_counters, &cgroup_id);
    if (stats) {
        __sync_fetch_and_add(&stats->packets, 1);
        __sync_fetch_and_add(&stats->bytes, pkt_len);
    } else {
        struct cgroup_stats new_stats = {
            .packets = 1,
            .bytes = pkt_len,
        };
        bpf_map_update_elem(&cgroup_counters, &cgroup_id, &new_stats, BPF_ANY);
    }

    // Only emit event every 10th packet (reduce ring buffer pressure)
    if (stats && (stats->packets % 10 != 0)) {
        return 1; // allow packet
    }

    // Parse packet headers
    __u16 protocol = 0;
    __u32 src_ip = 0, dst_ip = 0;
    __u16 src_port = 0, dst_port = 0;

    // Try to parse IPv4
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return 1;
    }

    // Check if IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return 1;
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return 1;
    }

    protocol = iph->protocol;
    src_ip = iph->saddr;
    dst_ip = iph->daddr;

    // Parse TCP/UDP ports
    if (protocol == 6 || protocol == 17) { // TCP or UDP
        void *transport = (void *)(iph + 1);
        if (protocol == 6) {
            struct tcphdr *tcp = transport;
            if ((void *)(tcp + 1) <= data_end) {
                src_port = bpf_ntohs(tcp->source);
                dst_port = bpf_ntohs(tcp->dest);
            }
        } else {
            struct udphdr *udp = transport;
            if ((void *)(udp + 1) <= data_end) {
                src_port = bpf_ntohs(udp->source);
                dst_port = bpf_ntohs(udp->dest);
            }
        }
    }

    // Emit event to ring buffer
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 1; // allow packet even if we can't log
    }

    e->event_type = EVENT_PACKET;
    e->cgroup_id = cgroup_id;
    e->pid = pid;
    e->uid = uid;
    e->protocol = protocol;
    e->direction = 0; // egress
    e->pkt_len = pkt_len;
    e->src_ip = src_ip;
    e->dst_ip = dst_ip;
    e->src_port = src_port;
    e->dst_port = dst_port;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);

    return 1; // always allow packet — observer only, no enforcement
}

char _license[] SEC("license") = "GPL";
