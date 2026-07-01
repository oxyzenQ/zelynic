// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Ring buffer event reader — consume BPF events from kernel.
//!
//! Events are produced by the BPF program (bpf/observer.bpf.c) and
//! consumed here via aya's RingBuf API.

use std::collections::HashMap;

/// Event type constants — must match BPF C source.
pub const EVENT_PACKET: u32 = 1;

/// Network event from BPF observer.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct NetworkEvent {
    pub event_type: u32,
    pub cgroup_id: u32,
    pub pid: u32,
    pub uid: u32,
    pub protocol: u16,
    pub direction: u16,
    pub pkt_len: u32,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub comm: [u8; 16],
}

impl NetworkEvent {
    /// Parse from raw bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < std::mem::size_of::<NetworkEvent>() {
            return None;
        }
        let event: NetworkEvent =
            unsafe { std::ptr::read_unaligned(data.as_ptr() as *const NetworkEvent) };
        Some(event)
    }

    pub fn comm_str(&self) -> String {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        String::from_utf8_lossy(&self.comm[..end]).to_string()
    }

    pub fn format_ip(ip: u32) -> String {
        format!(
            "{}.{}.{}.{}",
            ip & 0xFF,
            (ip >> 8) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 24) & 0xFF
        )
    }

    pub fn protocol_name(&self) -> &'static str {
        match self.protocol {
            6 => "TCP",
            17 => "UDP",
            1 => "ICMP",
            _ => "OTHER",
        }
    }
}

/// Aggregated stats per cgroup.
#[derive(Debug, Clone, Default)]
pub struct CgroupStats {
    pub packets: u64,
    pub bytes: u64,
    pub last_pid: u32,
    pub last_comm: String,
}

/// Event aggregator that processes raw event bytes.
pub struct EventAggregator {
    pub stats: HashMap<u32, CgroupStats>,
    pub total_events: u64,
    pub total_packets: u64,
    pub total_bytes: u64,
}

impl EventAggregator {
    pub fn new() -> Self {
        EventAggregator {
            stats: HashMap::new(),
            total_events: 0,
            total_packets: 0,
            total_bytes: 0,
        }
    }

    /// Process raw event bytes from the ring buffer.
    pub fn process_events(&mut self, events: &[Vec<u8>]) {
        for data in events {
            if let Some(event) = NetworkEvent::from_bytes(data) {
                self.total_events += 1;
                self.total_packets += 1;
                self.total_bytes += event.pkt_len as u64;

                // Only track top 100 cgroups to prevent unbounded memory growth
                if self.stats.len() < 100 || self.stats.contains_key(&event.cgroup_id) {
                    let stats = self.stats.entry(event.cgroup_id).or_default();
                    stats.packets += 1;
                    stats.bytes += event.pkt_len as u64;
                    stats.last_pid = event.pid;
                    stats.last_comm = event.comm_str();
                }
            }
        }
    }

    /// Print current stats summary.
    pub fn print_summary(&self) {
        println!("\n━━━ eBPF Observer Summary ━━━");
        println!("  Total events:   {}", self.total_events);
        println!("  Total packets:  {}", self.total_packets);
        println!("  Total bytes:    {}", format_bytes(self.total_bytes));
        println!("  Unique cgroups: {}", self.stats.len());
        println!();

        let mut sorted: Vec<_> = self.stats.iter().collect();
        sorted.sort_by_key(|(_, s)| std::cmp::Reverse(s.bytes));

        println!(
            "  {:<20} {:>10} {:>10} {:>8}",
            "PROCESS", "PACKETS", "BYTES", "PID"
        );
        println!("  {}", "─".repeat(52));

        for (cgid, stats) in sorted.iter().take(20) {
            println!(
                "  {:<20} {:>10} {:>10} {:>8}",
                if stats.last_comm.is_empty() {
                    format!("cgroup:{}", cgid)
                } else {
                    stats.last_comm.clone()
                },
                stats.packets,
                format_bytes(stats.bytes),
                stats.last_pid,
            );
        }

        if self.stats.len() > 20 {
            println!("  ... and {} more cgroups", self.stats.len() - 20);
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_event_from_bytes_too_short() {
        let data = [0u8; 4];
        assert!(NetworkEvent::from_bytes(&data).is_none());
    }

    #[test]
    fn test_network_event_from_bytes_valid() {
        let mut data = vec![0u8; std::mem::size_of::<NetworkEvent>()];
        data[0..4].copy_from_slice(&1u32.to_ne_bytes());
        data[4..8].copy_from_slice(&12345u32.to_ne_bytes());
        data[8..12].copy_from_slice(&1000u32.to_ne_bytes());

        let event = NetworkEvent::from_bytes(&data).unwrap();
        assert_eq!(event.event_type, EVENT_PACKET);
        assert_eq!(event.cgroup_id, 12345);
        assert_eq!(event.pid, 1000);
    }

    #[test]
    fn test_comm_str() {
        let mut event = NetworkEvent::default();
        event.comm[..5].copy_from_slice(b"brave");
        event.comm[5] = 0;
        assert_eq!(event.comm_str(), "brave");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
    }

    #[test]
    fn test_event_aggregator() {
        let mut agg = EventAggregator::new();
        let mut data = vec![0u8; std::mem::size_of::<NetworkEvent>()];
        data[0..4].copy_from_slice(&1u32.to_ne_bytes());
        data[4..8].copy_from_slice(&999u32.to_ne_bytes());
        data[8..12].copy_from_slice(&1000u32.to_ne_bytes());

        agg.process_events(&[data]);
        assert_eq!(agg.total_events, 1);
        assert_eq!(agg.stats.len(), 1);
    }
}
