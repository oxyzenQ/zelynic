// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
#![no_main]

use libfuzzer_sys::fuzz_target;

/// Fuzz socket parsing from /proc/net/tcp output.
/// This parses untrusted kernel output.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Try to parse lines as socket entries
        for line in s.lines() {
            // Parse hex addresses, ports, states
            let _ = parse_socket_line(line);
        }
    }
});

/// Simplified socket line parser for fuzzing
fn parse_socket_line(line: &str) -> Option<(u64, u32, u32)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }
    
    // Parse local address
    let local = parts.get(1)?;
    let remote = parts.get(2)?;
    let state = parts.get(3)?;
    let inode = parts.get(9)?;
    
    // Parse hex addresses
    let local_addr = u64::from_str_radix(local.split(':').next()?.trim(), 16).ok()?;
    let local_port = u32::from_str_radix(local.split(':').nth(1)?.trim(), 16).ok()?;
    
    Some((local_addr, local_port, 0))
}
