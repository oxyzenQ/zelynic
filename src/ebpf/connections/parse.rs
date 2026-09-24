// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pure parsers for the kernel socket tables (NIGHT-hunt-8).
//!
//! Every function here is a pure string -> value transform over the
//! documented /proc/net/{tcp,tcp6,udp,udp6} row format, unit-tested
//! with real-format fixtures — the walking/caching side lives in the
//! parent module and stays thin.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use super::{Proto, SocketInfo};

// ── Pure parsers (unit-tested) ──────────────────────────────────────────────

/// Parse one /proc/net/{tcp,tcp6,udp,udp6} data line into
/// (inode, SocketInfo). Header lines and malformed rows return None.
pub(crate) fn parse_proc_net_line(line: &str, proto: Proto) -> Option<(u64, SocketInfo)> {
    let mut fields = line.split_whitespace();
    let _sl = fields.next()?; // "0:" slot index
    let _ = fields.next()?; // local address (display uses the remote side)
    let remote = fields.next()?;
    let state = fields.next()?;
    let queues = fields.next()?;
    // skip tr:tm->when, retrnsmt, uid, timeout
    let _ = fields.next()?;
    let _ = fields.next()?;
    let _ = fields.next()?;
    let _ = fields.next()?;
    let inode: u64 = fields.next()?.parse().ok()?;

    // tx_queue:rx_queue is one field, both hex.
    let (tx_q, rx_q) = parse_queues(queues)?;

    let remote_addr = parse_endpoint(remote)?;

    Some((
        inode,
        SocketInfo {
            proto,
            remote: remote_addr,
            state: state_name(state)?,
            queued: tx_q > 0 || rx_q > 0,
            // The cookie is fd-side knowledge (pidfd_getfd + SO_COOKIE
            // during the fd walk, NIGHT-boost-26) — the socket TABLE
            // row cannot know it.
            cookie: None,
        },
    ))
}

/// Parse "00000000:00000000" queue field into (tx, rx).
fn parse_queues(field: &str) -> Option<(u64, u64)> {
    let (tx, rx) = field.split_once(':')?;
    Some((
        u64::from_str_radix(tx, 16).ok()?,
        u64::from_str_radix(rx, 16).ok()?,
    ))
}

/// Parse an fd directory-entry name ("/proc/<pid>/fd/<n>") into the
/// fd number (NIGHT-boost-26: the cookie join needs the RAW fd for
/// pidfd_getfd). Non-numeric names (impossible in fd/) yield None.
pub(crate) fn parse_fd_number(name: &std::ffi::OsStr) -> Option<i32> {
    name.to_str()?.parse().ok()
}

/// Parse "IPHEX:PORTHEX" into a display endpoint string.
fn parse_endpoint(field: &str) -> Option<String> {
    let (ip_hex, port_hex) = field.split_once(':')?;
    let port: u16 = u16::from_str_radix(port_hex, 16).ok()?;
    let addr = match ip_hex.len() {
        8 => SocketAddr::from((parse_ipv4_hex(ip_hex)?, port)),
        32 => SocketAddr::from((parse_ipv6_hex(ip_hex)?, port)),
        _ => return None,
    };
    Some(addr.to_string())
}

/// Parse the 8-hex-char little-endian IPv4 word into an address.
fn parse_ipv4_hex(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let bytes = hex
        .as_bytes()
        .chunks(2)
        .rev()
        .map(|pair| {
            let pair = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(pair, 16).ok()
        })
        .collect::<Option<Vec<u8>>>()?;
    Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

/// Parse the 32-hex-char IPv6 word (four byte-swapped 32-bit groups)
/// into an address.
fn parse_ipv6_hex(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for (i, group) in hex.as_bytes().chunks(8).enumerate() {
        let group = std::str::from_utf8(group).ok()?;
        // Each 32-bit group is stored little-endian: reverse its bytes.
        let bytes = group
            .as_bytes()
            .chunks(2)
            .rev()
            .map(|pair| {
                let pair = std::str::from_utf8(pair).ok()?;
                u8::from_str_radix(pair, 16).ok()
            })
            .collect::<Option<Vec<u8>>>()?;
        octets[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }
    Some(Ipv6Addr::from(octets))
}

/// Kernel state code -> canonical name (the SSK_state enum order).
fn state_name(code: &str) -> Option<&'static str> {
    Some(match code {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => return None,
    })
}

/// Parse an fd symlink target ("socket:[12345]") into the socket inode.
pub(crate) fn parse_socket_fd(target: &str) -> Option<u64> {
    let rest = target.strip_prefix("socket:[")?;
    let num = rest.strip_suffix(']')?;
    num.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic /proc/net/tcp row resolves to its inode, remote
    /// endpoint, state, and queue flags.
    #[test]
    fn parses_tcp_line() {
        let line = "  1: 0100007F:8D2A 8FAA5A0A:01BB 01 00000012:00000456 00:00000000 00000000  1000 0 424242 1 0000000000000000 100 0 0 10 0";
        let (inode, info) = parse_proc_net_line(line, Proto::Tcp).expect("valid row");
        assert_eq!(inode, 424242);
        assert_eq!(info.remote, "10.90.170.143:443");
        assert_eq!(info.state, "ESTABLISHED");
        assert!(info.queued); // tx=0x12 or rx=0x456 nonzero
        assert_eq!(info.proto, Proto::Tcp);
    }

    /// LISTEN sockets have no traffic direction and zero queues.
    #[test]
    fn parses_listen_line() {
        let line = "  0: 00000000:0016 00000000:0000 0A 00000000:000000 00:00000000 00000000     0 0 11111 1 0000000000000000 100 0 0 10 0";
        let (inode, info) = parse_proc_net_line(line, Proto::Tcp).expect("valid row");
        assert_eq!(inode, 11111);
        // LISTEN rows: the remote side is 0.0.0.0:0 (port 22 is the
        // LOCAL field) — the parser must report exactly that.
        assert_eq!(info.remote, "0.0.0.0:0");
        assert_eq!(info.state, "LISTEN");
        assert!(!info.queued);
    }

    /// IPv4 hex words are little-endian per byte pair: 0100007F is
    /// localhost, 8FAA5A0A is 10.90.170.143.
    #[test]
    fn parses_ipv4_hex() {
        assert_eq!(
            parse_ipv4_hex("0100007F").unwrap(),
            Ipv4Addr::new(127, 0, 0, 1)
        );
        assert_eq!(
            parse_ipv4_hex("8FAA5A0A").unwrap(),
            Ipv4Addr::new(10, 90, 170, 143)
        );
        assert!(parse_ipv4_hex("0100007").is_none()); // 7 chars
    }

    /// IPv6 hex is four byte-swapped 32-bit groups (::1 round trip).
    #[test]
    fn parses_ipv6_hex() {
        assert_eq!(
            parse_ipv6_hex("00000000000000000000000001000000").unwrap(),
            Ipv6Addr::LOCALHOST
        );
        // ::ffff:127.0.0.1 (IPv4-mapped)
        assert_eq!(
            parse_ipv6_hex("0000000000000000FFFF00000100007F").unwrap(),
            Ipv6Addr::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1])
        );
    }

    /// Queue field splits into (tx, rx) hex values.
    #[test]
    fn parses_queues() {
        assert_eq!(parse_queues("00000000:00000000").unwrap(), (0, 0));
        assert_eq!(parse_queues("0000000A:00000014").unwrap(), (10, 20));
        assert!(parse_queues("00000000").is_none());
    }

    /// fd symlink targets parse only for sockets.
    #[test]
    fn parses_socket_fd_targets() {
        assert_eq!(parse_socket_fd("socket:[12345]").unwrap(), 12345);
        assert_eq!(parse_socket_fd("socket:[0]").unwrap(), 0);
        assert!(parse_socket_fd("pipe:[12345]").is_none());
        assert!(parse_socket_fd("socket:12345").is_none());
        assert!(parse_socket_fd("/dev/null").is_none());
    }

    /// Unknown state codes are rejected, not guessed.
    #[test]
    fn rejects_unknown_state() {
        assert!(state_name("FF").is_none());
        assert_eq!(state_name("0A").unwrap(), "LISTEN");
    }

    /// Endpoint formatter covers both families.
    #[test]
    fn parses_endpoints() {
        assert_eq!(parse_endpoint("0100007F:0035").unwrap(), "127.0.0.1:53");
        assert_eq!(
            parse_endpoint("00000000000000000000000001000000:01BB").unwrap(),
            "[::1]:443"
        );
        assert!(parse_endpoint("nope").is_none());
    }
}
