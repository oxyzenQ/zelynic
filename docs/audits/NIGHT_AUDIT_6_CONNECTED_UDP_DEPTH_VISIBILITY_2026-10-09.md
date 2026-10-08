<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# night-audit-6 — connected-UDP visibility in eagle-eyes --depth (2026-10-09)

The owner's live session asked the verification question directly:
`sudo zelynic -v eagle-eyes brave --depth` listed 13 sockets for the
limited cgroup, rendered 10 endpoint rows, and every rendered row read
`tcp ESTABLISHED` — zero `udp` rows on a browser that speaks QUIC
(HTTP/3 over UDP/443) all day. Is the UDP path real, or is it a blind
spot? This record is the walk, the find, the fix, and the proof.

## The question, sharpened

The depth report's traffic focus promises per-endpoint byte
attribution joined from the BPF per-socket cookie maps. QUIC-era
traffic lives on UDP — if connected-UDP sockets never render, the
report answers "which endpoint is MOVING" with the UDP movers missing.
The one-bucket cgroup numbers would still be kernel-true (the
cgroup_counters are protocol-agnostic); the per-socket story would be
silently incomplete.

## The walk (source first, then the kernel)

1. **The observer is protocol-agnostic.** `ebpf/src/main.rs` attaches
   `cgroup_skb(egress)` and `cgroup_skb(ingress)` and books every
   packet onto `bpf_get_socket_cookie(skb)` — no protocol filter, and
   at the ingress attach the hook fires per-socket from
   `sk_filter_trim_cap` (UDP unicast included), so UDP bytes reach
   both `socket_counters` maps. Nothing here hides QUIC.
2. **The census enumerates UDP.** `src/ebpf/connections.rs`
   `read_socket_tables()` reads `/proc/net/{tcp,tcp6,udp,udp6}`;
   `Proto::Udp` rows ride the same inode join and the same
   pidfd_getfd + `SO_COOKIE` discovery. Nothing here hides QUIC.
3. **The display gate did.** `src/ebpf/render/detail.rs`
   `is_displayable()` accepted only
   `state == "CLOSE" && !remote.ends_with(":0")` for UDP, citing
   NIGHT-hunt-15's note: "/proc/net/udp uses state 07 for a connected
   UDP socket." That model is wrong about the connected case.
4. **The kernel said so, live.** An empirical probe (connect() a UDP
   socket to 8.8.8.8:443, bind() an unconnected one, read the new
   `/proc/net/udp` rows): the connected socket's row reads state
   `01` (TCP_ESTABLISHED), the unconnected one `07` (TCP_CLOSE). A
   connected UDP socket therefore failed the `CLOSE`-only gate and
   was filtered as listener noise — exactly the rows the `udp` tag
   exists to surface ("QUIC-era traffic lives there").

## The mechanism behind the owner's output

The limited cgroup's header said `13 sockets`; the traffic section
rendered 10 rows with no `+N more` overflow note (the cap is 12,
`report.rs` `SOCKET_LINES_CAP`). Both facts agree once the gate is
counted: 10 displayable TCP rows rendered, and the remaining sockets —
connected-UDP among them — were filtered BEFORE the cap, so they are
neither shown nor counted as hidden. The JSON document
(`depth_json.rs`) lists every held socket with no displayability
filter, which is why the JSON surface stayed honest while the text
report hid the rows.

## The fix

One gate, one place — `is_displayable()` in `detail.rs`, the gate the
live detail tree and the depth traffic focus share by construction:

```rust
Proto::Udp => {
    (socket.state == "CLOSE" || socket.state == "ESTABLISHED")
        && !socket.remote.ends_with(":0")
}
```

The remote guard keeps hunt-15's original victory (bound-only
listeners — chronyd, systemd-resolved, mDNS — stay hidden); the state
model now matches the kernel. The stale hunt-15 comment is corrected
in place, and the docs' standing claim ("Established TCP and connected
UDP only" — `USAGE.md`'s detail-tree row) is now behavior instead of
intent.

## The verification

- **Probe**: connected UDP reads `01`, unconnected reads `07` (live
  kernel, no privileges needed for own-namespace sockets).
- **Pins**: `displayable_connected_udp_is_traffic` (the gate: the
  QUIC shape shown, the nc shape shown, both `0.0.0.0:0` and `[::]:0`
  hidden, TCP law untouched) and `connected_udp_reaches_the_traffic_rows`
  (a state-01 UDP socket renders `142.250.191.78:443 udp ESTABLISHED
  [dl 5.0 KB | ul 700 B]` and ranks movers-first when it out-eats the
  TCP rows).
- **Battery**: 839 binary tests + 58 integration tests passed, zero
  failures, under `--features ebpf`; clippy (`--features ebpf
  --all-targets -D warnings`) and `cargo fmt --all --check` clean.
- **Frame A/B (10s, the fixed-seed harness)**: bytes/frame identical
  (1919.0 both runs), rows and width identical, density gini 0.3223 →
  0.3225, frame entropy 3.2049 → 3.2042, dirty cells 82.4 → 82.3,
  fps within run noise — the layout engine is untouched for the
  TCP-only fixture, as the gate-only change requires.

## Honest residuals

- The per-connection QUIC story is the LIMITER's own lane (schema v22,
  the CID-keyed per-socket shape): one UDP socket carries many QUIC
  connections, and `--per-socket` keys buckets by connection ID. The
  depth report's UDP row shows the SOCKET (its remote, its window
  bytes) — per-connection attribution inside one socket is
  enforcement bookkeeping, not socket-census work, and stays there.
- The fix's visible effect on a live host needs UDP traffic in the
  focus window; a host whose browsers disabled QUIC (or a 3s window
  where UDP moved nothing) still shows TCP rows only — with the
  difference that displayable UDP endpoints now render even when
  byteless, instead of being invisible at any traffic level.
