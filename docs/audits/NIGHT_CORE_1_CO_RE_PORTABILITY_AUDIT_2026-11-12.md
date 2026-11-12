<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# NIGHT-CORE-1 — the CO-RE portability audit (2026-11-12)

The owner's question, after the sibling audits landed the same shape
for zylaxion (function ABI contract, zero struct field derefs) and
zejtron (a hand-written runtime BTF parser, `core_relo len=0`
measured on its object): does ZELYNIC need CO-RE? The method is the
same one that answered the siblings: measure what the datapath
actually derefs, then measure what the compiled object actually
carries. No assumption rides from any other project — every number
below was taken from this tree today.

## Verdict (one breath)

**No.** Zelynic's two shipped objects carry ZERO CO-RE relocations
(`core_relo_len = 0`, measured on both) because the datapath makes
exactly ONE category of kernel-internal field access —
`bpf_sock.protocol`, twice — and that field sits at a frozen
UAPI-defined offset (12) no kernel in the verified matrix moves.
Everything else is helper-mediated (`bpf_sk_storage_get`,
`bpf_skb_cgroup_id`, `bpf_setsockopt`, ...) or reads UAPI context
fields the kernel translates at load time. The rustc limitation that
blocks CO-RE emission (no `preserve_access_index` equivalent) is
real but irrelevant here: there is nothing to relocate. Same verdict
as zylaxion and zejtron — third project in a row, each for its own
measured reason.

## Leg 1 — the code census (what the datapath derefs)

Counted over `ebpf/src/**/*.rs` at HEAD (2026-11-12, v80.2.0,
schema v34):

Helper-mediated access — 25 call sites, every one a stable UAPI
helper the floor kernel (5.15.0, night-netrunner-1) long predates:

| helper | sites | what it mediates |
|--------|-------|------------------|
| `bpf_sk_storage_get` | 5 | the socket-local hint row (`RecwnHint`) — the RECWN lane's rate + generation + measured-srtt row and the depth histogram's srtt peek |
| `bpf_setsockopt` | 5 | the quota saver's clamps (`SO_RCVBUF` for RECWN, `SO_MAX_PACING_RATE` for pacing) |
| `bpf_skb_ecn_set_ce` | 3 | the ECN-first lane's CE mark |
| `bpf_skb_cgroup_id` | 3 | the MMSPA walk's own-cgroup resolve |
| `bpf_get_socket_cookie` | 3 | flow identity (CAKE-shaped isolation, the observer's per-endpoint join) |
| `bpf_skb_load_bytes` | 2 | the QUIC header windows (bounded, compile-time-constant stack offsets) |
| `bpf_skb_ancestor_cgroup_id` | 2 | the MMSPA ancestor walk |
| `bpf_ktime_get_ns` | 2 | the token-bucket clocks |

Context-field reads — UAPI structs (`__sk_buff`, `bpf_sock_ops`),
the ABI the kernel translates at load time and freezes once added:

| field | sites | since |
|-------|-------|-------|
| `__sk_buff.len` (`SkBuffContext::len()`) | the size lane everywhere (`pkt_len`) | frozen UAPI |
| `__sk_buff.sk` (union read) | 2 (`enforce.rs` 258, `enforce_helpers.rs` 412) | the v4.10-era `sk` arm |
| `bpf_sock_ops.is_fullsock` | 2 (`pace_flow.rs` 177, `recwn_flow.rs` 237) | 4.16-era (the code's own pin) |
| `bpf_sock_ops.sk` (union read) | 1 per apply site (`recwn_flow.rs`, `pace_flow.rs`) | verified against v5.13 and v5.15 `net/core/filter.c` (the code's citation) |
| `bpf_sock_ops.srtt_us` | 1 (`recwn_flow.rs` 295 — the RTT lane's harvest) | 4.16-era (the code's own pin) |

Kernel-internal field reads — the census's entire yield:

| type | field | sites | offset |
|------|-------|-------|--------|
| `bpf_sock` | `protocol` | 2 (`recwn_flow.rs` 248, `pace_flow.rs` 188) | 12 |

That is the WHOLE list. No `tcp_sock` deref, no `task_struct` deref,
no `sk_buff` field deref (the skb's bytes ride the helper above), no
kernel-config-dependent member anywhere.

Zelynic-owned structs (`RecwnHint`, `HistRow`, the stats/debt/ring
rows) are map values this repo defines — their layout is a contract
between the object and the loader (`SCHEMA_VERSION_EXPECTED = 34`
pins it), not a kernel dependency.

## Leg 2 — the layout law for the one candidate

`bpf_sock.protocol`'s compiled offset, read from the dependency the
build actually uses (`aya-ebpf-bindings 0.3.0`, the x86_64
bindings; the mips64/s390x/powerpc64 files carry the same prefix):

```text
bound_dev_if @ 0, family @ 4, type @ 8, protocol @ 12
```

`struct bpf_sock` is UAPI (`include/uapi/linux/bpf.h`), append-only
by UAPI discipline — the prefix above has not moved since the struct
was exposed. The verifier validates program accesses against the
running kernel's own BTF `bpf_sock` type (BTF is already a hard
requirement of this datapath: `bpf_sk_storage` needs it), so an
offset-12 load lands in `protocol` on every kernel in the verified
matrix (floor 5.15.0). The two `protocol` reads are TCP guards
(`IPPROTO_TCP`) riding the fullsock guard the same sites perform —
a misread there would refuse a lane, never corrupt it, and the
layout law says it cannot even happen.

## Leg 3 — the ELF ground truth (what the object carries)

Built today from this tree (rustc `nightly-2026-09-18` =
1.100.0-nightly, bpf-linker 0.11.1 static musl), both shipped
objects inspected with readelf + a pyelftools `.BTF.ext` header
parse:

| object | size | `.BTF` | func_info | line_info | core_relo |
|--------|------|--------|-----------|-----------|-----------|
| `zelynic-limiter.o` | 1,097,112 B | present (map definitions) | 116 B | 57,284 B | **0** |
| `zelynic-observer.o` | 108,120 B | present (map definitions) | 84 B | 1,724 B | **0** |

The `.BTF.ext` header (`hdr_len = 32`, magic `0xEB9F`) carries
func_info and line_info blocks and a `core_relo_len` field reading
**0** in both objects — the same measured result the zejtron audit
took. The mechanism matches the sibling finding: clang's
`preserve_access_index` has no rustc equivalent, so bpf-linker
emits BTF for the map definitions plus func/line info and nothing
else. Every kernel-type offset in the instructions is a compiled
constant — and Leg 1 + Leg 2 show every such constant rides a
frozen UAPI layout. One object, every kernel in the verified
matrix, no relocation needed and none present.

Reproduce the parse:

```python
import struct
from elftools.elf.elffile import ELFFile
with open('zelynic-limiter.o', 'rb') as f:
    data = ELFFile(f).get_section_by_name('.BTF.ext').data()
    _, _, _, hdr = struct.unpack_from('<HBBI', data, 0)
    vals = [struct.unpack_from('<I', data, 8 + i * 4)[0] for i in range((hdr - 8) // 4)]
    print(dict(zip(['func_off', 'func_len', 'line_off', 'line_len', 'relo_off', 'relo_len'], vals)))
    # relo_len is the measured zero
```

## The histogram answer (the owner's Phase 1 question)

Asked before the histogram shipped; answered now with the object as
witness. Both metric halves read nothing that needs relocation:

- **The size half** — `SkBuffContext::len()` (UAPI `__sk_buff.len`,
  frozen ctx ABI) straight into zelynic's own `HistRow` buckets.
  No kernel struct, no CO-RE.
- **The srtt half** — `__sk_buff.sk` (UAPI union) ->
  `bpf_sk_storage_get` (helper, lookup-only flags 0) -> zelynic's
  own `RecwnHint.srtt_us` (own map value). The VALUE's origin is the
  RTT lane's harvest: `bpf_sock_ops.srtt_us` (UAPI ctx field,
  4.16-era, the floor covers it). No kernel-internal struct, no
  CO-RE.

The shipped `zelynic-limiter.o` carries the histogram and the
measured `core_relo_len = 0` — the histogram is one-object-everywhere
on the 5.15 floor by construction, and the schema v34 entry's "no new
helper, no CO-RE" claim holds against the wire.

## When CO-RE would become real (the tripwires)

The verdict is a measurement, not a policy — these are the shapes
that would flip it:

1. **A direct deref of a kernel-internal struct beyond
   `bpf_sock`'s frozen prefix** — reading `tcp_sock.srtt_us` from
   the data path, `task_struct` fields, any `struct sock` member
   past the UAPI projection.
2. **A field whose offset moves with kernel CONFIG** — anything
   the verifier's BTF check cannot pin to an append-only UAPI
   layout.
3. **A new hook family whose context is not UAPI-frozen.**

If one fires, the mitigation ladder in honest order: (a) keep the
access helper-mediated (`bpf_getsockopt(SOL_TCP, TCP_INFO)` answers
a UAPI `tcp_info` — the same door the srtt harvest already used
indirectly); (b) a runtime BTF reader at load time (the zejtron
pattern, ~600 LOC, no new toolchain lane); (c) a clang-built side
object — last, only, because it breaks the pure-Rust build posture
and adds a toolchain the tree does not carry.

## Scope of this audit

Static census + ELF inspection of the two objects built from this
tree; the runtime matrix proof remains the supermassive lane's
5.15 floor micro-VM (pinned on every push, the same evidence
KERNEL_COMPATIBILITY.md cites). This report records the portability
position beside that floor — it changes no code, no schema, and no
release decision.

<!-- ZELYNIC-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every doc — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`, `ebpf/src/**/*.rs`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
