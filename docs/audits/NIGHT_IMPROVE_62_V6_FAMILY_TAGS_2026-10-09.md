<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-improve-62 audit — the family the table knew, the tag now speaks

> Audit date: 2026-10-09 (night-improve-62, after night-improve-61).
> Scope: the owner's approved ask — support different tcp6/udp6. The
> kernel walks six socket tables; the tag spoke three spellings.
> Method: one enum split at the walk's source, one spelling point
> unchanged in law, every surface inherited it through the existing
> plumbing — six spellings, one as_str, zero new render code paths.

## 1. The collapse (the find)

`read_socket_tables` walks six tables into one inode-keyed map —
but the 57-era array collapsed the family at the door:
`/proc/net/tcp6` mapped to `Proto::Tcp`, `udp6` to `Proto::Udp`,
`raw6` to `Proto::Raw`. The suffix was unrecoverable downstream:
the table knew the family, the tag didn't. An IPv6 socket read
`tcp` at the tag, so the family reached the eye only through the
bracketed remote (`[::1]:443`) — and a dual-stack host's two kinds
of 443 were tagged identically. The owner's ask, verbatim intent:
support different tcp6/udp6.

## 2. The split (six variants, one spelling)

The `Proto` enum grew the three v6 variants (`Tcp6` / `Udp6` /
`Raw6`), the walk's array now maps six tables to six protos
one-for-one — the rows read like the kernel's own table list —
and `as_str` gained the three v6 spellings (`tcp6` / `udp6` /
`raw6`, the ss and netstat vocabulary, the operator's existing
dialect, not a new one). Two consumers moved with the law:

- `endpoint_text`: the 61-era three-if chain retired — the tag
  renders through the one `as_str` call alone (a fourth branch per
  family would have been a drift point born the same day the v6
  spellings landed; six spellings, one call, same output for the
  v4 rows).
- `is_displayable`: the v6 arms ride the existing gates by
  transport (`Tcp | Tcp6`, `Udp | Udp6`, `Raw | Raw6`) — the
  family changes the tag, never the census. The v6 remote guard
  needed zero new code: an unbound v6 socket's remote is `[::]:0`
  (or the mapped `[::ffff:...]:0` listener), both end in `:0`,
  so hunt-15's law filters the v6 listeners exactly as it filters
  the v4 ones.

## 3. The hunt finds beyond the ask

- **raw6**: the same ambiguity one table over — a v6 raw socket
  tagged plain `raw` has the identical ambiguity the owner is
  closing for tcp6/udp6. The family law carves no exceptions: the
  table name is the tag.
- **The stale module header**: `connections.rs`'s doc listed four
  tables (`{tcp,tcp6,udp,udp6}`) while six have walked since
  night-improve-57 — the header caught up here.
- **The doc surfaces**: USAGE's detail-tree vocabulary row and the
  GLOSSARY proto-tags entry re-spelled to the six-tag family; the
  depth report's canonical example gained a `tcp6` row (one v4
  example kept, one converted — the example shows both families);
  the `--depth --print-json` example gained a `tcp6` endpoint with
  the honest `null` figures (the join unresolved — no fabricated
  zeros, the traffic totals untouched).

## 4. The pins

The as_str unit pin (six spellings, one pin, parse.rs tests); the
v6 gate pins in the census family (tcp6 ESTABLISHED / LISTEN,
udp6's `[::]:0` listener hidden, raw6 unconditional); the depth row
pin (`[2001:db8::1]:443 tcp6 ESTABLISHED [dl 3.0 KB/s | ul 100 B/s]`
through the focus lane the udp and raw tags were pinned in, plus
the census fallback row carrying the same suffix); the JSON pin
(`"proto":"tcp6"` in the endpoints array, `"proto":"tcp"` pinned
beside it — the v4 spelling was never field-pinned before).

The v6 pins pushed detail_tests.rs over the LOC cap — the improve-44
law answered the same hour: the displayable-census family
(`is_displayable`'s pins, three tests) took their own file
(detail_census_tests.rs), the boost-26 bytes-family precedent, a
pure move (888 green before and after, fmt clean in between).

## 5. The A/B (the owner's protocol)

Baseline captured on the pre-change tree (0de5e4d) with
`./scripts/bench/frame-bench.py --save` before the first edit; the
after-capture runs on the landed tree per the 61-era protocol. The
change touches the detail-line render path (one `as_str` call
replacing a three-branch chain) and the walk's array — the numbers
are reported in the session record beside this audit. The expected
shape: noise-level (the branch chain was predictable-shape code);
nothing here is assumed — the frame harness measures it.

## 6. What was deliberately NOT touched

The bench fixtures (frame-bench drives synthetic sockets with the
v4 protos — changing them would break the A/B's comparability, the
baseline and the after must render the same shapes); the BPF side
(the observer is protocol-agnostic, keyed on cgroup + cookie — no
L4 filtering exists to split); the remote formatting (Rust's
`SocketAddr` display already brackets the v6 form, `[::1]:443`
since the parser's first day); the version (the owner's call
alone).
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
