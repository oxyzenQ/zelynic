<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The Golden Vectors — Release Attestation Appendix

Every release carries the usual cryptographic proof — the three
checksum files and the detached GPG signature documented in
[VERIFY_RELEASE.md](VERIFY_RELEASE.md) — which attests that an
artifact is authentic and intact. The golden vectors attest the
other half, the part a checksum cannot see: that the artifact's
**pure IP layer** — the deterministic parsing surface over all six
`/proc/net` table families — behaves EXACTLY as this appendix
records, byte for byte, on every host it will ever run on. Checksums
prove the package
was not tampered with; the vectors prove the behavior inside it is
the behavior the release notes describe.

## What the pure IP layer is

The pure layer is the side-effect-free parsing surface of the zelynic
engine: frozen `/proc/net/{tcp,tcp6,udp,udp6,raw,raw6}` row text in,
a structured verdict out — no clock, no filesystem, no environment,
no map iteration. The home is
`src/ebpf/connections/parse.rs` (the `golden_vectors` test module is
the **corpus of record**; this appendix mirrors it for reading, and
the test is the authority). Because the layer is a total function of
its input bytes, its behavior is *attestable knowledge*: the
determinism contract (the total row orders of
[STABILITY.md](STABILITY.md)) is what makes the engine's exact
verdicts ownable, reproducible, and worth pinning per release —
anyone with the corpus can reproduce the engine's parsing behavior
on any machine, forever.

## The ratification law

- The corpus is executable. `cargo test --locked golden_vectors`
  walks every vector and refuses any drift — no root, no eBPF, no
  network, any host, offline.
- Every CI run re-ratifies. The same battery rides the Dragon Guard
  CI workflow on every commit and every release tag, so a tagged
  release can never ship whose pure layer disagrees with this
  appendix.
- An output change IS a corpus change. If a future release changes
  one verdict — an endpoint spelling, a state name, a rejection —
  the corpus row changes with it, and the release notes must carry
  the verdict diff (the honest behavioral changelog, vector id by
  vector id). The diff between two releases' appendix states is
  exactly the pure layer's behavioral changelog between them.
- The vector ids are stable. `GV-NN:slug` never mutates meaning; a
  changed verdict keeps its id, a removed input retires its id, a
  new input takes the next number. The appendix keys on them; the
  test failure messages name them.

## How to ratify a build yourself

```bash
git checkout v80.3.1        # or any tag / commit
cargo test --locked golden_vectors
```

Three tests run: the corpus walk (`the_golden_corpus_ratifies_the_ip_layer`,
18 vectors), the state table pin (`the_state_table_is_canonical`,
the kernel's eleven codes and the eight refusal shapes), and the
corpus integrity pin (`the_corpus_keeps_its_names_unique_and_families_covered`).
All green = the build's pure IP layer matches this appendix exactly.

## The corpus

### GV-01:tcp-established-v4

Input (`Proto::Tcp`):

```
  3: 0100007F:8D2A 34120A0A:01F5 01 00000000:00000014 00:00000000 00000000  1000 0 777001 1 0000000000000000 100 0 0 10 0
```

Verdict: parses — inode `777001`, remote `10.10.18.52:501`, state
`ESTABLISHED`, queued `true` (rx `0x14` nonzero).

### GV-02:tcp-listen-v4

Input (`Proto::Tcp`):

```
  0: 00000000:0016 00000000:0000 0A 00000000:000000 00:00000000 00000000     0 0 22221 1 0000000000000000 100 0 0 10 0
```

Verdict: parses — inode `22221`, remote `0.0.0.0:0`, state `LISTEN`,
queued `false`.

### GV-03:tcp-time-wait-v4

Input (`Proto::Tcp`):

```
  9: 0100007F:8D2A 8FAA5A0A:01BB 06 00000000:00000000 00:00000000 00000000  1000 0 555003 1 0000000000000000 100 0 0 10 0
```

Verdict: parses — inode `555003`, remote `10.90.170.143:443`, state
`TIME_WAIT`, queued `false`.

### GV-04:tcp-established-v6

Input (`Proto::Tcp6`):

```
 24: 00000000000000000000000000000000:9C40 00000000000000000000000001000000:01BB 01 00000000:00000000 00:00000000 00000000  1000 0 888004 1 0000000000000000 100 0 0 10 0
```

Verdict: parses — inode `888004`, remote `[::1]:443`, state
`ESTABLISHED`, queued `false`.

### GV-05:udp-connected-v4

Input (`Proto::Udp`):

```
 12: 00000000:0000 0100007F:0035 01 00000000:00000438 00:00000000 00000000  1000 0 333002 1 0000000000000000 100 0 0 10 0
```

Verdict: parses — inode `333002`, remote `127.0.0.1:53`, state
`ESTABLISHED`, queued `true` (rx `0x438` nonzero).

### GV-06:raw-established-v4

Input (`Proto::Raw`):

```
  0: 00000000:0000 04030201:0000 01 00000000:00000012 00:00000000 00000000  0  0 444010 1 0000000000000000 0
```

Verdict: parses — inode `444010`, remote `1.2.3.4:0`, state
`ESTABLISHED`, queued `true`. A `connect()`ed raw socket (the ping
shape), port always `0`.

### GV-07:raw-unbound-v4

Input (`Proto::Raw`):

```
  0: 00000000:0000 00000000:0000 07 00000000:00000000 00:00000000 00000000  0  0 444011 1 0000000000000000 0
```

Verdict: parses — inode `444011`, remote `0.0.0.0:0`, state `CLOSE`,
queued `false`. An unbound raw socket reports its non-destination
verbatim.

### GV-08:raw6-close-v6

Input (`Proto::Raw6`):

```
  0: 00000000000000000000000000000000:0000 00000000000000000000000001000000:0000 07 00000000:00000000 00:00000000 00000000  0  0 444012 1 0000000000000000 0
```

Verdict: parses — inode `444012`, remote `[::1]:0`, state `CLOSE`,
queued `false`.

### GV-09:byte-swap-law-v4

Input (`Proto::Tcp`):

```
  5: 0100007F:8D2A 78563412:0050 01 00000000:00000000 00:00000000 00000000  1000 0 666005 1 0000000000000000 100 0 0 10 0
```

Verdict: parses — inode `666005`, remote `18.52.86.120:80`, state
`ESTABLISHED`, queued `false`. The byte-swap law's dedicated
witness: the kernel prints each address as one little-endian
32-bit word, so `78563412` — the LE spelling of `0x12345678` —
reads back `18.52.86.120` (`0x12.0x34.0x56.0x78`).

### GV-10:v6-mapped-endpoint

Input (`Proto::Tcp6`):

```
 31: 00000000000000000000000000000000:9C40 0000000000000000FFFF00000100007F:0016 01 00000000:00000000 00:00000000 00000000  1000 0 999006 1 0000000000000000 100 0 0 10 0
```

Verdict: parses — inode `999006`, remote `[::ffff:127.0.0.1]:22`,
state `ESTABLISHED`, queued `false`. The IPv4-mapped v6 display
form survives the round trip verbatim.

### GV-11:reject-unknown-state

Input (`Proto::Tcp`): the GV-01 row with the state column `FF`.

Verdict: REJECTED (`None`) — an unknown state code is never guessed
into a name.

### GV-12:reject-short-hex-endpoint

Input (`Proto::Tcp`): the GV-01 row with the remote endpoint
`0A0A123:01F5` (a seven-hex-digit address word).

Verdict: REJECTED (`None`) — an address word is exactly 8 hex
digits (v4) or exactly 32 (v6); nothing else parses.

### GV-13:reject-odd-address-width

Input (`Proto::Tcp`): the GV-01 row with the remote endpoint
`0000FFFF00000100:0050` (a sixteen-hex-digit address word).

Verdict: REJECTED (`None`) — the width gate accepts only the two
kernel-printed shapes.

### GV-14:reject-queue-without-colon

Input (`Proto::Tcp`): the GV-01 row with the queue column
`00000014` (no `tx:rx` colon).

Verdict: REJECTED (`None`) — the queue column is always one
`tx:rx` pair; a bare field is a malformed row.

### GV-15:reject-non-numeric-inode

Input (`Proto::Tcp`): the GV-01 row with the inode column
`garbage`.

Verdict: REJECTED (`None`) — the inode is the census's final sort
key; a non-numeric one is a malformed row, never a coerced zero.

### GV-16:reject-header-line

Input (`Proto::Tcp`):

```
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
```

Verdict: REJECTED (`None`) — the header row dies on the inode
parse; only data lines carry verdicts.

### GV-17:reject-truncated-row

Input (`Proto::Tcp`):

```
  3: 0100007F:8D2A 34120A0A:01F5 01
```

Verdict: REJECTED (`None`) — a row cut short of the queue column is
a malformed row.

### GV-18:udp6-close-v6

Input (`Proto::Udp6`):

```
 17: 00000000000000000000000000000000:9C40 00000000000000000000000001000000:0035 07 00000000:00000000 00:00000000 00000000  1000 0 444013 1 0000000000000000 100 0 0 10 0
```

Verdict: parses — inode `444013`, remote `[::1]:53`, state `CLOSE`,
queued `false`. The sixth table family's witness: `udp6` rows print
the same 32-hex address + port shape the `tcp6` and `raw6` rows do,
and the corpus demands every family carry at least one vector.

## The state table

The kernel's eleven TCP state codes, the exact canonical spellings
the layer publishes (the SSK_state vocabulary):

| Code | Name |
|------|------|
| `01` | `ESTABLISHED` |
| `02` | `SYN_SENT` |
| `03` | `SYN_RECV` |
| `04` | `FIN_WAIT1` |
| `05` | `FIN_WAIT2` |
| `06` | `TIME_WAIT` |
| `07` | `CLOSE` |
| `08` | `CLOSE_WAIT` |
| `09` | `LAST_ACK` |
| `0A` | `LISTEN` |
| `0B` | `CLOSING` |

Everything else is rejected — unknown codes (`FF`, `0C`), zero
(`00`), lowercase spellings (`0a`), single letters, two-letter
words, the empty string. The no-match contract (the eBPF-verifier
lineage: reject, never a soft guess) holds at the state column's
own grain.

## What this appendix does NOT attest

Honest scope, the same discipline the claims verification (QA.md)
holds everywhere: the corpus attests the PURE parsing layer — the
deterministic, environment-free transforms above. It does not
attest live kernel behavior; the /proc table a real kernel prints,
the eBPF attach paths, and the enforcement lanes are attested by
the 5.15-floor cross-distro matrix and the Supermassive CI battery
on real kernels, and the doctor's capability ladder
(`src/ebpf/helper_ladder.rs`) itemizes the kernel facts those lanes
stand on. The three proofs compose: the vectors for the parse law,
the matrix for the kernel law, the signature for the artifact law.

## The IP note

The corpus is also the engine's behavioral fingerprint in the
plainest sense: the exact verdicts on the exact frozen inputs are
proprietary knowledge — reproducible by anyone, but authored by the
one party that holds the determinism discipline end to end. A
competitor can read this appendix; matching it requires the
underlying order laws (the byte-swap handling, the width gates, the
state vocabulary, the final-inode tie) to hold across every distro
kernel the floor covers — which is precisely the work the ledger
records. The appendix ships inside the release package as the
ratification page: artifact (signature), behavior (vectors),
kernel (matrix) — three legs, one attestation.

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
