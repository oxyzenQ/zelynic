<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# night-hunt-40 — the five-lane root audit (2026-10-09)

The owner's mandate after night-audit-6's fix landed: hunt what is
still unknown, across the whole root repo, in five lanes — stability
and crash, code hygiene, optimization, security hardening, and LTS
stability — with a per-stage method and an explicit skip rule: a
stage already at peak is skipped and the skip is evidenced, not
asserted. This record is the walk, the finds, the fixes, and the
peaks.

Method note: three independent pattern sweeps (crash vectors, dragons,
security surface) ran over production `src/` first; every reported
find was then re-verified by hand against the source before any edit
— the sweeps' justified-invariant classifications were checked as
hard as their bugs.

## Lane 1 — stability and crash: 2 real panics, both fixed

The panic-discipline scan over ~31.7k LOC found exactly two reachable
crash vectors; everything else it surfaced was a verified-invariant
unwrap (guarded above its use) or a documented cast contract.

**Find 1 — the OSC 11 split-ST panic (`src/terminal/raw.rs`).**
`reply_front()` measured the reply span as `terminator_index + head +
(1 or 2)`. When an ST terminator's ESC landed as the buffer's final
byte — its backslash still in flight — `end` computed to
`bytes.len() + 1` and `&bytes[..end]` panicked: range end out of
range. That split is not exotic: it is the exact split-answer shape
`BgAsk::absorb` exists to reassemble, produced by any muxer or pty
that breaks the reply across input wakes, and the caller sits in the
eagle-eyes monitor loop — the crash ends a live session. The fix
treats a span past the end as an incomplete reply (`None`), parking
the partial under the existing cap; a pin proves the split fixture
reads `None` and the completed bytes still parse.

**Find 2 — the docker short-id char-boundary panic
(`src/ebpf/identity/container/docker.rs`, two sites).** Both
`&id[..12.min(id.len())]` spellings panic when byte 12 falls
mid-UTF-8 on a daemon-supplied `Id`. Docker ids are hex in practice,
but the parser deliberately survives a lying daemon — char-boundary
safety belongs to that same contract. `short_id()` now takes the
first 12 chars; two pins hold it.

**Verified clean, on the record:** no `unreachable!/todo!/
unimplemented!` in non-test code; all counter deltas use the
deliberate `wrapping_sub` + 2^63 discriminator (LRU restart vs wrap);
sizing math is saturating/checked throughout; every narrowing cast
found is either the documented BPF map-key contract or clamped before
the cast; the 20 highest-suspicion indexing sites each carry their
guard above the use. Visual/performance regression check: the battery
plus the byte-identical depth pins (lane 2's dedupe is provably
output-identical).

## Lane 2 — code hygiene: the dragons found, the honest residue noted

**Fixed this hunt:**

- A stale `#[allow(dead_code)]` plus a contradicted doc on
  `RingReads::absent()` — production's own `read_pinned_rings()`
  returns that spelling on schema mismatch; the "test-facing
  constructor, never through this spelling" note predates the call
  site.
- A stale `#[allow(clippy::too_many_arguments)]` on a four-argument
  function (`display.rs::collect_display_data`) — copied from the
  pre-split signature.
- Three identical `Proto` → `"tcp"/"udp"` ternaries (depth focus
  rows, basic census fallback, JSON document) collapsed into one
  `Proto::as_str()`.
- The depth traffic section's two arms carried two copies of the
  `SOCKET_LINES_CAP` loop and the verbatim overflow note; one
  `capped_rows()` law now serves both — byte-identical by
  construction, pinned by the depth report tests.
- One genuine zombie: `run_zel_as_user()` in the harness python lib,
  zero call sites since the changelog era, removed.

**Noted, deliberately not fixed:** the anti-drift "movers first"
ranking law exists in two copies (the live trees share one by
design; the depth focus carries its own — same semantics today, a
documented future drift point); the `[dl X | ul Y]` suffix
vocabulary has two spellings (one adds single-direction arms); the
block verb mirrors four strict-family strings by documented
symmetry. These are structural notes for a round with the frame
A/B harness in hand, not defects — none changes behavior today.

## Lane 3 — optimization: peak for this environment, evidenced

Skipped per the mandate, with the evidence: the audit environment
has no root, no live eBPF attach, and therefore no profiling data,
and the micro-optimization rule here is measurement-first. The sweeps
found no algorithmic offender (no accidental O(n^2), no hot-path
allocation loop worth a blind change), the prior perf lineage
(NIGHT_PERF_2 endurance audit, the boost series) already walked the
hot paths, and the one allocation-shaped candidate (the unbounded
`/proc/net/*` table materialization on a half-million-socket host,
lane 4's F-rank 11) is bounded by the machine's own socket table and
is a memory-pressure nuisance, not a win to claim blind. Any
micro-opt belongs to a session that can run the 10s A/B against a
live object.

## Lane 4 — security hardening: 2 fixes, and the hardened inventory

**Fixed:**

- The docker lane's daemon strings now pass `sanitize_comm` at the
  parse choke point (Id, Names, State status) — the sanitize.rs
  contract ("every downstream consumer safe by construction")
  previously stopped at the docker lane's doorstep, leaving refusal
  lines, ambiguous lists, and display labels rendering daemon bytes
  verbatim (the OSC 52 / forged-row / alt-screen families). Honest
  strings are byte-identical through the fast path.
- The probe honesty drift: `dir_is_clean()` read
  `u32::try_from(ino).unwrap_or(0)` while the identity lane keys its
  maps with truncating `id64 as u32` — on an inode past 2^32 the
  VERIFIED probe could consult the wrong row and measure inside a
  policed chain. One spelling now: the map key's own.

**The hardened inventory, verified rather than assumed:** no memory
unsafety in the ~60 unsafe sites (every invariant documented, the
regression-prone ones pinned); zero shell exec — the three Command
sites run fixed-argument tools (curl to a fixed URL behind a root
refusal, stty/reset/tput behind the PATH pin, self-exe probe roles);
every bpffs path is a fixed const, checked against the statfs magic
not path existence; /proc/net parsing is a skip-on-error Option
pipeline whose malformed rows reject, never misparse into wrong
data; rate/duration/during parsers do exact checked u128 math that
errors on overflow; the lock lives in root-owned 0700 /run/zelynic;
one canonical terminal sanitizer guards comm, argv, readlink, and
tag boundaries; the dangerous-target blocklist closes the numeric
`cg:` bypass.

**Disclosed by design (documented, not changed):** the rootless
docker socket candidate honors `XDG_RUNTIME_DIR` — reachable only
under an explicit `sudo -E`, an opt-in env leak; comm remains an
authentication-less identifier (an unprivileged process can spoof a
name and route targeting onto its own cgroup — bounded by design,
worth a threat-doc note); `unpin_all()` sweeps everything inside
zelynic's own bpffs directory (root-vs-root scope only); the update
cooldown's /tmp fallback stamp is a fail-open, disclosed
accepted-risk.

## Lane 5 — LTS stability: peak carried forward, plus lane 1's close-out

The long-term lineage is deep: the NIGHT_TOTAL_LTS series (rounds
1–11, two of them all-infra) and the MITIGATE endurance rounds
already audited data explosion, rate-row fleets, ceiling laws, and
lock posture. This hunt's LTS re-check over the same ground found no
new hidden failure mode; what it did find is that the one remaining
long-session failure mode was lane 1's split-ST panic — a monitor
that dies after hours in a muxer precisely because a split arrived
late in the session. That is now fixed and pinned. The standing
disclosures remain on the record: the u32 cgroup-id map key is safe
under the kernel's kernfs IDR allocation contract (documented
in-tree, kept); counter wrap is coherent across restarts by the
pinned discriminator; the JSON/frame surfaces' caps keep every
document bounded.

## The delta

- `4b99d16` — lane 1: the split-ST terminator panic in the OSC 11
  reply gate, fixed and pinned.
- `91d2361` — lanes 1+4: the docker lane's char-boundary panic and
  the daemon sanitize choke point, three pins.
- `ed3b029` — lane 4: the probe cleanliness law reads the map key's
  truncation spelling.
- `d14df57` — lane 2: the hygiene sweep (two stale allowances, one
  corrected doc, one Proto spelling, one deduped cap law, one zombie
  helper).
- `cde0eb1` — disclaimer compliance on the guide and the audit-6
  record (gatekeeper sweep flagged them).

Gates: 843 binary + 58 integration tests green under `--features
ebpf` (registry-lane build), clippy `-D warnings` and rustfmt clean
on both lanes, gate-keepers 17/17, prebuilt-lane parity on every
commit. No benchmark: no lane carried a performance change, and the
render-side dedupe is byte-identical by construction and pinned.
Permissions untouched (the gatekeeper's own `--fix` pass restored
the clone's umask-drifted 664s to the canonical 644/755), package
version untouched, no tags.

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
