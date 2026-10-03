<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-total-lts-5 depth audit — the killer-features pass, round two

> Audit date: 2026-10-03 (NIGHT-total-lts-5). Scope: the owner's ask
> narrowed to the product's two killer surfaces first — the limiter
> engine and the eagle-eyes monitor — then the UX/CLI surface, then
> the remaining Rust code, under the five infra areas (stability &
> crash, code hygiene, optimization, security hardening, LTS
> stability) and the peak-skip protocol. Audited at 9eb112d
> (NIGHT-hunt-Z9's HEAD; v20.0.0-rc.1; the eBPF enforcement object
> byte-pinned throughout — the commit gates re-prove parity).
> Method: lts-3 (2026-10-02) already read the kernel enforcement
> math, the render tree, and the CLI surface line by line, so this
> pass deliberately hunted the surfaces lts-3 did NOT name — the
> kernel observer modules (socket_flow, rate_ring, stats, the
> observer main), the userspace monitor ingestion path (connections,
> identity, the loader poll), the terminal diff engine, the
> userspace limiter policy/reclaim/format family — plus a
> crash-pattern sweep across the whole userspace tree. Status: ONE
> real find at an audit seam (the LRU eviction restart read as a u64
> wrap — the exact intersection of two prior audits that never
> cross-checked each other), closed with a one-boundary fix and four
> new pins; every other surface read SOUND at peak.

## 1. The mandate

The owner's ask: depth-audit the killer features again, total LTS,
honest. The instrument table:

| # | The ask | The instrument this audit used |
|---|---------|-------------------------------|
| 1 | Stability & crash over the limiter and the monitor | line-by-line reads of the surfaces lts-3 skipped (the observer's kernel modules, the ingestion path, the diff engine); the crash-pattern sweep (every unwrap/expect/panic/index across src/); the full battery fresh (681 + 47 / 0 failed after the close) |
| 2 | Code hygiene across the killer-feature dirs | the stale-claim hunt (the find: lts-5's own "backwards step is a wrap, full stop" doc paragraph, dead since dinner-6's LRU rider); module-boundary hygiene (the loader split that kept the 500-LOC contract) |
| 3 | Optimization of the hot paths | the poll-path read (the delta discriminator is two integer ops on an already-taken branch); the 10s frame A/B twice per side — bytes/frame byte-exact at 1,919.0 on all four runs |
| 4 | Security hardening at the feature surfaces | the monitor-honesty contract re-read (the phantom could poison the --depth shadow audit's bypass verdict); the /proc boundary family re-verified (pidfd, comm, cgroup, cookie join) |
| 5 | LTS stability of the feature contracts | the eviction family pinned (5 -> 9 rows); the unreachable corner documented and pinned as deliberate; USAGE limitation 11 updated to match the new behavior |

## 2. The find — the audit seam between dinner-6 and lts-5

Two prior audits, each correct in its own lane, never
cross-checked their intersection:

- **NIGHT-lts-5** (the wrap-coherence fix) pinned the poll delta
  to modulo-2^64 subtraction and documented its reason: a
  backwards step is a wrap, full stop — a claim written when the
  observer's counter maps were plain hashes whose entries never
  disappeared mid-session.
- **NIGHT-dinner-6's E1 rider** (2026-09-28) moved those same maps
  to the LRU lane and documented the trade: past 4096 distinct
  live cgroups an idle entry is evicted, and an
  evicted-then-returning cgroup restarts its accumulator.

Neither audit re-read the other's surface. The intersection — an
eviction restart IS a backwards step, and the wrap-coherent delta
would read it as a wrap — produced a phantom delta of
~2^64 - prev on exactly the hosts dinner-6 was protecting (dense,
churning, the "host server padat" class). Three surfaces carried
the phantom as real traffic:

1. **The returning row's rate column** — an 18-exabyte one-frame
   spike (`rate_bps` divides the phantom by the poll span; the
   formatter's EB terminal tier renders it honestly, which is
   exactly how visible the lie would be).
2. **The session leaderboard** — `SessionAcc` (u128 since lts-5,
   saturating since boost-16) folds the phantom in permanently:
   +18 EB to that cgroup's session total, a false crown that
   never decays. Boost-16's own audit closed the "wrap-around
   winner" at the accumulator layer with saturating adds; the
   phantom reopened the same corruption through the delta layer.
3. **The `--depth` shadow audit** (charger-core-1-a) —
   `run_focus_window` feeds `summary.total_bytes` /
   `total_ingress_bytes` into the NIC-vs-hooks comparison; a
   phantom inside the focus window reads as a massive BPF-side
   divergence — a false bypass verdict on traffic that never
   happened, from the tool whose job is to catch real bypasses.

The reachability is honest and narrow: it needs >4096 distinct
live cgroups with traffic inside one observe session AND an
evicted cgroup returning within one poll interval — the exact
extreme-churn envelope USAGE limitation 11 already documents as
the accepted-trade class. Monitor-only: no enforcement surface
reads these counters; the limiter's pinned stats maps are HASH,
not LRU, and never evict. But the monitor's own honesty contract
(the rate_ring module's law: "the LEDGER is the truth... the ring
never invents") is the rule the phantom broke, and lts-3's
verdict on this path ("SOUND, the ladder re-proven") was rendered
before the seam existed on the delta layer.

### The close

One boundary, every caller: `wrap_coherent_delta` itself. The
discriminator is the coherence bound the wrap pins' own doc
already stated — the modulo delta is exact while it stays under
2^63 bytes (~9.2 EB per poll interval, ~73 Pbps, nine orders past
any deployed link). Past that bound the "delta" is not a delta
any real interval produces, and on session-scoped maps the only
reachable producer is the LRU restart — whose honest delta is
`cur` itself, the fresh bytes booked since the re-insert:

```rust
fn wrap_coherent_delta(cur: u64, prev: u64) -> u64 {
    let delta = cur.wrapping_sub(prev);
    if delta >= HALF_SPACE { cur } else { delta }
}
```

All five NIGHT-lts-5 pins pass unchanged on the fixed code (the
wrap shapes land deep inside the band; the `u64::MAX`-from-zero
pin returns the same value through either arm). The family moved
to `src/ebpf/loader/delta.rs` (the connections/parse.rs precedent
— loader.rs sat at 497 lines and the change would have pushed it
past the 500-LOC cap; the split is a cohesion split, one theme
one module, the test wiring moving with the function so the pins'
`use super::wrap_coherent_delta` resolves unchanged).

The unreachable corner is on the record twice — in the function's
doc comment and in a pin: a restart whose gap (prev - cur) is
itself past 2^63 needs prev to hold 9.2+ EB accumulated inside
ONE session (~2.3 years of 1-Tbps traffic through one cgroup
with the monitor watching). The discriminator cannot see that
restart, it degrades to the old modulo reading, and the pin
(`the_unreachable_deep_restart_corner_degrades_to_modulo`)
documents the degradation as DELIBERATE so a future audit finds
it on the record instead of hunting it.

## 3. The limiter engine — SOUND, the un-lts-3 surfaces read

- **The userspace policy/reclaim pair** (policy.rs, reclaim.rs):
  the charger-core-2 mutation ledger with pre-apply raws, the
  rollback-after-mutation ordering, the dead-group reclaim's
  0-sentinel filter (`filter(|gid| *gid != 0)`), the depthbore-1
  dedup, the improve-29 unset-direction removal — re-verified by
  reading, every layer holding.
- **The format family** (format.rs): the Z7 exact round-trip
  twins, the boost-22 tier ladder with its u128 tenths, the lts-5
  wide ladder, the engrave-7 count compaction — no drift, all
  pinned.
- **The attach lifecycle** (limiter/mod.rs): the hunt-19
  operational-pin predicate, the hunt-28 bpffs preflight, the
  hunt-30 alignment preflight — holding.
- Kernel-side (math.rs, DRR, AMMSP, the datapath): PEAK, skipped
  per the protocol — lts-3 read them to the metal and the object
  is byte-pinned since.

## 4. The eagle-eyes monitor — the find's home, otherwise SOUND

- **The kernel observer modules lts-3 never named**, each read
  line by line this pass: socket_flow.rs (the stale-token belt's
  CAS form, the BPF_NOEXIST init race, the cookie-0 fallback
  documented in place), rate_ring.rs (the window protocol's
  stamp CAS + swap, the future-stamp poison rule, the documented
  SMP undercount bound), stats.rs (the atomic RMW views, the
  alignment pins, the wrap-horizon reasoning), and the observer
  main.rs (the NOEXIST + loser-re-lookup insert contract, the
  LRU posture, the license section).
- **The ingestion path**: connections.rs (the pidfd tri-state —
  the Copy redesign after the CI stack-overflow incident, pinned
  by its own regression test; the canonical /proc boundary; the
  cookie join's graceful degradation), identity/mod.rs (the
  majority-vote tally, the engrave-7 enrichment with prefix
  continuity and the 24-column display cap).
- **The terminal diff engine** (diff.rs): the byte-exact
  crossover, the tall-regime no-trailing-LF rule, the
  hunt-26 no-erase repaint, the ultimate-2 sink-death contract —
  zero live panic candidates, zero zombie code (the module's own
  allocation-reuse discipline verified by reading).
- The render tree itself: PEAK, skipped — lts-3's line-by-line
  pass stands, and this audit's benchmark seat (below) is the
  no-regression measurement that backs the skip.

## 5. The UX surface — Z9's pass honored, skipped

Z9 (2026-10-03, the immediately prior commit) swept the CLI
surface with a supermassive battery (121 rows) and closed three
finds of its own; the echo boundary, the shadowed positional,
  and the hidden-vocabulary contracts are hours old at audit
  time. Re-running that sweep would duplicate a fresh audit, so
  this pass's UX work was the crash-pattern sweep's CLI leg
  (every parse-path panic candidate — clean) and the rate
  display's interaction with this audit's find (the phantom
  rendered visibly through the formatter's EB terminal tier —
  which is precisely how the corruption would have been caught
  by eye, and why it deserved the fix anyway).

## 6. Optimization — PEAK, re-anchored post-change

The 10s frame A/B, twice per side (the honest variance protocol):

| Metric | Baseline (HEAD) | Fixed (this audit) | Reading |
|--------|-----------------|--------------------|---------|
| fps (render path) | 7204.8 / 6933.4 | 7145.6 / 7156.2 | distributions overlap; the baseline's own spread is wider than the difference |
| bytes/frame | 1,919.0 / 1,919.0 | 1,919.0 / 1,919.0 | **byte-exact, all four runs** |
| emit bytes/frame | 511.7 / 511.2 | 512.4 / 512.3 | in class |
| density gini | 0.3510 / 0.3514 | 0.3508 / 0.3508 | in class |
| frame entropy | 3.0209 / 3.0166 | 3.0214 / 3.0214 | in class |
| dirty cells/frame | 40.0 / 39.8 | 40.1 / 40.1 | in class |

The discriminator itself is two integer ops on a branch the
modulo subtraction already paid for; the poll path's cost is
unchanged by construction. The kernel object is byte-pinned
untouched.

## 7. Security hardening — the honesty contract is the surface

The monitor's security posture is its honesty: fabricated figures
are the monitor-class tool's equivalent of an injection (a wrong
number an operator acts on). The phantom violated the contract on
three surfaces at once; the close restores it. The /proc boundary
family (comm sanitize, pidfd, cgroup resolution, cookie join)
re-verified with no new untrusted-input class found — the three
known classes (comm, release tag, error echoes) are the ones
cybersecurity-1/2 and Z9 closed.

## 8. LTS stability — the pins and the docs

The eviction family pins: 5 -> 9 rows in
test/ebpf/loader_wrap_tests.rs (the restart reads fresh bytes;
the phantom arithmetic is dead; the discriminator boundary IS the
coherence bound; the unreachable corner degrades to modulo,
deliberately). The full battery after the close: 681 unit + 47
integration passed / 0 failed / 1 + 3 ignored; clippy and
rustfmt clean. USAGE limitation 11 now tells the truth about the
returning restart's reading; the stale lts-5 doc claim is
rewritten at the function itself.

## 9. The verdict table

| Area | Verdict | The one-line evidence |
|------|---------|----------------------|
| 1. Stability & crash | SOUND | the un-lts-3 surfaces read line by line; the crash-pattern sweep clean; 681 + 47 fresh; no live-path panic candidate |
| 2. Code hygiene | one find, closed | the stale "backwards step is a wrap, full stop" claim (dead since dinner-6's LRU rider) rewritten at the boundary it lied about |
| 3. Optimization | PEAK (skip) | the discriminator rides a paid branch; bytes/frame byte-exact 1,919.0 on all four A/B runs |
| 4. Security hardening | one find, closed | the eviction-restart phantom — a fabricated-figure vector on the rate column, the leaderboard, and the --depth shadow audit — dead at the one boundary |
| 5. LTS stability | SOUND + the seam closed | the wrap/eviction intersection pinned 5 -> 9; the unreachable corner documented twice; the two prior audits' seam now cross-checked on the record |

## 10. This audit's own honest residuals

- Live eBPF stress still rides the CI legs: the find's
  reachability window (the eviction shape) is a dense-host
  scenario the CI kernel (5.10, rootless) does not exercise —
  the discriminator's pins are the rootless proof, and the CI
  legs prove the rest.
- The deep-restart corner (gap past 2^63) is unreachable by
  ~22 orders of magnitude and pinned as a deliberate degradation;
  engineering around it (e.g. a heuristic on prev's magnitude)
  would add a second coherence rule for a shape no session can
  produce — declined, on the record.
- The `socket_cookies()` dedup is O(n^2) in resolved cookies per
  frame — bounded by the /proc walk's own scale (hundreds
  typically), measured in the class of the frame budget, and
  rebuilding it as a HashSet would churn the frame path this
  audit's benchmark just proved byte-exact — declined, noted.
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
