<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-hunt-36 audit — the supermassive depth question asked across all thirteen innovations, and the two live-lane holes it caught

> Audit date: 2026-10-08 (NIGHT-hunt-36). Scope: the owner's ask,
> verbatim intent — after private-research-4, "verify the supermassive
> test should already have this depth test" for the six named features
> (ECN-first policing, per-socket tier, time-windowed policies,
> CAKE-style flow isolation, QUIC-aware mode, guaranteed minimum) "or
> all innovations" — the thirteen-applied ledger from the audit-3
> innovation map. Method: the estate's own division-of-labor lens
> (improve-47's frame — surface in the v4 battery, law in the Rust
> pins, live kernel in the root-gated probes and the VM matrix),
> applied per innovation with signature sweeps across every live lane
> (v1 matrix, v2 survival, v3 container, ammsp-vs-legacy, the claims
> battery, the depth scripts), row-body reads to confirm the rows
> exercise behavior, and fresh empirical runs of every rootless lane
> this audit could reach. Audited at e8d2741 (hunt-35's tree).
> Status: eleven of the thirteen carry their full three-slice depth
> and stay at peak (skip-and-noted); TWO carried a live-lane hole —
> the per-socket tier and the --during window's own expiry had zero
> live enforcement rows anywhere in the estate — and both holes are
> closed with new v1 matrix rows.

## 1. The mandate

Improve-47 (2026-10-06) answered this question once, for the
private-research-4 feature family: all seven features carry real
depth tests, the division of labor coherent. This audit re-asks
after the grammar era moved underneath it — improve-53's
masterclass merge, improve-54's sweep merge, improve-55's
persistence retirement reshaped the v4 battery's rows — and widens
the lens to the owner's full thirteen, where the deeper question
lives: not "does a pin suite exist" but "does any lane measure this
feature's headline law on a real kernel".

## 2. Method

Three slices per innovation, the estate's own doctrine:

1. **The Rust pins** — the kernel-side and userspace-side law,
   natively compiled (the `#[path]`-wired test/ tree runs the real
   ebpf source, not a mock).
2. **The suite rows** — which supermassive battery carries the
   feature, and whether the rows assert behavior or layout.
3. **The live lane** — the root-gated probes and VM matrix rows
   that enforce the feature on a real kernel and measure the
   datapath's own ledger.

Signature sweeps (`per.socket`, `--during`/expiry, `ecn`, `cake`,
`quic`, `drr`, `ring`, `shadow`, `bypass`, `atomic`, `rollback`,
`verified`, `docker`) ran across every live lane; every hit was read
at the row level (the count alone proves nothing); the rootless
lanes ran fresh.

## 3. The thirteen-innovation depth map

| # | Innovation | Rust pins | Suite rows | Live lane | Verdict |
|---|---|---|---|---|---|
| 1 | AMMSP | ammsp_tests + ammsp_flush_lines_tests | v1 test_ammsp_subtree + test_ammsp_fairshare; the ammsp-vs-legacy A/B battery (the whole VM leg) | VM matrix, all four legs | at peak |
| 2 | Fair-Shared Bucket (DRR inside AMMSP) | drr_tests 8, drr_share 9, drr_ledger 8, drr_take 3, drr_highload 3, drr_sim | v1 test_ammsp_fairshare — the live starvation battery | VM matrix | at peak |
| 3 | CAKE-style flow isolation | cake_isolation_tests (the 476-LOC flow-shape sim), cake_battery 9, cake_tests 8, the DRR family above | v1 fairshare/DRR rows — the scheduler under live load | VM matrix | at peak |
| 4 | Per-socket tier | types_tests (the SocketBucket layout), the ecn fleet sims, display/persist round-trips | v4 stage 12 (the flag surface) | **NONE — the hole** | **filled, this audit** |
| 5 | Time-Windowed Policies | during_tests 21, during_user_tests 13, persist_window_tests 3 | v4 stage 10 (the 14-case grammar ladder) | **expiry never watched — the hole** | **filled, this audit** |
| 6 | ECN-first policing | ecn_tests 11, ecn_socket_tests 3 | v1 rate ladder + curl rows (the policer under load); the claims battery's precision row (kernel-admitted vs configured) | ect-probe (the root-gated live probe) + VM | at peak |
| 7 | QUIC-aware mode | quic_tests 10 | the claims battery's QUIC attribution rows (live) | VM | at peak |
| 8 | Guaranteed minimum | drr_guarantee_tests 11, guarantee_resolve_tests 12 | v4 stage 11 (the 11-case law ladder); the claims floor rows | guarantee-probe (root-gated) + VM | at peak |
| 9 | Bypass Detection (Shadow Mode) | bypass_tests 5, render/bypass_tests 8 | v2 test_bypass_audit — BOTH sides: an AF_PACKET stream must flag the shadow (bypassed_tx/bypassed_both in the depth JSON), honest policed traffic must read CLEAN | VM | at peak |
| 10 | Self-Proving Enforcement | probe_ledger/probe_role/probe_report_tests | v1 VERIFIED rows + test_probe_failed (the honest failure side); v4 stage 12's --no-test surface | VM | at peak |
| 11 | Container-Native Resolution | docker_tests, container_tests, pathwalk_tests | v3 container battery (30 rows) | the container workflow (real runtimes) | at peak |
| 12 | Atomic Multi-Target with Rollback | policy_tests (capacity_admit, the ledgered write), ammsp atomic | v1 multi_group / block_multi / unstrict_multi / mixed — the `::` lanes whole-or-refused | VM | at peak |
| 13 | In-Kernel Time-Series Ring | rate_ring_tests | v1 ring rows (the sustain/ladder windows), v2 ring-under-kills, the claims ring rows | VM | at peak |

## 4. The two finds — the same class, one root cause

**Find 1: the per-socket tier had no live lane.** The signature
sweep returns zero `per.socket`/`per_socket`/`PER_SOCKET` hits
across v1, v2, v3, ammsp-vs-legacy, the claims battery, and the
depth scripts — the flag's only suite presence was v4's parse
surface (stage 12: the valid parse rides the one verb that owns it,
the group verb's refusal). The Rust slice is real (the
natively-compiled socket_flow sims, the SocketBucket layout pins),
and improve-47's map named exactly those slices — but the third
slice every other kernel-side feature carries was absent: no lane
ever enforced `--per-socket` on a real kernel and measured the
feature's headline law, USAGE.md's own sentence — "the cgroup's
TOTAL is bounded by rate x concurrent sockets, NOT by rate" — a
law that can only be observed with N live connections under one
policy.

**Find 2: the --during window's expiry was never watched close.**
v1's `during` hits are English prose; the claims battery's are
before-vs-during enforcement snapshots; the Rust slice is the
window math (pure pins — the span/daily/margin grid,
`span_ended_is_the_only_removal_predicate`) and the userspace
bridge; v4 stage 10 is the grammar ladder. Every one of those is
green and real — and none of them is the design's own headline
live-behavior claim: "the KERNEL decides when the window is over —
no daemon, no cron; every zelynic visit re-stamps the clock
bridge". No lane ever applied a short window, waited past it, and
watched the row lift itself.

The root cause is one class: features whose depth grew as
pins-plus-parse during their build-out era (private-research-4's
schema work landed with the v4 surface contract; improve-47
verified the slices that existed) never picked up the live row the
older enforcement features were born with. The per-socket tier is
the only one of the thirteen with NO live row at all; the during
family is the only one whose live claim (self-expiry) had no row —
its apply-and-stay shape was covered by the claims battery's
no-daemon row, but the window's close was not.

## 5. The fixes — two v1 matrix rows, the mirror discipline

**Row 1: `test_per_socket_burst` (6.0 s, 6 clients, 1 MB/s).** The
mirror of test_curl_burst: the same N-client burst machinery, the
OPPOSITE sharing verdict. The shared row proves ONE bucket (ledger
ratio ≤ 1.60); this row proves every connection its OWN, with the
boost-27 discipline (ceilings ride the kernel ledger, floors ride
the client totals):

- scale-up: ledger / (rate x span) ≥ 2.5 — six buckets flowing; a
  silently-shared bucket reads ≤ 1.60, so the gap discriminates by
  construction;
- per-connection cap: every client ≤ (rate x window + burst) x 1.25
  — each connection feels the rate;
- per-connection floor: every client ≥ 0.50 x rate x window — each
  bucket actually delivered (a silent degrade to the shared lane
  reads ~rate/N per client and fails here);
- ceiling: allowed ≤ (clients + 1) x (live x rate + burst) x 1.02 —
  each socket's own budget plus the cgroup's shared DRR fallback
  bucket (the cookie-0 lane), exact by construction;
- the tier round-trip rides alongside: download_per_socket true on
  the status JSON (display_json's own field), then the standard
  enforcement proofs.

**Row 2: `test_during_expiry` (1 MB/s, a 3 s window).** Three
verdicts on one target:

- under the window: the limit row is live at the rate (the apply's
  own status read);
- past the window (+2 s margin for the clock bridge): a PLAIN
  status visit lifts the expired row — monitor.rs's own visit law
  (the lazy sweep, `sweep_expired_windows_best_effort` on every
  status read), the row gone from the JSON, no unstrict typed;
- unpoliced after the lift: a measured 5 s download reads ≥ 10x the
  retired cap — with the policy row gone from the map, the
  datapath has nothing to enforce.

Both rows ride the desktop matrix right after test_curl_burst (the
shared-bucket row they mirror), both SKIP honestly on a host whose
baseline cannot feed them, and both carry the house arithmetic in
their row detail (the numbers a red run would need).

## 6. The empirical runs — fresh, rootless, on this tree

| Lane | Command | Result |
|---|---|---|
| The full Rust battery, ebpf lane (CI's own lane) | `cargo test --features ebpf --locked` | 834 + 53 passed, 0 failed (1 + 3 root-gated ignores, unchanged) — improve-47's 812 plus the hunt-30/34 growth |
| The supermassive v4 CLI surface | `./scripts/supermassive/supermassive-test-v4.sh` | 147 passed, 0 failed, 0 skipped (the post-improve-55 count, fresh green) |
| The v1 engine self-test | `--self-test` | 34 passed, 0 failed — the new rows import and wire clean |
| The v2/v3/ammsp engine self-tests | `--self-test` | 10, 12, and the classifier/delta/resolver/runner battery — all green |
| The two new v1 rows, live | the VM matrix | **the next supermassive run carries them** — the estate's standing division for root-gated rows (ammsp_subtree landed the same way: engine-verified on the tree, live-proven by the VM legs) |

## 7. The verdict

Eleven of the thirteen innovations carry their full three-slice
depth and are at peak — skip-and-noted, nothing to add, the correct
entry for a depth audit whose subjects already carry their depth
(improve-47's frame, re-verified post-merge). The two that did not
— the per-socket tier and the --during expiry — carried the same
hole class (pins-and-parse depth without a live measurement) and
both are closed: the v1 matrix now proves the per-socket budget law
(N connections, N buckets, the scale-up the shared lane forbids)
and watches a time window close (the visit-lift and the unpoliced
after) on every VM leg. The residuals are the honest ones: the two
rows' live green belongs to the next supermassive VM run (CI
carries it on this push, the same lane that proved every other new
row), and the QUIC flow-key's CID-finer bucketing under --per-socket
(schema v22's browser shape) rides the Rust quic pins plus the
claims rows — a live N-HTTP/3-connections row would need a QUIC
client in the VM rootfs, an owner-scope call recorded here, not
silently skipped.
<!-- ZELYNIC-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every .md — perfect sync across every .md file is
  a known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`, `ebpf/src/**/*.rs`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
