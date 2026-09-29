<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The Depth-Traffic Focus and Report-Compaction Audit — eagle-eyes --depth, status, list-apps

> Audit date: 2026-09-30 (NIGHT-private-research-3 & think-like-light-years-3).
> Scope: the three surfaces the owner named — the eagle-eyes depth
> mode, `zelynic status`, `zelynic list-apps` — audited for the
> ability gap ("focus network traffic, not just basic current") and
> the style directive ("more compact and simple to view").
> Status: upgraded, pinned, benchmarked, shipped in the same commit.

## 1. The mandate

Two directives, one pass. First, the ability: the depth mode should
SUPPORT FOCUSING NETWORK TRAFFIC — "not just basic current now".
Second, the style: the three surfaces should render more compactly
and simply. The audit walked each surface's code path live (the
handler ladder, the render composition, the JSON document, the pin
family) before changing anything, hunting for the exact class each
directive names.

## 2. Findings — the depth audit

**Finding 1 (the ability gap, confirmed): the depth report's socket
section was the BASIC CURRENT census.** The one-shot handler
(commands/eagle.rs) assembled its report from four sources — the
identity walk, the /proc connection walk, the pinned policy maps,
the identity depth walk — and never loaded an observer. The
per-endpoint byte attribution the live monitor owns since
NIGHT-boost-26 (the observer's per-socket cookie maps joined onto
the /proc census) therefore never ran on the report: a `--depth`
reader saw `curl (4242) → 142.250.191.78:443 tcp ESTABLISHED` with
no figures. The machinery existed end to end — `Observer::attach`,
`poll_and_summarize`'s per-direction deltas, `socket_bytes`' point
lookups, the cookie discovery walk — the report simply never wired
itself to it.

**Finding 2 (the style debt, confirmed across all three surfaces).**
The depth report restated its own headline two more times in the kv
spine (`package id: cg:1234` and `package name: cat-test` under a
headline reading `cg:1234 — cat-test`), split one fact across two
lines three times (`run from user` + `run from path`, `cgroup
memory` + `cgroup cpu`, the census line's `socket holders`), spent
a line on the `act on this:` header, and blanked a line after the
title bar and between every section. `status` blanked two filler
lines per report (the engrave-5 breathing gap and the pre-footer
gap; the clean and stale branch frames blanked two each). `list-apps`
blanked one line between its census and the header the census
counts. None of the blanks carried information; the grids and the
title bar already do the separating.

**Finding 3 (hunted beyond the mandate): the JSON document could not
express the focus window at all.** `EndpointJson` carried no byte
fields and the target object no window totals — additive fields
were needed for the new ability to reach scripts, and the honest
null (no window ran) had to stay distinguishable from a zero
traffic window (one ran, nothing moved). The displayability gate
(`detail::is_displayable`) was private, forcing the new section to
either duplicate it or share it — sharing it is the drift-proof
move, so it went pub(crate).

**Finding 4 (hunted, deliberately NOT changed).** The live
monitor's own frame path is untouched by this pass by construction
(render/eagle, footer, border, session, diff engine — zero lines
moved); the A/B in docs/PERFORMANCE.md is the proof. The `--focus`
flag deliberately does NOT apply to the live view: its frames ARE a
focus window already, and the one-line stderr note says so (the
`--interval`-on-depth mirror image). `list-apps`' column widths,
sort order, and JSON shape stay untouched — the compact directive
retires filler, not contracts.

## 3. The fix — the focus window

The handler's new phase (run_focus_window): attach the observer
(announced on stderr — a report that silently sleeps looks hung;
stdout stays byte-clean for both output modes), seed the delta
baseline with a discarded poll (the same horizon contract the live
monitor's opening poll owns), sleep the window (default 3s,
`--focus 1s..30s`, the shared duration grammar with its typo tips,
parsed BEFORE the root guard), close with the second poll, refresh
the census, and join the cookie maps onto it. The composition is
pure (render/depth_traffic.rs, fixture-pinned): the kernel's
per-cgroup window totals plus the per-endpoint attribution, movers
first, `[dl X | ul Y]` — the live view's own vocabulary. Failure
modes are honest by contract: a failed attach/poll is the one-line
note under the basic census, a quiet window is the no-traffic
verdict, an empty join keeps the totals (kernel truth) with
figure-less rows (the one-frame-tolerance contract the live join
carries).

The honesty bounds, stated where they live (USAGE.md, the JSON
reference, this audit): the cgroup totals include traffic from
sockets that died mid-window (the kernel's LRU entries stay
booked); the endpoint attribution covers exactly the sockets the
closing /proc walk resolved cookies for — so the endpoint sum can
sit below the totals, and both numbers are true. Sockets that moved
nothing render no figures, never a fabricated zero; the JSON's
`traffic: null` stays distinguishable from a zero-traffic window.

## 4. The fix — the compact pass

One rule, applied everywhere: a report surface is title bar,
content lines, signature stamp — zero blank filler. The depth
report's kv spine compacts to the facts the headline cannot carry
(`run from: uid 1000 (cat) · /home/cat`, `resources: 12.5 MB
memory · 1m:2s cpu`, `started: 10m:20s ago`), the act tail merges
its header into the first line, and the socket section becomes the
traffic section when a window ran. `status` and its branch frames
stack title → watchdog → census → header → grid → rows → stamp.
`list-apps` lands the census on its header row. The census table,
the column contracts, the JSON shapes, and the flagship chrome
(purple title bar, lowercase headers, the monitor's grid, green
rows, the signature footer) are unchanged — the pin family holds
both the new positives and the retired-duplicate negatives.

## 5. Verification

- `cargo test --locked`: 492 + 46 green (0 failed) — including the
  six new traffic pins (composition, ranking, noise gate, cap,
  quiet window, not-measured note), the JSON traffic pins, the
  focus parse-ladder pins (typo, bounds, legal-edge-reaches-root),
  and the updated compact-spine/zero-filler pins.
- `cargo fmt --check` clean; `cargo clippy --all-targets
  --all-features -D warnings` clean.
- The 10s frame A/B (A = 6cb6f83, B = this tree; the standard
  harness protocol): bytes/frame 1,919.0 → 1,919.0 (identical to
  the decimal), density gini 0.3571 → 0.3573, frame entropy
  3.0025 → 3.0019, dirty cells 39.5 → 39.5, fps +0.5% (machine
  noise) — the live frame path is untouched by construction; the
  full record lives in docs/PERFORMANCE.md.
- Rootless-pin discipline: every new pin is fixture-driven (the
  composition is pure over its inputs); the handler pins surface
  before the root guard, so the suite is deterministic on any uid.
- Local gate batteries re-run at commit time (gate-keepers,
  build.sh check-all -q within the two-minute local budget).

## 6. Residuals (honest)

- The full focus window (observer attach → sleep → poll → join)
  cannot run in THIS development container (no cgroup v2, no
  CAP_BPF, no KVM for the sandbox micro-VM). The window's
  mechanics are exercised by the pin family and the compile-verified
  wiring; the live end-to-end path belongs to the owner host or the
  CI root lanes (the same residual every observer-dependent change
  in this repo carries — the boost-26 precedent for the join, the
  boost-25 precedent for the attach).
- The observer attach cost (verifier time, tens of milliseconds)
  rides every `--depth` invocation now; on a healthy host this is
  under the window itself and invisible next to the 3s sleep. An
  owner who wants the report without the window has no opt-out
  flag yet — `--focus 1s` is the floor, and the pause is always
  announced. Deliberate: an opt-out would reintroduce the
  silent-basic-report the directive just retired (over-engineering
  guard: no flag for a need the owner did not name).
- The README's `eagle-eyes-depth.png` demo asset still shows the
  pre-compact report shape (the old kv spine and the basic socket
  census). Regenerating it needs a root eBPF host (the report
  renders from live cgroups); the text contract — USAGE.md's
  sample block and the pin family — is the source of truth, and
  the screenshot follows at the next owner-host capture session.
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
