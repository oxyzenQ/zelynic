<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-hunt-29 audit — the probe family, round four, and the synthetic-cookie fixture that closed lts-7's residual

> Audit date: 2026-10-07 (NIGHT-hunt-29). Scope: the owner's ask —
> "audit round 4 over the probe* family, or stress the fixture
> bench that resolves synthetic cookies (hunting the blind spot I
> documented)" — the owner's words, translated; BOTH candidates
> approved, hunted to the bottom.
> Audited at cb3e3c8 (night-total-lts-6's HEAD; v50.0.0-alpha.1; the
> eBPF enforcement object byte-pinned). Method: probe.rs,
> probe_role.rs, probe_report.rs and their three pin files read line
> by line (round four of the family's coverage — lts-7 had the
> feature engines, lts-6 the foundation, this pass took the
> self-proving probe the owner calls the TIER S ability), then the
> frame harness's fixture variant engineered and stressed exactly as
> lts-7's residual list specified it.
> Status: ONE real find in the probe family (the root-cgroup row the
> server-placement lane never checked — closed with a three-line
> gate, a hoisted predicate, and one new pin); the fixture closure
> landed as the second code commit (the join lane is measured frame
> work now, the fps reading bisected and honest); every other probe
> surface read SOUND at peak.

## 1. The mandate

The owner's ask: the probe* family audit round 4, or the fixture
bench that resolves synthetic cookies — the two natural candidates
the lts-6/lts-7 closing notes named, both approved "until every
surface is at peak, nothing left, ready for LTS" (the owner's
words, translated). The instrument table:

| # | The ask | The instrument this audit used |
|---|---------|-------------------------------|
| 1 | Probe family, stability & crash | every early-return lane walked against its cleanup duty (children killed, cgroups removed, pipes closed); the expect() inventory re-read (the connect-loop invariant — unreachable by construction, lts-6's own verdict, re-verified) |
| 2 | Probe family, code hygiene | the placement family's closure hoisted from a buried inner closure to named fns (one predicate, one IO half, one dir reader, one gate) — the shape the two 500-line splits had already established for the waiting/cgroup/map-read families |
| 3 | Probe family, optimization | nothing re-optimized: the probe is a 3s-window one-shot, not a hot path; the one candidate (the ledger_snapshots double iteration) is the honest-read contract itself |
| 4 | Probe family, security | THE FIND — the server-placement premise verified instead of assumed (section 2) |
| 5 | LTS stability | the verdict bands, the combined ledger verdict, the teardown belt, the window gate — all re-read against their pins (838 + 48 / 0 failed) |
| 6 | The fixture closure | lts-7's residual engineered, stressed for determinism (frame 1 byte-identical across runs), A/B'd against the cookie:None era, and the fps delta bisected to its honest cause (section 4) |

## 2. The find — the root-cgroup row the mkdir lane never checked

The probe server's home is a transient root-level cgroup, and the
module's own header claims the server "lives outside every policy for
the window (checked against BOTH policy maps)". The refused-mkdir
lane pays that check (`our_chain_is_clean`, whose first hop IS the
root cgroup). The successful-mkdir lane never did — the premise
"root-level = outside every policed subtree" silently assumed the
ROOT cgroup itself can never carry a policy row.

It can. Three roads lead there:

- `Target::parse("cg:<id>")` accepts any numeric id directly into
  the policy map — including the root cgroup's own kernfs inode.
- A root-resident process name resolves to the root cgroup id
  through the same /proc walk every other name target rides — the
  exact shape of minimal and container hosts, where PID 1 sits
  directly in the root (the CI micro-VM class).
- The enforcement object resolves the NEAREST policed ancestor per
  packet (`enforce.rs`'s ammsp_resolve_root) — so a row on the root
  polices every root-level child, the probe's server home included.

The blast shape it bought: a server throttled at the ROOT's rate is
not the unlimited peer the verdict's physics assumes. A flow landing
inside the target's band by coincidence reads VERIFIED over a limit
the probe never measured (root rate in [0.2, 1.05] x target rate
produces exactly that — the floor is 20%, the ceiling 5% plus one
super-packet); a starved flow reads UNVERIFIED with no note able to
name the cause. The ledger leak veto cannot rescue it either: the
target's own rows admit everything the throttled server managed to
offer, so the ledger stays inside its envelope and the leak lane
stays silent.

The fix is the family's own shape — a placement gate, not a redesign:

- `probe_role.rs`: the chain walk's inner closure hoisted into the
  named family (`cgroup_id_is_policed` pure, `cgroup_id_is_clean`
  the IO half with the never-a-guess read-failure arm,
  `dir_is_clean` the kernfs-inode reader, `root_cgroup_is_clean`
  the new pub(crate) gate).
- `probe.rs`: the mkdir-succeeded lane now stands down with its own
  honest note when the root carries a row — "no unpoliced lane
  exists for the probe server (the blast would measure the root's
  rate, not the target's)" — the same conservative class as the
  blocked-policy and dormant-window gates. The empty home is
  removed on the way out, the residue discipline kill_and_reap
  carries for the occupied homes.
- One new pure pin drives every predicate shape (clean both sides,
  dl-only row, ul-only row — the dual-apply shape — and empty
  maps): `a_root_row_in_either_direction_marks_the_id_policed`.

A root-row host has no clean placement for the peer by construction
— every cgroup is under root. The stand-down is the only honest
verdict; the owner's target-of-root probe (which itself resolves
correctly through the CLIENT side — the client nests under the
target's row either way) pays the same gate and reads UNVERIFIED
with the note, which is the truth: a root-wide policy cannot be
verified from a peer inside it.

## 3. The probe family re-reads — SOUND at peak

- **probe.rs (the orchestrator)**: the direction selection and the
  blocked-policy stand-down re-read against their documented
  posture (a block needs no probe — the drop ledger IS the verdict);
  the ledger baseline/close pairing (same ids, same order, the
  wrapping_sub deltas are the u64 counter contract); the teardown
  belt's three-lane error discipline; the budget-truth read's
  timing. Every early-return lane carries its cleanup — the
  window-dormancy and rel_path gates return before any child
  exists, the spawn-failure lanes kill in reverse spawn order, the
  success path reaps both children and both homes. SOUND.
- **probe_role.rs (the roles)**: the connect-loop expect is the
  lts-6 verdict re-verified (unreachable by construction — the
  loop's exits are Some or bail); the zero-linger RST cut, the
  grace-sleep ordering (the pid write lands before the first
  socket exists), the blast/drain split, the one-line protocols —
  all re-read against the Z1/Z7 lineage. SOUND.
- **probe_report.rs (the verdicts)**: the bands, the envelope, the
  leak veto's rank order, the starved-notes stack — every pure
  function re-read against its pin set (the three pin files froze
  them long ago; round four found nothing the pins do not already
  hold). SOUND.

## 4. The fixture closure — lts-7's residual, engineered and stressed

The frame harness's fixture built its socket detail with
`cookie: None` (the graceful-degradation shape), so the join lane —
`socket_cookies()` (the lts-7 HashSet dedup), the loader
point-lookups, `apply_socket_bytes`, the `[dl X | ul Y]` figure
rendering — never ran under the benchmark. lts-7's own residual list
named the closure: "a future fixture variant that resolves synthetic
cookies would close the blind spot for the next audit." This audit
is that audit.

The fixture variant (bench.rs, the second code commit):

- Every socket carries a kernel-shaped synthetic u64, unique per
  socket across the fixture, plus one dup'd-fd pair per detail
  cgroup (fd 3 holds fd 0's socket again — same remote, same
  cookie, the shared-socket-table-row shape the walk matches twice
  and the dedup absorbs). 36 walked sockets fold to 27 distinct
  join keys per frame.
- Every frame runs the monitor loop's exact wiring:
  `socket_cookies()` for the key set, a synthetic cookie-map result
  (lifetime counters, pure in (cookie, frame) — deliberately NO
  LCG draws, so the traffic stream the A/B protocol freezes stays
  untouched), `apply_socket_bytes` for the install.

The stress evidence:

- **Determinism**: frame 1 byte-identical across independent runs;
  the +/-0.0001 gini/entropy drift across full runs is the
  frame-count-window noise class lts-7 already documented.
- **The 10s A/B** (cb3e3c8 vs the fixture commit): bytes/frame
  BYTE-EXACT at 1,919.0 both sides (the logical frame is the boxed
  render; row count unchanged, the figures live inside the existing
  line budget); gini 0.3500 -> 0.3218, entropy 3.0320 -> 3.2092
  (real content — the intended delta); dirty cells 40.0 -> 82.4
  (the figures grow every frame, the same churn the live lifetime
  counters produce at their own cadence); emit 511.5 -> 536.9.
- **fps 7203.9 -> 5722.4 (-20.6%)**, bisected before landing: the
  cost splits -17.8% into the join COMPUTE and -2.7% into the
  install + figure rendering + diff churn. The number is the
  DEBUG-profile truth of the harness (test profile, unoptimized) —
  the same block costs ~1-2us in the release lane the live monitor
  runs. The honest reading is the closure's own point: the old
  7203.9 measured a frame that SKIPPED the join work the live loop
  always did. The fps drop is the blind spot's price becoming
  visible, not a regression; the A/B protocol itself is intact
  (any layout change now compares like-for-like, both sides
  carrying the join).
- The dense-host 4096-socket exactness stays where it already
  lives — the `socket_cookies_dense_fixture_stays_exact` unit pin.
  The bench's 27-key scale is the frame-cadence lane; the pin's
  4096-socket shape is the scale lane.

## 5. This audit's own honest residuals

- The root-gate's live lane (a real policed root cgroup) is the CI
  supermassive battery's to exercise — the rootless harness cannot
  write the policy map; the pure predicate and the gate wiring are
  pinned, the live shape is named here as the residual.
- The bench's join stands in for the loader's point-lookups with
  synthetic values — the syscall cost of the live join (2 per
  cookie) remains lts-7's documented design note, owned by the
  point-lookup-vs-iteration trade it already recorded.
- The fps reading is debug-profile truth by the harness's own
  design (it always was); a release-profile harness would need a
  separate lane, and the owner has not asked for one — noted, not
  engineered (the A/B protocol only ever needed like-for-like).

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
