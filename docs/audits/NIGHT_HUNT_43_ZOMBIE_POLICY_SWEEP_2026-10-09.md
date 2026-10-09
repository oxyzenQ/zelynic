<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-hunt-43 audit — the zombie-policy sweep, and the baseline panel's own retire_dead

> Audit date: 2026-10-09 (night-hunt-43 + NIGHT-hunt-34 v2). Scope:
> the owner's ask — the residual 0ed6dcf's census sweep could never
> name (a cgroup that dies with its policy standing still needs a
> manual `sudo zelynic recover`), and the eagle-eyes baseline panel
> below the cgroup process table still carrying no retire_dead
> mitigation of its own. Method: walk the zombie's whole lifecycle
> against every existing collector's gate, then land the two
> collectors the class needs (kernel-side and render-side), then
> hunt the landings themselves for the holes the first pass missed.
> Two holes found and fixed the same night. Audited at 044ca58
> (night-hunt-42's HEAD); landed across four commits (9f928ac,
> 5445a68, 6d4e384, c5d6cee) plus the live-proof stage (7ef4fb3).

## 1. The find (fixed): the residue every collector's own gate keeps

**The bug.** Hunt-34 v1 fixed the level below the panel (orphan
census state — a ring whose POLICY is gone), and its lane verdict
read "clean" — but the class one level above went unnamed: a policy
row whose CGROUP died. Every collector gates on the policy census:
`sweep_census_orphans` collects state no policy names (a zombie's
policy row is exactly that proof — the sweep KEEPS its state), the
removal paths collect what a live hand asks, and `recover` walks
orphan policies only when its human runs it. So the zombie held:

1. **A permanent ghost verdict** on the `baseline · policy
   aggregate` panel — the lane folds every key the ring read
   carries, identity or not, and the dead root's ring keeps its
   pre-death windows until they rotate out, then folds quiet
   zeros: `cg:NNN  steady 0 B/s` forever.
2. **Census slots** for the life of the pin epoch — the 1024-entry
   budget the whole reclaim family keeps proportional to LIVE
   policies, frozen one root at a time on a churning host (the
   per-job scope, the exited container, the closed session).
3. **An active-limit lie on status** — a dead cgroup counted as
   enforcement until the next manual recover.

**The fix, kernel side** (`sweep_zombie_policies`, the new
`src/ebpf/limiter/zombie.rs` — the family's third collector): the
two-signal liveness walk, the session board's own retire_dead
predicate one home over. A root retires only when no identity
entry stands AND every direction it holds a policy in is quiet:
the ring stamps only on kernel-side DELIVERY, so no live stamp for
the full 8s horizon is proven silence, and the grace rides the
ring's own rotation (a root that died mid-traffic waits for its
last delivered second to age out). The belt is load bearing: an
alive-but-unresolvable root (a process that entered a cgroup
namespace after its apply — the one shape where identity lies)
still stamps while it delivers, and traffic vetoes retirement.
Fail-closed for reclamation: an absent ring LENS (a stale pin
epoch) proves nothing and every root in that direction waits.
Retirement is recover's own shape per root (groups captured
read-before-delete, both legs deleted, state reclaimed once both
legs are confirmed gone, dead groups swept at the tail), riding
the status visit and all three apply-family tails, ordered
between the window sweep and the census sweep — the census pass
then mops up any state a FAILED zombie reclaim just orphaned in
the same visit.

**The fix, render side** (`BaselineLane::retire_dead`,
render/baseline.rs): the panel's own mitigation, the session
board's law restated for the lane — no identity entry AND no
window traffic for a 3-frame grace hides the row. The retirement
is DISPLAY-ONLY by design, and the design is the second find of
the night (see section 3): deleting the learned state would be
worse than the ghost, because the ring read re-seeds a dropped key
the very next frame while the kernel row stands — the hidden row
must stay hidden, not churn back as `learning 1/8`. The streak map
rides the lane's own key set (a key whose ring row left the read
takes its streak with it).

## 2. The placement (the visit law, one more collector)

The sweep rides exactly the sites the window and census sweeps
ride, with one new cost named openly: the Limiter's identity map is
lazy (write operations never load it), so the sweep triggers the
load itself — behind a no-policies short-circuit, so the common
host pays nothing and a mutation visit with rows to judge pays one
/proc walk. Not placed in `recover`: that command's explicit scan
IS this operation with the diagnostic report in front of it.

## 3. The hunt's own first find — the traffic leg (fixed in 6d4e384)

The panel's first landing gated on identity ALONE and would have
hidden the verdict of an unresolvable-but-delivering root. The
session board never had the hole (its predicate rides TWO signals);
the panel now carries the board filter's own predicate verbatim —
identity first (the happy path builds no active set), the frame's
`window_active` set on the first miss, a row hides only when BOTH
signals are absent for the grace. A zero-byte delta is not traffic
(window_active's own law — only moved bytes count).

## 4. The hunt's second find — the never-delivered silence (fixed in c5d6cee)

The design walkthrough for the live stage caught the sweep's own
belt reading an absent ring ROW as `Unknown` (veto). The ring is
created lazily — at the first ALLOWED packet — so a direction that
never delivered holds NO row: the BLOCK lane's rate-0 direction
delivers nothing by contract, and every blocked-then-dead root
would have been unretirable forever, along with every one-way
stream's quiet leg. The fix rides the creation law: an absent row
IS the never-delivered verdict (Silent); `Unknown` survives only
for the absent LENS. A quiet side gain: retiring never-delivered
zombies also closes their id-reuse hazard — a recycled inode
number can no longer inherit a standing policy.

## 5. The live proof (7ef4fb3)

`stage_server_zombie_sweep` in scripts/supermassive/
supermassive-test.py — the orphan-census stage's twin, the
owner-approved supermassive lane: the DELIVERED zombie (apply,
2s of traffic under the policy so both rings stamp, the client
exits, the horizon rotates, `status -v --print-json` retires the
row), asserting both surfaces (the verbose trace and the JSON's
gone row), with the idempotent `u --all` teardown that leaves the
pin slate the desktop phase expects.

## 6. Pins and A/B

Kernel side: seven pins in test/ebpf/limiter/zombie_tests.rs (the
decision matrix, the traffic belt, the lens veto, the block-lane
shape, the census's three verdicts with the horizon boundary
itself — window w-7 live, w-8 silent — and the trace wording).
Render side: six pins in test/ebpf/render/baseline_retire_tests.rs
(the grace, the flap guard, the signal guard, the state-survival
law, the streak retain law, the traffic leg with the zero-byte
shape). Frame bench A/B (10s, fixed-seed harness, 9f928ac vs the
landed tree): fps 5630.7 -> 5593.6 (-0.66%, run-to-run noise on
the shared host — the fixture resolves every root, so the panel's
walk is an unevaluated short-circuit there), density_gini
0.3225 -> 0.3226, frame_entropy 3.2039 -> 3.2007, dirty cells
82.31 -> 82.25, bytes/frame identical — every visual metric
inside its noise band, the sweep itself not in the render path at
all (the hunt-34 precedent).

## 7. Audited clean (the night's negative results)

| surface | verdict | the why |
|---|---|---|
| the session board (session.rs) | clean | retire_dead stands (mitigate-1); the panel's new law mirrors it without touching it |
| the board filter (focus.rs) | clean | `window_active`'s zero-byte law re-verified — the panel's traffic leg rides it verbatim |
| the footer census (footer.rs) | clean | board-based (already filtered); top-consumer fallback chain intact |
| the connection map (connections.rs) | clean | clear-then-rebuild behind the 3s TTL; `apply_socket_bytes` replaces wholesale — no growth surface |
| the monitor loop (commands/monitor.rs) | clean | the lane retire rides after refresh (streaks judge the read's own key set); identity TTL-refreshed by the poll |
| during/window interplay | clean | the window sweep's unstrict owns expired spans; the zombie sweep owns dead roots; an orphaned window row is the census sweep's own subject — convergent |
| unwrap/expect/panic scan (production tree) | clean | every hit is a test context or a guarded invariant (the build-stamp parser, the schema const parser, the connect loop) |
| LTS growth audit (long sessions) | clean | session acc capped 4096 with retirement; lane bounded by the ring read; streak maps ride their owners' key sets; conns TTL-rebuilt |

## 8. Named residuals (owner's call, not fixed — the over-engineering guard)

1. **The never-delivered zombie with an absent lens.** A zombie on
   a stale pin epoch (rings unreadable) never auto-retires — the
   lens cannot prove silence, and silence must be read, never
   assumed. The manual `recover` scan (identity-only, reported
   before it cleans) remains the tool for stale epochs. Bounded by
   the epoch: a fresh load re-pins and the sweep owns everything
   after.
2. **The alive-unresolvable-quiet root.** A root whose processes
   all entered a cgroup namespace after its apply, quiet for the
   horizon, is observationally identical to a dead root and
   retires with it. The shape requires an application-level
   `unshare(CLONE_NEWCGROUP)` under a standing policy (the CLI's
   own doors refuse the resolvable-to-root form at apply time);
   the estate's fail-open posture (enforcement preserved over
   bookkeeping) is honored by the traffic belt for every root that
   IS delivering. Named here so the day a report arrives, the
   diagnosis is one grep away.
3. **The sweep has no unpin ladder.** A status visit whose sweep
   takes the LAST policies leaves the empty skeleton pinned (the
   ladder belongs to the removal family; status never carried it).
   The next `u`/`recover`/apply-era unpins or reuses it — the
   pre-existing behavior of every status-side sweep, unchanged.
<!-- ZELYNIC-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths or symbol names. Maintainers update source code but may
  forget to sync every doc — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`, `ebpf/src/**/*.rs`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
