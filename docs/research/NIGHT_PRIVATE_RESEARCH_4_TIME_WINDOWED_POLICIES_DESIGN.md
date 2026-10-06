<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The time-windowed policies design brief (NIGHT-private-research-4 candidate, 2026-10-05)

The owner's question, verbatim intent: how should a temporary limit
spell itself on the CLI — `sudo zelynic ss brave 100kb --time
10:10`? — with the external research (DeepSeek, Tier A #4)
proposing `--during 09:00-17:00` / `--until 2026-10-15`, CLI-only,
no daemon, around 200 LOC, and the owner asking for more research
before any implementation because "this will create a new CLI."
This document is that research: the grammar options with one
rejected on the record, the datapath engineering that makes
daemonless time windows real (and the wall-clock wall every BPF
designer hits), the interactions with the laws this repo already
pinned, the honest LOC, and the recommendation. No implementation
ships with this doc — the decision it asks for is grammar and
sequencing only.

## 1. The problem, stated as the owner meets it

A limit today is forever until somebody remembers to lift it. The
sysadmin shapes a backup job for two hours and leaves 500kb on the
machine for the weekend; the parent blocks video at dinner and
unblocks it manually three times a week. What both shapes want is
the row to carry its own lifetime: apply once, the policy enforces
for the window, and the kernel itself decides when the window is
over — the same fire-and-forget posture every other zelynic
surface already owns (the pinned bpf_links ARE the daemon; README
claim 1, proven live by proof-claims.sh). The QoL gap is real and
the owner's ranking (Tier A, strong but optional) is the right
one: this is the feature that makes zelynic trivial to drop into
a maintenance window without a second mental note.

## 2. The grammar — three candidate shapes, one of them incoherent

### Option A — `--until <when>` (one-shot auto-expire): the v1

```
sudo zelynic strict-single brave 100kb --until 18:00
sudo zelynic strict-single steam 2mb --until +90m
sudo zelynic strict-single backup 10mb --until 2026-10-15
```

Semantics: the row applies NOW and expires at the named instant.
The instant may be a clock time today (18:00, an error if already
past — the owner retries with `+90m`), a relative duration
(`+90m`, `+2h30m`, `+7d`), or an absolute date (optionally
date-time). At expiry the datapath stops enforcing on its own; the
next zelynic invocation sweeps the dead row through the existing
unstrict/reclaim path. Always coherent: "limit with auto-expire"
has a beginning (now), an end (the instant), and no third state to
name. Works on every lane unchanged — `-d`/`-u`, `--per-socket`,
`block-single` (a bedtime block that lifts itself is the killer
combination of the whole feature).

### Option B — `--during <window>` (recurring daily window): the v2

```
sudo zelynic strict-single brave 100kb --during 09:00-17:00
sudo zelynic block-single shorts-app --during 22:00-06:00
```

Semantics: the row lives indefinitely; enforcement is active only
inside the window each day, and the window wraps midnight
(22:00-06:00 is six evening hours plus six morning hours — the
comparator is pure arithmetic, not a cron). Shares every piece of
machinery with Option A except the test: a two-sided
time-of-day compare instead of a single deadline. It is the
work-hours shape the external research named, and it is the
deferred-start shape too — "active from 10:10" is simply a window
whose end the owner must name anyway. Sequencing: v2, only after
Option A has carried the wall-clock bridge in production for a
cycle; recurring windows multiply every residue in section 3 by
the row's lifetime.

### Option C — `--time HH:MM` (the owner's sketch): REJECTED as a grammar

The owner's `--time 10:10` reads as "apply this at 10:10." A
one-shot CLI that has already exited cannot act at 10:10 — an
actor at a future instant is a daemon, a systemd timer, or a cron
line, and all three break the no-daemon headline (README claim 1,
the claim the whole architecture hangs from). The daemonless
reinterpretation — apply now, hold INACTIVE until 10:10 — is not
an instant at all: it is a window whose start is 10:10 and whose
end the grammar does not name ("until when?" has no answer inside
`--time 10:10`), which makes the flag ambiguous by construction
(forever? an hour? until the next flag?). The rejection record:
the grammar is refused, and the NEED behind it (deferred start)
is served honestly by Option B spelled out
(`--during 10:10-18:00`) or by a short `--until` chain applied at
the right moment. Nothing else in the ecosystem gives a one-flag
deferred start without a resident process — the honest answer is
that the flag cannot exist.

## 3. The datapath — how a limit expires with no daemon

### 3.1 The wall-clock wall, stated honestly

BPF has no wall clock. `bpf_ktime_get_ns` is CLOCK_MONOTONIC
(since boot, suspend excluded); `bpf_ktime_get_boot_ns` includes
suspend; neither reads the wall, and no helper in the cgroup_skb
proto set exposes CLOCK_REALTIME. A "09:00-17:00" policy must
therefore translate its wall-clock promise into the clock the
datapath CAN read, and the bridge is the same one every
userspace-writes-kernel-reads lane here uses: a pinned Array
carrying `wall_minus_mono_ns`, stamped by userspace at every
attach and every apply-family mutation. The one-shot CLI IS the
refresh channel — each invocation re-zeros the drift.

The drift residue, on the record: NTP slew is bounded at ~500 ppm
(~43 s/day worst case) and a manual `date -s` jumps arbitrarily;
between CLI visits the offset goes stale by exactly that. The
window edges are advisory to within the offset's age — a host
that runs any zelynic command daily holds the error under a
minute, and the design exposes a fire-early margin (default 2s)
so an expiry never fires LATE by the stale side. The alternative
— wall time in the datapath — does not exist in the kernel's
helper set; the residue is the price of the no-daemon claim and
it is stated, not hidden.

### 3.2 Where the expiry lives

A new `Policy` field was considered and rejected for v23: it
mutates the pinned 24-byte layout every row carries for a feature
a minority of rows will use. The chosen shape is a side map —
`policy_expiry` (HashMap, root cgroup id -> wall-clock ns),
keyed at the resolved policy root exactly like every other
per-policy lane, written by the apply path beside the policy row,
absent for every pre-v23 row. The datapath reads it AFTER the
policy hit on the policed path only — the unlimited fast path
pays nothing, the NIGHT-lts-2 law holds verbatim. An absent entry
is today's behavior exactly.

The expired verdict: a row past its instant answers ALLOW, per
packet, until swept — the enforcement the row promised has
finished, and the verdict is the fast path's miss shape, not a
new lane. The SWEEP is the removal the repo already owns: every
userspace command's mutation entry checks expiry rows and drives
them through the existing unstrict/reclaim path (reclaim.rs), so
the AMMSP generation bump, the bucket reclamation, the pin
hygiene, and the status rows all ride the machinery that exists.
The CLI is the daemon — the sentence this whole design is.

The `--during` comparator (v24) is a pure-core function the
math.rs discipline demands: `window_active(wall_ns, start_s,
end_s)` with the midnight wrap, core-only, rootless-pinned beside
the token math it sits next to in the datapath. The datapath
wiring is one map read plus the call.

### 3.3 The correction to the original sketch

The private-research-4 candidate list sketched this as a
"time-indexed extension of the already-versioned rate_ring." The
correction goes on the record here: rate_ring is a MONITOR — the
delivered-rate time series `status` reads — and a policy schedule
is a POLICY surface; putting enforcement state inside a monitor's
map would couple two contracts the architecture deliberately
keeps apart (the ring's own docs carry the law: "drops never
enter the ring... not a second ledger"). What survives from the
sketch is the intent — kernel-side time decisions, map-resident,
no re-attach, no daemon — and the placement moves to the policy
lane where every other per-row semantic already lives.

## 4. The interactions with laws already pinned

* The AMMSP generation belt: the datapath's expired-allow is NOT
  a mutation (no belt fires — the row simply answers expired per
  packet); the SWEEP is a removal and rides unstrict's existing
  gen bump, which zeroes every lane's stale state the way it
  already does. No new belt.
* The probe: `policy_still_stands` (probe_role.rs) gains the
  expiry read — a row that expired mid-window is a teardown
  shape the probe's existing belt already knows how to name (the
  "vanished row" verdict family), so a `--until 5s` policy probes
  honestly instead of verifying a corpse.
* `status`: the row prints its own lifetime ("until 18:00
  (47m left)" / "expired, awaiting sweep" / "during 09:00-17:00,
  outside window") — the JSON gains `expires_wall_ns` and
  `window_start_s`/`window_end_s` fields. The display is display
  work; the law is the datapath's.
* TZ/DST residue: the CLI converts local to UTC at apply time; a
  long-lived `--during` row drifts one hour across a DST boundary
  until re-applied. Solving this in-kernel means tzdata in BPF —
  absurd on its face; the residue is stated and the re-apply is
  the fix.
* `block-*`: a block with an expiry is the bedtime shape, and it
  composes with nothing new — the rate-0 verdict is a verdict,
  the expiry is row-level.

## 5. The honest cost

The external research's ~200 LOC covers the datapath check and
the CLI parse. This repo's discipline doubles it: the parse
family with its error surface (~80), the apply-path writes and
the offset stamp (~60), the pure-core comparator with its
rootless battery (~120 incl. tests), the datapath wiring and the
schema v23 bump with its two-tree sync (~60), the sweep through
reclaim (~60), status/JSON display (~80), docs and the
CHANGELOG-era note (~80). Honest total: 500-540 LOC including
tests and docs, or ~300 if the sweep and display ride a later
task. The risk register is short because the machinery is short:
offset staleness (section 3.1, margin + stated), the sweep depends
on CLI visits (a host that never runs zelynic again keeps a dead
row that no longer polices — the safety inverse of today's
"applied and forgotten," and strictly safer), DST (stated), and
the usual one-time re-apply contract a schema bump carries.

## 6. The recommendation

Ship `--until` as v23: the one-shot auto-expire on every lane,
the side map, the offset bridge, the sweep, and the status rows.
Ship `--during` as v24 on the same bridge after a production
cycle. Never ship `--time <instant>` — the grammar is incoherent
and the need it gestures at is a window. The owner's sketch
becomes, in the shipped grammar:

```
sudo zelynic ss brave 100kb --until +2h        # the temporary shape
sudo zelynic ss brave 100kb --during 09:00-17:00   # the recurring shape
sudo zelynic block-single shorts --during 22:00-06:00   # the bedtime shape
```

## 7. What this deliberately does NOT do

No daemon, no cron, no systemd timer, no config file, no
weekday-aware schedules (a v5+ consideration if ever), no
tzdata engine, no automatic re-attach, and no second CLI verb —
the window rides the strict-family grammar the owner already
types, as flags, the way `--per-socket` did.

## 8. The owner's decision (2026-10-06): one flag, three shapes

> Status: SHIPPED as schema v23 (the night-during series, this
> repo's own commits) — the grammar, the side map, the bridge, the
> margin, the sweep, the status surfaces, and the wall-form
> persistence all landed; this section stands as the decision
> record they were built from.

The grammar question sections 2 and 6 asked is now answered by
the owner, and the answer OVERRIDES the sequencing
recommendation of section 6: not `--until` as v23 and `--during`
as v24 after a production cycle, but ONE unified `--during`
whose argument shape alone selects the semantics — the one-shot
auto-expire, the recurring window, and the absolute date, all
under the one spelling, in ONE schema bump (v23):

```
sudo zelynic strict-single brave 100kb --during 09:00-17:00
sudo zelynic strict-single steam 2mb   --during 2026-10-15
sudo zelynic ss backup 500kb           --during 2h
sudo zelynic ss backup 500kb           --during 20d
```

* `HH:MM-HH:MM` (UTC) — the recurring daily window of Option B,
  midnight wrap included (`22:00-06:00` is the bedtime shape).
* `YYYY-MM-DD` (UTC) — the row is active for the whole named
  day and expires at 00:00:00 UTC the next day: "during" read
  literally, the Option A date shape folded under the same
  spelling. A date already fully past is refused at parse time;
  a future date holds the row DORMANT until it arrives (the
  deferred-start need section 2 refused for `--time`, served
  honestly here because the date bounds BOTH ends).
* a DURATION — the row applies now and auto-expires after the
  duration. Grammar: one value, one unit; units `s`, `m`, `h`,
  `d`, `mn`, `y` (seconds, minutes, hours, days, months,
  years; `mn` is month so `m` stays minute); bounds 1s floor,
  10y ceiling. Months are 30 days and years 365 days — the
  fixed-calendar translation a daemonless CLI can make with no
  tzdata engine; stated as the contract, not hidden.

The unified spelling costs nothing the split sequencing saved:
the three shapes share every piece of machinery (the side map,
the bridge, the sweep), and the grammar disambiguates on shape
alone (two `:` inside a `-`-joined pair = window; four `-`, no
`:` = date; digits + unit = duration), so no flag-combination
rules exist to document. The `--time <instant>` rejection of
section 2 stands verbatim, and the UTC-only decision (owner's
call, recorded here) drops section 4's local-to-UTC conversion:
the CLI takes UTC input directly, so the DST residue shrinks to
the long-lived daily window drifting one hour across a DST
boundary until re-applied (unchanged) and no conversion
surprises exist at all.

### 8.1 The storage delta the unified shape drives

The side map grows from the section 3.2 minimal shape
(`policy_expiry`, one wall ns word) to a tagged window row —
renamed `policy_window` for the same honesty, because a
recurring window is not an expiry — carrying both shapes:

* SPAN rows (duration, date) store `[start_mono_ns,
  end_mono_ns)` — the wall instants PRE-TRANSLATED into the
  kernel's monotonic clock at apply time. A hardening over the
  doc's v23 sketch: a span decided in monotonic terms cannot
  drift with NTP slew or a manual `date -s` at all (the
  section 3.1 residue shrinks to the suspend note below),
  because `bpf_ktime_get_ns` and the userspace
  `CLOCK_MONOTONIC` read (the monotonic_ns helper, format.rs)
  are the same clock domain.
* DAILY rows store `[start_s, end_s]` seconds-of-day UTC; the
  per-packet comparison reads the wall through the offset
  bridge (section 3.1 unchanged: the one-entry pinned
  `wall_clock_offset` Array, stamped at every attach and every
  apply-family mutation — the CLI is the refresh channel). The
  fire-early margin (default 2s) now skews BOTH edges toward
  less enforcement: the window opens `margin` LATE and closes
  `margin` EARLY, so a stale offset under-enforces by at most
  the margin and never over-enforces — the safe direction a
  limiter fails in.

The dormancy law (one entry, both directions): the map is keyed
at the RESOLVED POLICY ROOT exactly like section 3.2 named, one
shared map both hooks read — a row's two legs share one window.
Every apply-family invocation sets the whole window state the
way improve-29 made it set the whole leg state: `--during X`
writes X, an apply WITHOUT `--during` REMOVES any existing
entry (a stale window expiring a fresh forever-row is the
one-level-up twin of the stale-leg find). The unstrict/reclaim
sweep removes it with the legs. The expired/dormant verdict is
section 3.2's verbatim: ALLOW per packet, the miss shape, no
AMMSP belt, until swept.

The suspend residue, stated: CLOCK_MONOTONIC does not count
suspend, so a span on a host that sleeps ages in wall time
slower than its monotonic deadline implies — a `--during 20d`
on a laptop that sleeps nights outlives the wall-calendar 20
days by exactly the slept time. The wall-promise shapes (date,
daily window) are unaffected. The duration promise is "N awake
days" and is stated as such in the flag's help text.

Persistence (snapshot/restore) serializes the WALL-CLOCK form
(a duration leg stores its wall end instant; a daily window
its seconds-of-day pair), because a monotonic deadline is
meaningless across a reboot — the pinned maps are empty after
boot regardless (bpffs starts clean), and restore re-translates
wall to the fresh monotonic base through the same bridge. A
restored row must never convert "auto-expires" into "forever":
that inversion would flip the feature's whole safety direction.

### 8.2 The honest cost, revised

The 500-540 LOC estimate of section 5 carries over with two
additions: the unified grammar's parse family and error surface
grows (~120 with its battery), and the persistence pair's
window fields (~60). Honest total: 620-680 LOC including tests
and docs, still one schema bump, still no daemon — the
"CLI is the daemon" sentence of section 3.2 unchanged.

### 8.3 The owner's revision (2026-10-06, later the same day): duration-only

> Status: SHIPPED as night-during-7 — the parse family refuses
> the window and date shapes by name; this section is the second
> decision record, standing beside section 8's first.

After a production cycle with all three shapes live, the owner
revised the grammar to ONE shape — the timer:

```
sudo zelynic ss brave 100kb --during 1h     # after 1 hour, auto-expire
sudo zelynic ss backup 500kb --during 20d   # after 20 days, auto-expire
```

The recurring window (`09:00-17:00`) and the whole-day date
(`2026-10-15`) are refused at parse time, the wording naming
the removed shape and the duration that replaced them — the
owner's words: no more `09:00-18:00/2026-10-15`, support only
the timer. The units and bounds are unchanged (s m h d mn y,
1s..10y, months 30 days, years 365), and the duration half of
section 8's record stands verbatim.

What the revision deliberately does NOT change (the read-side
belt, stated in the kernel core's own header):

* The verdict core still honors every kind a pinned row may
  carry — a DAILY row written by an older build keeps its hours;
  a grammar change never narrows a map.
* `restore` still re-translates a state file's wall-form windows
  verbatim (the DuringSpec Span/Daily variants are the restore
  lane's vocabulary now — reachable, never flag-creatable), so
  an auto-expire promise survives the revision never converting
  into forever.
* The parse lost its one impure rung: a duration needs no wall
  clock, so `parse_during` takes the string alone and the
  parse-before-execute ladder is purely string-in verdict-out.

The honest cost of the revision is NEGATIVE on the parse family
(the window/date arms and their calendar deleted, the grammar
battery flipped to refusal pins) and zero everywhere else — no
schema bump (the window row's shape is untouched), no datapath
change, the prebuilt lane re-pinned only because the kernel
core's header text is part of the tree hash.
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
