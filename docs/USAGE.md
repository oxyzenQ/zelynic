<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# zelynic — Complete Usage Guide

This is the flagship reference for using zelynic day to day: every
command explained, real workflows, the exact mental model of how
enforcement works, and — importantly — an honest list of what zelynic
does **not** do. If you read one document before relying on zelynic,
read this one. Build instructions live in the
[README](../README.md); this guide starts after the binary works.
New here and the wall of sections looks heavy: [GUIDE.md](GUIDE.md)
is the simplified end-to-end walkthrough (the four-command flow, and
exactly when plain `strict` is enough vs when `--floor`, `--ceil`,
`--per-socket`, or `--during` earn their keep) — this page remains
the complete reference.

---

## Table of contents

1. [The 30-second version](#the-30-second-version)
2. [How zelynic actually works](#how-zelynic-actually-works)
3. [Command reference](#command-reference)
4. [Global flags](#global-flags)
5. [Workflows and recipes](#workflows-and-recipes)
6. [Honest limitations — read this](#honest-limitations--read-this)
7. [Troubleshooting](#troubleshooting)
8. [JSON reference for scripting](#json-reference-for-scripting)
9. [Exit codes](#exit-codes)
10. [FAQ](#faq)
11. [Maintainer's map](#maintainers-map)

---

## The 30-second version

```bash
sudo zelynic list-apps            # find the app + its cgroup id
sudo zelynic strict brave 100kb   # limit it (download AND upload)
sudo zelynic status               # verify the limit is live
sudo zelynic eagle-eyes           # watch traffic live, ranked (q to quit)
sudo zelynic ee cg:1234 --depth   # who/what IS this cgroup? (one shot)
sudo zelynic unstrict brave       # remove the limit
```

Limiting is **fire-and-forget**: the command writes rules into pinned
BPF maps and exits. The kernel enforces from that moment on — no
daemon, no service, no config file. Nothing runs in the background
burning CPU or battery.

---

## How zelynic actually works

Understanding three facts prevents 90% of surprises:

**1. zelynic limits cgroups, not processes.**
The Linux kernel puts every app into a *control group* (cgroup). zelynic
attaches two tiny eBPF programs at the cgroup-v2 root — one for ingress
(download), one for egress (upload). Every packet that crosses any
cgroup boundary is classified by its cgroup ID and checked against a
rate policy in a BPF map. Enforcement is pure kernel work: no proxy, no
`tc`, no `LD_PRELOAD`, no userspace hop.

**2. A "target" is resolved once, at command time — and the limit
follows the whole subtree.**
When you type `zelynic strict brave 100kb`, zelynic walks
`/proc`, finds every process whose name is `brave`, resolves the cgroup
each one lives in, and writes one policy per cgroup (per direction).
That resolution is a **snapshot** — see
[Honest limitations](#honest-limitations--read-this) for what that
means when you launch new apps later. A numeric cgroup ID (from
`list-apps`) targets one cgroup exactly, skipping name matching —
and the `cg:`-prefixed form every display surface prints
(`cg:18571` in the `status` table, the eagle-eyes footer, and the
suggested `ss` command) is the same direct target: the prefix
round-trips (NIGHT-boost-37), so a copied label always works.

The policy itself is **subtree-aware** (NIGHT-private-research-2,
MMSPA): a limit set on a cgroup polices every process that spawns
BENEATH it — child cgroups, grandchild cgroups, at any depth —
sharing ONE budget. A subprocess that lands in a fresh scope under
a limited target inherits the limit automatically; the kernel
resolves the covering root per packet, so descendants born an hour
after the strict are covered the moment their first packet moves.
No daemon, no config, no re-run. The one bound: a hierarchy deeper
than 32 levels from the cgroup root resolves unlimited (see the
honest limitations).

**3. State lives in the kernel, pinned under `/sys/fs/bpf/zelynic/`.**
Programs, links, and policy maps are pinned there, which is why
enforcement survives zelynic exiting. `status` simply reads the pinned
maps back. `recover` removes orphaned pins left by a kill mid-operation.
That directory lives on bpffs — a pseudo-filesystem — so **reboot wipes
it** (and re-assigns cgroup IDs anyway): limits are not reboot-persistent.

---

## Command reference

Names follow one grammar (NIGHT-improve-53, the masterclass
unification): **strict** applies limits, **block** cuts access
entirely, **unstrict** removes limits — ONE verb per family, and
`-all` sweeps every user app. The target grammar picks the lane: a
single target (`brave`, `cg:18571`, `docker://nginx`) rides the
single lane, and a `::`-separated list
(`brave::curl::pacman`) rides the group lane — one shared bucket
for every member. The separator DOUBLED because container native
grammar owns the single `:` (`docker://nginx`,
`k8s://prod/web-abc`, and the `cg:` display prefix), so the list
byte sequence is one they can never contain. The short forms: `s`
= strict, `b` = block, `u` = unstrict, `ee` = eagle-eyes (the
`alias = canonical` pairing is the same one-glance form `--help`
prints, NIGHT-boost-29). The fleet sweeps are `--all` lanes of
the family verbs now (NIGHT-improve-54): `s --all`, `b --all`,
`u --all` — the retired `-all` spellings (strict-all, block-all,
unstrict-all, their sa/ba/ua short forms, and blade-2's limit-all/
la before them) refuse with a redirect tip naming the runnable
verb + flag spelling. The twelve retired masterclass spellings —
strict-single, strict-multi, ss, sm, block-single, block-multi,
bs, bm, unstrict-single, unstrict-multi, us, um — carry the same
redirect contract, their tips naming the family verb — e.g.
`zelynic s brave 100kb`,
`zelynic s brave::curl::pacman 1mb`, or `zelynic ee brave
--interval 1s`.

### strict — limit one app, or a group sharing one rate

```bash
sudo zelynic strict <target> or <target::target::target> [rate] [-d <rate>] [-u <rate>] [flags — documented below]
sudo zelynic s brave::curl::pacman 1mb # the group lane: one shared rate
```

- `<target>`: a process name (`brave`), a cgroup ID (`18571`, from
  `list-apps`; the `cg:18571` display form round-trips verbatim —
  paste what `status` or eagle-eyes shows you), or a `::`-separated
  list for the group lane (`brave::curl::pacman`, `cg:1234::1245`)
  — see [the group lane](#strict--the-group-lane-one-shared-rate-for-several-apps)
  below.
- The policy covers **the target's whole subtree** with ONE shared
  budget (NIGHT-private-research-2, MMSPA): every process that
  spawns under the target's cgroup — at any depth, born at any
  time after the apply — inherits the limit automatically, and
  all of them draw from the same token bucket. `status` shows the
  subtree's traffic aggregated on the target's own row. Nested
  targets resolve NEAREST-root-first: a strict on A (100kb) plus a
  strict on B under A (50kb) gives B's subtree the 50kb budget
  and A's remaining subtree the 100kb one. See
  [How zelynic actually works](#how-zelynic-actually-works) and the
  [honest limitations](#honest-limitations--read-this) for the
  32-depth bound.
- `--per-socket` changes WHAT the rate caps
  (NIGHT-upgrade-charger-core-3b, Tier B #7): every CONNECTION gets
  its own bucket at the rate, enforced beyond the cgroup — the
  server shape (one process, many sockets: a multi-client server
  where no single connection can hog its siblings' budgets). The
  attribution is the kernel's own per-packet socket naming
  (`bpf_get_socket_cookie`, the same helper the observer's
  per-endpoint byte join has ridden since NIGHT-boost-26 — no
  tracepoint, no polling). The budget law is the honest one: the
  cgroup's TOTAL is bounded by rate x concurrent sockets, NOT by
  rate — that is what per-socket means (cap each connection at
  500kb and 8 live connections can move 4mb together). Packets the
  hook cannot attribute to a socket (cookie 0 — rare early-ingress
  paths) fall back to the cgroup's shared DRR budget, still
  policed. The lane rides the single lane only: a `::` list IS the
  shared-budget answer (one group bucket for every member — the two
  shapes refuse together, before any parsing), and block needs no
  bucket lane at all. `status` marks the rate cells (`500.0 KB/s
  /socket`) and the JSON carries `download_per_socket` /
  `upload_per_socket`; a policy mutation zeroes every socket's
  leftover tokens through the MMSPA generation belt, so a lowered
  limit never leaks the old burst to a live connection.
  The lane is ECN-first too (schema v21, the per-socket convergence
  closure): a connection's over-budget packet is delivered
  CE-marked instead of dropped whenever the kernel can set the
  codepoint (ECT-capable traffic), and the marked bytes charge a
  debt word inside the connection's own bucket that its own
  deliveries pay back — the same mark-before-drop contract the
  cgroup lanes ride, one connection at a time. The scope question
  this lane was deferred on ("N connections each halving their
  windows on per-connection marks is an aggregate-collapse shape")
  is closed by the rootless fleet sims (test/ebpf/limiter/
  ecn_socket_tests.rs): per-connection budgets are independent, so
  each connection converges on its own stream and the aggregate
  rides N x per-connection — no collapse term, and the fleet beats
  the same fleet under per-connection drops. Non-ECT traffic (the
  RFC 3168 majority) refuses the helper and drops exactly as
  before; the per-connection budget law gains only the one-time
  64 KiB ECN slack, so the aggregate honest bound is N x
  (rate x t + burst + 64 KiB).
  The mark is provable live: `sudo ./scripts/bench/ect-probe.sh`
  blasts ECT(0) UDP through a real --per-socket policy and reads
  the CE codepoint back at the receiver (the rootless
  `--self-test` pins the instrument in CI).
- The lane is **QUIC-aware** (schema v22, NIGHT-private-research-4
  candidate): QUIC (HTTP/3) multiplexes many connections over ONE
  UDP socket — the browser shape (Chromium and Firefox share a
  single socket across every QUIC session, demuxed by connection
  ID) — so a plain socket cookie would collapse all of them into
  ONE budget and the "each connection its own bucket" promise
  above would quietly mean "the whole socket". The datapath now
  keys the bucket by the packet's QUIC connection ID when the
  header carries it: handshake packets (long headers) carry the
  IDs with explicit lengths and key statelessly; data packets
  (short headers) carry the peer's ID whose length is connection
  state, LEARNED from the handshake's own length bytes and gated
  by a confirmation rule (the same length must be seen twice —
  the throwaway ID a QUIC peer replaces mid-handshake can never
  poison the lane alone). Everything the parser cannot carry —
  non-QUIC UDP, other QUIC versions, unconfirmed geometry,
  zero-length IDs, IPv6 extension headers — rides the plain
  socket key, exactly the pre-v22 behavior: the lane refines
  attribution, never degrades it. The same keying restores the
  CAKE flow-isolation lane (the fair-shared budget below) for
  HTTP/3 without any flag — it is automatic, and a browser's
  concurrent QUIC downloads isolate per connection instead of
  sharing one flow bucket. One boundary to know: a
  SINGLE-direction policy (`-d` only, or `-u` only) does not parse
  the unpoliced direction (the unlimited fast path stays parse-
  free — the pinned perf law), and the unpoliced direction's
  handshake packets are where the policed side's CID geometry is
  learnable — so single-leg policies keep QUIC data on the socket
  key (the pre-v22 behavior). The dual-leg default (`strict
  <target> <rate>` polices both directions) learns both.
- The shared budget is **fair-shared** (NIGHT-upgrade-charger-core-1c,
  the DRR lane): a shared first-come-first-served bucket let ONE
  greedy subprocess consume every token the instant it refilled and
  starve its siblings indefinitely — the cgroup /A at 100kb with
  subprocess #1 greedy meant #2..#100 got ~nothing, forever. Now the
  shared bucket is a POOL (its refill and aggregate are exactly the
  policy it always had) and every leaf cgroup spends from its own
  small bucket that draws from the pool in quanta: a leaf holds at
  most one quantum (the rate's 100ms share, floored at the 64 KiB GSO
  admit law) at a time — it can only draw when empty — and a draw
  takes at most half of what the pool visibly holds (so an interleaved
  sibling always finds the other half; a leaf re-draws the moment it
  empties, keeping the single-flow shape the legacy trickle it always
  was — paced draws proved TCP-hostile on the CI daemon row and were
  removed).
  dinner-28, the K > 2 truth: the half-draw residue law splits a
  TWO-asker pool evenly, but across MORE drawers the takes decay
  geometrically per position (50%/25%/12.5%... of the pool) — the
  live fair-share battery measured the worst leaf at 3.35x its fair
  share while the quietest starved below a single admit, the
  aggregate staying exactly the policy the whole time. The v16
  close: the take is further capped by pool/(learned+2), the
  learned drawee count kept per pool (the drr_pool_state maps);
  a cold pool keeps the exact v13 law. The deep-dive section
  below carries the updated measured bounds. NIGHT-hunt-Z5, the
  instrument split: the live supermassive battery certifies the
  CEILING (the aggregate band and the single round judged as its
  name says — inside the policy) and the anti-monopoly bound; the
  anti-starvation law's proof is the rootless sims that pin it per
  push (drr_ledger_tests), with the live quietest recorded as an
  advisory diagnostic — a drop policer promises the ceiling, never
  the floor, and the sender's TCP recovery is the sender's to
  give.
  Measured shapes: a single active leaf converges to the whole budget
  (the pool's equilibrium sits where its half-draws equal its full
  consumption — and the convergence rides the packet arrival cadence:
  a lone flow in deep retransmit backoff gathers its quantum through
  half-draws stretched across the RTO gaps, so a SHORT window can
  read the transient — the CI leg that measured one 64 KiB quantum
  in a 4s window against a 50kb policy (16.4 KB/s, 32.8%), where the
  legacy lane's in-place refill would already have admitted; it
  converges back over longer windows and the harness's measured row
  re-samples the under-band side, never the over-band one); two
  equal-demand leaves split it — worst case 2:1
  under adversarial always-first arrival, ~1:1 under real interleaved
  traffic — where FCFS measured 100:0. The fairness is statistical,
  not a formal round-robin guarantee (iteration over leaves is
  impossible in a cgroup_skb hot path — the honest bound is one
  quantum of slop); the stale-quantum belt zeroes any leaf's tokens
  the moment a policy mutation outlives them (the MMSPA generation
  stamp, applied to buckets), and the group lane (`strict a::b`)
  keeps the FCFS shape by documented scope (its members are
  enumerated by the apply itself, so the unknown-leaf starvation
  problem does not exist there).
- The fair share is **bracketable** (improve-40, schema v24: the
  guarantee lanes, floor/ceiling + hierarchical borrowing — the
  HTB rate/ceil idiom carried into a policer that cannot queue).
  `--floor 100kb` guarantees every subprocess under the target at
  least 100kb of the shared budget, however greedy its siblings —
  a PRIORITY, not a reservation: no tokens are held back, an idle
  subprocess costs nothing, and the unspent share stays in the
  pool for whoever is under their ceiling (the pool's own
  accumulation IS the lender — no carve-out, no daemon).
  `--ceil 300kb` caps every subprocess at 300kb even when its
  siblings are idle and the pool is rich — and it binds a LONE
  subprocess too (a cap that folds when siblings appear is not a
  cap). One flag sets BOTH directions' rows, the `--during`
  shape; the bracket validates against every direction the apply
  sets (floor <= ceil <= rate, per direction — a side that could
  never bind is a mis-typed rate, refused before the root ask)
  and is not offered beside `--per-socket` (the bracket polices
  subprocess leaves; per-socket polices each connection at the
  full rate — different lanes). The per-direction spellings
  (improve-40-b) bracket ONE direction's rows for the asymmetric
  link: `--floor-download 100kb` guarantees the download side
  only, `--ceil-upload 200kb` caps the upload side only — one
  spelling per side (`--floor` beside `--floor-download` refuses:
  the both-directions flag and its twin are one spelling apart,
  not a wider guarantee), and a per-direction side whose direction
  the invocation removes (no `-d` rate, so no download row)
  refuses outright, the improve-29 removal law named in the
  wording. `status` renders the pair as a
  grey subordinate line under the row (`guarantee: floor 100.0
  KB/s ceil 300.0 KB/s (per subprocess)` — equal pairs; a split
  renders direction-prefixed halves: `guarantee: dl floor 100.0
  KB/s / ul floor 50.0 KB/s (per subprocess)`), the verbose apply
  trace carries each leg's own pair beside the burst, and
  `--print-json` gains `floor_bps` / `ceil_bps` for the equal
  shape (absent when unset or split) plus the additive
  `download_floor_bps` / `download_ceil_bps` /
  `upload_floor_bps` / `upload_ceil_bps` for the split. The honest
  over-subscription law: when the floors' sum exceeds the pool's
  refill (leaves are dynamic; the config cannot know how many
  will ask), the floors degrade to the pool law — the pool never
  hands out what it does not have — and the quietest keeps the
  unfloored no-starve bound (pinned rootlessly by the guarantee
  battery, both sides: the fleet sims and the law pins). The
  bracket is provable live in REAL cgroups:
  `sudo ./scripts/bench/guarantee-probe.sh` (root required; the
  rootless instrument lane is `--self-test`) — four real leaf
  cgroups under one bracketed target, the floor's promise, the
  ceiling's cap, the pool law, and the per-direction split's
  ledger row, all measured on the running kernel.
- A positional `rate` sets **both** download and upload. `-d`/`-u` set
  them independently — and they take precedence: if either flag is
  present, the positional rate does not apply (no silent mixing), so
  `strict brave 100kb -d 1mb` limits download only.
  NIGHT-hunt-Z9 closed the shadow's two silent shapes: the positional
  is still PARSED (a typo'd value surfaces its did-you-mean tip
  before the root ask — `s brave not-a-rate -d 100kb` used to sail
  past the input boundary unexamined) and a valid one prints one
  stderr note naming what was dropped (`positional rate '100kb'
  ignored — -d/-u flags take priority`), the same
  ignored-input honesty `--print-json`, `--interval`, and `--focus`
  carry; stdout and exit codes are untouched. The
  unset direction is also REMOVED if a previous apply had enforced
  it (NIGHT-improve-29: `s brave 100kb` then `s brave -d 1mb`
  used to silently keep the old upload leg — the documented
  "download only" contract now holds in the map itself; re-specify
  `-u` when you want to keep both legs under one apply).
- `--force-this`: the ONE safety override (NIGHT-improve-30 — the
  former `--allow-dangerous` and `--force` pair, unified): permits
  rates below 1kb (can effectively brick an app) AND limiting the
  protected system blocklist (root, systemd, kthreadd, ... — 57
  names; see `--help`). The retired spellings are refused with a
  redirect tip. The blocklist match is FAMILY-aware
  (NIGHT-depthbore-1): a target that EXTENDS a listed name is guarded
  too — `systemd-resolved` (the display-enriched full name of the
  kernel-truncated `systemd-resolve` entry) and `sshd-session`
  (OpenSSH 9.8+'s per-connection process) both refuse without the
  override, where the old exact match let them through — and
  the `s --all`/`b --all` sweeps, which match the same comms the
  display enriches, used to sweep those daemons INTO the user-app
  set. Fail-safe by design: an innocent app that merely shares a
  prefix costs one `--force-this`. The numeric door enforces the same
  contract (NIGHT-blade-18): a bare id (`48181`) or the display form
  (`cg:48181`) resolves to its live member processes and runs the
  same family-aware blocklist on their names, so `s cg:<sshd's
  cgroup>` refuses exactly like `s sshd` — the old bypass, where
  every numeric spelling skipped the guard entirely, is closed. An id
  with no live members (a dead id, or a container view that resolves
  nothing) stays allowed: the policy against it can never match a
  socket — true for LEAF positions (NIGHT-hunt-Z3 correction: the
  cgroupfs ROOT itself never reaches that walk; see the next
  paragraph).

The root catch-all arm (NIGHT-hunt-Z3): a policy keyed at the
cgroupfs root (`cg:1` on the host — the node the hooks attach to) is
not one app's limit — the MMSPA ancestor walk resolves EVERY socket
on the machine through the root's row, so the root position is
refused whatever spelling reaches it: the explicit id (`s cg:1`),
a name whose processes live in the root cgroup (a daemon on a
no-systemd guest, where every comm's cgroup IS the root — checked
after the privilege ask, so the non-root refusal ladder is
unchanged), and the `s --all`/`b --all` sweeps (the root row
rides the skipped system roster however it is named; `--force-this`
includes it with a warn naming the blast radius). The refusal names
the machine-wide semantics and teaches the same `--force-this` lift
every other guard arm teaches. Container targets are excluded on
purpose: they resolve to the workload's own scope subtree, never the
namespace root.

The list grammar (NIGHT-blade-18, doubled to `::` by
NIGHT-improve-53): the `::` lists of the group lane are validated
as a whole before anything runs. Empty members (`a::::b`, `a::` —
a dropped app is a named mistake, not a silent skip), members
containing `/` (`a/` — comm can never carry a path separator), and
punctuation-only members (`;` — and unquoted in a shell this exact
byte splits commands) are all refused with the offending member
named. A member carrying a single `:` outside the `cg:` prefix
(`brave:curl::steam`) is the old single-colon grammar half-migrated
— refused with the separator law named, before any parsing, so it
never dies as a late no-match on a process name that cannot exist.
A one-distinct-member list (`brave::brave`) needs no separator —
hunt-30's "single is single" read through the merge. What stays
legal on purpose: numeric and `cg:<id>` members (their safety
rides the blocklist arm above), and alnum-bearing unknown names —
`s '$(reboot)::b' 1mb` stays the graceful refusal that echoes the
payload verbatim as data, never executes it (and since
NIGHT-dinner-11 it exits 1 — the no-match contract in
[Exit codes](#exit-codes)). A container URI inside the list is
refused with the fix named (charger-core-2's contract, carried
over the separator change: the group lane shares ONE bucket
across its members, and a container workload owns its own apply —
see the container targets paragraph in the strict section above).

The burst contract (no flag, by design): every policy banks a token
bucket of one second of traffic — rate bytes read straight — clamped
between a 64 KiB floor and a 100 MB ceiling (`BURST_FLOOR_BYTES` /
`BURST_CEIL_BYTES` in the layout contract; NIGHT-lts-8 raised the
floor from 4 KB). The floor is the largest single packet the kernel
hands the hook (GSO egress / GRO ingress super-packets, 64 KiB): a
bucket capped below it could NEVER admit that packet class, so a
trickle-rate policy under GSO traffic would bar its own data
packets forever — the floor guarantees every default-kernel packet
is admissible once a burst window accumulates. At rates below
~65 KB/s the floor dominates and a fresh bucket's initial credit is
one maximal super-packet (64 KiB) — a one-off, still smaller than
the 8-second credit any rate at or above ~65 KB/s earns. Under
extreme many-CPU bursts on one bucket the consume path retries
contention-lost deductions up to four times (schema v8), so a
concurrent deduction between one packet's read and its CAS no
longer falsely drops an affordable packet.

The command answers with the affirmative epilogue (NIGHT-improve-28):
a green `OK.` and the follow-up commands in the same green tier —
`Run 'zelynic unstrict brave' to remove, or 'zelynic status' to
check.` The enforced facts (rates, policy counts — one policy per
direction per cgroup, so a name resolving to two cgroups counts four)
live in `zelynic status`, not in the success echo.

The SELF-PROVING ENFORCEMENT (NIGHT-upgrade-charger-core-1-b): after
the apply lands, the strict family measures the limit it just wrote
before it claims it (the single lane since the beginning; the
group lane and the sweep since NIGHT-hunt-30, the owner's parity
find — the group probes the first list member, whose landing the atomic
contract guarantees, and the sweep probes the first applied app,
standing down with a named skip note when the fleet saturated —
measuring a lane that may not have landed would be a verdict built
on a guess). A fresh child cgroup is born under the target (inside
the subtree the policy covers, by construction — the same lane the CI
battery proves, on symmetric policies AND both single-direction lanes
alike: the supermassive matrix's probe family runs the live verify
against a download-only and an upload-only apply too, NIGHT-hunt-Z2's
regression pair for the Z1 direction split), one sacrificial client
moves real traffic through it
for a 3s loopback window against an unpoliced server (a transient
root-level cgroup, outside every policy), and the kernel's own ledger
brackets the window as the cross-check. The counted bytes come from
whichever end RECEIVES them — the client for download probes, the
server for upload probes (NIGHT-hunt-Z1: the sending side's own count
is its local socket buffer, not what the policy let through; the
receiver's count is the delivered truth, cut hard at the window edge
by a zero-linger close so trailing retransmits cannot over-run the
window's budget). The block that prints after
the epilogue carries the direction, the measured flow against the
target, the budget it was measured against (3s of refill plus the
burst), the kernel count, and the verdict: `enforced: VERIFIED` when
the flow stayed inside what a working bucket can admit. `VERIFIED`
means measured, not hoped — no other rate limiter checks its own
enforcement at all. The verdict bands share the CI harness's physics
(BAND_HI 1.30's family plus the in-flight slack), and the probe is
ONE-SIDED by nature: enforcement can only under-deliver a budget,
so a flow inside the ceiling is verified and a flow above it is
FAILED — `exit 1`, the red block with every number attached, and the
recover/re-apply path named. A probe that could not measure (server
unreachable, cgroup entry refused, a target too busy feeding its own
traffic — the ledger note says so) is `UNVERIFIED`: exit 0 with the
honest reason, never a vacuous pass and never a failed apply. An
empty target cgroup — its processes between spawns, or every one of
them exited while the limit stands — still measures: the probe
nests its own client under the target and resolves the cgroup by
inode when no member process can name its path. The
residency belt: the client's cgroup is verified from /proc before
the window opens, because an unentered probe measures an unlimited
path — the worst lie a verifier can tell. `--no-test` keeps the
scripted apply-only shape (CI lanes use it); a blocked (rate-0)
policy skips the probe by design — the drop ledger IS the block's
verdict. The probe costs ~4 seconds and one transient cgroup pair
(kill, reap, rmdir — no residue); the target's own traffic during
the window shares the budget and is named in the note when it does.

The ledger-refusal proof (NIGHT-hunt-Z7, the dual-limit hardening):
the kernel row carries BOTH counters now — `X admitted, Y refused
through the ledger` — and the verdict listens to the refused half.
The flow band alone had two live false-negative shapes: a probe whose
own TCP acknowledgments ride the POLICED counter-direction
(`-d 1kb -u 1kb` — the ACK egress spends the upload bucket beside
the target's own traffic) measures ~0 B against a limit that is
visibly biting, and a ceiling above the path's own delivery (`-d
1tb` — the flow floor is 600 GB over a window loopback moved 807 MB)
can never cross the floor. Both used to read UNVERIFIED while the
same maps held the truth: hundreds of KB the kernel REFUSED. Now a
starved flow with refusals inside the envelope is `VERIFIED` on the
ledger-refusal proof — a `proof:` row names its basis so it is never
conflated with the flow's own numbers — while a ledger that admits
beyond the envelope is `FAILED` on the leak lane (`the kernel ledger
admitted more than the budget allows`) whatever the flow measured,
and a silent ledger under a starved flow stays UNVERIFIED with the
reason that names its shape (the counter-direction starvation note,
or the cannot-be-tested-from-this-loopback note). The reason stack
is a stack: every cause its own `note:` row — starvation,
concurrency, the multi-leaf per-cgroup ledger (`the target spans N
cgroups ... window ledger: cg:A X in / Y refused, ...`), and the
budget's own history (the bucket's token count at window start —
`the bucket held 3.1 KB of its 65.536 KB burst at window start`:
a re-apply inherits a spent bucket, and the nominal budget line no
longer pretends otherwise). The leak envelope carries a deliberate
(window + 2s) span allowance — the ledger delta brackets the window
with spawn grace and teardown, and the veto must never false-fire on
boundary effects; per-socket policies skip the leak lane (every
connection spends its own bucket; the count is unknown) but keep the
refusal proof.

Configured rates display EXACTLY (the same task's round-trip
contract): what you type is what every config surface prints —
`-d 100.51kb` traces as `100.51 KB/s`, shows `100.51 KB/s` in
`status`, and the verify block names `100.51 KB/s` — one-decimal
rounding never hides a byte of the configured number again (the
one-decimal display stays for MEASURED values: counters, measured
flows, the monitor's live rates). A comma-carrying rate gets its own
repair instead of a generic parse error: `100,50kb` suggests
`100.50`, `1,000kb` suggests `1000` (never `1.000` — that would
silently scale the value 1000x).

Name matching details worth knowing: it is case-insensitive and matches
the kernel's `comm` name (max 15 chars). It matches **all** cgroups that
contain at least one process with that name — a browser plus its
crash-handler helper both match `brave`. Use `list-apps` /
`eagle-eyes <id>` to inspect what actually carries the traffic,
and target the cgroup ID directly when you want surgical precision.

Container targets (NIGHT-upgrade-charger-core-2, TIER A):

```bash
sudo zelynic strict docker://nginx 100kb
sudo zelynic s k8s://prod/web-abc 1mb
sudo zelynic unstrict docker://nginx
```

The reference resolves to the workload's cgroup id and everything
after that is the strict single lane's machinery unchanged — policy write,
self-probing enforcement probe, `unstrict` round-trip. `docker://`
accepts a container name or an id prefix (the `docker ps` hex, at
least 4 chars) and resolves through the Engine API over
`/var/run/docker.sock` (or the rootless daemon's
`$XDG_RUNTIME_DIR/docker.sock`); the container's cgroup is found
under `/sys/fs/cgroup` in both cgroup-driver shapes
(`docker-<id>.scope`, `docker/<id>`). `k8s://<namespace>/<pod>`
resolves through the kubelet's `/var/log/pods` directory names
(`<namespace>_<pod>_<uid>`) and targets the POD cgroup — every
container in the pod plus the infra container shares the limit.
A restarted pod leaves a stale log dir behind: only the live pod
owns a `pod<uid>` cgroup, and that is the disambiguator; an
unresolved tie names both uids and points at `list-apps`.

Every failure is specific, never the generic no-match — the input
was a well-formed reference whose infrastructure answered: "docker
socket not found", "no container named 'x'", "no pod 'y' in
namespace 'z'", each with its discovery tip. A stopped container
is named as such: the daemon's own status word rides the error,
because a stopped container's cgroup is torn down at exit — there
is no live workload to target. A policy left behind against a
dead cgroup is collected automatically by the next
mutation-capable visit (night-hunt-43's zombie sweep — the
two-signal walk: no identity entry, no ring traffic for the 8s
horizon; a stale pin epoch where the rings cannot be read rides
the cgroupfs death proof instead — the root's directory gone from
a complete walk, 0c3ba04); `zelynic recover` remains the manual,
reported override for the shapes the automatic walk cannot
conclude (a cgroupfs census past its bounds, a view that cannot
see the root's branch). Container targets
ride the single lane: a `::` list cannot carry them (the group lane
shares ONE bucket across its members — a container workload owns
its own apply), so `s docker://a:nginx::brave` is refused with the
fix named.
The dangerous-target blocklist does not apply to container
targets: it names HOST system processes whose throttling can lock
the operator out, while a container policy can starve only the
workload. The eagle-eyes target grammar stays process-name /
cgroup-id (its `/`-separator cannot carry a URI) — watch a
container's cgroup by its `cg:<id>` from `list-apps`.

### strict — the group lane: one shared rate for several apps

```bash
sudo zelynic strict brave::curl::pacman 1mb
sudo zelynic s curl::pacman::aria2c 1mb
```

All listed targets share **one** rate collectively: if one app saturates
it, the others starve. Use it for download tools you want to cap as a
pool (`curl::pacman::aria2c 1mb`), not for apps that each need their own
guaranteed slice — apply separate `strict` calls for that (one target
each).

The apply is **atomic** (NIGHT-upgrade-charger-core-2): every target
resolves before the first policy write, and one unresolvable name
aborts the whole invocation with `nothing was limited` — the error
names the missed targets and how many were resolvable, so scripted
fleet automation never lands in a half-configured state. A mid-flight
write failure (a full map, an ENOMEM) rolls the transaction back to
the exact pre-apply state: a target that already had a limit gets it
restored at its own rate and group, a fresh target returns to
unlimited. The `s --all` and `b --all` sweeps deliberately keep
the best-effort sweep — their target lists are snapshots of live
state, and an app exiting mid-sweep must not abort the fleet's limits.

The apply is **verified** (NIGHT-hunt-30, the owner's parity find):
the group lane carries the single lane's own self-proving
enforcement — the probe measures a real flow through the FIRST
member's subtree
(the atomic contract guarantees that member landed) and prints the
same `enforced: VERIFIED` block, the multi-leaf note naming the
group's per-cgroup ledger. `--no-test` keeps the scripted
apply-only shape (CI lanes use it); a blocked (rate-0) group stands
down on the drop-ledger note — the block family's own verdict.

The shared bucket's lifecycle (NIGHT-lts-7): every invocation banks a
fresh group id, and the group maps hold 256 slots each — a group's
slots are now returned when its LAST reference goes (an unstrict of
the group's last member, or an apply that overwrites the old
policies), so a long-lived host cycling group-lane invocations
cannot fill the maps. Before lts-7 the slots were never reclaimed:
after ~256 invocations the next group's bucket could not materialize
and its members silently enforced unlimited (the fail-open lookup).
The kernel side now also degrades a failed group lookup to each
member's own bucket at the group rate — over-admission against the
shared intent, never unlimited (schema v8).

### strict --all — cap every user app

```bash
sudo zelynic s --all 500kb
sudo zelynic s --all -d 1mb -u 500kb
```

Snapshots the current app list (same resolution as above) and applies
the rate to every non-system app. System/dangerous targets are excluded
unless `--force-this`. This is the command where the snapshot semantics
matter most — newly launched apps afterwards are **not** covered; re-run
it after starting new apps.

The sweep is **verified** (NIGHT-hunt-30, the owner's parity find):
when the whole fleet landed (no saturation), the probe measures a real
flow through the first applied app's subtree and prints the same
`enforced: VERIFIED` block the singles carry. A saturated sweep
(some rows left unlimited at the 1024-row policy ceiling) skips the
probe with a named note instead — the skipped member may be the very
lane the probe would name, and an unlimited path reads FAILED by its
own numbers, a verdict built on a guess. `--no-test` keeps the
scripted apply-only shape.

### block

Every block verb takes `--during` (night-during, schema v23;
the owner's duration-only revision): a blocked row with a window
lifts itself — `b shorts --during 8h` blocks for eight hours
and stands down when they are over (no daemon, no cron; the same
one-shape grammar the strict family takes: `<N><unit>`, units
s m h d mn y, bounds 1s..5y). The KERNEL decides when the window
is over; the ROW is collected by the next zelynic visit — every
apply, and since NIGHT-hunt-30 the read visits too (`status`,
`recover`: the commands the owner actually runs to check state),
so an expired row never waits for a manual
unstrict (the hunt-30 session's core find: stale rows sat in
`status` as "awaiting sweep" until a mutating command happened
to run).

```bash
sudo zelynic block brave
sudo zelynic b brave::curl::pacman
sudo zelynic b --all [--force-this]
```

Cut internet access entirely — packets are dropped at the cgroup
boundary in both directions. Same target grammar (single target or
a `::` list) and `--force-this` contract as strict. `unstrict`
removes a block exactly like it removes a rate limit (blocks and
limits live in the same policy maps; a blocked cgroup shows a
0-rate policy in `status`).

### unstrict

```bash
sudo zelynic unstrict brave            # one target
sudo zelynic unstrict brave::curl::pacman  # the list lane, same verb
sudo zelynic u --all                    # emergency reset: removes everything
```

Removes policies for the resolved cgroups and reports how many policies
(dl + ul) it removed — the same counting strict uses, so "4 policies"
in and "4 policies" out line up. Every removal also reclaims the
cgroup's token-bucket and stats entries behind it (NIGHT-improve-10):
the 1024-slot maps stay proportional to live limits, so a long-lived
host with churny cgroups never reaches the point where new limits
would silently stop applying (verbose mode traces each reclaim). The `u --all` reset also
removes the pin directory itself: after it, `status` reports a clean state.

### recover — crash cleanup

```bash
sudo zelynic recover
```

If zelynic was killed mid-operation (SIGKILL, OOM, power loss), pin
files can be orphaned. `recover` detects and removes them, and
reclaims the bucket/stats state of dead-cgroup orphans alongside
their policies (the same LTS budget unstrict maintains). Safe to run
anytime — it does nothing when state is clean. `status` tells you when
you need it ("stale bpf pin files detected").

night-hunt-43: a dead cgroup's standing policy no longer waits for
this command — the zombie sweep rides every mutation-capable visit
(`status`, every apply), retiring a root whose identity entry is
gone and whose rings have been silent for the full 8s horizon (the
two-signal law; `-v` traces each retirement). `recover` remains the
manual, REPORTED override — and for a stale pin epoch (the rings
unreadable, silence unproven) the sweep rides the cgroupfs death
proof: a root whose directory is gone from a COMPLETE walk of the
mount retires without the silence read (death is the stronger
verdict, 0c3ba04); recover stays the tool for the census's own
inconclusive shapes (a tree past the walk's bounds, a cgroup
namespace that cannot see the root's branch).

NIGHT-hunt-30: recover also runs the WINDOW-DEATH pass before its
orphan scan — an expired `--during` row is not crash residue (its
cgroup is alive, its clock is over), but it used to ride the scan as
a "live" policy and read "nothing to recover" while stale rows
waited for a manual unstrict. The window pass reaps what the clock
says is dead (a `Windows: N expired row(s) swept` line names it),
and the orphan census below counts only rows whose clock still
stands — window-death first, crash-residue second.

NIGHT-master-4 (the honesty hardening): every verdict recover prints
is VERIFIED. A failed policy-map read errors out (never a fabricated
"Orphans: none"), the removed-file counts come from the teardown's
own results, and an incomplete sweep — orphan policies that could not
be deleted — prints its result line but EXITS 1 with a retry tip, so
`zelynic recover && next-step` scripts retry instead of trusting a
success the filesystem did not grant. When the orphan sweep takes the
last policies, the empty enforcement skeleton is unpinned too (the
same no-residue ladder the unstrict family runs — a verified zero,
never an assumed one).

NIGHT-lts-8 (the leftovers question, closed): hosts that ran the
retired snapshot/restore pair may still carry its state file at
`/var/lib/zelynic/limits.json`. It is inert — nothing in zelynic
reads it, writes it, or chokes on it — so the full-cleanup ladder
sweeps it as old-install hygiene: `u --all`, `recover`, and the
no-residue unpin (the ladder that runs when the last policy leaves)
all remove it best-effort, with a one-time `[cleanup] legacy state
swept` line naming what left. The sweep never touches anything else
under `/var/lib/zelynic` — a directory with other content keeps the
directory.

NIGHT-dinner-23 (the count-honesty and style hardening): the
none-branch verdict reports BOTH dimensions the maps just read —
`Orphans: none (2 policies across 1 cgroup, all live)` — where the
old line printed the cgroup count under the noun "policies" ("all 1
policies" on a box carrying two dl+ul policies), and names the
empty skeleton (`no policies pinned`) instead of a vacuous zero
count. The report renders in the diagnostic family's verdict
contract (the update-check / doctor idiom): banner in bold brand
purple, State verdict words in the bold semantic tier (`clean` /
`valid` in status green, `STALE` in warning yellow), orphan
findings in warning yellow, affirmative Result values in status
green with partial-failure results in warning yellow, and every
quoted runnable command in suggestion white — all degrading to plain
text when piped, like every styled surface.

### status — what is limited right now

```bash
sudo zelynic status [--print-json]
```

Reads the pinned maps and prints the active limits: how many dl/ul
policies, and a table of cgroup / download / upload / allowed /
dropped per cgroup, with labels resolved by majority vote over the
live processes inside each cgroup.

Status is a daemon visit (NIGHT-hunt-30, the hunt-30 session's core
find): before the table renders, the visit sweep collects every
expired `--during` row — the kernel already stopped policing it at
its window's end, and the row used to sit in the table as an
"awaiting sweep" line with its stale rate until a mutating command
happened to run ("the brave on status should gone but this need
manual"). Now the check IS the collection: the sweep's unstrict
traces on stderr name what was reaped, and the table counts only
what the clock says is alive. A concurrent operation holding the
lock skips the sweep silently — the row renders with its honest
"awaiting sweep" lifetime line, collected by the next quiet visit.
`--print-json` rides the same lane, so automation's
`active_limits` counts live windows only.

Reading the last two columns (spelled out after the rc.2 long-run
audit showed the pair can read as a mystery):

- **allowed** — the cumulative BYTES that passed enforcement for
  the cgroup while its limit was active (download and upload are
  booked into one row). This is the traffic that actually flowed,
  not a rate: divide it by the time since the limit was applied
  and you get the enforced average.
- **dropped** — the cumulative BYTES the token bucket discarded:
  the cgroup tried to burst above the configured rate, the bucket
  was momentarily empty, and the packet took the drop branch (a
  rate-0 `block-*` policy books everything here — an unbooked
  drop would be invisible enforcement). Dropping is how the limit
  teaches TCP to slow down: after a drop the sender backs off and
  retransmits, so the retransmitted data reappears inside
  `allowed` later — which is why a healthy limit shows `dropped`
  as a tiny fraction of `allowed` (a 6h50m unattended rc.2 run
  measured 4.4 MB dropped on 3.4 GB allowed, 0.13%).

Both counters live for the lifetime of the limit: re-applying
`strict` with a different rate keeps the accounting continuous
(the long run re-tightened its target mid-run and the totals
carried), and `unstrict` reclaims the stats row once both
directions are gone, so the next `strict` starts from zero. The
table shows the byte pair; `--print-json` carries all four
counters (packets_allowed, packets_dropped, bytes_allowed,
bytes_dropped) where automation reads them — one metric per
cell, evidence of enforcement rather than a live rate meter.

The output IS the eagle-eyes style (NIGHT-engrave-5, the owner's
audit — the surface was the last uppercase holdout): the purple
flagship title bar (the same anchor the monitor carries), lowercase
purple column headers over the
monitor's own full-width purple grid (flush with the left edge, the
`|---` shape), data rows in status green (the calm tier — every row
is a live, enforced limit), the watchdog and census prose in grey
(`watchdog: 30s remaining`, `active limits: N dl, N ul`; warn yellow
only when the watchdog is expired), and the signature footer —
`v<version> (<commit>) by oxyzenQ`, the commit hash injected at
build time from `git rev-parse --short HEAD` (never hardcoded, so
the stamp always names the exact build) — bottom-left
(NIGHT-boost-5). The branch states carry the same chrome: a clean
system renders the frame with one grey `no active limits` line, a
stale-pin state renders the warn-yellow finding with the recovery
command in suggestion white. The watchdog line appears only when
the BPF auto-expiry deadline is actually ARMED; a dormant watchdog
prints nothing ("Watchdog: not set (enforcing)" was retired as noise
— it read like a state, but it was the absence of one).
`--print-json` keeps the `"watchdog"` field unchanged for scripts.

NIGHT-private-research-3 (the compact-and-simple pass, the owner's
directive): the breathing-gap filler lines retired on every report
surface — the title bar, the watchdog, the census, the header row,
the grid, the data rows, and the signature stamp now stack with zero
blank fillers between them. Same facts, same chrome, same table
contract; two to three fewer lines per report and no vertical scroll
for a one-limit status check. The pin family in
test/ebpf/display_tests.rs holds the compact contract.

### list-apps — discovery

```bash
zelynic list-apps [--print-json]
```

Lists every cgroup with live processes: process, procs, sockets,
cgroup id, uid — the report-table family's eagle-eyes style since
NIGHT-engrave-5 (the flagship title bar, lowercase purple headers,
the monitor's purple grid, green rows, the grey census line above
the table; the old "━━━" banner and uppercase headers were the
pre-eagle idiom). Since NIGHT-private-research-3 the census line
sits directly on the header row — zero blank fillers between the
title bar and the data (the same compact contract status owns). The procs/sockets columns expose multi-tenancy —
a row labeled `alacritty` hosting 4 processes and 7 sockets is
probably carrying your `curl`. Works without root; enforcement
commands do not.

Without root the socket column under-reads (NIGHT-master-4): another
user's `/proc/<pid>/fd` answers EACCES to an unprivileged scan, so
their rows count processes correctly and sockets as zero. One
warn-yellow stderr line discloses it (`unprivileged: other users'
socket counts read as zero — run with sudo for the full census`) in
both text and JSON modes — stdout stays byte-clean for scripts, the
exit code stays 0.

### eagle-eyes — the unified live monitor

```bash
sudo zelynic eagle-eyes [targets] [flags — documented below]
sudo zelynic eagle-eyes <target> --depth [--print-json]
```

One surface for the former `observe` + `top` pair (NIGHT-boost-1;
`ee` is the short alias, NIGHT-improve-25 — the singular `eagle-eye`
alias is removed, and typing it lands on a redirect tip pointing
here). It is an INTERACTIVE monitor and refuses non-terminal stdio
(NIGHT-boost-28): piped or redirected output (`sudo zelynic ee |
grep`) exits with a branded error before any terminal state or BPF
load — the scripted-output surfaces are `status --print-json` and
the `--depth` one-shot below; a redirected stdin refuses the same
way, because the `q`/`t` keys would never arrive. Since
NIGHT-dinner-18 the monitor also holds the launch-time existence
gate (the eBPF-verifier lineage the strict family carries): a
TARGETS spec that resolves to nothing — `sudo zelynic ee typo`,
or a cgroup ID whose processes are gone — exits 1 with the branded
no-match error and the `list-apps` tip BEFORE the TUI opens,
instead of entering a fullscreen session that only names the miss
in a frame note (a partial miss still opens: the frame renders the
unresolved names in place, and apps started mid-session appear on
the next refresh). Apps are RANKED
by session accumulation (NIGHT-boost-5):
rank 1 is whoever has moved the most bytes since the monitor
started — a heavy downloader that stops keeps its crown until
another app's accumulated total passes it. Rows persist across
quiet frames (an app that goes idle stays on the board with em-dash
rates and its accumulated TOTAL — no more collapsing to "waiting
for traffic..." once traffic has been seen), with per-cgroup detail
lines naming the processes and remote endpoints inside.

**No BLOAT TUI — on purpose (NIGHT-dinner-29, re-cut by
night-improve-58).** A bloat TUI is an interactive application:
menus to walk, a cursor to steer, screens inside the screen,
commands to memorize — an interface you operate. zelynic refuses
the genre, not the keyboard: the live monitor is a REPORT that
draws itself — one ranked frame, refreshed on the interval, honest
at every refresh — with exactly six keys (night-improve-58): `q`
quit, `t` theme, up/down scroll the focused section, left/right
switch it (left is always the `top process` table, right always the
baseline police panel — the `=>` marker in the focused section's
header lane names the section the arrows steer, night-improve-61's
owner glyph). The scroll is the owner's own call: on a server or
desktop with a standard-height terminal, "raise the window" was the
old advice for rows the frame cut — the arrows walk them instead,
the terminal keeps the space it has. Nothing to navigate beyond
that, nothing to select, nothing to configure mid-session: watching
is still reading, not playing. The moment you want to ACT on what
the frame shows, that is another command in another terminal —
`strict`, `block`, `rates` — the monitor's job is to show the data,
the CLI's job is to move it, and the display never becomes the
game.

#### The baseline lane (NIGHT-improve-1a, EAGLE EYES V2)

While the monitor runs it also reads the pinned time-series rings
(the kernel's own last-eight-seconds window of DELIVERED bytes per
policy root, charger-core-3a) once per frame, folds every completed
window into a running baseline, and renders the verdict in its own
ruled section under the table (NIGHT-engrave-9: a blank line and
the table's own grid line open the section, so the verdicts read as
a section, never as the table's last rows — the table ranks session
bytes, the panel lists per-policy roots, and the two axes no longer
share a column block; NIGHT-engrave-10: the section DOCKS — on a
tall terminal it sits flush against the pinned footer, directly
above the "top consumer" headline, and the blank slack rides between
the table and the section's separator, never between the verdict
rows and the footer they answer to; night-improve-72: the section's
visibility no longer rides the table's appetite — the layout
withholds the panel's guaranteed-visible floor (separator, header,
one verdict row, the scroll note) from the table's row budget
whenever the panel has rows to show, so a board rich enough to fill
the frame — scrolling up to the busy head ranks included — can
never starve the section out of the frame; a terminal too short to
hold both keeps the table, the primary view):
`learning n/8` while the
horizon fills, then
`steady <rate>` with the learned figure, and `above +N%` /
`below -N%` (warn yellow) when delivered traffic departs from the
baseline two windows in a row. A single focus target gets the same
verdict as a `baseline` row inside its key/value block. The lane
reads whatever is pinned, fail-soft: nothing policed, a stale
pre-v15 object, or maps torn down mid-session renders no baseline
(the honest absence, the same contract the status JSON's
`rate_ring` field owns) — and a read that fails resets the learned
state, so a re-applied policy starts learning fresh instead of
serving a frozen verdict for a dead policy.

The verdicts describe the POLICY's delivered aggregate (the ring is
keyed at the resolved policy root — for a `--per-socket` policy the
series is every connection's allowed bytes rolled up, the MMSPA
contract), and the focus row joins by exact cgroup id only: a
cgroup governed by an ANCESTOR's policy gets no row, because the
ancestor's aggregate cannot be split back down to the leaf, and an
unmarked aggregate would read as the leaf's own rate. The bands are
conservative on purpose: a window deviates only beyond ±50% of the
baseline AND 4 KiB absolute, and the flag renders after two
consecutive deviating windows — one burst window is a hiccup. The
flag self-clears when the EMA follows the traffic (a sustained step
change flags for about three windows, then reads as the new
steady): the baseline tracks what the target does now, it does not
pin the past forever.

### eagle-eyes --depth — the one-shot deep inspection (NIGHT-master-1)

The `--depth` flag turns the eagle into a report (the `--info`
alias is retired in NIGHT-blade-4 — one spelling; typing the old
flag lands on the `--depth` tip): `sudo zelynic ee cg:1234 --depth`
prints everything zelynic knows about one target and exits. No TUI
and no interactive-stdio gate — piped stdout is legal here (that
refusal belongs to the live view above), so
`zelynic ee 12345 --depth | less` works. The same
'/'-separated target grammar and autodetection apply
(`ee 12345/brave` prints one report per resolved cgroup; a name
targeting several cgroups reports each), and the report answers the
question a bare `cg:1234` row leaves open — WHAT is this:

```text
╭────────────────── zelynic eagle-eyes --depth ──────────────────╮
  cg:1234 — cat-test
  3 processes · 2 holders · 5 sockets
  ────────────────────────────────────────────────────────────────
  run from:         uid 1000 (cat) · /home/cat
  cgroup:           /sys/fs/cgroup/cat-test
  enforcement:      limited (shaping) — dl 100.0 KB/s · ul 100.0 KB/s
  accounting:       1.4 GB let through, 6.2 MB dropped (0.44% of what arrived)
  resources:        12.5 MB memory · 1m:2s cpu
  started:          10m:20s ago
  command:          ./cat-test --serve
  ────────────────────────────────────────────────────────────────
  pid     name                 type    perm  st  thr  rss      started  exe
  1234    cat-test             binary  755   S   4    1.3 MB   10m:20s  /home/cat/cat-test
  ────────────────────────────────────────────────────────────────
  network traffic (3s focus · arrival): dl 4.1 MB/s · ul 113.3 KB/s
   curl (4242) → 142.250.185.78:443 tcp ESTABLISHED [dl 4.1 MB/s | ul 100.0 KB/s]
   curl (4242) → [2607:f8b0:400a::]:443 tcp6 ESTABLISHED
  ────────────────────────────────────────────────────────────────
  act:  zelynic strict cg:1234 500kb
        zelynic block cg:1234
        zelynic ee cg:1234
```

The package name is the identity ladder (majority-vote comm, else
the cgroup path's basename — a systemd scope names itself — else
honestly `unknown`). The per-process census carries the type
(binary or script: a shebang-launched script is classified by
probing the first argv arguments after argv[0] for a `#!` source,
because /proc/<pid>/exe always names the interpreter), the
executable's permission bits, the state letter, the thread count,
the resident memory, the exe path, and the start age — all
best-effort per process (a member that exits mid-walk renders
partial facts, never an error). argv and every readlink result are
sanitized at the boundary the same way comm is
(NIGHT-cybersecurity-1) — a hostile process cannot forge report
lines. `--print-json` emits the whole report as one compact JSON
document (see the JSON reference below):

```bash
sudo zelynic ee 12345 --depth --print-json | jq '.targets[0].procs[0]'
```

NIGHT-blade-5 (the depth peak upgrade) sharpened the report three
ways. A limited target now carries its enforcement ACCOUNTING — the
kernel's own ledger (the cgroup_limiter_stats row), rendered as what
got through versus what the limit killed, with the drop share of
everything that arrived ("1.4 GB let through, 6.2 MB dropped (0.44%
of what arrived)"); an enforced cgroup with no booked traffic yet
says "enforced, nothing booked yet" instead of inventing zeroes. The
cgroup CONTROLLER's own resource view rides the summary: resident
memory from `memory.current` and accumulated CPU time from
`cpu.stat`'s `usage_usec` — the two counters no /proc walk can
reconstruct (memory.current includes page-cache and kernel-side
charges; cpu.stat is the scheduler's accounting across every task
that ever ran in the cgroup, the exited ones included). Both are
best-effort: a cgroupv1-only host or an unresolvable path simply
omits the rows. And every report block ends with the ACT-ON-THIS
tail — three copy-paste commands (limit, block, watch) keyed to the
exact `cg:` id the report just dissected, so the natural next step
is one paste away for a newcomer while staying precise for an expert
(the id round-trips through the same autodetection that resolved the
target; the friendly name sits one line above for reading).

NIGHT-blade-7 (the sharpness audit) tightened what the census
itself can tell a triage eye. The `perm` column carries the special
bits — a setuid-root binary renders `4755`, not the anonymous `755`
the plain-rwx mask left (the same four-digit convention `stat`
uses). The new `st` column carries the /proc state letter (S
sleeping, R running, D uninterruptible, Z zombie, T stopped) — a
D-state or zombie member is a first-glance signal the readable table
previously dropped while the JSON carried it. And a member whose
on-disk binary was replaced or removed after it started (a package
upgrade mid-run, a loader that deleted itself) keeps its exe path
and gains the kernel's own `(deleted)` marker, on the text cell and
as the `exe_deleted` boolean in the JSON document — the marker is
the triage fact, not formatting noise. Under the hood the same audit
closed a hang: the argv shebang classification probe now opens with
O_NONBLOCK, so a FIFO planted in a target's cwd can no longer stall
the root-invoked report forever (an attacker-controlled argv path is
probed, never trusted).

NIGHT-private-research-3 & think-like-light-years-3 (the depth
traffic focus): the report now answers "which connection is eating
RIGHT NOW", not just which endpoints exist. `--depth` attaches the
observer for a short FOCUS WINDOW (default 3s, `--focus 1s..30s`
tunes it), announces the window on stderr (`[eagle-eyes] traffic
focus: measuring a 3s window` — a report that silently sleeps looks
hung; stdout stays byte-clean for both output modes), then prints
the window's own section: the kernel's cgroup totals for the window
(dl/ul) plus every endpoint's per-socket bytes, movers ranked first
— the exact per-endpoint attribution the live monitor's frames
carry (NIGHT-boost-26's cookie join), composed once for the
one-shot report. A quiet window is a measurement ("no traffic in
the window"), a failed window is the honest note
("network traffic: not measured — <reason>") under the basic
socket census, and `--print-json` carries the window as the
`traffic` object (`window_secs` / `download_bytes` /
`upload_bytes`, null when unmeasured — distinguishable from a
zero-traffic window) with `download_bytes`/`upload_bytes` fields on
each endpoint row. The same pass compacted the report itself (the
owner's more-compact-and-simple directive): the kv spine dropped
its twin `package id`/`package name` lines (the headline IS the
package identity), user and exe directory merged into one `run
from` line, the controller's memory/cpu pair merged into one
`resources` line, every filler blank line retired, and the act tail
lost its header (the commands name their own verbs).

NIGHT-private-research-7 (the arrival-rates pass — the owner's own
transcript drove it): every dl/ul figure on both eagle-eyes surfaces
is now a per-second ARRIVAL rate, so a figure can be compared
against the policy two lines above it with no mental math. The
depth report's traffic header carries the `arrival` label
(`network traffic (30s focus · arrival): dl 40.0 KB/s · ul 1.1 KB/s`)
and every endpoint suffix divides by the window's own seconds
(`[dl 40.0 KB/s | ul 940 B/s]`) — the owner once read `[dl 1.2 MB]`
over an invisible 30s window as a rate and concluded a 200 KB/s
policy was bypassed (it was not: the arrival rate was 40 KB/s and
the drops were booked the whole time). `arrival` itself is the
honesty label: these are PRE-VERDICT figures — what reached the
cgroup, including what the limit then dropped; `status`'s
allowed/dropped ledger is the twin that splits them. The enforcement
line completes the answer with the `(shaping)` tag — when the
window's bracketing ledger reads saw the dropped counter MOVE,
`limited (shaping) — dl 200.0 KB/s · ul 200.0 KB/s` says the limit
was actively biting during the window, on the line itself, with no
`status` round-trip. The live monitor's endpoint suffixes joined the
same vocabulary: the per-socket cookie counters are differenced
frame over frame (the join carries THIS FRAME's movers), and each
figure divides by the measured poll-to-poll span — the same honest
denominator the download/upload columns use, the same per-second
vocabulary the footer's speed pair speaks. A connected-but-quiet
socket keeps its lean row: absence is the "quiet now" signal. The
footer's session speed pair carries the arrival label too
(`peak arrival dl | ul`, `avg arrival dl | ul`) — a peak above the
policy is the demand the limit absorbed, not a bypass.

The same honesty contracts ride the focus window as every ledger
in this document: the cgroup window totals are the KERNEL's own
counters (they include traffic from sockets that died mid-window);
the per-endpoint figures cover exactly the sockets the closing
/proc walk resolved cookies for — their sum can sit below the
totals, both numbers are true, they answer different questions.
Sockets that moved nothing render no figures (never a fabricated
zero), and the `--focus` flag on the LIVE monitor answers with one
stderr note (`--focus ignored (the live monitor is already
continuous — it owns --depth's traffic-window job)`) — the mirror
image of the `--interval` note the one-shot mode owns.

The BYPASS AUDIT (NIGHT-upgrade-charger-core-1-a) rides the same
window, and it is the honesty check no other rate limiter runs: the
report compares what the interfaces physically moved
(/sys/class/net counters) against what the cgroup_skb hooks saw (the
observer's machine-wide totals) over the focus window, and prints
the gap. A healthy machine renders one compact line (`bypass audit:
clean — cgroup hooks and interfaces agree (tx shadow 0%, rx shadow
2%)`). A window where the gap exceeds BOTH thresholds — 25% of
interface tx or 40% of interface rx (the receive band is looser:
every frame the stack dropped before socket demux — firewall drops,
port scans — lands in that gap without being a bypass) plus an
absolute floor (1 MiB tx / 2 MiB rx per window, so quiet windows do
not flag on rounding) — prints the full block: both sides' figures,
the shadow's share, the likely paths (AF_XDP, RDMA/RoCE, AF_PACKET
raw injection — traffic that never traverses the cgroup_skb hooks
zelynic enforces through, which NO cgroup rate limit can see or
shape), and the triage commands (`ss -etu` / `lsof -i` — find the
mover with no ordinary socket). `--print-json` carries the same
audit as the top-level `bypass_audit` object (`verdict` one of
`clean` / `bypassed_tx` / `bypassed_rx` / `bypassed_both` /
`unavailable`; null when no window ran). The scope is deliberately
MACHINE-wide and honestly labeled so: interface counters have no
per-process attribution — that is exactly what a bypass means — so
the audit names the gap and hands over the triage tools instead of
guessing a culprit. An unreadable /sys/class/net is the named
`unavailable` verdict, never a fabricated clean, and io_uring
zerocopy sends do NOT trip it (those still ride the socket sendmsg
path — verified against the io_uring source at implementation
time, and stated here because the feature brief guessed otherwise).

Two honesty contracts ride the mode. The live-only `--interval`
flag answers with exactly one stderr note (`--interval ignored
(--depth prints one report and exits)`) — stdout and the exit code
stay the report's own. And target resolution keeps the ladder,
hardened at NIGHT-dinner-18: a target that resolves to no live
cgroup — a typo'd NAME or a cgroup ID whose processes are gone — is
the actionable error with the `list-apps` tip (exit 1, the same
no-match verdict the strict family owns; the old depth pass
fabricated an empty report around a dead ID). The empty-census line
("no live processes — the cgroup is empty or its members exited")
now belongs to the exit race alone: the target was live at the
launch gate and its members left before the walk ran. Enforcement
state follows the status contract: nothing pinned is honestly
`unlimited`, pins that exist but cannot be opened are the
stale-pins error with its `recover` tip, and a failed policy read
is an error — never a fabricated verdict.

The SMOOTH OPEN (NIGHT-boost-25, the owner's masterclass loading
audit): the monitor used to run its whole eBPF load on the main
screen — a blank frozen terminal for the verifier's duration, then
a sudden full-frame flash when the dashboard appeared. Now the
alt screen and a quiet loading frame (the full chrome: title bar,
gradient rails, the pinned footer, and one grey
`loading observer…` note) arrive the moment you press Enter; the
BPF load, the identity walk, and the opening poll all run under
that frame, and the first live frame rewrites it in place with no
clear and no blank flash — the only visible change is the note row
becoming `waiting for traffic…` (plus whatever traffic already
exists). If the load fails, the terminal restores your shell and
the branded error prints there, clean. `-v` keeps the trace-first
sequence: the attach diagnostics print on the main screen before
the TUI takes over (stderr writes during the live frame would
garble it), so the trace itself is the loading feedback.

Subprocess detail is a two-level TREE (NIGHT-boost-21): a process
holding one live socket renders inline (`└ curl (4242) →
10.90.170.143:443`); a multi-socket process expands its endpoints
as indented children under a header that carries the socket count
(`└ firefox (4242) 3 sockets:` with `├`/`└` endpoint lines). The
ranked table caps each expansion at two children — the socket walk
sorts established-first, queued-first, so the two shown are the
live ones, the header's count carries the scale, and the total
detail budget stays at the flat list's four lines per row (overflow
folds into the `+N more socket-holding processes` summary). The
focus view (one target, one cgroup) expands every endpoint — the
deep answer to "who exactly is talking inside this cgroup".

Every endpoint line carries its own byte figures (NIGHT-boost-26,
the 2.4 frontier closed): `└ curl (4242) → tcp 142.250.185.78:443 [dl
10.2 GB | ul 180.0 KB]` — the dl/ul vocabulary of the footer's
speed pair (**dl** = download, **ul** = upload, lowercase L), the
figures measured over THIS report's focus window (default 3s,
`--focus` widens it) — the same suffix shape the live monitor
carries, over the live monitor's own since-attach horizon instead;
the two surfaces are one family, their horizons are their own
(NIGHT-hunt-38: the glossary's `dl`/`ul` entry decodes the pair
once for both). The tag itself carries the family since
night-improve-62: a v6 socket reads `tcp6 [2001:db8::1]:443` — the
ss/netstat spelling, the family at the tag instead of only through
the bracketed remote. The kernel itself names the owning socket per
packet (`bpf_get_socket_cookie` in both cgroup_skb hooks: the
sender on upload, the receiver on download), the observer bumps a
per-socket LRU byte map keyed by that cookie, and userspace joins
the map onto the endpoint table the /proc walk builds
(pidfd_getfd + `SO_COOKIE` resolves each held socket's cookie — a
root-only syscall pair, degrading gracefully to figure-less rows
when a host refuses it). The focus view also RANKS each process's
endpoints by their bytes — the hungriest endpoint first, so a
five-connection process answers WHICH connection is eating at a
glance; the live monitor's capped tree expansions rank the same
way (NIGHT-hunt-38 — what a two-slot cap hides is never the
answer). Sockets that
moved nothing since the monitor started render no suffix (a lean
row, never a fabricated zero), and under extreme socket churn
(4096+ warm sockets at once) the LRU may age a cold entry out —
an evicted-then-resumed socket restarts its accumulator, the
documented best-effort bound.

The frame is a PINNED composition (NIGHT-boost-14, the owner's
masterclass engraving; REBUILT to the owner's dashboard spec by
NIGHT-engrave-4; the line-by-line lookup reference with the example
frame lives in "The frame, line by line" below): the table floats
under the header and the footer
stays near the bottom of the terminal whatever the table does —
the footer block in the owner's exact line order: the consumer
headline (`top consumer is curl` — the rank-1 cgroup's busiest
process by the NIGHT-hunt-8 autodetect: socket detail first, the
label's comm second, the raw label last, so the headline never goes
dark over an identity miss; the name renders brand purple inside
the grey block), the session census (`478 packets + 1 cgroups` —
SESSION packets since NIGHT-engrave-4, the same horizon as the
bytes: one accumulator in the session state, both directions, where
the pre-engrave-3 census mixed a per-frame packet count with a
session cgroup count; the counts ride the SI compact ladder since
NIGHT-engrave-7 — small figures stay verbatim, an eight-hour
`2244843` reads `2.2M`, the counter-explosion hardening), the flat
total row
(`total usage internet in 1h:20s = 10.2 GB`, NIGHT-engrave-3: the
session uptime and the grand total ALONE — SI decimal, the same
ladder every byte figure rides — with the per-frame rates retired
at the owner's "only total consume bandwidth" call), the
session speed pair (NIGHT-engrave-6, directly below the total row —
the owner's data-center spec: `peak arrival dl | ul = 20.2 GB/s | 1.0
GB/s`, the session's peak per-direction arrival rates, tracked as running
maxima of the per-frame watched-set deltas in the session state
beside the totals; and `avg arrival dl | ul = 10.2 GB/s | 1.1 MB/s`,
the per-direction session totals divided by the SAME uptime the
total row renders — the three lines of the paragraph share their
legs and their clock, so they can never disagree. Both speak the
ARRIVAL label (night-private-research-7): they count what REACHED
the interface, pre-verdict — a peak above the policy is the demand
the limit absorbed, not a bypass. Both render
honest zeroes (`0 B/s`, never the limiter's BLOCKED verdict — the
observer measures, it does not judge), both ride the same watched
scope as the grand — a filtered frame's pair describes the watched
set, one paragraph one story — and a saturated 400G peer reads
`40.0 GB/s` through the same EB-capped SI ladder every figure
uses), the
actionable line (`limit target with 'sudo zelynic s curl 100kb'` —
the owner's engrave-4 wording: since NIGHT-engrave-7 the quoted
command rides the ACTIVE theme's brand tier (purple under
netrunner, each theme's own accent under itself — the owner's call),
the `s` short alias the CLI already carries, and
the engraved default rate — a named, documented constant, the one
fixed suggestion value on a line whose every other fact is derived
live), one blank of air, the status line — the frame's legend `1s
realtime - theme netrunner - q quit - t theme - ↑↓ scroll - ←→ section` (NIGHT-engrave-2, completed by night-improve-58),
grey, riding every compression tier — the owner's NIGHT-engrave-3
gap, and the signature copyright as the frame's last row. The
census, the consumer autodetect, and the limit suggestion retired
at NIGHT-engrave-3 came BACK at the owner's engrave-4 call,
re-cut to the exact new wording; the second grid stayed retired.
All footer text renders calm grey except the purple grid, the
purple build stamp, the brand-purple consumer name, and the
white suggestion command — subordinate information reads dimmer
than the data it annotates, actionable accents brighter. The grid
lines JOIN the frame's rails edge to edge (NIGHT-engrave-3: the
dashes begin at column 0 — the owner's `|---`, never `| ---` — so
the left border reads as one integrated line). The tiers are a
STATIC traffic light (the takeover blink is gone — eye strain):
rank 1 champion red, rank 2 warning yellow, rank 3 and below
status green; the subprocess usage lines render grey. A breathing
blank line sits under the title bar, and the grid under the
column header is brand purple, same source as the header text
above it. The column headers are lowercase
(NIGHT-engrave-1): `top process`, `download`, `upload`, `total`.
Every text row in the monitor starts lowercase (NIGHT-engrave-3's
call — the uppercase carriers retired with their lines).

The frame's BACKGROUND follows the terminal (NIGHT-boost-26): the
monitor asks the terminal for its background color at open (OSC 11,
standard query) and paints the frame in that color — a grey-themed
terminal gets a grey eagle-eyes. Grid lines, data, and info keep
the active theme; only the canvas follows the terminal. The follow
is LIVE and FAST (NIGHT-boost-32, cadence tightened to 250 ms at
NIGHT-boost-34): the monitor re-asks on a quarter-second cadence
and absorbs the answer from its input drain, so a mid-session
terminal background change (alacritty's live config reload, the
owner's repro: purple while the frame stayed black) is followed
within roughly 300 ms — one cadence plus one 50 ms wake — no
blocking, no stall, keys unaffected. A terminal that does not
answer renders exactly as before.

Frame borders (NIGHT-boost-20): the whole monitor reads as one
rounded box — the title bar's corners connect to its own purple fill
as the top border, every content row wears gradient-colored side
rails (the active theme's brand color sweeping dark to bright and
back down the frame — the cosmostrix msg-border triangle-wave
contract), and the frame closes on a full-width floor row that
sweeps the same wave ACROSS the columns (NIGHT-engrave-11, the
horizontal masterclass: every horizontal line the frame draws —
top border, grid lines, closing floor — rides the one chroma
method the rails ride, dark corners, glowing center, one
continuous wave on all four edges). Since NIGHT-improve-41 the
sweeps ride the
chroma dragon engine on truecolor terminals — the OKLab polar
interpolation ported from cosmostrix (the perceptual color space
where midpoints stay clean, lightness steps read even, and the
ramp's floor is 42% of the brand's perceived LIGHTNESS — the same
hue, honestly darker, never mud). The chroma engine is PRIMARY; a
terminal that cannot render truecolor falls back to the legacy
colors byte-for-byte: the NIGHT-boost-23 linear-light
interpolation on 256-color terminals (quantized onto the xterm
cube), the theme's flat brand color on 16-color terminals, and the
plain glyphs when piped. When the terminal's truecolor claim
cannot be trusted, `--color-mode` forces the legacy depth for the
whole process.
The
rails claim two columns and the closing row one line, budgeted
BEFORE anything renders — the column ladder, the footer pin, and
the detail trimming flow through the inset geometry unchanged. The
theme fallbacks themselves carry the NIGHT-boost-23 audit contract
(see docs/BRANDING.md section 2.2): nearest-cube brand/ok indices,
visibility-corner warn/hot, pairwise-distinct 16-color SGRs within
every theme, and the uniform grey ramp for subordinates.

Theme cycling (NIGHT-boost-18, improve-27): `t` cycles the frame's
palette forward (the uppercase `T` twin was retired by
NIGHT-engrave-2 — one simple key, modulo wraparound at the catalog
edge) — twelve themes in total (`netrunner` the default, then
`night_cyber`, `forest`, `spaceflight`, `carbon`, `atomic`, the
NIGHT-engrave-7 frontier five: `cafe`, `server`, `moonlight`,
`hacker`, `depth_sea`, and the NIGHT-dinner-30 deep neon
masterclass purple `curiosity`), the
cosmostrix cycle contract. A theme change repaints within the same
50ms wake and the footer's status line names the active theme
(`1s realtime - theme atomic - q quit - t theme - ↑↓ scroll - ←→ section`, NIGHT-engrave-2's
relocated legend — and since NIGHT-engrave-3 the title bar's
top-right hint is retired, so the status line is the legend's ONLY
home); the theme lives
ONLY inside the monitor — every other zelynic surface (help,
errors, status) keeps the default purple branding (see
docs/BRANDING.md section 2.2 for the palette table).

Dynamic screen size (NIGHT-boost-14): the loop probes the terminal
geometry every 50ms wake and renders a change within one wake — not
at the next refresh tick, so even `--interval 60` resizes instantly.
Adaptive compact mode on narrow frames: the subprocess detail hides
(below a 55-column frame, where the border inset drops under the
53-column total-column boundary — NIGHT-engrave-4 moved the boundary
up two columns with the right gutter; the column ladder itself is
the threshold now, one source of truth where a parallel constant
used to drift) and every
detail line is cut to the frame width, so a long process or endpoint
string can never wrap the frame or shift the pinned footer. Short
terminals compress the footer through a tier ladder (NIGHT-engrave-4
re-cut it for the rebuilt block; NIGHT-engrave-6 grew the top tiers
with the speed pair — 11/10/5/3) — the air above the status
line drops first (the owner's gap above the copyright survives to
Compact), then the census family and the limit suggestion (the speed
pair drops with the census: survival outranks statistics, the total
row alone carries the one-line story), then the consumer
headline and the roof grid — before the table loses its rows; the
total row, the status line, and the copyright survive at every
height. The row count follows the terminal height
— there is no `--limit`: the window IS the budget. DOWNLOAD and
UPLOAD carry live per-direction RATES; TOTAL carries the
session-accumulated bytes (the "total accumulated" function v10
had). The frame's rails are SYMMETRIC (NIGHT-engrave-4): the title
bar carries the same two-column gutter the rows use, the label
column absorbs the remaining width, and every table row ends at
the two-column RIGHT gutter — the TOTAL column's figures close two
columns before the right rail with the same air the left gutter
gives the rank, never flush against the border the way the owner
spotted ("too near the border, hard to see"). The column header's
rank cell is blank — the digits speak for themselves — and the
`top process` title spans the whole identity region (rank cell +
gap + label column), so it starts at the frame's canonical text
column, the same line every footer and note row starts on, instead
of floating past the blank rank cell (NIGHT-engrave-4: the owner's
"too distance from border"). Frames render through the
diff-based engine (NIGHT-improve-2): only the rows that changed
since the previous frame are written — one write syscall per frame,
an unchanged frame costs zero I/O at every terminal height
(NIGHT-improve-6), and the screen is never wiped or scrolled
mid-session (no flicker, no drift, no alt-screen scrollback side
effects). Every table row carries the session-accumulated TOTAL,
and the footer's total row sums the whole leaderboard — every
candidate, not just the rows shown. Byte figures keep one decimal
on every tier and promote at the rounding edge (999_950 B is
"1.0 MB", never "1000.0 KB").

The data-format ladder is LTS-complete (NIGHT-boost-22): byte
figures render B -> KB -> MB -> GB -> TB -> PB -> EB, the whole u64
domain. The minimum is the byte, the maximum the exabyte — u64::MAX
is ~18.4 EB, so the EB tier is the honest terminal for every figure
whose integer IS u64 (zettabytes, 1e21, need 71 bits and stay
unreachable in u64: the u64 ladder never renders a tier its integer
cannot reach). A long-lived server's lifetime totals cross the TB
ceiling in ~9.5 days of saturated 10G traffic, and the ladder keeps
every cell at most 8 columns wide on the way up ("999.9 PB"), with
the saturated ceiling rendering "18.4 EB" — never the five-digit
"18446.7 TB" the old TB-terminal formatter drew. Rate parsing keeps
its kb..tb unit grammar (MAX_RATE is 1 TB/s — no NIC on earth
justifies a petabyte-per-second policy), while lifetime DISPLAY
answers in the units the traffic actually earned. The formatter
itself is exact integer math in u128, the same discipline as the
fractional rate parser; the rate conversion feeding it is a
saturating division (a saturated counter renders "18.4 EB/s",
never a wrapped figure).

The zettabyte-and-beyond half of the ladder is real since
NIGHT-lts-5 (the server long-endurance contract: "harden and robust
for future when reach limit of zelynic like possible 1 zettabyte ZB
even quettabyte QB"), and it lives on exactly the surface that can
honestly carry it — the SESSION accounting. The scale architecture,
one paragraph: the kernel's per-cgroup counters are u64 by BPF-map
contract and WRAP at 18.4 EB (~4.7 years of 1-Tbps traffic through
one cgroup — a real long-endurance server horizon); the userspace
deltas went WRAP-COHERENT with them the same night (modulo-2^64
subtraction in the loader — the old saturating clamp turned every
post-wrap poll into a zero delta, sending the wrapped cgroup
silent: frozen rates, frozen totals, for another full 18.4 EB); and
the session accumulator widened to u128, folding those wrap-coherent
deltas into totals whose honest ceiling is ~340 million QUETTABYTES
(~8.7e21 years of 1-Tbps traffic — past the SI prefix list's own
end). The board's TOTAL column and the footer census render through
the u128 ladder — B, KB, MB, GB, TB, PB, EB, ZB, YB, RB, QB — so a
months-long monitor on a fat pipe says "1.0 ZB" and means it, while
every kernel-map surface (the limiter's policy figures, the
per-socket lifetime columns) keeps the u64 ladder whose truth those
maps actually hold. One width, one ladder, one truth: a formatter
never renders a tier its integer cannot reach.

The positional `targets` filter is autodetected per token: all digits
means a cgroup ID (find one with `list-apps`), the `cg:18571`
display prefix round-trips (NIGHT-boost-37 — a label copied off
the table watches the cgroup it names), anything else a
process name — and names watch ALL matching cgroups, the same
whole-app semantics as strict/block. One target that resolves to a
single cgroup switches to the deep focus view: per-direction deltas,
rate, lifetime totals (both lifetime counters summed — download and
upload since attach, never a per-refresh delta), and every
socket-holding process with its endpoints, uncapped. Multiple
targets (`12345/brave/firefox`) keep the ranked table, filtered.
An empty segment in the slash list is refused, not dropped
(NIGHT-dinner-16, the blade-18 colon contract mirrored): `brave//`
is a usage error naming the empty segment — a hollow spec can only
be a typo, and a typo that silently drops a watch target is the
exact mistake the grammar now refuses.
Resolution re-runs every frame against the live identity map, so an
app started mid-session appears on the next refresh. Default refresh
1s — realtime precision; `--interval` calms it down to at most 60s.
**Quit with `q` — the only quit key** (NIGHT-hunt-16; ESC and Ctrl+C
are drained, never treated as quit). One exit path exists besides
`q`, and it cannot be triggered by any key: a dead output sink
(NIGHT-ultimate-2) — a piped monitor whose reader closed, a sink
that filled — ends the session quietly on the next frame instead of
spinning forever on discarded writes; the alt screen restores, the
eBPF observer detaches, exit 0. A slow-but-open reader never trips
it (a full pipe blocks, it does not error). If the monitor is
killed violently (`kill -9`, `pkill`), the violent-death guard
(NIGHT-boost-33) restores the terminal itself — and for the state
where even that is not enough (the guard could not arm, a foreign
app's stuck modes, a screen that survived it all), `zelynic
--reset-terminal` (NIGHT-hunt-31) is the in-place rescue: five
defense-in-depth layers (ANSI restore, ANSI clear, `stty sane`,
`reset`, `tput reset`) plus the sudo-interposition lane
(NIGHT-improve-31, its post-exit half re-shaped in
NIGHT-improve-34: under sudo's `use_pty` the command's fds are a
throwaway pty, so the rescue resolves the user's REAL terminal
through the sudo monitor and repairs it directly — and after sudo
exits, the bounded orphan READS the terminal before touching it:
sudo's own exit-restore skips when the flags were changed under
it, so the usual case needs no second touch at all, and when the
monitor's raw residue IS still there the orphan cures ONLY the
output lane (OPOST|ONLCR, the anti-staircase pair — never the
input flags, so the shell's live line editor keeps its own echo:
the blanket re-apply it replaces double-echoed and ate typed
characters after a HEALTHY-terminal rescue), works with or
without sudo, blind-typed when the screen shows nothing.

#### The frame, line by line — the annotated reference

The prose above carries the design rationale; this subsection is the
lookup reference (NIGHT-docs-13): one example frame, then every
element with the facts it carries — the horizon each figure counts
over, the scope it sums, and where the number comes from. The frame
below is the classic 80x24 terminal at the Full footer tier: three
of twenty-two watched cgroups fit the window budget, the rest fold
into the hidden note (the census still counts all of them — a
figure never lies about the board just because the window is small).
Color annotations follow the frame; the text layout is byte-exact
with what the renderer draws.

```text
╭───────────────────────────── zelynic eagle-eyes ─────────────────────────────╮
│                                                                              │
│=> top process                                download     upload      total  │
│──────────────────────────────────────────────────────────────────────────────│
│    1  cg:7001 (brave)                        2.1 MB/s   180 KB/s    10.2 GB  │
│    └ brave (4242) → tcp 142.250.185.78:443 [dl 2.0 MB/s | ul 88.0 KB/s]      │
│    2  cg:73402 (firefox +1)                  3.4 MB/s   210 KB/s     901 MB  │
│    └ firefox (4242) 3 sockets:                                               │
│        ├ tcp 104.18.32.7:443 [dl 3.1 MB/s | ul 174.0 KB/s]                   │
│        └ tcp 104.18.32.115:443 [dl 296.0 KB/s | ul 36.0 KB/s]                │
│    3  cg:73511 (curl)                               —          —     4.2 MB  │
│   (+19 more — ↑↓ scroll)                                                     │
│──────────────────────────────────────────────────────────────────────────────│
│  top consumer is brave                                                       │
│  1.2K packets + 22 cgroups                                                   │
│  total usage internet in 1h:20s = 11.1 GB                                    │
│  peak arrival dl | ul = 24.6 MB/s | 1.2 MB/s                                 │
│  avg arrival dl | ul = 2.9 MB/s | 143.6 KB/s                                 │
│  limit target with 'sudo zelynic s brave 100kb'                              │
│                                                                              │
│  1s realtime - theme netrunner - q quit - t theme - ↑↓ scroll - ←→ section   │
│                                                                              │
│  v50.0.0-rc.1 (a1b2c3d) by oxyzenQ                                           │
╰──────────────────────────────────────────────────────────────────────────────╯
```

The header block:

| Element | What it is |
|---|---|
| Title bar | The frame's own top border: bold brand purple, rounded corners, filled to the full width. Identity only — `zelynic eagle-eyes` unfiltered, `zelynic eagle-eyes — 2 targets` filtered, the focus view names the cgroup. No key hints live here (the footer's status line is the legend's only home). |
| Breathing gap | One blank line under the title bar — the header never sits jammed against the brand. |
| Column header | Lowercase `top process` spanning the whole identity region (rank cell + gap + label column), with `download` / `upload` / `total` right-aligned over their numeric columns — the figures below close under their titles, never flush against the right rail (two columns of air, the symmetric right gutter). |
| Grid | Full-width brand-purple line under the header (and roofing the footer) — the dashes join the side rails edge to edge: `\|---`, never `\| ---`. |

The ranked table:

| Element | What it shows |
|---|---|
| Rank | Session-accumulated order: rank 1 has moved the most bytes since the monitor started. A heavy downloader keeps its crown after stopping; rows persist across quiet frames. |
| Row colors | The static traffic light: rank 1 champion red, rank 2 warning yellow, rank 3+ status green — takeover never blinks (eye-strain call). |
| `download` / `upload` | LIVE per-direction rates: this frame's delta divided by the MEASURED poll-to-poll span (NIGHT-lts-3 — the honest denominator, not the nominal cadence the beat scheduler only approximates). A quiet app renders an em dash (`—`) — the observer measures, it does not judge (never "BLOCKED", which is a limiter verdict). |
| `total` | Session-accumulated bytes for that cgroup (download + upload since the monitor started) — the ranking key. |
| Label | The cgroup's identity: `cg:<id> (<comm>)`, with a `+N` suffix when more than one process holds sockets inside — `(brave +22)` reads "the brave cgroup, 23 socket-holding processes: brave plus 22 more". |
| Detail tree | The socket-holding processes inside the cgroup, grey: one displayable endpoint renders inline (`└ brave (4242) → tcp 142.250.185.78:443`); a multi-socket process gets a header carrying its count (`└ firefox (4242) 3 sockets:`) with the two hungriest endpoints as children — the cap ranks bytes-desc (NIGHT-hunt-38), so what it hides is never the answer. Every endpoint names its protocol and family (`tcp` / `tcp6` / `udp` / `udp6` / `raw` / `raw6`, night-improve-61: the owner's find — only UDP carried a tag, so the one protocol most rows speak read like the unnamed default; night-improve-62: the v6 tables stopped collapsing into the v4 spellings, so a dual-stack host's rows read their family at the tag — the ss/netstat vocabulary, `[::1]:443` alone no longer carries the hint), saturated sockets carry `[busy]`. Established TCP and connected UDP only — listeners and TIME_WAIT are noise, filtered. Each endpoint carries its own arrival rate when the join resolved it (`[dl X | ul Y]` — **dl** = download, **ul** = upload, both lowercase L: the same two-letter vocabulary the rate columns and the footer's speed pair speak; the figures are that endpoint's per-second ARRIVAL rate over the measured span — the per-socket counters differenced frame over frame, night-private-research-7 completing NIGHT-boost-26) — a socket that moved nothing this frame keeps its lean row (absence is the "quiet now" signal). |
| Scroll note | `(-N above · )+M more — ↑↓ scroll` (night-improve-58): the window IS the budget (no `--limit`) and the arrows walk it — the counts name the rows above the window and the rows the room cut; the count rides the same SI compact ladder as the census. |

The pinned footer — the frame's dashboard, in the owner's exact line
order. Every figure names its horizon and scope:

| Line | What it carries |
|---|---|
| `top consumer is brave` | WHO is eating the network: the rank-1 cgroup's busiest process by the autodetect chain — socket detail first, the label's comm second, the raw label last (`cg:7001` when identity is unresolved) — so the headline never goes dark. Brand purple inside the grey block: the one living thing in the footer. |
| `1.2K packets + 22 cgroups` | The session census. Packets: SESSION packets since the monitor started, both directions, the same horizon as the bytes. Cgroups: the board the frame watches — a filtered frame counts its filtered board. Both counts ride the SI compact ladder: small figures stay verbatim (`24 packets`), an eight-hour `2244843` reads `2.2M` — no raw u64 ever explodes the line. Every candidate counts, not just the rows the window showed. |
| `total usage internet in 1h:20s = 11.1 GB` | The story in one line: session uptime and the grand total ALONE (the per-frame rates retired at the owner's call — only totals consume bandwidth). The grand sums the whole leaderboard, every candidate. The uptime ladder reads `45s` / `12m:34s` / `3h:7m` / `2d:5h`. |
| `peak arrival dl | ul = 24.6 MB/s \| 1.2 MB/s` | The session's PEAK per-direction ARRIVAL rate: running maxima of the per-frame watched-set rates, each peak divided by the span IT was measured over at fold time (NIGHT-hunt-38 — a historical peak renders at its own span forever; a later frame's span jitter can never restate it) — never reset, the session horizon. Arrival means pre-verdict: what REACHED the interface, including what a limit then dropped — a peak above the policy is the demand the limit absorbed, not a bypass (night-private-research-7 relabeled the line for exactly that read). Honest zeroes at rest (`0 B/s`). |
| `avg arrival dl | ul = 2.9 MB/s \| 143.6 KB/s` | The session's average per-direction arrival rate: the same per-direction totals the grand sums, divided by the SAME uptime the total row renders — the three lines of the paragraph share their legs and their clock, so they can never disagree. |
| `limit target with 'sudo zelynic s brave 100kb'` | The action: a ready-to-paste command for the consumer the headline just named — the `s` short alias, and the `100kb` engraved default (the one fixed suggestion value on a line whose every other fact is derived live). The command rides the ACTIVE theme's brand tier — the frame's two living accents, the thing to read and the thing to act on. |
| status line | The legend: `1s realtime - theme netrunner - q quit - t theme - ↑↓ scroll - ←→ section` — the poll interval, the active theme's name, and the whole six-key map (night-improve-58): quit, theme, the scroll arrows, the section arrows. Rides every compression tier. |
| Build stamp | `v50.0.0-rc.1 (a1b2c3d) by oxyzenQ` — version, git hash, author, brand purple: the frame's quiet closing paragraph. |
| `(identities unresolved — labels show raw cgroup IDs)` | The rare honesty note: the /proc walk found no identities this frame, so labels render raw IDs. It rides only when true. |

Colors, on a live terminal: the footer text renders calm grey except
the purple grid, the purple build stamp, the brand-purple consumer
name, and the theme-accented suggestion command — subordinate
information reads dimmer than the data it annotates, actionable
accents brighter. On 256-color terminals the gradient quantizes
onto the xterm cube; 16-color terminals render the rails flat;
piped output renders the plain glyphs you see above.

Short terminals compress the footer through a tier ladder — the
window never scrolls and the footer never detaches; lines drop in a
fixed order before the table loses a single row:

| Tier | Footer lines | What drops |
|---|---|---|
| Full | 11 | nothing — the whole dashboard, with its air |
| Compact | 10 | the blank above the status line (the owner's gap above the copyright survives) |
| Minimal | 5 | the census family and the limit suggestion — the speed pair drops with the census (survival outranks statistics; the total row alone carries the story) |
| Tiny | 3 | the consumer headline and the roof grid — total row, status line, copyright only: the survival floor |

Reading order, the five-second answer to "who is eating my
network": the headline names the eater, the census says the scale,
the total row says the session's story, the speed pair says how
hard it ran, and the suggestion line is the action — copy it, paste
it, the limiter takes over from the observer.

### doctor — support check

```bash
zelynic doctor [--print-json]
```

Reports kernel version, cgroup v2 layout, BPF filesystem, pin state,
and whether your machine can run zelynic. Run this first on a new
distro. The BPF-filesystem check verifies that `/sys/fs/bpf` is a
real mounted bpf filesystem (statfs), not merely a directory that
happens to exist (NIGHT-hunt-28) — the kernel creates that directory
on every system, so existence alone says nothing.

The BUILD block under the `Build:` flavor verdict (night-improve-66)
carries the exact artifact facts: `Version` (crate version), `Commit`
(git sha), `Variant` (the canonical build label — the release matrix
platform id, or the detected arch-libc for plain builds), `Built`
(UTC stamp), `Rustc` (the toolchain that compiled this binary), and
`Profile` (the optimization verdict — release builds state the full
`opt-level=3, lto=fat, codegen-units=1, panic=unwind, strip=yes`
contract; a development build says so and never claims the release
contract). `--print-json` mirrors the same six facts under the
`build` object, field-for-field with the text lines.

---

## Global flags

| Flag | Effect |
|------|--------|
| `-h, --help` | The single end-to-end reference (commands, flags, formats, examples). No separate man page exists — this is it. |
| `-V, --version` | Version + build report (build label, hash, timestamp, lane-honest Signature). Parses at every level — after a subcommand's arguments too (NIGHT-boost-12). |
| `--check-update` | Checks the latest GitHub release. **Refuses to run as root** — it is a plain network fetch and must not ride sudo. Swarm-bounded (NIGHT-critical-infra-1): at most one completed network exchange per hour per user — a per-user runtime stamp (`$XDG_RUNTIME_DIR/zelynic-update.stamp`, `/tmp/.zelynic-update-<uid>` fallback) arms after a real exchange (success or HTTP error, never a DNS/timeout failure); an invocation inside the window prints the disclosed throttle verdict (remaining minutes, exit 0) instead of fetching. Remove the stamp to force a check. |
| `-v, --verbose` | stderr diagnostic trace: target resolution (pids per cgroup), every policy write (rate + burst), BPF lifecycle (pin reuse, schema, link mode), plus loader-level eBPF debug — object size, kernel release, load/attach timings, and the loaded map inventory (id, type, key/value size, max_entries, the `bpftool` facts). JSON output stays clean. |
| `--print-json` | Machine-readable output — the surface set is `status`, `list-apps`, `eagle-eyes --depth`, `doctor`: one compact JSON line each, the stable v11 scripting API (see the JSON reference below). Every other surface renders text (enforcement verbs, the live `eagle-eyes` monitor, `-h`, `-V`, `--check-update`), and the flag never silently no-ops (NIGHT-boost-24, the depth report joined the set at NIGHT-master-1): on a surface that ignores it, exactly one stderr line notes `--print-json ignored (JSON surface: status, list-apps, eagle-eyes --depth, doctor)` — stdout and exit codes are untouched, so scripts stay clean. |
| `--color-mode MODE` | Force the terminal color depth: `0` mono, `16` classic palette, `8`/`256` xterm cube, `24`/`32` truecolor (NIGHT-boost-23, the cosmostrix contract). Default is AUTO: the ladder falls back per terminal — truecolor where the environment reports it, the 256 cube, the 16 palette, mono under `NO_COLOR`/pipes. The flag is the escape hatch for the environment that LIES (COLORTERM inherited over SSH into a terminal that is not truecolor, tmux passthrough without Tc): forcing the depth the terminal actually honors makes every surface — errors, help, the monitor frame and its gradient rails — render correctly what truecolor escapes would garble. Invalid values exit 2 with the allowed grammar. |

Privilege matrix in short: enforcement and monitoring commands
(`strict*`, `block*`, `unstrict*`, `recover`, `status`, `eagle-eyes`)
require root and fail fast with a sudo tip otherwise;
`list-apps`, `doctor`, `--help`, `-V` run on any uid;
`--check-update` is the one surface that refuses root.
Full matrix: [docs/SAFETY_ANALYSIS.md](SAFETY_ANALYSIS.md).

---

## Workflows and recipes

**Discover, limit, verify, remove** (the core loop):

```bash
sudo zelynic eagle-eyes               # who is eating bandwidth? (q to quit)
sudo zelynic list-apps                # confirm name + cgroup id
sudo zelynic strict brave 100kb
sudo zelynic status                   # see the policy + counters
# ... browse with the limit active; check a speed test site:
# 100kb means 100 KB/s = 0.8 Mbps on speed-test readouts (decimal SI)
sudo zelynic unstrict brave
```

**Cap a pool of download tools** (the group lane, `::`-separated):

```bash
sudo zelynic s curl::pacman::aria2c 1mb
```

**Asymmetric limits (e.g., slow uploads for a game):**

```bash
sudo zelynic strict firefox -d 5mb -u 500kb
```

**Focus a noisy background updater:**

```bash
sudo zelynic eagle-eyes               # ranked; ↑/↓ scrolls, ←/→ switches section
sudo zelynic eagle-eyes 8066          # zoom in, see endpoints (q to quit)
sudo zelynic ee 8066 --depth          # who runs it, from where, since when
sudo zelynic strict 8066 50kb          # target the cgroup id directly
```

**Scripted monitoring** (JSON is stable, jq-friendly):

```bash
sudo zelynic status --print-json | jq '.limits[] | select(.bytes_dropped > 0)'
sudo zelynic ee 8066 --depth --print-json | jq '.targets[0].procs[0].exe'
```

**After a crash or a weird state:**

```bash
sudo zelynic status                   # "stale bpf pin files detected"?
sudo zelynic recover
```

---

## Honest limitations — read this

zelynic is deliberately small and stateless. These are real behaviors,
not bugs — knowing them makes the tool predictable.

**1. Rules are a snapshot of TARGETS, not of subtrees.**
When you run `zelynic strict A 100kb` or `s --all 100kb`,
zelynic resolves the apps that exist **at that moment** and writes
their cgroup rules. What happens next splits in two:

- **Processes that spawn UNDER a limited target are covered.**
  (NIGHT-private-research-2, MMSPA.) A subprocess that gets its own
  child cgroup beneath a limited cgroup inherits the limit and
  shares its budget — automatically, however deep the tree grows,
  however late the spawn. The kernel resolves the covering root per
  packet; nothing watches, nothing enumerates, no daemon.
- **A NEW top-level app is still not covered.** If you launch an
  app whose cgroup is not under any limited cgroup — the usual
  case on systemd distros, where every fresh app launch gets its
  own sibling scope — that newcomer is unlimited until you re-run:

```bash
sudo zelynic s --all 500kb             # run again to sweep in newcomers
```

The precise rule: enforcement follows **cgroups**, not processes,
and each policy covers **its cgroup and every descendant**. A new
process that *joins an already-limited cgroup* (e.g., you run
`curl` inside the same terminal session that is already limited)
**is** limited. A new process under a limited target's subtree
**is** limited. A new process whose cgroup sits outside every
limited subtree is not. One bound applies: a hierarchy nested
deeper than **32 levels** below the cgroup root resolves unlimited —
no real deployment reaches a third of that (systemd sessions sit
around 6, container runtimes around 4); it is stated here because
"no exception" deserves the one exception it has, in print.

The subtree share is **fair-shared, statistically**
(NIGHT-upgrade-charger-core-1c, the DRR lane): no leaf can hold
more than one quantum at a time, and the pool's refills flow to
whichever leaf is empty and asking — but the split is bounded-share
fair, not a formal round-robin guarantee (a cgroup_skb hot path
cannot iterate leaves). The measured bounds: two equal-demand
leaves split worst-case 2:1 under adversarial always-first
arrival, ~1:1 under real interleaved traffic; below ~656 KB/s the
fairness granularity coarsens (the quantum is floored at the
64 KiB GSO admit law, so at a 100kb policy one quantum is 0.64
seconds of budget — leaves alternate on quantum boundaries
instead of never), and at those same trickle rates a LONE flow
in deep retransmit backoff can read a short-window under-delivery
(the half-draws gather the quantum across the RTO gaps — one
64 KiB quantum measured in a 4s window against a 50kb policy on
a CI leg; the flow converges to the budget over longer windows).
A leaf that goes idle strands at most its one
quantum until the LRU reaps it; the stale-quantum belt zeroes
any leaf's tokens the moment a policy mutation outlives them.
NIGHT-hunt-Z5 (2026-10-02) put the numbers behind this paragraph
in the CI round ledgers and split the battery's instruments
accordingly: the single round's sender offered under the cap and
delivered 327 KB/s (one 64 KiB admit per ~200 ms — the min-RTO
cadence), the many24 quietest read 78 B on every leg (the
response header admitted, the data segments never banking one
admit), and no take law can move a frozen sender — so the
ceiling rows carry the live verdicts and the anti-starvation law
stays pinned by the rootless sims.

dinner-28 (the K > 2 close, v16): the 2:1 bound above is the
TWO-asker shape; the live fair-share battery found that across
more drawers the half-draw takes decay geometrically per position
(the worst leaf at 3.35x its fair share, the quietest below one
admit, the aggregate exactly the policy) — and the close is the
learned-share draw: the take further capped by pool/(learned+2),
the learned drawee count of the last completed 100ms epoch, kept
per pool in the drr_pool_state maps. A cold pool (learned 0) keeps
the exact v13 residue law; the position ratio under the learned
cap is 1.34 at 6 leaves and 1.18 at 24 — both far inside the
battery's 1.75x + one-quantum bound, which the simulation battery
pins rootlessly alongside the decay it replaced.

**2. Limits do not survive reboot.**
Pins live on bpffs (`/sys/fs/bpf/zelynic/`), which is wiped at boot —
and cgroup IDs are re-assigned by the kernel anyway. After a reboot,
re-apply your limits. There is no boot-time persistence layer by
design; if you need one, a systemd unit or shell profile calling
zelynic is a user-side decision. (The `snapshot`/`restore` pair that
briefly shipped a state-file lane is retired whole — NIGHT-improve-55:
the owner's live-test verdict was that a dump you must remember to
run is a workflow your own script already owns, and the state-file
apply did not change that. A unit file calling the strict family IS
the desired state. Typing either retired spelling lands on the
redirect tip.)

**3. Name resolution needs the app to be running.**
`strict` matches live processes in `/proc`. An app that is not
running has no cgroup to resolve — start the app first, or target a
cgroup ID from an earlier `list-apps` if you know it. A name that
matches nothing prints `No cgroup found for '<name>'` plus a
`list-apps` tip.

**4. A name can match more than one cgroup.**
`strict brave` limits every cgroup containing a process named
`brave` — including browser helpers (e.g., a crash-pad handler). That
is usually what you want (the app's whole footprint), but for surgical
control, target the cgroup ID directly and verify with
`eagle-eyes <id>`. Status labels show the majority-vote process name
plus what lives inside, so mis-attribution is visible rather than
silent.

**5. Rates are decimal SI and per direction — fractions included.**
`100kb` = 100,000 bytes/s = 0.8 Mbps on a speed-test site, and
`5.5mb` = 5,500,000 bytes/s (NIGHT-boost-15: the value grammar is
`[0-9]+(\.[0-9]+)?` before the lowercase unit — exact u128 integer
math, rounded half-away-from-zero at the final byte; a fractional
input that rounds to zero is rejected because `0` is the block
verdict. NIGHT-hunt-31 extended the same fractional grammar to
durations — `1.5h` parses to 5,400 seconds, with a fractional
duration that rounds to zero rejected because `0` means infinity).
A positional rate sets **both** directions — `strict brave
100kb` limits upload too, not just download. Minimum 1kb,
maximum 1tb; both bounds overridable with `--force-this` — below
1kb an app can stop working entirely (that is the dangerous the flag
asks you to own).

**6. Monitoring surfaces also need root.**
`status`, `eagle-eyes` read BPF maps; only `list-apps`, `doctor`,
`--help`, `-V` are unprivileged. This is kernel map access, not a
policy choice.

**7. Kernel 5.13+ with cgroup v2.**
Old distributions booting cgroup v1 cannot host zelynic. Run `zelynic
doctor` on a new machine; the full feature-dependency and distro
matrix lives once in
[docs/KERNEL_COMPATIBILITY.md](KERNEL_COMPATIBILITY.md).

**8. One enforcement-changing operation at a time.**
A non-blocking file lock (`flock` on `/run/zelynic/zelynic.lock`, inside a
root-only directory) guards
strict/block/unstrict/recover: a second concurrent operation exits
immediately with "another zelynic operation is in progress — wait for
it to finish, then retry" rather than waiting silently or interleaving
map writes. A teardown racing an apply is detected after the fact and
reported with a `recover` tip.

**9. Counters are cumulative evidence.**
The ALLOWED/DROPPED columns in `status` are cumulative bytes for the
lifetime of the limit — allowed passed, dropped discarded by the token
bucket, the retransmits reappearing inside allowed — and they carry
over rate changes, resetting only when the limit is removed. They
prove enforcement is biting, but they are not a live throughput
meter. Use `eagle-eyes` for live rates.

**10. The CLI surface is frozen (v11).**
Commands, flags, and output formats are stable API from v11.0.0.
Removed surfaces (`man`, `completions`, `unblock`, `-i`, `--live`,
`--duration`, `--help-all`, and the NIGHT-boost-1 merge
`observe`/`top` -> `eagle-eyes`) exit with a usage error on
purpose — `--help` is the single reference. (`--info` returned at
NIGHT-master-1 as the `eagle-eyes --depth` alias and is retired
again in NIGHT-blade-4 — `--depth` is the one spelling; the short
`-i` stays retired.)

**11. eagle-eyes' counter maps hold 4096 entries per direction
(LRU).**
The monitor's counter maps hold 4096 entries per direction (raised
from the port-time 256 in NIGHT-improve-8, then 1024 → 4096 in
NIGHT-improve-31 for dense hosts: Kubernetes nodes, CI runners with
per-job systemd scopes, and container hosts can push past 1024 live
cgroups — the same hole improve-8 closed, at 4x the scale; the
capacity is a session-scoped map-creation attribute, no pin or
schema migration, 128 KiB of kernel payload memory per session plus
the LRU's per-entry node overhead).
Since the NIGHT-dinner-6 E1 rider (2026-09-28) the maps are LRU
hashes, the lane the socket cookie maps have always ridden: an
idle cgroup's entry ages out on its own, and a live cgroup always
finds room — a long-lived session on a dense host no longer hands
its first 4096 cgroups lifetime slots while later arrivals count
nothing. The accepted trade: a cgroup evicted while idle and then
returning restarts its accumulator, so session TOTALS under
extreme churn (more than 4096 concurrent live cgroups in one
session) are best-effort — exactly the posture the per-socket
figures document. Since NIGHT-total-lts-5 the returning restart
also READS as a restart: the poll delta discriminates the LRU
restart from a counter wrap at the half-space coherence bound, so
the returning cgroup's frame reports its fresh bytes (the
leaderboard keeps the pre-eviction history it already held) —
never the 18-exabyte wrap phantom the bare modulo delta once
answered. One userspace bound rides on top: the leaderboard
carries at most 4096 cgroups per session — but since
NIGHT-mitigate-1 (2026-10-07) that bound is LIVE, not a freeze:
a row whose cgroup is gone (no identity entry and no window
traffic — the board filter's own hiding rule) retires after a
3-frame grace, freeing its slot for the fresh cgroup the old
freeze would have refused forever (the first-4096-own-the-board
posture a decade-long dense-churn monitor could not survive).
Live rows never retire, however long they idle — the
session-leaderboard contract (rank by what an app ate this
session) is unchanged, and the retirement stands down entirely
while the identity walk itself is down (an empty map is a failed
walk, not proof of death). The footer census reports the board's
count, the same bound. The flow itself is never touched: a full map
loses the COUNT, not the packet (the allow-and-skip contract).

**12. The monitor's metric set is exactly this — and that is the
point.**
`eagle-eyes` answers one question class — *who is eating the
network* — with a closed set of figures: per-direction live rates
(the DOWNLOAD/UPLOAD columns), session-accumulated totals per app
(the TOTAL column and the footer's grand row), the session speed
statistics (max and average per direction, NIGHT-engrave-6), the
session census (packets + cgroups), and kernel-named cgroup →
process attribution with endpoint trees. Nothing else is missing
from that class, and nothing else is coming: interface-level
"how full is the pipe" totals (nload/bmon's lane), per-connection
quality metrics such as RTT and retransmits (kyanos's lane),
reverse-DNS/SNI enrichment, and history/persistence/daemon mode
are all deliberate rejections — each would widen the class rather
than master it, and the last would violate the one-shot
architecture (see
[docs/RESEARCH_TOOLCHAIN_AND_MONITORING.md](RESEARCH_TOOLCHAIN_AND_MONITORING.md)
Part 2 for the full class comparison and the rejection log). A
session *minimum* speed line ("total low") is rejected for a
structural reason: any idle interval drives the minimum toward
zero, so the figure is ~0 at rest and carries no information —
max + average are the session pair that does. The single
sanctioned frontier item — per-endpoint byte attribution (which
socket is consuming, not just which sockets exist) — shipped as
NIGHT-boost-26 and speaks per-second arrival rates since
night-private-research-7: every endpoint line carries its own
`[dl | ul]` rate figures, and the focus view ranks a process's
endpoints by their bytes (the closing design is documented in
[docs/RESEARCH_TOOLCHAIN_AND_MONITORING.md](RESEARCH_TOOLCHAIN_AND_MONITORING.md)
2.4, with the kernel-side verification trail).

---

## Troubleshooting

| Symptom | Meaning / fix |
|---------|---------------|
| `root required — eBPF operations need CAP_BPF` | Re-run with `sudo`. Only `list-apps`/`doctor`/`--help`/`-V` skip this. |
| `--check-update` refuses to run as root | Re-run **without** sudo. It is a plain network fetch. |
| `zelynic help` exits 2 with a tip | By design: help is the `--help` flag, not a subcommand (the single-tier reference). The tip names the spelling (NIGHT-boost-13). |
| Unknown flag after a full command shows NO "use `--`" tip (e.g. `s brave 550kb -i`) | Honest silence: the escape-hatch tip prints only where following it actually parses (the NIGHT-boost-13 probe re-parses with the splice). No tip means the positional slots are full — the usage line under the error is the failing command's own grammar, and nothing more fits. |
| `--json` (a habit from other tools) | The vocabulary rescue tips the zelynic spelling: `--print-json` (NIGHT-boost-13). |
| `No cgroup found for '<name>'` | The app is not running (or the name is wrong). Start it, check `zelynic list-apps`, or target a cgroup ID. |
| `Invalid rate '1MB'` (with a tip) | Units are lowercase. The tip suggests the fix (`1mb`; fractional twins like `5.5MB` -> `5.5mb` work the same way). |
| `Invalid interval '90s'` | Refresh interval must be 1s..60s. |
| `Stale BPF pin files detected` / `stale bpf pin files detected` | A previous run was killed mid-operation (the wording lowercased with the NIGHT-engrave-5 restyle). Run `sudo zelynic recover`, then re-apply limits. |
| `Failed to load BPF object` with `caused by:` lines under it | Every runtime error now prints its full cause chain (NIGHT-hunt-28) — read the `caused by:` lines: they name the exact map, syscall, and errno (e.g. `failed to create map 'X' with code -22`). If the chain ends in a pin/EINVAL shape instead, it is the mount below. |
| `error parsing BPF object: error parsing ELF data` at startup (strict/limit) | Two distinct causes share this one error text, both fixed at the source. (1) Address misalignment (NIGHT-hunt-30, the 2026-09-20..21 occurrences): aya's ELF parser reads the embedded object straight out of the binary's `.rodata` and requires the buffer's address to be 8-byte aligned — the plain `include_bytes!` static had that only by linker luck, per host per build. Both objects are now embedded inside an `AlignedElf` wrapper, aligned by construction, with a load-path preflight that names any violation precisely ("address is N bytes past an 8-byte boundary"). (2) A bpfel object damaged on disk (NIGHT-hunt-29): cargo never re-verifies build outputs, so a truncated artifact stayed "fresh" and every rebuild re-embedded it; builds now structurally validate both objects and self-heal a damaged one, visible as a `cargo:warning` naming the exact violation (e.g. `truncated: section header table (10 x 64 at 4984) exceeds the 1000-byte file`) followed by one forced relink. A binary already showing this error only needs a rebuild from current source: `cargo pro-native-gnu`. |
| `/sys/fs/bpf is not a mounted bpf filesystem` | The limiter pins its maps under `/sys/fs/bpf/zelynic`, and pinning needs a real bpffs mount — a directory merely existing there is not enough (the kernel always creates it; some distros never mount bpffs on it). Fix: `sudo mount -t bpf bpf /sys/fs/bpf`, made permanent via fstab or a systemd mount unit. Note `eagle-eyes` needs no bpffs (its maps are unpinned) — if the monitor works but strict/limit fail, this is exactly it. |
| `invalid CPU znver3` (or any CPU name) from bpf-linker during `cargo pro-native-gnu` | Fixed (NIGHT-hunt-28): the alias's `-C target-cpu=native` used to leak into the nested eBPF build and reach bpf-linker as `--cpu <host-cpu>`, which it rejects. build.rs now strips host-CPU and host-linker rustflags from the nested build's environment; the aliases work on any host CPU. |
| `the pinned nightly toolchain ... is not installed` / `bpf-linker is not on PATH` (build time) | One command fixes both — and since NIGHT-improve-16 it finishes the whole host setup: `./scripts/dev/bootstrap-ebpf.sh` installs the pair, fixes its own PATH for the build, persists the `~/.local/bin` export to `~/.profile`, and builds the flagship binary (NIGHT-host-1). If bpf-linker already sits in `~/.local/bin`, put that directory on PATH. `the pure-Rust eBPF build failed with prerequisites present` is a real compile error — read the nested cargo output above it. The old "BPF object file not found" error class is gone (objects are embedded). |
| `BINARY GATE: refusing to test a zelynic that is not this checkout's build` (supermassive-test / supermassive-test-v2 / limiter-depth-test startup) | Working as designed (NIGHT-improve-16): the harness resolves the checkout's own build first — repo target outputs, newest mtime wins — and hard-aborts when the resolved binary's `-V` version differs from the checkout's Cargo.toml. Before the gate, the 2026-09-21 debian13 run silently tested a stale `/usr/bin/zelynic` v4.0.0-alpha (repo build had never succeeded there) and filed 12 decoy failures: `unrecognized subcommand 'block-single'`, v4 rate guards rejecting v11 rungs, `no limit row ... in status JSON` (v4 schema). Fix: `./scripts/dev/bootstrap-ebpf.sh` (prerequisites + flagship build, one command), or `--binary ./target/pro-native-gnu/zelynic` for an existing matching build. |
| `bootstrap-ebpf.sh` looks stuck on the bpf-linker download | It is the one big fetch (~100 MB) and can take minutes on slow links. On a terminal the script shows a live progress bar for exactly this step (NIGHT-hunt-24); piped/logged runs stay quiet. Killing it mid-download is safe — re-running skips whatever already finished. |
| `error: missing manifest in toolchain 'nightly-...'` from rustup, or a build dying inside rustup commands | The dated nightly install is damaged — an interrupted `rustup toolchain install` (Ctrl-C, power loss, full disk) leaves the toolchain listed while its manifests are gone, so every component operation fails even though `rustc` itself still runs (which is why it slips past naive checks). Fix: run `./scripts/dev/bootstrap-ebpf.sh` again — it detects the damaged state, removes the toolchain, and reinstalls it from scratch, no manual rustup commands (NIGHT-hunt-27); the build.rs preflight names this exact state with the same one-command repair. |
| Monitor won't exit | Press `q` — the only quit key (NIGHT-hunt-16). ESC and Ctrl+C are deliberately drained, never treated as quit. If a wedged terminal swallows the `q` byte: `pkill zelynic` from another shell — the violent-death guard (NIGHT-boost-33) restores the terminal itself (termios, main screen, cursor). |
| Screen broken after `kill -9` / terminal garbled | `zelynic --reset-terminal` (NIGHT-hunt-31) — the in-place five-layer rescue: ANSI restore + clear, `stty sane` (the kernel-side raw mode no escape byte reaches), `reset`, `tput reset` (when run as root, the three externals resolve through the pinned system PATH, `/usr/sbin:/usr/bin:/sbin:/bin` — the NIGHT-lts-1 defense-in-depth belt; the common no-sudo rescue is unchanged). Works with or without sudo, blind-typed: type it and press Enter even if the screen shows nothing. Under sudo the rescue additionally targets the REAL terminal (NIGHT-improve-31, the post-exit half re-shaped in NIGHT-improve-34): sudo 1.9.14+ interposes a pty by default, so the rescue's own fds are a throwaway pseudo-terminal — it discovers the user's terminal through the sudo monitor (`SUDO_PID`), repairs it directly, and redirects `stty sane`/`reset` onto it. After sudo exits, a bounded orphan re-applies ONLY what is still broken, and only the output lane: sudo's own exit-restore skips when the flags were changed under it (which the direct repair does on purpose), so the healthy case gets zero post-exit touches, and the monitor-raw-residue case gets exactly OPOST|ONLCR back — never the input flags a live shell line editor owns (the blanket re-apply it replaces double-echoed typing and ate the first typed character after a rescue on a HEALTHY terminal). The guard (NIGHT-boost-33) restores the terminal automatically on violent deaths; the flag is the explicit recovery for the residual cases (guard could not arm, foreign app's stuck modes, SGR pen linger). |
| Limit seems not enforced | Check `sudo zelynic status` — is the cgroup listed? Verify the app's traffic is actually flowing through the limited cgroup (`eagle-eyes <id>`). If the app was restarted after the limit was set, re-apply (see limitation #1). |
| Two zelynic commands interfered | The lock is deliberately non-blocking: the second command exited with "another zelynic operation is in progress". Wait for the first to finish, re-run it. If pins ended up inconsistent: `recover`. |

When diagnosing, add `-v`: the verbose trace shows the exact pid-to-
cgroup resolution and every policy write, which answers most "what did
it actually do?" questions in one run.

---

## JSON reference for scripting

`--print-json` output is stable API (v11 contract). Every command
emits ONE compact single-line JSON document per invocation
(NIGHT-boost-3, the machine-first contract — `jq`-ready and
NDJSON-friendly; pretty-print on the consumer side with `| jq '.'`).

The scope is the report surfaces (NIGHT-boost-24 honesty audit;
NIGHT-master-1 added the fourth): `status`, `list-apps`, `doctor`,
and the `eagle-eyes --depth` one-shot report. The flag parses
anywhere (it is global), but the enforcement verbs, the live
`eagle-eyes` monitor, and the early exits (`-h`, `-V`,
`--check-update`) render text; when the flag rides one of those, a
single stderr line names the honoring surfaces and the output itself
is untouched. The featureless (dormant-mode) build answers with its
honest smaller set (`doctor` only — the other three are eBPF
surfaces).
Field shapes:

`status --print-json`:

```json
{"watchdog":"enforcing","active_limits":2,"limits":[{"cgroup_id":18571,"label":"brave","download_bps":100000,"upload_bps":100000,"packets_allowed":232,"packets_dropped":4718,"bytes_allowed":29520,"bytes_dropped":8031234}]}
```

The complete field reference (night-improve-60 — the owner read
`window_secs: 8` against a `--during 5h` policy and could not tell
which number owned the expiry; every field a limit row can carry,
one table, script-facing):

| field | shape | what it is |
|-------|-------|------------|
| `watchdog` | `"enforcing"` \| `"active"` \| `"expired"` | the BPF auto-expiry deadline's state: `enforcing` when no deadline is armed (limits without `--during` never expire), `active` while the deadline is in the future, `expired` once it passed |
| `active_limits` | number | how many limit ROWS follow (one per policed cgroup — a cgroup with both directions policed is still one row) |
| `limits[].cgroup_id` | number | the cgroup v2 id the policy is pinned to |
| `limits[].label` | string | the resolved identity, majority vote over the live processes inside the cgroup (`cg:89976 (brave)`) |
| `limits[].download_bps` / `upload_bps` | number \| `null` | the enforced rate per direction; `null` when that direction is unlimited (never a fabricated zero) |
| `limits[].download_per_socket` / `upload_per_socket` | boolean | present only when the direction was applied `--per-socket`: the rate names a PER-CONNECTION budget, not the cgroup cap |
| `limits[].floor_bps` / `ceil_bps` | number | the per-subprocess guarantee pair, present when both directions carry the SAME pair |
| `limits[].download_floor_bps` / `download_ceil_bps` / `upload_floor_bps` / `upload_ceil_bps` | number | the per-subprocess pair when the directions DIFFER (the split shape; the merged pair above is then absent) |
| `limits[].packets_allowed` / `packets_dropped` | number | cumulative packet counts under the limit (both directions booked into one row) |
| `limits[].bytes_allowed` / `bytes_dropped` | number | cumulative BYTES: what passed enforcement, what the token bucket discarded. Lifetime counters — re-applying `strict` keeps them continuous; `unstrict` reclaims the row |
| `limits[].rate_ring` | object | the last eight seconds' per-second delivered bytes, per direction — a traffic MONITOR, not the policy window (see the callout below) |
| `limits[].window` | object | the row's `--during` policy window — the thing that expires (see the callout below) |

**`rate_ring.window_secs` is not the policy window — read this
before scripting against it.** The two `window` words live in
different objects and own different clocks:

- `limits[].rate_ring.window_secs` is ALWAYS `8` — the SPAN of the
  traffic history: eight one-second byte slots, oldest first. It
  never counts down, never expires anything, and reads `8` whether
  the policy lives 5 minutes or 5 hours. A `--during 5h` policy
  that shows `"window_secs": 8` is NOT expired or shortened — the
  field simply has nothing to do with the policy's lifetime (it is
  the denominator for `sum(bytes) / window_secs`, the row's average
  delivered rate over the last eight seconds).
- `limits[].window` is the policy's own clock: `kind` (`"span"`),
  `state` (`"active"` / `"dormant"` / `"outside"` / `"expired"` —
  `active` means the policy is enforcing NOW), and the WALL instants
  `start_wall_ns` / `end_wall_ns` (nanoseconds since the epoch —
  the same pair the human table's `window: until ... (5h left)`
  line renders). The remaining lifetime is
  `end_wall_ns` minus now; nothing in `rate_ring` changes it.

jq recipes for the two clocks (the seconds-left readout the human
table prints, and the ring's average rate):

```bash
# Seconds left on every windowed policy (the "(5h left)" line, scripted).
sudo zelynic status --print-json | jq '
  .limits[] | select(.window != null) |
  {label, kind: .window.kind, state: .window.state,
   seconds_left: ((.window.end_wall_ns / 1e9) - now | floor)}'

# Average delivered rate over the ring's own horizon, per direction.
sudo zelynic status --print-json | jq '
  .limits[] | select(.rate_ring != null) |
  {label,
   avg_dl_bps: ((.rate_ring.download.bytes // [] | add // 0) / .rate_ring.window_secs),
   avg_ul_bps: ((.rate_ring.upload.bytes   // [] | add // 0) / .rate_ring.window_secs)}'
```

`rate_ring` (NIGHT-upgrade-charger-core-3a, EAGLE EYES V1) joins a
limit row when the pinned object keeps a time-series ring for its
cgroup AND that cgroup has booked traffic under the policy — the
kernel's own rolling window of delivered bytes, eight one-second
slots, so the SHAPE of the last eight seconds survives between
polls (a monitor sampling at `--interval 30s` reads the true peak
and cadence, not a 30s mean):

```json
"rate_ring":{"window_secs":8,"download":{"bytes":[0,0,0,1048576,1048576,524288,1048576,655360],"live":5,"peak_bytes":1048576},"upload":null}
```

`window_secs` is the SPAN the series covers — eight one-second
slots (NIGHT-hunt-30: it used to carry the per-slot width `1`,
which read as the whole window and made `sum(bytes) / window_secs`
overcount eight-fold; the per-slot granularity is `bytes.len()`,
one sample per second, so the average rate over the horizon is
`sum(bytes) / window_secs`). `bytes` is OLDEST-first (the last entry is the current, still-filling
window — a window mid-second reads low); `live` counts how many of
the eight windows hold data (the honest horizon); `peak_bytes` is
the largest COMPLETED window (the current one never qualifies — it
can only grow). A direction with no ring entry renders `null`, and a
limit row with no ring at all omits the field entirely — absent is
honestly absent (a fresh policy with no traffic yet, or a pinned
object from before the v14 reload), never a fabricated empty
series. The ring is a monitor, not a ledger: the exact cumulative
truth stays the `packets_*`/`bytes_*` fields beside it. For a
`--per-socket` policy the series is the cgroup's AGGREGATE (every
connection's allowed bytes roll up to the same root key, the MMSPA
contract) — the per-connection budget law is the one the
`per_socket` fields below state. The live monitor folds this same
series into the per-policy baseline verdicts (EAGLE EYES V2, the
eagle-eyes section above) — detection is temporal by nature, so
the verdicts live only in the live TUI, never in this one-shot
JSON; scripts that want to run their own detector read this field.

`window` (night-during, schema v23) joins a limit row when the
policy carries a `--during` window — the additive-field rule the
`rate_ring` join set: `kind` ("span" or "daily" — the daily
kind rides only rows an older build wrote; the grammar is
duration-only now), `state` (the status vocabulary: "active",
"dormant", "outside", "expired"), a span's `start_wall_ns` /
`end_wall_ns` (WALL-clock ns since epoch — never the monotonic
deadlines the map carries, which reset with the boot and mean
nothing to a script), and a daily window's `start_s` / `end_s`
(seconds-of-day UTC, wrapping midnight when start > end). Rows
without a window carry no field at all:

```json
{"cgroup_id":18571,"label":"brave","download_bps":100000,"window":{"kind":"span","state":"active","start_wall_ns":1791288000000000000,"end_wall_ns":1791291600000000000}}
```

`download_per_socket` / `upload_per_socket`
(NIGHT-upgrade-charger-core-3b) appear on a limit row only when that
direction's policy was applied with `--per-socket` — the boolean that
says the row's `download_bps`/`upload_bps` number names a
PER-CONNECTION budget (the cgroup total is rate x concurrent
sockets), never the cgroup cap:

```json
{"cgroup_id":18571,"label":"nginx","download_bps":500000,"download_per_socket":true,"packets_allowed":232}
```

`list-apps --print-json` (the `total` field counts every cgroup the
scan resolved — including any whose comm was unreadable at scan
time and therefore has no row — while `apps[]` carries the named
rows, so the pair can differ by the unnamed few; every row's fields
are complete). night-improve-64 joined the census's second number
and its honesty flag (additive, trailing): `socket_cgroups` is the
"M with live sockets" figure the human census line carries beside
`total`, and `census_complete` is the machine form of the
partial-census note — `false` when unprivileged, because the socket
census is per-pid privilege-gated and rows may under-read (other
users' sockets count zero; the stderr note rides beside the JSON
for humans, stdout stays byte-clean either way):

```json
{"total":142,"apps":[{"process":"brave","cgroup_id":18571,"uid":1000,"processes":4,"sockets":9}],"socket_cgroups":57,"census_complete":true}
```

`eagle-eyes <target> --depth --print-json` (NIGHT-master-1): one
`targets[]` array — a report object per resolved cgroup, a
`{"target":...,"error":...}` miss per name that resolved to nothing
(multi-target specs only; a full miss exits 1 with the text error):

```json
{"targets":[{"target":"cg:1234","cgroup_id":1234,"name":"cat-test","cgroup_path":"/sys/fs/cgroup/cat-test","uid":1000,"user":"cat","enforcement":"limited","download_bps":100000,"upload_bps":100000,"group_id":0,"oldest_started_secs":620,"processes":1,"socket_holders":1,"sockets":2,"traffic":{"window_secs":3,"download_bytes":12400000,"upload_bytes":340000,"endpoints":[{"pid":4242,"comm":"curl","proto":"tcp","remote":"142.250.185.78:443","state":"ESTABLISHED","download_bytes":12400000,"upload_bytes":300000},{"pid":4242,"comm":"curl","proto":"tcp6","remote":"[2001:db8::1]:443","state":"ESTABLISHED","download_bytes":null,"upload_bytes":null}]},"procs":[{"pid":1234,"comm":"cat-test","uid":1000,"user":"cat","ppid":1,"state":"S (sleeping)","threads":4,"rss_kb":1234,"exe":"/home/cat/cat-test","exe_deleted":false,"kind":"binary","script":null,"permission":"755","cwd":"/home/cat","cmdline":"./cat-test --serve","started_ago_secs":620,"started_epoch":1758900000}],"endpoints":[{"pid":4242,"comm":"curl","proto":"tcp","remote":"142.250.185.78:443","state":"ESTABLISHED","download_bytes":12400000,"upload_bytes":300000},{"pid":4242,"comm":"curl","proto":"tcp6","remote":"[2001:db8::1]:443","state":"ESTABLISHED","download_bytes":null,"upload_bytes":null}]}],"bypass_audit":{"window_secs":3,"nic_tx_bytes":12900000,"nic_rx_bytes":13000000,"bpf_tx_bytes":340000,"bpf_rx_bytes":12450000,"shadow_tx_bytes":12560000,"shadow_rx_bytes":550000,"verdict":"bypassed_tx"}}
```

`enforcement` is `"unlimited"` | `"blocked"` | `"limited"`; an
unlimited direction carries `null` bps, never a fabricated zero. A
`--per-socket` policy's rate figures carry the `/socket` unit in
the text report and `download_per_socket` / `upload_per_socket` in
the JSON (charger-core-3c, the same marker the status table owns —
an unmarked rate would read as the cgroup cap the policy does not
carry).
`traffic` (NIGHT-private-research-3) is the focus window's kernel
totals — `{"window_secs":3,"download_bytes":...,"upload_bytes":...,"endpoints":[...]}`
when a window ran, `null` when it could not (observer attach or
poll failure — distinguishable from a zero-traffic window, which
serializes with zero totals); each endpoint row's
`download_bytes`/`upload_bytes` carry that socket's window bytes,
`null` when the join resolved nothing for it.
The traffic object's own `endpoints` array (night-improve-63,
additive) is the window's ranked attribution — the same rows the
text focus view renders, movers first (bytes descending), the
byteless behind them — so `jq '.targets[0].traffic.endpoints'`
answers "who moved the window's bytes" straight from the object
that owns the window, without re-deriving the cookie join from the
census rows (the target-level `endpoints` array stays the full
live socket census, untouched — the two arrays answer different
questions).
`bypass_audit` (NIGHT-upgrade-charger-core-1-a) is the focus
window's interface-vs-hooks shadow verdict, machine-scope:
`{"window_secs":3,"nic_tx_bytes":...,"nic_rx_bytes":...,"bpf_tx_bytes":...,"bpf_rx_bytes":...,"shadow_tx_bytes":...,"shadow_rx_bytes":...,"verdict":"clean"}`
with `verdict` one of `"clean"` / `"bypassed_tx"` / `"bypassed_rx"`
/ `"bypassed_both"` / `"unavailable"`, and `null` when no window
ran — the same absence-vs-zero distinction every optional field
carries.
`kind` is `"binary"` | `"script"` | `null` (unreadable), and a
script row's `script` field carries the shebang source path the
classifier found. `exe_deleted` (NIGHT-blade-7) is true when the
kernel marked the member's exe readlink `(deleted)` — the on-disk
binary was replaced or removed after the process started. The
`permission` string carries the special bits the same way the text
report does (`4755` for a setuid binary).

`doctor --print-json` reports the capability check fields — the
system facts (`system.kernel`, `system.cgroup_v2`,
`system.cgroup2_mount_path`, `system.bpf_fs_mounted`,
`system.is_root`), the binary's own verdicts (`build_flavor`:
`"full-life"` / `"half-life"`; `ebpf_lane`: `"source-built"` /
`"registry-prebuilt"` / `"dormant (not compiled)"`), the
`warnings` array, and — night-improve-64, additive — the BPF pin
lattice's verdict under `pins`: `{"state":"clean"|"active"|"stale","files":N}`
(the same verdict the human report's "Pins:" line renders —
`active` means the four enforcement pins are all present, `stale`
is the partial lattice the `zelynic recover` hint applies to).
The field is ABSENT where it cannot speak honestly: a half-life
build owns no lattice, an unprivileged run must not audit root's
pins, and an unreadable directory is absent too — never a
fabricated verdict. night-improve-66 adds the `build` object —
the artifact identity the human report's BUILD block renders:
`version` (raw semver, no `v`), `git_sha`, `variant` (the
canonical build label), `build_time` (UTC), `rustc_version` (the
toolchain that compiled the binary), and `profile` (the
optimization verdict — `"release, opt-level=3, lto=fat,
codegen-units=1, panic=unwind, strip=yes"` for shipping builds; a
development build states its mode and never claims the release
contract). The same additive rule holds both directions: every
field the new binary emits is populated, and a pre-improve-66
document (no `build` key) still parses — the block is honestly
absent, never fabricated:

```json
{"system":{"kernel":"6.18.0","cgroup_v2":true,"cgroup2_mount_path":"/sys/fs/cgroup","bpf_fs_mounted":true,"is_root":true},"ebpf_supported":true,"build_flavor":"full-life","ebpf_lane":"source-built","build":{"version":"50.0.0-beta.1","git_sha":"83375c3","variant":"linux-amd64-v3-gnu","build_time":"10/9/2026 19:40 (UTC)","rustc_version":"rustc 1.98.1 (48a229cea 2026-09-01)","profile":"release, opt-level=3, lto=fat, codegen-units=1, panic=unwind, strip=yes"},"warnings":[],"pins":{"state":"active","files":4}}
```

A missing limit list with `"active_limits": 0` and `watchdog: "enforcing"`
means exactly that: nothing is limited right now.

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (including informational output like `--help`, `status`). |
| 1 | Runtime failure — root missing, BPF object absent, stale state, or a named target that resolved to nothing. The error carries a branded `error:` label and often a white `tip:` line. |
| 2 | Usage error — unknown command/flag, missing arguments, invalid values. clap renders it with did-you-mean suggestions for typos, the usage line is the FAILING command's own grammar (NIGHT-boost-13), and every escape-hatch tip is verified before printing: a "use `--`" tip that fails when followed is dropped. |

The no-match contract (NIGHT-dinner-11 — the eBPF-verifier lineage
applied to the CLI surface: reject, never a soft no-op): a command
that names a target — `strict`, `block`, `unstrict`, either lane —
whose target resolves to nothing prints the branded error and exits 1,
so a script can tell the typo'd `s cg8401` from an enforced
limit. The `--all` apply sweeps (`s --all`, `b --all`) exit 1
when the identity map offers nothing to enforce; `u --all` on
an already-clean system stays exit 0 — the requested state already
holds, the same clean-state precedent `recover`'s clean path owns.

---

## FAQ

**Does limiting slow my whole system?**
No. Two eBPF programs run per packet crossing a cgroup boundary —
nanosecond-scale work, no userspace involved. Benchmarks live in
[docs/PERFORMANCE.md](PERFORMANCE.md).

**Why does `strict brave 100kb` also slow my uploads?**
A positional rate means both directions. Use `-d`/`-u` to split them
(and if you pass both a positional and `-d`/`-u`, one stderr note
names the positional that was ignored — the flags decide).

**I limited an app but a speed test shows full speed.**
Three usual causes: (1) the app was restarted after you set the limit —
re-apply; (2) the traffic flows through a different cgroup than the one
you limited — check `eagle-eyes`/`status` labels and target the cgroup ID;
(3) unit conversion — 100kb is 0.8 Mbps, verify against
[limitations #5](#honest-limitations--read-this).

**Can I limit myself out of SSH?**
The dangerous-target blocklist guards `sshd` and friends by default;
`--force-this` is the explicit override. If you do brick connectivity,
recovery is a reboot away (limits do not survive it) or
`sudo zelynic u --all` from any working session.

**Where is the config file?**
There is none — CLI flags only, ever. State lives in pinned BPF maps,
not in your home directory.

**Does it work on macOS/BSD?**
No. zelynic is Linux-only (cgroup v2 + eBPF). It is a Linux-native tool
by design.

**How do I quit eagle-eyes?**
Press `q` — the only quit key (NIGHT-hunt-16). ESC was removed as a
quit key in NIGHT-hunt-12 (escape sequences from arrows/mouse made
accidental quits too easy); Ctrl+C quit was removed in NIGHT-hunt-16
for the same single-key contract as htop/vim — the title bar says
"q quit" and nothing else quits. The `t` key (NIGHT-boost-18; the
`T` twin was retired by NIGHT-engrave-2 at the owner's "better only
simple 't'" call) cycles the monitor's theme — an action key, never
a quit key. One non-key exit exists (NIGHT-ultimate-2): a dead
output sink — a piped reader that closed — ends the session quietly
by itself; no key can trigger it and no live reader can. If a
violent death (`kill -9`) or a foreign TUI ever leaves the screen
broken: `zelynic --reset-terminal` (NIGHT-hunt-31) recovers it in
place — no re-opened terminal, no second shell, with or without
sudo (NIGHT-improve-31 handles sudo's interposed pty).

**Can I select and copy/paste text while the monitor runs?**
No — box mode takes the pointer AND kills terminal-side selections on
a fixed beat (NIGHT-improve-7 + NIGHT-improve-8, superseding the
NIGHT-strict-1 mouse clause). The monitor enables mouse tracking
(1000 press/release, 1002 button-drag, 1006 SGR encoding) for its
whole lifetime, so click-drag selects nothing and middle-click never
lands in the monitor's stdin. The one hole mouse tracking cannot
close is the terminal's own Shift+click bypass — no escape sequence
can switch that off — so the monitor additionally re-emits the
whole frame every 100 ms while it runs: terminals clear a selection
the moment its cells are rewritten (the same physics that makes
`watch` output unselectable), which means a Shift+click selection
cannot outlive one beat, and every copy path that needs a live
selection (Ctrl+Shift+C, right-click Copy) finds nothing to copy.
Every mode is restored on exit: press `q` and selection/paste work
again immediately, nothing stays captured. Honest physics boundaries,
documented not hidden: an X11-style terminal that mirrors a COMPLETED
selection into the PRIMARY clipboard at button release can still
catch whatever re-accumulates after the last beat (a terminal-side
behavior no Linux application can retract), and a Select All + Copy
fired inside a single 100 ms beat lands before the next rewrite —
both are terminal emulator features outside any application's reach.
Pasted bytes that do reach stdin are drained like any other non-`q`
input — a paste whose first byte is `q` still quits (the
NIGHT-hunt-16 q-only contract). The contract is enforced by unit
tests (`test/terminal/mouse_contract_tests.rs` pins the byte
sequences, the guard beat, and the loop scheduler, and scans the
whole source tree for any unsanctioned terminal-mode literal;
`test/terminal/diff_tests.rs` pins the guard's whole-frame
repaint), so a future commit cannot silently loosen or widen the
takeover.

---

## Maintainer's map

Where things live when a command changes (update these together):

| Change | Files to touch |
|--------|----------------|
| New/changed command or flag | `src/cli/mod.rs` (definition), `src/commands/mod.rs` (dispatch), handler in `src/commands/`, `src/commands/help.rs` (reference), `test/integration/help_pins.rs` (drift pins: `test_help_lists_every_command` + removal pins) + `test/integration/surface_pins.rs` (alias/removal wiring), README Commands block |
| Monitor rendering | `src/ebpf/render/` (`eagle.rs`, `focus.rs`, `detail.rs` — line builders), `src/terminal/mod.rs` (monitor loop), `src/terminal/diff.rs` (diff engine + quit keys live in mod.rs), `docs/BRANDING.md` |
| Rate/interval parsing | `src/ebpf/limiter/format.rs`, `src/cli/ux.rs` (typo tips) |
| CLI error tips and usage lines | `src/cli/ux.rs` (the bridge: typo/vocabulary/authority rescues, redirects, usage regeneration), `src/cli/argv.rs` (escape-hatch honesty probe, failing-command walk), `test/cli/` (ux + argv pins), `test/integration/cli_ux.rs` (binary-level pins) |
| Status/JSON shapes | `src/ebpf/display.rs` — JSON is stable API, treat changes as breaking |
| Sandbox / root-VM testing | `scripts/sandbox/` (`zelynic-sandbox.sh` entrypoint, `rootfs-pack.py` provisioner, `sandbox-init.sh` PID 1) + [docs/SANDBOX.md](SANDBOX.md) — the local KVM micro-VM for root-requiring harnesses when the host has no sudo |
| Docs after any behavioral change | This file + README + CHANGELOG; `docs/SAFETY_ANALYSIS.md` for privilege changes |
| Security-relevant change | `SECURITY.md` posture table + `docs/SAFETY_ANALYSIS.md` audit section — move them together |

Quality gates before every commit: the two commands and what each one
runs are documented once in
[CONTRIBUTING.md](../CONTRIBUTING.md) (`build.sh check-all` +
`gate-keepers.sh`).

Frame-level render changes additionally get the 10s A/B benchmark:
`scripts/bench/frame-bench.py` before/after, reporting density gini, frame
entropy, fps, dirty cells, and (NIGHT-improve-2) the diff engine's
emitted bytes per frame against the logical frame (protocol in the
script header).

Source of truth is always `src/**` — if any doc (including this one)
disagrees with the code, the doc is wrong; open a PR.
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
