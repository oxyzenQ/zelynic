<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-skill-1 audit — the master depth question: is zelynic at peak?

> Audit date: 2026-11-07 (night-skill-1, the owner's verify task).
> Scope: ONE question — is the mechanism, the innovation, and the
> skill actually at peak, or is there a gap the whitepaper missed?
> This is a VERIFY task under the peak-skip protocol: a surface at
> peak gets "peak — skipped, no change warranted" with the evidence;
> a gap gets its failure mode, its evidence, and its minimum fix.
> No new features, no new BPF programs, no schema bumps. Audited at
> 57bfe0d (the clone the audit read; the report itself lands as this
> task's single `research:` commit).

## The method, stated before the findings

The record was read before it was judged: the whitepaper
(QUOTA_SAVER_PHYSICS.md), the estate map (COSMIC_DRAGON_ARC.md), the
innovation ledger (INNOVATIONS.md), the claims ledger
(CLAIMS_VERIFICATION.md), the threat model (THREAT_MODEL.md), the
silent-killer inventory and blade-6 endurance table (STABILITY.md),
the three signed audits the task names (NIGHT_DRAGON_1 2026-10-27,
NIGHT_NETRUNNER_2 2026-11-05, NIGHT_NETRUNNER_3), and the harness
(quota-saver-ab.py, quota-saver-ab-vs-legacy.sh). Then the code the
record rests on was read in full: recwn.rs, ecn.rs, pace.rs,
math.rs, enforce.rs, limiter.rs, recwn_flow.rs, pace_flow.rs,
reclaim.rs, and the map declarations. Every number quoted below was
re-derived with code (arithmetic recomputed, not trusted), and every
file:line was opened. The honest boundary: this host has no root, no
kernel 5.15, and no eBPF, so no wire was measured here — the live
legs are CI-owned (the standing boundary NIGHT_DRAGON_1 records).
What this audit CAN and did do: verify the record's internal
consistency, re-derive its arithmetic, and re-read the mechanism
against the kernel truths the lanes claim.

## Phase 1 — the inventor's inventory

| Surface | Current verdict | Dated audit that signed it | Gap suspected? |
|---|---|---|---|
| Quota saver mechanism (RECWN v25, ECN v26, EDT v27, telemetry v28) | PEAK — five rungs measured, eight physics losses, campaign formally closed | QUOTA_SAVER_PHYSICS.md 2026-11-07 (the peak declaration) | No |
| Per-packet flow (the smoothbore) | SMOOTHBORE — one linear chain, single-writer state, one friction find closed | NIGHT_NETRUNNER_2_FLOW_AUDIT 2026-11-05 | No |
| Scale profile (server-first, four axes) | SIGNED — server-first, capable cockpit, fleet = composition | NIGHT_DRAGON_1_MASTER_SCALE_PROFILE_AUDIT 2026-10-27 | No |
| Metrics design (eagle-eyes, the sampled RTT lane) | SIGNED — datapath rejected on measured cost, userspace sample 194 ns | NIGHT_NETRUNNER_3_EAGLE_EYES_METRICS | No |
| Endurance (every long-lived class) | LTS-READY — bounded/rebuilt/reaped, 300-cycle churn oracle | STABILITY.md blade-6 table; NIGHT-long-horizon-1 2026-09-27 | No |
| Claims ledger | EVERY claim mapped to LIVE/PIN/CI | CLAIMS_VERIFICATION.md (NIGHT-lts-6) | No |
| Threat boundary | HONEST — defends/does-not-defend printed | THREAT_MODEL.md | No |
| Innovation ledger (the fourteen scales) | GREEN on Code/Doc/Test, one drift flagged and closed | COSMIC_DRAGON_ARC depth audit 2026-11-03 | No |
| Skill positioning (vs traditional tools) | PRINTED — per-cgroup, no daemon, 0.00% measured | README vs-traditional-tools; NIGHT_DRAGON_LTS_1 sharpest-skill 2026-10-27 | No (extended, not contradicted, below) |

Nine surfaces, nine signed verdicts, zero suspected gaps entering
Phase 2. The four questions below are the owner's own; each answer
carries its evidence.

## Phase 2 — the four questions

### Q1: Is the mechanism at peak? — PEAK, with two named caveats that are not gaps

**The curve is the formula, re-derived.** The five predictions
recompute exactly from `(network_speed - rate_limit) / network_speed`
on the whitepaper's 1080 kb/s base: 95.4 / 90.7 / 72.2 / 53.7 / 7.4
percent at 50kb / 100kb / 300kb / 500kb / 1mb — the printed rows to
the printed decimal. The deltas reproduce too (-0.5 / -5.7 / +7.5 /
+6.0 / +32.9 pp), as do the vs-legacy deltas (+0.25 pp download,
-0.42 pp upload at 100kb, recorded in quota-saver-ab-vs-legacy.sh's
header verbatim) and the B-storm share (4.34 / 37.54 MB = 11.6
percent, printed as "about 12"). Nothing in the curve is
internally inconsistent.

**The window law never clamps inside the measured band.** The Layer-1
window (rate x 200 ms) computes 10 / 20 / 60 / 100 / 200 KB at the
five rates — every row lands mid-band in [2 x MSS = 2920 B,
1 MiB] (recwn.rs:81, :87, :112-130). The clamps are structural
guards, not measured-band distortions: the floor only binds below
~14.6 kb/s, the ceiling only above ~5.24 mb/s. The curve the
whitepaper declares is the unclamped law's curve.

**No non-physics loss exists in the datapath.** The cores carry no
lock anywhere — CAS compare_exchange and volatile reads only
(math.rs:88-117, ecn.rs:105-126), the documented BPF ISA posture.
The policed path adds exactly two steady-state costs over the bare
bucket math, each one LRU lookup with no write (recwn_prime,
recwn_flow.rs:229-248; pace_prime, pace_flow.rs:250-268), both
documented load-bearing at their call sites (enforce.rs:234-255).
The one superlinear spot the tree ever had (the O(egress x ingress)
merge) and the one friction (a second socket-cookie fetch whose
answer cannot differ within one invocation) were closed before the
measurement campaign — NIGHT-lts-2/think-like-light-years-3 and
NIGHT_NETRUNNER_2's smoothbore fix respectively (enforce.rs:233).
An audit that hunts for a removable lock, lookup, or copy finds
none; the -5.7 pp at 100kb is physics loss 3 (the sender's own
timers and ramp), not engineering debt.

**The 1mb rescue is the lanes, not noise.** The evidence chain:
(a) ECN cannot fabricate savings — the budget law bounds marked
delivery to `refill + burst + one 64 KiB GSO` and a CE-ignoring
flow settles at exact drop-parity (ecn.rs:27-56, :103), so the
margin must be bytes the sender never sent; (b) the bytes the
sender never sends were measured directly on the counterfactual
leg — scenario B retransmitted 4-7 MB in every 30-second run, 4.34
MB (11.6 percent of the leg) in the 1mb run — while scenario A's
paced upload moved 6.19 MB with no storm; (c) the download side
rides the same physics with a second lane under it: the RECWN pin
at 1mb is a 200 KB buffer, far below the receive buffer the
unenforced stack auto-tunes toward (the kernel's own ceiling,
megabytes), so the in-flight/bufferbloat storm that produces
retransmissions is bounded before the policer speaks.

*Named caveat one, recorded not fixed:* the whitepaper quotes no
per-lane counter for the 1mb download leg — the lane decomposition
(ce_marked_bytes vs the RECWN booking) that would split the +33 pp
between the two download lanes is measurable but not quoted. The
closure rule itself forbids adding a number without a harness run
(QUOTA_SAVER_PHYSICS.md section 7), the claim as stated ("the
lanes' work", "the ECN-first lane rescued what the barely-binding
throttle could not") is mechanism-true, and the vs-legacy
counterfactual prices the lanes honestly. Under the peak-skip
protocol: no change warranted; the decomposition belongs to the
next campaign on a new wire, not to this record.

*Named caveat two, derived not measured:* the kernel's internal
pacer applies a 40 us minimum hrtimer delay; on a non-GSO 1460-byte
segment that floor stops honoring pacing above ~36.5 MB/s
(1460 / 40e-6) — 36x the highest measured rate, kernel-owned,
outside every claimed row, and irrelevant with TSO/GSO on (pacing
applies per skb, the real-NIC default). Within the claimed
50kb-1mb band there is NO rate at which the pin silently fails:
`pacing_decision` (pace.rs:70-88) rejects only rate 0 (the block
verdict, where no pacing rate can help) and clamps only at the uapi
u32 ceiling (4.29 GB/s); the uapi option sets SK_PACING_NEEDED for
any finite nonzero value; the convergence paths (active before the
first data packet, per-RTT re-apply on rate changes, the documented
passive-child first-window residue and the LRU-eviction-keeps-last-
pin shape) are stated in the lane's own header (pace_flow.rs:31-51).
Named, not silent — the lane's honest remainder, verbatim.

**Verdict Q1: peak — skipped, no change warranted.** The whitepaper's
campaign is closed under its own rules and survives this audit's
re-derivation; the two caveats are recorded observations that the
closure rule already governs.

### Q2: Is the scale at peak? — PEAK

**The four axes hold against the code as read, not as remembered.**
Per-host packet path: try_enforce is one linear chain with a fixed
lookup count (enforce.rs:47-540), O(1) in the packet and independent
of workload population — the unlimited fast path pays two lookups
(identity + policy, enforce.rs:92-123), the policed path pays a
documented chain, the MMSPA walk is memoized and depth-bounded at 32
(mmspa_resolve.rs, mmspa.rs MMSPA_MAX_DEPTH). Per-host population:
one policy row per cgroup per direction; the maps that scale with
population (memo, leaf buckets, socket/flow buckets, hints) are all
LRU 4096 per direction — the declarations are the evidence
(mmspa_resolve.rs:74, :83; drr_flow.rs:57-109; socket_flow.rs:109-114;
cake_flow.rs:85-124; quic_flow.rs:116-123; recwn_flow.rs:80;
pace_flow.rs:77). Fleet: deliberately no controller, composition by
orchestration is the documented model (NIGHT_DRAGON_1 sections 2/4/6,
NIGHT-improve-55's unit-file verdict). Operator: eagle-eyes/doctor/
JSON unchanged.

**The 4096-entry families cannot stall at 4096 live keys — it is
LRU semantics, not capacity planning.** An insert into a full BPF
LRU hash evicts the least-recently-used entry; there is no stall
path. The memo is generation-stamped (schema v12, NIGHT-perf-0), so
an entry that outlives its policy's mutation is retired by an O(1)
counter bump rather than trusted. The monitor's census maps are 4096
LRU per direction with the accepted churn trade PRINTED (USAGE
limitation #11: an evicted-while-idle cgroup that returns restarts
its accumulator — session totals under more than 4096 concurrent
live cgroups carry the documented bound).

**The 1024 policy ceiling is a documented hard limit, not an
unannounced cliff.** USAGE.md names it in three places (line 654
"the 1024-row policy ceiling"; line 701 "the 1024-slot maps stay
proportional to live limits"; the limitation block at 2057-2066
recording the raise history — port-time 256, NIGHT-improve-8's
1024, NIGHT-improve-31's 4096 for the MONITOR's census maps). The
limiter's own maps pin it in code (limiter.rs:190-282: policy,
bucket, stats, ring at 1024; group at 256). The rings and the stats
ledger are census-bounded by that same 1024 — they cannot overflow
where the policy map did not. NIGHT_DRAGON_1's residual ("this audit
did not re-derive the per-map maximums") is satisfied here: the
per-map maximums ARE the declarations above, re-read this audit.

**Verdict Q2: peak — skipped, no change warranted.** The scale claim
is still true at its anchors, and the ceilings are printed where a
future reader trips over them.

### Q3: Is the endurance at peak? — PEAK

**The blade-6 table's anchors were re-opened this audit.** The
rate-ring reclaim (the hunt-Z4 finding — the rings were "the one
census-bounded map nothing handed back"): reclaim.rs carries the
bucket/ring/stats reclaim on unstrict/recover, and its own trace
line names the family ("bucket/ring/stats slots returned to the
1024-entry LTS budget", reclaim.rs:42-45). The 300-cycle churn: the
harness exists as the record states (scripts/depth/endurance-test.py,
27 KB, with the .sh wrapper), its oracle is fail-loud by
construction — a slot leak of one entry per cycle exhausts a cap
mid-run and the next apply fails (STABILITY.md's own wording), so
the proof needs no watcher. The monitor's dead-sink class: the
blade-6 table's "quiet death on a dead sink" row is pinned by
test/terminal/sink_death_tests.rs (133 lines) — the forever-monitor
class has a test that fails if it returns. The silent-killer
inventory's other rows (counter wrap, fd close, child reaping,
diff buffers, TTL rebuilds) were re-walked at their citations and
none has slipped.

**The honest boundary, repeated:** no root, no 5.15 kernel, no eBPF
on this host — the churn was not re-run here and this audit does
not pretend it was. The class evidence is the harness's fail-loud
construction, the reclaim code at its named sites, the test pin,
and the standing CI legs that run the live surfaces on every push.
Nothing in the record shows a class slipping since blade-6 signed
it.

**Verdict Q3: peak — skipped, no change warranted.**

### Q4: Is the skill "the sharpest"? — PEAK on the claimed axes; behind on the unclaimed axes, all of them conceded in print

The six-class walk, both directions per class (what it does that
zelynic does not; what zelynic does that it does not):

| Class | It does what zelynic does not | zelynic does what it does not |
|---|---|---|
| tc/HTB/TBF | queue-based shaping (delays, not drops) — smoother download TCP at the same rate; class hierarchies with borrowing; runs on any kernel with tc | per-cgroup attribution without interface takeover; MMSPA subtree resolution; per-app ingress without an ifb hop; ECN-first marking; the RECWN lane — a receive-window clamp tells the remote sender to slow down, a thing no qdisc can say; wire-measured quota accounting |
| nftables + tc | firewall/NAT integration; file-defined rulesets; arbitrary 5-tuple matches | no config file and no ruleset-swap class; fire-and-forget pinned kernel state; cgroup-path attribution carrying the quota-saver lanes; enforcement below any app's cooperation |
| trickle (LD_PRELOAD) | runs unprivileged; delays rather than drops on cooperative libc sockets | bypass resistance (trickle is defeated by static binaries, non-libc sockets, setuid, any uncooperative app — exactly the class THREAT_MODEL opens with); UDP/QUIC coverage; kernel-side truth; whole-cgroup coverage |
| wondershaper | two-command whole-line shaping; fq_codel queue smoothing both directions (ingress via ifb) | per-app granularity (an interface cap taxes every workload on the host); no script or state file to maintain; the saver lanes; per-cgroup bypass resistance |
| cgroup v2 + tc (the manual composition) | queue-based shaping at the qdisc; the net_cls-era workflow some operators know | the composition IS zelynic's automation: cgroup v2 removed net_cls, so the manual shape needs ifb-plus-tc filters per cgroup and root-qdisc surgery that collides with any other qdisc policy; zelynic needs none of it and adds MMSPA, ECN/RECWN/EDT |
| bpftrace-based policers | arbitrary observability of any kernel event | actual enforcement with a stable hook class and pins that outlive the tool; a bpftrace policer is a resident process (the daemon zelynic refuses) with per-packet kprobe cost above cgroup_skb and no enforcement ABI |

**The honest verdict.** The owner's positioning — "the most
efficient way to rate-limit on Linux: no daemon, no config, no app
cooperation, wire-measured" — is TRUE on the axes it names: no
competitor in the table does per-app bypass-resistant limiting in
both directions without a daemon, without a config file, without
app cooperation, and with a published measured-savings curve.
Where competitors win, zelynic does not claim the axis, and every
one of those concessions is already printed: queue-based
smoothness (a real qdisc delays; zelynic's download side is a
policer, and the -5.7 pp at 100kb is that tax measured on the
wire), unprivileged operation (trickle), whole-interface
simplicity (wondershaper), kernels below the 5.15 floor
(KERNEL_COMPATIBILITY.md), firewall/NAT integration (nftables).
Ahead where it claims, behind where it does not claim, and the
behind is in writing — that is what a sharpened position looks
like. The README's vs-traditional-tools table (README.md:110-123)
survives this walk; the two classes it omits (manual cgroup+tc,
bpftrace) are added above, both losing to zelynic on every axis the
positioning names.

**Verdict Q4: peak — skipped, no change warranted.** The comparison
table needs no edit: it is a summary, not the ledger, and the
ledger (this section plus THREAT_MODEL plus the USAGE limitations)
is current.

## Phase 3 — gaps found

**None.** No code commit, no schema version, no BPF program, no
syscall, no doc surgery. The two observations Phase 2 surfaced are
recorded where they belong — inside the audit that found them —
because the whitepaper's closure rule (no number without a harness
run; no section the whitepaper does not need) and the peak-skip
protocol both say the same thing: a measured record at peak is not
edited to feel complete.

1. The 1mb download-leg lane decomposition (ce_marked_bytes vs the
   RECWN booking) is unmeasured in print — next campaign's first
   row, on a new wire, through the harness. Not a gap in this one.
2. The kernel internal pacer's 40 us hrtimer floor yields a derived
   silent-fail boundary at ~36.5 MB/s on non-GSO paths — outside
   the claimed band, kernel-owned, no fix in zelynic's control.
   Recorded so the next auditor does not re-derive it.

## Phase 4 — the verdict

zelynic's mechanism is at peak on the four axes.

- **Mechanism:** peak. The whitepaper's five-rung curve re-derives
  to the printed decimal from its own formula (all predictions,
  deltas, vs-legacy numbers, and the B-storm share recomputed this
  audit); the window law never clamps inside the measured band; the
  datapath carries no lock, no removable copy, no removable lookup
  (the last friction was closed in NIGHT_NETRUNNER_2, two days
  before the campaign); the 1mb rescue is mechanism-consistent with
  directly measured counterfactual evidence; the EDT pin honors the
  policy rate at every rate in the claimed band with the residues
  named in the lane's own header.
- **Scale:** peak. NIGHT_DRAGON_1's four axes hold against the map
  declarations as read this audit; the 4096 families are LRU (no
  stall is expressible); the 1024 policy ceiling is documented in
  three places and pinned in code; the rings/stats are
  census-bounded by the same 1024; the fleet posture is the
  documented composition model.
- **Endurance:** peak. The blade-6 silent-killer table's anchors
  re-opened clean: the hunt-Z4 ring reclaim is in reclaim.rs at its
  named sites, the 300-cycle churn harness exists with its fail-
  loud oracle, the dead-sink quiet death is test-pinned, and no
  class has slipped.
- **Skill:** peak on the claimed axes; the unclaimed axes are
  conceded in print (THREAT_MODEL, the USAGE limitations, the
  vs-traditional-tools table), and the six-class walk found no
  competitor that beats zelynic on any axis the positioning claims.

The gaps found: none. The recommended next action: none — peak
confirmed. The next measurement belongs to a new wire (the 1mb lane
decomposition is its first row), which is a new campaign, not a
defect in this record.

## Gate results

- Change class: docs-only (this report + one index row in
  docs/README.md). Benchmark skipped by the owner's own rule — a
  docs-only change runs no benchmark.
- `scripts/gate-keepers.sh` applicable lanes run locally on the
  changed files: SPDX header contract, emoji sweep, permission
  policy, language purity, audits-index coverage — results in the
  commit message body. The Rust lanes (`build.sh check-all`,
  fmt, clippy, cargo test) are CI-owned on this host: no cargo/
  rustc exists here and there is no sudo to install one — the same
  standing boundary the live-eBPF legs already carry, and no Rust
  byte changed.
- CI owns the rest: the standing battery, the kernel-clippy lane,
  and the supermassive legs run on every push.

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
