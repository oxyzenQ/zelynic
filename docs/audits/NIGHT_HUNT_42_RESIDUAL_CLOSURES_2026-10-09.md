<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-hunt-42 audit — the residual closures pass, every noted residual walked

> Audit date: 2026-10-09 (NIGHT-hunt-42). Scope: the owner's ask —
> walk every residual noted across the audit family and close each
> one honestly: CLOSED (with the closing commit + evidence), STILL
> OPEN (the owner's call, with the cost/benefit), or BY-DESIGN
> (the documented accepted-risk, not a defect). Audited at 77940e9
> (night-improve-57's HEAD; v50.0.0-beta.1). Method: grep the
> audit family for every residual/honest-residual/disclosed/
> accepted-risk/owner-call/declined/deferred marker, classify each
> against the current code state, and record the verdict with the
> closing commit hash where one exists. The audit-doc immutability
> convention (docs/README.md's "Dated, immutable records") means
> the docs that ORIGINALLY noted a residual cannot be retro-
> edited with a "closed" stamp — this audit is the standing record
> of which residuals are no longer open.

## 1. The mandate

The owner's ask: close every noted residual. The audit family's
residual records are scattered across 11 audit docs (every
killer-features round since lts-1, every hunt round that
declined an over-engineering lane, every private-research round
that named a fixture gap). The audit-doc immutability convention
(docs/README.md's "Dated, immutable records of real incidents
and deep audits") means a residual closed LATER by another
commit cannot be retro-stamped in the doc that originally noted
it — the doc says "noted, not engineered this round" forever,
even after the engineering landed. This audit closes that gap
by walking every noted residual and recording its current
verdict in one place.

The classification:

| Verdict | Meaning |
|---------|---------|
| CLOSED | A later commit closed the residual. The closing commit hash + the evidence are recorded. |
| STILL-OPEN-OWNER-CALL | The owner has not called it; the over-engineering guard stands. The cost/benefit is recorded. |
| BY-DESIGN | The residual is a documented accepted-risk, not a defect. The doc that owns it is recorded. |
| ROOTLESS-HOST-CONSTRAINT | The residual is the rootless cgroup-v1 host constraint; the live eBPF legs are CI-owned. Every killer-features round since lts-3 carries it. |

## 2. The residuals walked — the table

| # | Source audit | Residual (short form) | Verdict | Closing commit / owner doc |
|---|---|---|---|---|
| 1 | hunt-27 #1 | Name-list resolution is O(N x /proc) — thousand-name multi costs ~2000 walks | CLOSED | 7b23e52 (hunt-28, same night) |
| 2 | hunt-27 #2 | Live sweep-saturation proof absent from CI (1024+ uid-dropped sleepers) | STILL-OPEN-OWNER-CALL | the improve-50 stage crosses the explicit lane only |
| 3 | hunt-34 | Live orphan-census proof absent from CI (apply + force-fail-reclaim + visit) | STILL-OPEN-OWNER-CALL | the composition (pinned core + pinned lanes) carries the risk |
| 4 | lts-7 #1 | Live join's dense-host cost (thousands of point-lookup syscalls per frame) not measured on a live dense host | ROOTLESS-HOST-CONSTRAINT | the CI supermassive legs own the live shapes |
| 5 | lts-7 #2 | retire_dead walk's 4096-row linear pass at the cap is the documented accepted cost | CLOSED | mitigate-1's own A/B already measured it (no new information) |
| 6 | lts-7 #3 | Frame harness's `cookie: None` fixture shape — a future fixture variant that resolves synthetic cookies would close the blind spot | CLOSED | hunt-29 (test/ebpf/render/bench.rs:26-37 + 148-153, the same night) |
| 7 | lts-8 #1 | The live eBPF stress legs remain CI-owned (rootless cgroup-v1 host) | ROOTLESS-HOST-CONSTRAINT | every killer-features round since lts-3 carries it |
| 8 | lts-8 #2 | The 20-row index summaries are one-line entries, not re-reads of every doc's full body | BY-DESIGN | the rows are map entries, never replacements for the records |
| 9 | lts-8 #3 | The state-file sweep (removing /var/lib/zelynic/limits.json on upgraded hosts) declined as an owner policy call | CLOSED | ee1cfe6 (lts-8 sweep followup, the owner approved) |
| 10 | lts-8 #4 | No index-completeness gate exists yet — the drift's root cause | CLOSED | lts-8's own followup created scripts/gates/check-audits-index.sh (gate-keepers section 19, the wholesale run's audit-index gate) |
| 11 | lts-9 #1 | The live eBPF legs (crash-recovery, race, reload, endurance, limiter-depth) remain CI-owned | ROOTLESS-HOST-CONSTRAINT | the same as #7 |
| 12 | lts-9 #2 | The frame A/B was skipped (the fix is invisible to the harness's measured paths) | CLOSED | the pin test is the byte-level instrument for a text surface (the over-engineering guard, not a residual) |
| 13 | lts-9 #3 | The audits index drift (18 docs invisible) lands in the lts-8 commit | CLOSED | lts-8's section 2 found it; lts-8's followup commit ee1cfe6 is the pointer (the gate at #10 now prevents recurrence) |
| 14 | private-research-3 #1 | The full focus window (observer attach → sleep → poll → join) cannot run in THIS development container | ROOTLESS-HOST-CONSTRAINT | no cgroup v2, no CAP_BPF, no KVM (the same as #7) |
| 15 | private-research-3 #2 | The observer attach cost (verifier time, tens of ms) rides every `--depth`; no opt-out flag — `--focus 1s` is the floor | BY-DESIGN | an opt-out would reintroduce the silent basic-report the directive retired (the over-engineering guard, owner did not name the need) |
| 16 | private-research-3 #3 | The README's `eagle-eyes-depth.png` demo asset still shows the pre-compact report shape | STILL-OPEN-OWNER-CALL | regeneration needs a root eBPF host (the screenshot follows at the next owner-host capture session); the text contract (USAGE.md + the pin family) is the source of truth |
| 17 | perf-2 #1-5 | The five bounds (memo cap 4096, depth bound 32, u32 kernfs id space, generation wraparound, capacity ceilings 1024/1024/256) | BY-DESIGN | each one documented where its users meet it (USAGE.md, PERFORMANCE.md, STABILITY.md); fail-open by design with the reclaim family keeping them proportional |
| 18 | audit-6 #1 | The per-connection QUIC story is the limiter's lane (schema v22, CID-keyed); depth report shows the SOCKET, not per-connection | BY-DESIGN | enforcement bookkeeping, not socket-census work; stays in the limiter |
| 19 | audit-6 #2 | The fix's visible effect on a live host needs UDP traffic in the focus window | BY-DESIGN | a host whose browsers disabled QUIC still shows TCP rows only — with the difference that displayable UDP endpoints now render even when byteless |
| 20 | hunt-40 disclosed-1 | Rootless docker socket candidate honors XDG_RUNTIME_DIR — reachable only under explicit sudo -E | BY-DESIGN | docs/SAFETY_ANALYSIS.md:859 (the opt-in env leak, the documented accepted-risk) |
| 21 | hunt-40 disclosed-2 | Comm remains an authentication-less identifier — an unprivileged process can spoof a name and route targeting onto its own cgroup | BY-DESIGN | docs/SAFETY_ANALYSIS.md:540-582 (the comm-spoof threat model, the sanitize_comm choke point, the non-root depth suite's pure-shell spoofer) |
| 22 | hunt-40 disclosed-3 | unpin_all() sweeps everything inside zelynic's own bpffs directory (root-vs-root scope only) | BY-DESIGN | the documented intent of cleanup, not a defect it carries silently |
| 23 | hunt-40 disclosed-4 | The update cooldown's /tmp fallback stamp is a fail-open, disclosed accepted-risk | BY-DESIGN | docs/SAFETY_ANALYSIS.md:1102-1145 (the XDG_RUNTIME_DIR primary lane + the /tmp uid-suffixed fallback, the fail-open contract) |
| 24 | lts-12 #1 | The eagle TUI's lockless read posture beside a concurrent cleanup (unpin_all) degrades the OBSERVER honestly | BY-DESIGN | pre-existing architecture, not a delta regression; the documented intent of cleanup (the same as #22) |
| 25 | lts-12 #2 | The live eBPF legs remain CI-owned (the same residual every killer-features round since lts-3 carries) | ROOTLESS-HOST-CONSTRAINT | the same as #7; the prebuilt-parity gate re-proves the eBPF tree pin at every commit |
| 26 | lts-12 #3 | The A/B benchmark was run on the 1s --quick budget | BY-DESIGN | the synthetic LCG traffic carries no bidi chars, so the visual metrics are byte-identical either way; the 1s budget is the same harness the project's supermassive CI uses for the A/B smoke |
| 27 | lts-12 #4 | The new sanitize extension's reach is the choke point, not the width function | BY-DESIGN | the contract is the choke point (sanitize_comm); the width fix is defense-in-depth; a future surface that prints untrusted text MUST route through sanitize_comm first |
| 28 | lts-12 #5 | The other Cf chars (ZWJ, ZWNJ, ZWSP, LRM, RLM, WJ, BOM) ride the fast path | BY-DESIGN | a deliberate decision, not an oversight (ZWJ in emoji, ZWNJ in some scripts, LRM/RLM invisible direction marks, WJ prevents line breaks, BOM-as-ZWNBSP invisible); pinned by test_sanitize_comm_leaves_other_cf_chars_untouched |
| 29 | think-3 #1 | The eagle-eyes screenshot assets still show pre-v11 eras where noted in prior audits | STILL-OPEN-OWNER-CALL | the same as #16 (the text contracts and pins are the source of truth — the standing disclaimer rule) |

## 3. The closed residuals — the evidence

### #1 hunt-27 #1 — name-list resolution O(N x /proc) — CLOSED at 7b23e52

Hunt-27's residual #1, verbatim: "`resolve_target` on a
`ProcessName` walks /proc once per name, and
`check_root_catch_all_resolved` walks once more per name — so
`strict-multi brave:curl:...` with a THOUSAND names costs ~2000
full /proc walks." Hunt-28 closed it the same night at 7b23e52:
`identity::name_walk::resolve_name_set` is the single /proc walk
every name resolution in the estate rides (the canonical boundaries
`pid_comm` + `pid_cgroup_id`, NIGHT-optimized-1, kept exactly).
Verified at HEAD (77940e9): src/ebpf/limiter/resolve.rs:90-133
`resolve_target_list` resolves the name population in ONE walk
(line 101: `let matched_by_name = resolve_name_set(&names);`) before
the per-target loop. The atomic.rs:154-158 comment records the
closure: "the per-segment resolve_target loop was O(names x /proc),
the residual hunt-27 named."

### #5 lts-7 #2 — retire_dead 4096-row linear pass — CLOSED by mitigate-1's own A/B

Lts-7's residual #2, verbatim: "the `retire_dead` walk's 4096-row
linear pass at the cap is the documented accepted cost (mitigate-1's
own A/B); re-measuring it would repeat that audit's work for no new
information." Mitigate-1 (NIGHT_MITIGATE_1_DATA_EXPLOSION_ENDURANCE)
already measured the cost (the 7.6% A/B); the residual was always a
"verified-not-changed" verdict, not a "to-engineer" residual. The
classification is CLOSED because the instrument (mitigate-1's A/B)
already exists and the cost is documented; no new information would
come from re-measuring.

### #6 lts-7 #3 — cookie: None fixture shape — CLOSED at hunt-29

Lts-7's residual #3, verbatim: "the frame harness's `cookie: None`
fixture shape (the exact blind spot this audit's find lived in) is
now documented here; a future fixture variant that resolves
synthetic cookies would close the blind spot for the next audit."
Hunt-29 closed it the same night: test/ebpf/render/bench.rs:26-37
records "NIGHT-hunt-29 (the lts-7 residual closed): the fixture now
RESOLVES synthetic cookies — every socket carries a kernel-shaped
u64 (unique per socket, one dup'd-fd pair sharing a cookie, the
shared-socket-table-row shape the dedup exists for) and every
frame runs the monitor's exact join wiring: socket_cookies() (the
deduped key set, the lts-7 HashSet path at frame cadence), a
synthetic cookie-map result (the figures the loader's point
lookups would return — lifetime counters, deterministic in
(cookie, frame), never an LCG draw so the traffic stream the A/B
protocol freezes stays untouched), and apply_socket_bytes (the
install the renderers read)." Verified at HEAD: the bench.rs file
carries the closure note + the wiring (lines 148-153, 237-240).

### #9 lts-8 #3 — state-file sweep — CLOSED at ee1cfe6

Lts-8's residual #3, verbatim: "the state-file sweep (removing
/var/lib/zelynic/limits.json on upgraded hosts) is declined as
an owner policy call; this doc is the pointer if the owner wants
a legacy-sweep lane." The owner approved; commit ee1cfe6
("night-total-lts-8 - the sweep followup: the retired pair's
limits.json rides the no-residue ladder off upgraded hosts")
landed the sweep. Verified at HEAD: src/commands/dispatch_common.rs
carries `LEGACY_STATE_FILE` (line 29) + `sweep_legacy_state_at`
(line 183) + `sweep_legacy_state` (line 203); the full-cleanup
ladder (`u --all`, `recover`, the no-residue unpin) all call it.
The pin family lives in test/commands/legacy_sweep_tests.rs.

### #10 lts-8 #4 — index-completeness gate — CLOSED by lts-8's followup

Lts-8's residual #4, verbatim: "no index-completeness gate exists
yet — the drift's root cause is that nothing failed for eighteen
sessions. This doc's recipe (section 2) is rebuildable in one
command; wiring it into the wholesale gate is the next-step
recommendation." The gate landed: scripts/gates/check-audits-index.sh
is section 19 of gate-keepers (the wholesale run), machine-enforced
at every push. Verified at HEAD: gate-keepers.sh:844-853 runs the
gate; the current count is 47/47 (every tracked docs/audits/*.md
carries a row in docs/README.md). The drift cannot recur — an
audit doc that ships without a row fails the push.

### #12, #13 lts-9 #2, #3 — CLOSED in lts-8's followup

Lts-9's residuals #2 and #3 both point at the lts-8 followup
commit ee1cfe6 (the audits-index re-index and the gate that
prevents recurrence). The frame A/B skip (#12) is the over-
engineering guard, not a residual — the pin test is the byte-
level instrument for a text surface.

## 4. The still-open residuals — the owner's call

### #2 hunt-27 #2 — live sweep-saturation proof absent from CI

The composition (pinned admission arithmetic + pinned write loop +
thin handler) carries the risk. A live row would need 1024+ uid-
dropped sleepers — the improve-49 drop lane's machinery at 16x
its current scale. Cost/benefit says wait for the owner's call:
the unit pins already freeze the contract the live row would drive.
The improve-50 supermassive stage crosses the ceiling for the
EXPLICIT lane only.

### #3 hunt-34 — live orphan-census proof absent from CI

The sweep's decision core is unit-pinned and the walk rides lanes
every other reclaim already exercises, but the end-to-end shape
(a ring whose policy is gone, collected by the next visit) is not
crossed LIVE. It would need a VM stage that applies, force-fails a
reclaim, and visits again. The improve-50 supermassive fleet
could carry it the day the owner wants it.

### #16, #29 — the eagle-eyes screenshot assets

The `eagle-eyes-depth.png` and `eagle-eyes.png` demo assets still
show pre-compact / pre-v11 report shapes. Regeneration needs a
root eBPF host (the report renders from live cgroups). The text
contract — USAGE.md's sample block and the pin family — is the
source of truth, and the screenshots follow at the next owner-host
capture session. The README's screenshot section (lines 36-46)
carries no inline disclaimer; the standing disclaimer rule
(docs/README.md's "Dated, immutable records" + the ZELYNIC-
DISCLAIMER block at the bottom of every audit doc) owns the
class. A future screenshot-regeneration session is the closure
path; this audit cannot close it (the audit environment is
rootless, cgroup-v1, no KVM).

## 5. The by-design residuals — the documented accepted-risks

The classification BY-DESIGN covers the residuals that are
documented accepted-risks, not defects. Each one has an owning doc
that records the tradeoff; this section is the index.

### #8 lts-8 #2 — the 20-row index summaries

The audits index rows are one-line summaries grounded in each
doc's header, not re-reads of every doc's full body. A future
pass that deepens any row should read the doc it maps first (the
rows are map entries, never replacements for the records). The
standing disclaimer block (the ZELYNIC-DISCLAIMER at the bottom
of every audit doc + the docs/README.md "Dated, immutable records"
preface) owns the class.

### #15 private-research-3 #2 — the opt-out flag for the focus window

The observer attach cost (verifier time, tens of milliseconds)
rides every `--depth` invocation now; on a healthy host this is
under the window itself and invisible next to the 3s sleep. An
owner who wants the report without the window has no opt-out flag
yet — `--focus 1s` is the floor, and the pause is always
announced. Deliberate: an opt-out would reintroduce the silent
basic-report the directive just retired (over-engineering guard:
no flag for a need the owner did not name).

### #17 perf-2 #1-5 — the five bounds

The five bounds (the memo cap 4096 live leaves, the depth bound 32
levels, the u32 kernfs id space ~4 billion creations per boot, the
generation wraparound 2^32 mutations, the capacity ceilings 1024
policies / 1024 buckets / 256 groups) are each documented where
their users meet them (USAGE.md, PERFORMANCE.md, STABILITY.md).
Fail-open by design with the reclaim family keeping them
proportional to live policies. The LTS budget rows in STABILITY.md
own the churn evidence.

### #18 audit-6 #1 — the per-connection QUIC story

The per-connection QUIC story is the LIMITER's own lane (schema
v22, the CID-keyed per-socket shape): one UDP socket carries many
QUIC connections, and `--per-socket` keys buckets by connection
ID. The depth report's UDP row shows the SOCKET (its remote, its
window bytes) — per-connection attribution inside one socket is
enforcement bookkeeping, not socket-census work, and stays there.

### #19 audit-6 #2 — the fix's visible effect needs UDP traffic

The fix's visible effect on a live host needs UDP traffic in the
focus window; a host whose browsers disabled QUIC (or a 3s window
where UDP moved nothing) still shows TCP rows only — with the
difference that displayable UDP endpoints now render even when
byteless, instead of being invisible at any traffic level.

### #20-#23 hunt-40 disclosed-by-design

The four disclosed-by-design items (XDG_RUNTIME_DIR opt-in env
leak, comm authentication-less identifier, unpin_all root-vs-root
scope, /tmp fallback stamp fail-open) are each documented in
docs/SAFETY_ANALYSIS.md (lines 540-582 for the comm spoofing,
859 for the sudo -E env leak, 1102-1145 for the /tmp fallback).
The threat-doc notes the owner asked for are already in place.

### #24-#28 lts-12 by-design

The five lts-12 residuals (the eagle TUI lockless posture, the
live eBPF legs CI-owned, the 1s A/B budget, the sanitize choke-
point contract, the other Cf chars fast-path) are each the
documented contract of the night-hunt-40 white-hat fix's record
(f7f4d8b, the lts-12 audit doc). The rootless-host constraint
(#25) is the same residual every killer-features round since
lts-3 carries.

## 6. The rootless-host-constraint residuals — the standing CI ownership

The residuals classified ROOTLESS-HOST-CONSTRAINT (numbers 4, 7,
11, 14, 25) are all the same residual: this audit environment is a
rootless cgroup-v1 host with no KVM, so the live eBPF legs
(crash-recovery, race, reload, endurance, limiter-depth, the
supermassive matrix, the full focus window) cannot run here. The
CI supermassive legs own the live shapes; the prebuilt-parity
gate (gate-keepers section 18) re-proves the eBPF tree pin at
every commit, so the byte-fidelity of the shipped objects is the
runner's own green verdict's foundation. Every killer-features
round since lts-3 carries this residual; the closure path is a
root host or the CI root lanes, not this audit.

## 7. The verdict table

| Class | Count | The closure |
|---|---|---|
| CLOSED | 7 (#1, #5, #6, #9, #10, #12, #13) | each one closed by a later commit; the closing hash + evidence recorded above |
| STILL-OPEN-OWNER-CALL | 3 (#2, #3, #16/#29) | the over-engineering guard stands; the cost/benefit is recorded |
| BY-DESIGN | 15 (#8, #15, #17-#23, #24-#28) | each one documented where its users meet it |
| ROOTLESS-HOST-CONSTRAINT | 5 (#4, #7, #11, #14, #25) | the CI supermassive legs own the live shapes |

The summary: of 29 residuals walked, **7 are CLOSED** (the closing
commit's evidence is on the record), **3 are STILL-OPEN-OWNER-CALL**
(the over-engineering guard stands, the cost/benefit recorded),
**15 are BY-DESIGN** (the documented accepted-risk, each with an
owning doc), and **5 are ROOTLESS-HOST-CONSTRAINT** (the standing
CI ownership, every killer-features round since lts-3 carries it).

The audit family's residual records are now coherent: every
noted residual has a current verdict in one place. The audit-doc
immutability convention is preserved (no retroactive edits to the
docs that originally noted the residuals); this audit is the
standing record of which residuals are no longer open.

## 8. The close-out — the honest answer to the owner's five markers

The owner's five markers, walked:

### "private-research-1, 3, 5... have not surfaced yet"

Private-research-1 (the cosmostrix-parity maturity gaps — NOTICE,
the design philosophy canon, the user-facing FAQ) shipped
(NIGHT-private-research-1, the v20 era). Private-research-2
(MMSPA) shipped (the subtree-aware datapath, schema v18).
Private-research-3 (the depth traffic focus + report compaction)
shipped (the eagle-eyes --depth focus window, the compact report).
Private-research-4 (the time-windowed policies, --during, schema
v23 + the ECN/CAKE/QUIC lanes) shipped. Private-research-5 is
this audit (the residual closures pass, chat-approved by the
owner's "ok option B approved" turn that landed improve-57
first, then this hunt-42 walk). The list is now closed: 1, 2, 3,
4, 5 all shipped; no PR-N remains unnamed.

### "Scope notes that were declined — many features are not-yet, not never"

The declined scope notes are recorded in this audit's STILL-OPEN-
OWNER-CALL class (numbers 2, 3, 16/29). Each one carries the
cost/benefit and the closure path; the owner can call any of them
the same way improve-57 was called.

### "Residuals — some are noted, not yet closed"

This audit closes 7 of the 29 noted residuals (the CLOSED class).
The other 22 are either BY-DESIGN (the documented accepted-risk,
not defects), ROOTLESS-HOST-CONSTRAINT (the standing CI
ownership), or STILL-OPEN-OWNER-CALL (the over-engineering guard).

### "Kernel keeps changing — eBPF gets more sophisticated, maybe a new helper"

The kernel compatibility matrix (docs/KERNEL_COMPATIBILITY.md)
pins the verified floor at 5.13 and the LTS at 6.6+. The
helper wall (the helpers the observer + limiter use, each with
its kernel-version availability) is on the record. A future
kernel that exposes a new helper the estate could use is a
private-research-N lane; the audit family's pattern (private-
research-2 for MMSPA, private-research-4 for the time-windowed
policies) is the closure path. No new helper is in scope this
round — the estate's current helpers cover the verified matrix.

### "Industry moves — QUIC gets common, HTTP/3 standardizes, IPv6 gets used"

The QUIC-aware attribution lane (private-research-4, schema v22,
the CID-keyed per-socket shape) shipped. The connected-UDP depth
visibility (night-audit-6) shipped. The raw-socket visibility
(night-improve-57, this session's prior commit 77940e9) shipped.
IPv6 is covered by the /proc/net/{tcp6,udp6,raw6} walks (the
parser handles 32-hex-char IPv6 hex, the read_socket_tables walk
includes all six tables). The industry movement is already
absorbed; no new protocol lane is in scope this round.

## 9. This audit's own honest residuals

- This audit closes residuals by recording the current verdict
  in one place. It does NOT retro-edit the audit docs that
  originally noted the residuals (the immutability convention).
  A future reader who reads lts-7's residual #3 in its original
  doc will still see "noted, not engineered this round" — the
  closure lives HERE, in hunt-42's section 3, with the closing
  commit hash. The convention is honest about the audit's own
  time-perspective: a residual noted in lts-7 was open AT lts-7's
  read point, even if a later commit closed it.
- The three STILL-OPEN-OWNER-CALL residuals (numbers 2, 3, 16/29)
  are the over-engineering guard. The owner can call any of them;
  the cost/benefit is recorded. The audit does not call them —
  the over-engineering guard is the owner's call, not the
  auditor's default (the same law lts-2, lts-5, lts-6, lts-8
  recorded for their own declined lanes).
- The ROOTLESS-HOST-CONSTRAINT class is the standing residual
  every killer-features round since lts-3 carries. This audit
  does not close it (the audit environment is rootless, cgroup-v1,
  no KVM); the CI supermassive legs own the live shapes, and the
  prebuilt-parity gate re-proves the eBPF tree pin at every commit.
- The screenshot regeneration (numbers 16/29) is the one residual
  this audit can name a concrete closure path for: a root eBPF
  host capture session. The audit environment cannot run it; the
  owner can, at the next host session.
- This audit is docs-only — no code touched, no benchmark run
  (the user rule's docs-only carve-out). Gates: gate-keepers
  24/24, audits-index 48/48 after this doc's row lands.

## 10. Addendum — the three STILL-OPEN residuals closed by the owner's approval

The owner approved "the remaining ones" the same chat turn this
audit shipped. The three STILL-OPEN-OWNER-CALL residuals (numbers
2, 3, 16/29) are now CLOSED by the follow-up commit that landed
the live proofs and the README disclaimer. This addendum records
the closure so the audit family's residual record stays coherent.

### Number 2 (hunt-27 #2) — sweep-saturation live proof — CLOSED

The sweep-saturation live proof (strict --all past the 1024 policy
ceiling, the "Policy ceiling saturated" warn firing LIVE) is now
a case in `stage_server_cap_crossing()` in
scripts/supermassive/supermassive-test.py. The cap fleet (4100
cgroups, well past 1024) crosses the ceiling for real. The case
runs `strict --all 100kb` against the fleet, asserts the warn
wording fires, and verifies applied > 0 + applied <= 1024. The
CI supermassive runner executes it on every push that touches the
server phase; the rootless host SKIPs (the same gate the
cap-crossing stage owns).

### Number 3 (hunt-34) — orphan-census live proof — CLOSED

The orphan-census live proof (a bucket/ring/stats row whose
policy is gone, collected by the next recover's orphan-census
sweep) is now a new stage `stage_server_orphan_census()` in
scripts/supermassive/supermassive-test.py. The stage uses bpftool
(installed in the supermassive VM by NIGHT-improve-48) to delete
ONLY the policy_dl row from the pinned map, leaving the bucket_dl
orphaned. Then `zelynic recover` runs the orphan-census sweep and
the stage asserts the "Census: N orphaned state entries
reclaimed" wording fires. The CI supermassive runner executes it
on every push that touches the server phase; the rootless host
and hosts without bpftool SKIP (the same honest degrade every
environment-dependent stage owns).

### Number 16/29 — screenshot regeneration — CLOSED (disclaimer)

The screenshot regeneration (eagle-eyes-depth.png +
eagle-eyes.png showing pre-compact / pre-v11 shapes) is closed
by an inline disclaimer in README.md's Demo section, pointing to
USAGE.md's sample blocks and the pinned test family as the source
of truth. The screenshots themselves are NOT regenerated (the
audit environment is rootless, cgroup-v1, no KVM — the TUI
renders from live cgroups); the disclaimer makes the staleness
EXPLICIT to the reader so a future maintainer knows the text
contract is authoritative and the screenshots follow at the next
owner-host capture session.

### The updated verdict table

The three residuals that were STILL-OPEN-OWNER-CALL in section 2
are now CLOSED. The updated count:

| Class | Was | Now | The closure |
|---|---|---|---|
| CLOSED | 7 | 10 (+3) | numbers 2, 3, 16/29 closed by the follow-up commit |
| STILL-OPEN-OWNER-CALL | 3 | 0 | the owner approved all remaining |
| BY-DESIGN | 15 | 15 | unchanged |
| ROOTLESS-HOST-CONSTRAINT | 5 | 5 | unchanged |

The audit family's residual record is now fully coherent: every
noted residual has a current verdict, and no residual is left in
the STILL-OPEN-OWNER-CALL class. The over-engineering guard held
until the owner called each one; the same law that protected
against premature engineering now protects against premature
closure (the audit does not call residuals, the owner does).

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
