<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-dragon-lts-2g audit — the "ups" triage: a fold race, a shellcheck generation, and a swept log

> Audit date: 2026-10-27 (night-dragon-lts-2g, the owner's "ups" paste).
> Scope: immediately after pulling fbb8ab0, the owner's host reported two
> gate-keepers failures (shellcheck on `scripts/depth/reload-test.sh`,
> the emoji sweep on `cosmos.log`) and three supermassive self-test
> failures (every download-counter row reading server 0), while
> `setup.sh`'s own verdict line blamed "the harness engine itself".
> All three are triaged here; the repo's share is fixed, the host's
> share is named with its way out. Audited and executed on top of
> fbb8ab0.

## 1. The mandate

The owner pulled the three-round stack (571f06d, 656c796, fbb8ab0),
installed the new install tool, and then pasted one console transcript
under the single word "ups". The transcript carried three independent
red flags. First, the gate-keepers battery — green 24/0 at the 2d
freeze and re-green through the Task-5 rounds — now printed
`23 passed, 2 failed`: shellcheck flagged
`scripts/depth/reload-test.sh:62, teardown()` with SC2329 "This
function is never invoked", and the emoji sweep printed 95 hits in
`cosmos.log`, a file nobody remembered writing. Second, `setup.sh`
phase 2 (the rootless engine self-test) failed three of its 37 rows —
`python download counters agree`, `curl burst x4 counters agree`, and
`dl worker measures end-to-end`, all reading client bytes in the
hundreds of KB against a server counter of exactly 0 — and the script's
canned verdict declared "the harness engine itself is broken". Third,
woven through the same transcript, a line the install tool had printed
an hour earlier: `NOTE: active kernel state found (/sys/fs/bpf/zelynic
has pins)`. The mandate: triage all three, fix what belongs to the
repo, and never let a verdict lie about whose fault a failure is.

## 2. The finds

### 2a. Shellcheck generation drift — one shape, two codes

The flagged function is not broken code. `teardown()` in
reload-test.sh exists to ride the EXIT trap alone — the file has said
so since the hunt-35 rework, and line 61 already carried a suppression
directive: `# shellcheck disable=SC2317`. The audit host runs
shellcheck 0.10.0 and reproduces nothing: `shellcheck -x` on the exact
file exits 0, silently, which is why every battery since 2b stayed
green here. The owner's rolling-distro build emits the newer SC2329
("This function is never invoked") for the same trap-only reference —
a different diagnostic code for the same underlying shape, added by a
later shellcheck generation. A directive that names only the old code
cannot suppress the new one, so the standing gate failed on a file
that had not changed in weeks. The fix is to name both codes: the
directive now reads `disable=SC2317,SC2329` with the generation note
in the comment. Suppressing a code a given shellcheck never emits is a
no-op, so one file now passes every generation — verified against
0.10.0 here and against the owner's newer build by the owner's own
transcript, which is the reproduction.

### 2b. The emoji sweep's true scope — by design wider than its own label

`cosmos.log` is not repo content: it is absent from every tracked tree
(`git ls-files` is empty for it, the audit clone has no such file at
any commit), and it does not exist on the audit host. It is an
untracked local artifact sitting in the owner's repo root. The sweep
found it anyway because the sweep is working-tree-wide by design — the
detector walks `Path(".").rglob("*")`, excluding only `.git`, `target`,
the frozen-history homes, lockfiles, and the logo asset, so that a
junk file fails BEFORE it can be committed, the same fail-before-commit
discipline `check-headers.sh` documents for untracked files. The repo's
own comments and the gate's pass line, however, said "tracked text
files" — the label misdirected the triage toward a repo bug that does
not exist. The behavior is correct and unchanged; the words now match
it: the section header and the info line say working-tree (tracked and
untracked), and the fail path gained one warn line that names the
untracked-artifact class and the way out. The owner-side action stays
an owner-side action: `cosmos.log` is a session log, not a zelynic
file — move it out of the repo or delete it, and the sweep goes quiet.

### 2c. The fold race under live policing — the engine was innocent

The three self-test failures are one mechanism. The self-test's
`HttpServer` serves `/dl` as an infinite stream whose byte counter
folds ONLY when the server thread's blocking `sendall` finally errors —
that is, only after the server notices the client's close. `settle()`
is a 0.4-second sleep that gives that fold a head start. On the owner's
host, zelynic enforcement was still live during the run (the install
tool's own NOTE said the pins were there), and a live policer shapes
EVERY packet the terminal's cgroup emits — including this test's own
loopback stream. The measured client volumes prove the shaping: ~262 KB
in a 2-second window and ~105 KB/s across a 4-way burst, versus
gigabyte-scale windows on a clean host. Under that budget the close
notice itself rides the saturated policed egress, the fold lands after
the 0.4-second window, `peek()` reads 0, and `agree()`'s 0.5..1.5 band
fails honestly about numbers that never had a chance to agree. The
forensics seal: the ONE download row that passed folded exactly one
CHUNK — server 262144, byte-for-byte the 256 KiB blob the server sends
per loop iteration — meaning that row's fold landed mid-drain with the
first chunk counted and the second still queued. The same tree, on the
unpoliced audit host, scores 37/0 with 100.0% agreement at gigabyte
scale. This is the NIGHT-improve-21 fold race (that find: the upload
counter peeked before its connection ended, "seen live once as upload
4.49 GB vs 0") with a new trigger: not scheduler starvation in a
container, but the host's own enforcement policing the measurement
rig. The engine is innocent; the verdict line was not.

## 3. The fixes

Four files, all small, all in the honesty-not-behavior direction.

- `scripts/depth/reload-test.sh` — the suppression directive extended
  to `SC2317,SC2329` with a comment recording the generation split and
  the live sighting (0.10.0 silent, a rolling build flagging SC2329
  through the standing gate on 2026-10-27).
- `scripts/supermassive/supermassive-test.py` — `agree()` gained the
  zero-fold diagnostic: when the client moved bytes and the server
  counter never folded, the row's detail now says so, names the
  fold-at-close race, points at `zelynic status` / `sudo zelynic
  u --all` / re-run, and carries the seen-live note with the date. The
  verdict stays FAIL — the numbers genuinely disagreed — but the FAIL
  now carries its cause instead of a mystery.
- `scripts/setup.sh` — the phase-2 die line no longer claims "the
  harness engine itself is broken". It now names the failing-rows
  command and the zero-fold shape with the clear-and-re-run way out.
  The old wording was the exact sentence that sent the owner hunting
  for a broken engine while their own enforcement policed the test.
- `scripts/gate-keepers.sh` — the emoji sweep's header comment and
  info line now say what the code does (working-tree-wide, tracked or
  not, new files fail before commit), and the fail path gained the
  untracked-artifact warn. No check added, none removed, no behavior
  change — five lines of truth alignment.

Process note, recorded because it recurred: the Edit tool converted
tab indentation to 8-space runs across whole hunks for the second time
(setup.sh drifted to a 66-line diff, reload-test.sh to 55 — the first
occurrence is documented in the Task-5 worklog and rode commit
b64629d before being folded). The playbook held: `shfmt -w` restored
the canonical tabs (setup.sh back to a 2-line diff, reload-test.sh to
7), and `gate-keepers.sh` — a 900-plus-line tab-indented file — was
edited through a tab-safe python patcher with single-anchor idempotence
guards instead of the Edit tool, keeping its diff at exactly the
intended lines.

## 4. The verification stack

Every touched surface re-verified on the audit host after the edits.
Syntax and static layers: `bash -n` clean on all three shell files,
`shellcheck -x` (0.10.0) exits 0 on all three — including the extended
directive, proving the dual-code form is at least a no-op on the old
generation — and `shfmt -d` reports all three canonically formatted,
which also certifies the tab restore. Python layers: `ruff check` and
`ruff format --check` pass on the harness (0.17.3, the repo's
.ruff.toml contract), `py_compile` clean. Behavioral layers: the
engine self-test re-run end to end — 37 passed, 0 failed, 0 skipped,
14.5s, with the four previously-failing rows agreeing at 100.0% and
gigabyte scale; the full gate-keepers battery — 25 passed, 0 failed,
safe to commit (the same 25-check battery the owner's transcript
counted as 23+2; optional-tool presence moves individual WARNs, not
the verdicts). The prebuilt lane is untouched by construction — no
file under `ebpf/` moved, so the manifest pin still describes the
shippable tree, confirmed by the battery's prebuilt-parity section.

## 5. The verdicts

The shellcheck gate is generation-proof: one directive suppresses both
diagnostic codes, the old generation stays silent, the new generation
stays silent, and the gate stops failing on a file that has not
changed. The emoji sweep is ruled correct-as-designed with mislabeled
prose, now relabeled; its 95 hits belong to `cosmos.log`, an untracked
owner-local artifact outside the repo's authority, and the sweep did
its fail-before-commit job by seeing it at all. The self-test's three
failures are ruled environmental with a mechanism, not a defect: the
host's own live enforcement policed the test's own loopback stream and
the fold-at-close counter lost the settle race — engine innocent at
37/0 on the clean host, and the class already carries a house name
(NIGHT-improve-21). The repo-side fixes make the next occurrence name
itself: a zero fold now prints the race, the check commands, and the
clear-and-re-run path, and the die line can no longer falsely convict
the harness. Owner-side actions, restated for the record: remove or
relocate `cosmos.log`, clear the standing enforcement with
`sudo zelynic u --all` (or inspect it first with `zelynic status`),
and re-run `./scripts/setup.sh` — phase 2 should go 37/0 on the now-
unpoliced stream.

## 6. Honest residuals

The settle window is still a sleep, not a fold barrier: a policed or
heavily loaded host can outrun 0.4 seconds, and the failure mode is
now a named FAIL rather than a pass or a false conviction — making
`settle()` wait for an actual fold-count quiescence would need open-
connection tracking in the server, which this round deliberately did
not spend. `agree()`'s band is 0.5..1.5, so a partial fold like the
74.4% row still passes; that is honest (the band exists to absorb
buffering) but coarse, and the exact-one-CHUNK fingerprint documented
here is the sharper instrument if it ever matters. The shellcheck
estate is heterogeneous across hosts and will stay that way; the
dual-code directive is the portable answer, and any future
generation-split gets the same treatment. The tab-drift tooling
incident is now twice-documented and played around both times; it
remains an upstream tool behavior, worked around by shfmt plus tab-
safe patchers rather than fixed. And `cosmos.log` itself stays the
owner's file: the repo can sweep it, name it, and refuse to commit
beside it, but only the owner can decide where it lives.

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
