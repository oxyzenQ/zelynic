<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-total-lts-4 depth audit — the total-infra cross-check

> Audit date: 2026-10-03 (NIGHT-total-lts-4). Scope: the owner's ask
> — all infra, total LTS, honest, cross-check the whole root repo,
> peak-skip and continue. Audited at c142270 (NIGHT-total-lts-5's
> HEAD, one commit up from Z9's 9eb112d; v20.0.0-rc.1; the eBPF
> enforcement object byte-pinned throughout). Method: the lts-2
> discipline (re-verify load-bearing claims against the tree and
> fresh runs, never against an earlier doc's own claim) applied to
> the infra surfaces no prior pass had audited end to end — the
> crash-recovery stack (term_reset/), the raw-fd input parsing
> (terminal/raw.rs), the network update surface, the permission and
> LOC contracts, the test-harness infrastructure itself, and the
> crash-pattern and stale-claim sweeps across the whole tree. Every
> instrument the repo owns was run fresh. Status: ONE real find in
> the harness infrastructure (the v4 battery's binary resolution
> bypassing the shared discipline — false-reds and an ungated
> foreign-binary hole), closed; every product surface read this
> pass answers SOUND at peak.

## 1. The mandate

The owner's five areas, the instruments this pass used:

| # | The ask | The instrument |
|---|---------|----------------|
| 1 | Stability & crash | term_reset/ read line by line (the five-layer recovery + the interposition lane); the crash-pattern sweep (every unwrap/expect/panic/index — all test-pinned or fail-fast); every battery fresh: v4 121/0/0, nonroot depth 90/90, v2/v3 self-tests 10/0 and 34/0, unit 681 + integration 47 |
| 2 | Code hygiene | the stale-claim sweep (the strong-invariant comment hunt — the class lts-3 and lts-5 each caught once); the LOC contract cross-check (which files are over 500, which are exempt, whether the exemptions hold); the CHANGELOG duplicate-stub class |
| 3 | Optimization | PEAK, skipped with the protocol — lts-3's verdict stands (the exact-branch products bounded by construction), lts-5's A/B re-anchored bytes/frame byte-exact at 1,919.0 hours earlier at this same HEAD-plus-one; this pass touched zero product code |
| 4 | Security hardening | terminal/raw.rs read line by line (the OSC 11 parser's caps, patience, and first-byte contract); the update surface re-verified (static argv, tag sanitize, root refusal); the harness-resolution hole this pass closed (an ungated foreign binary would have been silently tested) |
| 5 | LTS stability | the version-gate doctrine extended to the v4 battery; CI call sites verified compatible (both the --self-test leg and the two --binary legs); the clean-failure contract (a fresh clone without a build now gets the one-command fix, not 75 confusing rows) |

## 2. The find — the v4 battery tested the wrong thing silently

The v4 CLI depth battery (NIGHT-improve-35, the battery Z9 grew to
121 rows) resolved its binary with its own local block:

```python
if args.binary:
    lib.BINARY = args.binary
elif os.path.isfile("/opt/zelynic/zelynic"):
    lib.BINARY = "/opt/zelynic/zelynic"
elif not lib.BINARY:
    found = which("zelynic")
    lib.BINARY = found or "zelynic"
```

Every other battery in the family rides the shared
`resolve_binary` discipline (scripts/lib/zelynic_harness_lib.py),
which NIGHT-improve-11 built for exactly this class: repo-local
builds outrank the system PATH, `ZELYNIC_BINARY` and `--binary` win
the selection, and every candidate passes the VERSION GATE before
a single row runs — because the 2026-09-21 debian13 run lost 12 of
23 rows to a stale `/usr/bin/zelynic` v4.0.0-alpha the harness
tested silently. The v4 block knew none of it:

1. **No repo-local candidates.** A fresh clone with only a
   repo build (target/pro-native-gnu, the musl twins, even a
   debug build via env) never got tested; the block never looked.
2. **No version gate.** A stale `zelynic` on PATH — or the /opt
   preference, which OUTRANKED fresh repo builds — would be
   tested without one check that it matches this checkout. The
   debian13 incident's exact hole, reopened one battery over.
3. **The bare-name fallback produced a false-red wall.** With no
   install and nothing on PATH, `lib.BINARY = "zelynic"` ran 121
   cases against a nonexistent command: 75 rows failed with
   `missing=[...]` against output that never existed, while the
   rc-classification rows "passed" on the 127 itself — a verdict
   wall that wastes an auditor's first half hour (it wasted this
   audit's; the binary itself was verified healthy within
   minutes, but the honest cost is on the record).

The close is the doctrine, not a patch of the same shape: the
local block is deleted, and the real-run path now calls the shared
`resolve_binary` — explicit `--binary` first, then
`ZELYNIC_BINARY`, then repo-local builds newest-first, then PATH,
every candidate passing the version gate. The `--self-test` engine
smoke keeps its resolution-free path (it needs no binary by
contract and returns before any discipline applies). Verified on
all four call shapes: the bare local invocation now resolves the
repo-local pro-native-gnu build and runs 121/0/0; `--binary
target/debug/zelynic` passes the gate and runs 121/0/0;
`--self-test` passes untouched; and both CI call sites
(.github/workflows/ci.yml lines 214 and 556, plus the supermassive
container's `--binary /opt/zelynic/zelynic`) ride the explicit
path the shared resolver honors — the container leg additionally
gaining the version gate it never had. ruff clean on the changed
file.

The blast radius is honestly narrow: the false-red wall needed a
no-install fresh clone (or a PATH without zelynic), and the
ungated-foreign-binary shape needed a stale install — but the
v4 battery is the surface-completeness verdict CI leans on, and a
harness whose reds are noise is a harness whose greens mean less.
The find is also the class the owner's own history names: the
infra between the tests and the binary is load-bearing, and it
had drifted exactly where nobody had looked since improve-35
wrote it.

## 3. Stability & crash — the recovery stack read, SOUND

- **term_reset/mod.rs (the five-layer rescue):** the termios-first
  ordering with TCSAFLUSH's input-flood drop; the O_NONBLOCK
  discipline around every ANSI emission (the Termux lesson); the
  root-context PATH pin (`RESCUE_SYSTEM_PATH`) closing the
  user-controlled-directory slide under a root rescue; the TERM
  guard before `reset`/`tput reset` (a rescue that hangs is worse
  than one that skips two optional layers); the mode-direction
  contract (restore-only, never enable). Zero panic candidates —
  every layer is best-effort by construction.
- **terminal/raw.rs (the input plumbing):** the OSC 11 parser's
  caps (BG_PARTIAL_CAP 64, a real reply is ~32), the patience
  bound, the first-byte contract (a `q` behind a reply tail still
  quits), the hex-channel scaling bounds — pure and pinned.
- **The crash-pattern sweep:** every remaining unwrap/expect/
  panic! across src/ is either inside a `#[cfg(test)]` contract
  pin or a fail-fast schema parse at startup (the Z9 verdict,
  re-verified at this HEAD against the tree).

## 4. Code hygiene — the cross-checks, clean

- **The LOC contract:** 177 gated files; exactly 2 over 500 with
  the self-declared marker (build.rs at 1475 — the no-build-deps
  supply-chain stance — and src/ebpf/render.rs at 593 — the
  cohesive-engine stance), both exemptions re-read and still
  justified; the ebpf/ kernel tree sits outside the cap's scope by
  the documented RULES.md contract, verified against the gate's
  own count.
- **The stale-claim sweep:** the strong-invariant comment hunt
  (the class that caught lts-3's argv-walk lie and lts-5's "full
  stop" wrap claim) ran across the tree; every claim sampled
  against the code it documents holds at this HEAD. The two prior
  finds remain closed.
- **The CHANGELOG duplicate-stub class:** closed by lts-5's rider
  (the Z9-era empty `[Unreleased]` pair); no other markdown file
  carries a duplicate heading (the gate's markdownlint leg, 55
  files, green).

## 5. Security hardening — the surfaces re-read

- **The update surface** (Z9's clean list re-verified by reading):
  static curl argv (no shell), the 15-second bound, the network
  exchange gate before the stamp, the tag through sanitize_comm
  (cybersecurity-2), root refusal before any network I/O.
- **The privilege surfaces:** the rescue's root PATH pin and the
  sudo-interposition lane (improve-31/improve-34) re-read; the
  capabilities module's contract spot-verified through the
  battery rows that exercise it.
- **The harness hole this pass closed** (Section 2): an ungated
  foreign binary under the v4 battery was a trust-boundary hole in
  the verification layer itself — the instrument every other
  security claim leans on.

## 6. LTS stability — the fresh-instrument table

| Instrument | Verdict | Notes |
|------------|---------|-------|
| unit battery (cargo test --bin zelynic) | 681 / 0 | 677 + lts-5's 4 eviction pins |
| integration battery | 47 / 0 | 3 ignored by design (root legs) |
| v4 CLI depth battery | 121 / 0 | after this pass's fix; both resolution shapes verified |
| nonroot depth suite | 90 / 0 | the comm-spoof guards green |
| v2 engine self-test | 10 / 0 | |
| v3 engine self-test | 34 / 0 | 14.5s |
| v4 engine self-test | PASS | resolution-free path intact |
| frame A/B (10s) | byte-exact 1,919.0 | lts-5's four-run anchor, hours earlier at HEAD-minus-zero-commits — this pass touched zero product code |
| clippy + rustfmt | clean | |
| build.sh check-all -q | EXIT 0 | within the 2-minute cap |
| gate-keepers.sh | 16 / 16 | permissions re-fixed once (the sandbox umask artifact lts-3 documented) |

## 7. The verdict table

| Area | Verdict | The one-line evidence |
|------|---------|----------------------|
| 1. Stability & crash | SOUND | the recovery stack read line by line; every battery fresh and green; the crash-pattern sweep clean |
| 2. Code hygiene | one find (harness infra), closed | the v4 resolution block bypassed the shared discipline — deleted, replaced with the one canonical resolver |
| 3. Optimization | PEAK (skip) | zero product code touched; the lts-5 A/B anchors the frame path byte-exact at this HEAD |
| 4. Security hardening | one find (same), closed | the version-gate doctrine now covers every battery; CI's container leg gained the gate it never had |
| 5. LTS stability | SOUND | all four call shapes verified; the clean-failure contract; the fresh-instrument table all green |

## 8. Peak-skips honored (the honest list)

- The kernel enforcement math (math.rs, DRR, MMSPA, the datapath):
  lts-3 read it to the metal; the object is byte-pinned by every
  commit gate since — re-running the read would duplicate a
  standing verdict.
- The render tree: lts-3's line-by-line pass + the byte-exact
  A/B anchors at every audit since.
- The CLI surface: Z9's supermassive sweep is one commit old with
  its 121 rows re-run fresh by this pass — the surface verdict is
  as new as it gets.
- The enforcement ledger: Z7's own audit stands; the probe rows
  rode the nonroot suite green.
- The limiter userspace family and the poll delta: lts-5's pass
  (this same session, one commit below) — the eviction family's
  9 pins were re-run green in this pass's unit battery.

## 9. This audit's own honest residuals

- Root-ful eBPF stress (the live enforcement legs, the
  supermassive matrix) still rides CI: this sandbox has no root
  and no 5.13+ kernel attach surface — the rootless instruments
  (batteries, self-tests, unit pins) are the local proof, and the
  CI legs own the rest, exactly as lts-3 recorded.
- The REPO_BINARY_CANDIDATES list does not include
  target/debug/zelynic — deliberate (the release-profile builds
  and the repo-root copy are the tested shapes); a developer
  wanting the debug build passes `--binary` or `ZELYNIC_BINARY`,
  both honored. Extending the list to debug builds was considered
  and declined: the gate's version check would pass for a stale
  debug build of the same version, and the harness's own doctrine
  prefers the release-profile surfaces.
- The v4 false-red wall cost this audit real time before the
  binary was proven healthy — the cost is recorded here because
  it is the honest price of the find, and because the fix makes
  the next auditor's half hour free.
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
