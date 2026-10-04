<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# NIGHT-hunt-32: the scripts disease audit — harness-vs-reality drift swept out of every lane (2026-10-04)

The owner's mandate: audit every script in the tree so the repo "does
not catch the disease again", and confirm peak stable LTS. The
disease is not one bug — it is a family this session already met four
times, each time wearing a different coat:

* **S1, the misdiagnosed skip reason** — a check cannot run and its
  message names the wrong cause. proof-claims.py once blamed
  "kernel < 5.1" when kernel.bpf_stats_enabled was simply boot-OFF
  (healed in 5d81e46); check-actions-pins.sh told anonymous callers
  "retry after the quota resets" when their 60/h ceiling can never
  reach the 70-call floor (healed in 4cfaa27).
* **S2, the structurally dead path** — code that cannot succeed on a
  default machine no matter how many times it is retried.
* **S3, the tool-parity blind spot** — a gate that warns-and-skips
  where the author sits while CI enforces it with a pinned tool
  (rustfmt, ruff 0.16.8, shfmt v3.10.0, shellcheck v0.10.0 — four
  incidents this session).
* **S4, the stale claim** — a comment or output line asserting a
  number or fact that no longer matches reality (the "1000 req/h"
  header vs the live 5000/h PAT read).

The audit swept all 55+ scripts under scripts/ in four lanes: three
parallel read-only passes (owner-facing infra/release, CI-coupled,
rig-harness) plus a self-audit of the enforcement layer (gates/,
gate-keepers.sh, proof-claims.py). Every finding below was verified
against live source before any heal was written; one agent claim died
in verification (the reload-test curl traffic IS inside the policed
cgroup — siblings share it — the drop-read bug was the column, not
the topology).

## The headline findings (ranked by what they did to the truth)

**1. crash-recovery-test.sh was dead on every machine ever built.**
`$PIN_DIR` was referenced eight times and defined nowhere — the
NIGHT-hunt-21 dedup moved the helpers into harness_lib.sh without
moving the constant, and the suite's own `set -euo pipefail` killed
every run at Test 1 ("PIN_DIR: unbound variable"). Eight of nine
tests never executed anywhere. Worse: had the suite ever run, its
"enforcing"/"Stale" greps match strings the status surface never
prints (display.rs says "no active limits" and "stale bpf pin files
detected"), and every apply targeted the comm `curl` with no curl
process alive — dinner-11's no-match hard error, discarded via
`2>/dev/null`, so every verdict would have failed for the wrong
reason. Healed: PIN_DIR now lives in harness_lib.sh (pin.rs's
constant, the python lib's twin), a long-lived sleep target carries
the applies, the greps ride the display contract, and a trap cleans
up.

**2. endurance-test.py could never PASS on HEAD.** The pin-family
set-equality expected 13 members while the live attach surface pins
26 (the loader pins every map — 22 — beside the 2 programs and 2
links; the rig's own output says "26 pinned object(s)"). The family
grew; the set did not. And the group-round proof was doubly dead:
`strict-multi "cg:A:cg:B"` — the multi grammar splits on every colon
(safety.rs), so the shape parsed as a bogus process named `cg` and
the atomic preflight aborted every group round at resolution. Healed:
the 26-member set re-derived from pin.rs + the loader, the numeric
ids form `f"{cg_a}:{cg_b}"`, and the exhaustion story now names its
real oracle (fresh quasi-random group ids against the 256-slot group
maps — single rounds rewrite fixed keys, so the 1024 caps were never
the exhaustible surface the docstring claimed).

**3. benchmarking.py printed measurements it never made.**
bench_stress pgrep'd for a zelynic process every second against a
one-shot CLI that had already exited — the samples stayed empty and
the summary printed "RSS: max=0KB", "CPU: max=0.00%" as facts.
bench_concurrent waited on five parallel strict-singles and counted
every one as a successful op — four of five are fast flock refusals
(non-blocking lock, EWOULDBLOCK is a hard error), so "ops/sec"
measured rejection latency. bench_memory read `bpftool prog show`
with no tool guard: an absent bpftool printed "BPF programs: 0" as a
kernel fact. The docstring promised "BPF map sizes" via a function
that was never called and could not parse its own output. Healed: the
stress window now measures what is true (enforcement liveness per
sample, the zero-daemon fact measured via exact-name pgrep, system
CPU from /proc/stat — the docstring's original promise — and pin
stability), admission and refusal are counted apart, bpftool absence
is a loud skip, the dead function is gone, and the binary rides the
shared resolver's version gate.

**4. race-condition-test.sh had three verdicts that could not fail.**
Test 1 blamed the lock for an absent curl target. Test 2's pass
condition (`CRASHED -le 5`) was a tautology — CRASHED counts exactly
five waits — and it counted graceful refusals as crashes. Test 3
called log_pass in BOTH branches while grepping capitalized strings
the surface prints lowercase. Healed: a real target, signal deaths
(rc >= 128) counted apart from graceful refusals, and a state check
that can fail.

**5. ammsp-vs-legacy-test.py violated its own docstring.** "A file
that exists but does not execute is a hard FAIL, not a skip" — the
code SKIPped and exited 0, and through supermassive-init's
`[ -x ]` + exit-code guard a broken-but-executable staged binary
read as "AMMSP vs legacy ... PASS" in CI: the one-sided delta proof
the harness exists to forbid. Healed: an existing-but-unhealthy
candidate (explicit, env, /opt staging, or fetched) returns the
hard-FAIL marker and the harness exits 1 with re-staging hints; the
loud SKIP survives only for the nothing-found case, exactly where
the docstring draws its line.

**6. version-to.sh — the release-blocking false OK.** The README lane
printed "OK README.md → vN (badge + example)" unconditionally while
today's README carries no badge, no release URL, and no Version line
for any of the four patterns to match: a claimed rewrite that never
happened, in the exact tool the owner runs for the v20 cut. Healed:
the lane probes for a version surface first and reports honestly
either way.

**7. supermassive-test-v3.py missed the family's binary gate.** The
total-lts-4 heal that closed the stale-decoy hole for v4 (its own
comment describes the exact hole) never reached v3: /opt outranked
fresh repo builds with no version gate, and a vanished binary made
stages 3/4's "refuses clean" rows read PASS over a CLI that never
ran. Healed: the shared resolver with its version gate, ordered so
`--self-test` still runs green on a binary-less host (the CI smoke
lane's shape — verified live in this audit's sandbox).

**8. reload-test.sh read the wrong column and passed either way.**
The drop read took awk field $5 of a status row — the UPLOAD-RATE
number, because the "cg:ID (comm)" label shifts every field left of
it — and Test 4's verdict called log_pass in both branches. The
suite also depended on external example.com traffic and cleaned up
with a loose `pkill -f`. Healed: drops come from the status JSON's
limits[].bytes_dropped (display_json.rs, the stable contract), the
verdict fails honestly when no drops occurred, and the traffic source
is a loopback blob server — self-contained like the rest of the
family, killed by PID.

**9. install-bpf-linker.sh could save an error page as the archive.**
`curl -sL` without `-f`/`--retry` (the bootstrap twin carries both)
let a 404/5xx land in the tarball with exit 0; the extraction ladder
ran inside an if-context that suppresses errexit, so a failed
decompression fell through to `return 0` and the honest FAIL never
fired — the script died later as a raw `install: cannot stat`. The
asset was also hardcoded x86_64. Healed: the twin's curl contract
mirrored, every ladder leg fail-closed, the arch case from
bootstrap, and an empty-download guard.

**10. setup.sh's menu gave advice that cannot work.** `sudo
./scripts/package/install.sh` — install.sh refuses sudo outright in
source-build mode. The correct form is `./scripts/package/install.sh
--system` (internal escalation); uninstall's line matched its own
usage ("run WITHOUT sudo") after the fix.

## The smaller heals, in one breath

harness_lib.sh gained the repo anchor and a bash version gate (the
python twin's NIGHT-improve-16 discipline: a stale decoy build is
refused, and the build remedy names the living bootstrap flow, not
the retired `cargo build --release` path); smoke-cli.sh's `--help`
extracted a Usage: block its own header never carried (it silently
printed nothing and exited 0 — remaining drift in the very file
b51d9bf healed) and its leak row counted the bpffs ROOT (foreign
pins false-FAIL on shared hosts) instead of the product's own pin
dir; wait-for-ci.sh's empty-jobs read now separates a failed fetch
(opaque — block) from a genuinely jobless run (infra — re-run);
refresh-prebuilt.sh dies on an unreadable toolchain channel instead
of writing `toolchain = ""` into the manifest's provenance;
uninstall.sh treats an unreadable pin dir as pins-present (the safe
direction) instead of silently skipping the kernel-enforcement
guard; build.sh's tally uses `failed=$((failed + 1))` (the
`((failed++))` form returns 1 at zero and only survived inside the
`if main` errexit suppression — refactor-fragile), a failed
`rustup target add` no longer prints "Rust toolchain ready", and a
missing rustfmt/clippy component is named as itself instead of a
formatting/lint verdict; frame-bench.py diagnoses absent cargo in
one line and its quick flag now owns the env var (an exported
QUICK=1 used to relabel every full run); bootstrap-ebpf.sh's "~100
MB" download claim met the CDN's actual ~27 MB, and the .profile
evidence requires an ACTIVE export line, not a commented-out
mention; the "every push" CI claims in v4.py/v4.sh/supermassive-
init.sh now say "every push that touches the Rust/scripts surface"
(ci.yml is paths-filtered); v2.py's known-options list carries the
phase flags it accepts, the phase banner says 1/6, and its
docstring states the real preflight-then-server order; v1's
KNOWN_FLAGS carries the blade-4 phase flags; v3.py's timeout comment
cites the walker's real bounds (depth 32, visits 4096 — pathwalk.rs);
zelynic-sandbox.sh's requirement list drops host-side curl and the
--smoke line calls the smoke battery what it is; install.sh's
pre-built scenario no longer claims the release pipeline assembles
the layout; limiter-depth-test.py's overhead skip names its real
constraint (the 900gb non-binding clamp, not the 1 TB/s parser
ceiling), the kernel-span ladder carries a 6.16 rung (6.12 "newest
LTS generation" contradicted KERNEL_LTS_LINES three rows apart),
and vanished verdict rows now record SKIPs with reasons instead of
silently not appearing; proof-claims.py's stage_pure_ebpf comment
states that claim 1's limit is live at stage entry, and
stage_footprint's attach child drains via DEVNULL (a PIPE that was
never read was a theoretical >64KB deadlock).

## Verified NOT diseases (so nobody re-flags them)

install.sh:37 and uninstall.sh:278's hardcoded nightly pins are
gate-enforced twins (check-rust-version-sync.sh fails CI on drift);
generate-release-notes.sh is clean end-to-end (self-test green, its
budget layering consistent with release.yml's independent tripwire);
every build.sh tool-absent warn names the true cause and a working
fix (honest S3, by design); version-to.sh's Cargo.lock stale-WARN is
backstopped by crates-io.yml's tag==Cargo.toml gate; the
supermassive engines' enforcement proofs read zelynic's own status
JSON — no sibling shares the 5d81e46 run_time_ns disease, and no
never-drained pipe exists anywhere the lanes looked.

## Deliberately left, documented here

v3.py's kind node-name override is CI-shape-specific and fails loud
elsewhere; install-flow-test.sh's third resolution policy is
loud-only (no silent wrong result); supermassive-init.sh's
SKIP-labeled row counting as a FAILURES probe is fail-loud by
design; rootfs-pack.py fetches its base over plain HTTP with no
checksum — an observation, not a disease: no text claims
verification there (the contrast with the legacy binary's sha512
discipline is worth a future hardening pass, not this audit).

## Verification

The shell quad at CI-pinned versions (shfmt v3.10.0, shellcheck
v0.10.0 with -x) is clean across all 18 touched .sh files; ruff
0.16.8 format + check clean across all 10 touched .py files; the
engine self-test battery is green end to end — proof-claims 23/23,
ammsp 12/12 (including the resolver-shape pin), supermassive v1
34/34, v2 10/10, v3 PASS on a binary-less host (the CI smoke
lane's exact shape), v4 PASS. The rig-only suites (crash-recovery,
race, reload, endurance, benchmarking) carry the falsifiable
corollary of this audit: they were dead or lying before, so on the
owner's next nightpc run each should either PASS or fail with a
reason that names its true cause — the one behavior the disease
family never allowed.
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
