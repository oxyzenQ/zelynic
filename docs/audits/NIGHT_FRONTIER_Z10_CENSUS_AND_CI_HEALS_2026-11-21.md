<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# night-frontier-Z10 — the census verdict, the seat's stand-down, and the two CI heals (the verifier census and the histogram leg)

Date: 2026-11-21. Session scope: keep watch on the red lanes the
Z10 rung-2 landing left behind, hunt beyond what the owner found,
and record the for-all tier's measured verdict honestly.

## Find 1: the verifier census priced the observer after its own session died

Run 44700704011's verifier-budget leg failed with
`price: 'observe_egress' — the kernel does not expose verified_insns`
on a kernel that exposes it. The log sequence names the bug: the
links walked at 31.249 (prog ids 7 and 8 alive), one
`os.close(master_fd)` in the census's `finally` block, and the
pricing met ENOENT at 31.263. Closing the pty master ends the
eagle-eyes monitor session, the session's Drop un-attaches the
links, and the kernel unloads the programs within milliseconds —
the test priced programs that no longer existed. The ledger's
observe pins (70/70) had been sourced from a run that won the
unload race by luck.

Fix: the master closes after teardown (scripts/supermassive/
verifier-budget-test.py). Validation: run c700864's supermassive
verifier-budget leg priced BOTH observer programs at 70/70 —
exactly at their pins, the deterministic walk the ledger's law
claims — and printed MASS-VERDICT: PASS.

## Find 2: the Verify lane's histogram leg could never produce a sample

The leg applied a 100kb cap and ran one 15s curl. The measured
transfer was 1.86 MB in 737 skbs (GRO hands the hook ~2.5 KB skbs)
and the tick records every 2^10-th packet PER CPU, so a single-CPU
path never reached one tick — zero samples was deterministic, not
unlucky. The leg B netem 300ms also stayed on the path, where the
adaptive window itself caps the wire near 100 KB/s regardless of
the applied rate (the failed run's 124 KB/s measured throughput).

Fix: the leg deletes the netem qdisc first, applies 2mb to keep the
phase bounded, and runs two 15s curls (.github/workflows/
supermassive-verify.yml). Validation: run 44877687876's Phase 1.5
read back `histogram OK: dl size samples=7 p50=4096 p95=16384
p99=16384 non-zero buckets=3`. Three lint residues on the first
patch (three comment lines over the yamllint 120-character
ceiling, a shellcheck SC2034 loop variable, and Phase 2's
`tc qdisc change` refusing on the deleted qdisc) were fixed in the
follow-up commit (`replace` creates or amends alike); the wholesale
Gate-keepers seat then passed.

## Find 3: the for-all emission tier's verdict is beyond every seatable machine — the seat stands down by measurement

The night matrix's fifth seat (the D8 for-all harness, 3x8 at
unwind 68) was killed mid-symbolic-execution TWICE on the hosted
16 GB runner (runs 44727607551 and 44876980805, both at the 24-25
minute mark, no solver verdict printed, the sibling seats alive
past minute 27). The extended census (scripts under the session's
own record; results recorded in proofs/src/kani_terminal.rs and
docs/INNOVATIONS.md's D8 section) measured ELEVEN shapes across
two machines: on the 4 GB / 2 CPU sandbox, 2x8@68, 3x4@68, 1x8@68,
2x4@36, 2x6@44, 1x4@36, 1x4@24, and the MINIMAL 1x1@16 all die in
the kernel's global OOM (dmesg: cbmc, anon-rss 3.35 GB, the
sandbox's ceiling). The measured law: the weight is INVARIANT to
the domain dimensions — the engine's own symbolic heap (the frame
vectors the emission swaps and clones, the emission buffer's
growth, the model's rows, and the panic-path machinery the direct
indexings carry), not one shrinkable circuit, is the wall.

The harness's own measured-heaviest single path was removed first
(the symbolic-length `truncate`'s slice-index panic branch; rows
are full-width now, the variable-length dimension rides the
sampled tier) and the wall held. A red that can never become a
verdict is not an honest finding shape, so the seat leaves the
proofs-night matrix until one of its named levers lands: per-loop
unwind annotations on a toolchain generation that carries them, a
behavior-preserving proof-friendly indexing form inside the
engine, or the lemma decomposition that splits the stream
conformance into per-token theorems. The theorem statement stays
in the tree; the per-push conformance evidence rides the sampled
property tier and the golden vectors.

## The session's other finds

- The first Proofs Night red was an external runner kill, not a
  solver verdict — the workflow's 300-minute budget was never the
  binding constraint.
- The Supermassive E2E run on the healed commit carried one
  cancelled shard (the archive-latest-kernel surface lane, exactly
  17 minutes in, its log ending in an Azure BlobNotFound) — one
  re-run was dispatched; if the shard re-cancels at the same wall
  time, the cap-versus-real-duration question has real numbers.

## Validation trail

- Local: `scripts/build.sh check-all -q` ALL PASSED (fmt, clippy
  `--all-features` with the ebpf prerequisites bootstrapped, 283
  tests, policy, version anti-patterns); `scripts/gate-keepers.sh`
  27 passed / 0 failed / 0 skipped with the full linter set
  installed (yamllint, actionlint, shellcheck, shfmt, codespell,
  markdownlint-cli2 at the CI-pinned 0.18.1, ruff).
- Hosted: the push batch on c700864 went green on thirteen lanes
  (Gate-keepers, Proofs, Miri, CodeQL, Security Audit, CI, Fuzz,
  netrunner-night-C77, Supermassive, Supermassive Server,
  Supermassive Container E2E, Supermassive Verify — the last with
  the healed histogram leg), and the dispatched Proofs Night on
  the healed commit seats the four Z6 theorems.

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
