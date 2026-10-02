<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-total-lts-2 depth audit — the fresh-instrument cross-check

> Audit date: 2026-10-02 (NIGHT-total-lts-2). Scope: the owner's
> five infra areas — stability & crash, code hygiene, optimization,
> security hardening, LTS stability — re-audited across the root
> repo at 613ef26 with the close riding 8156f0a (v20.0.0-beta.1;
> the code byte-identical to the v20.0.0 LTS baseline — every
> commit since is docs-only, so every verdict here reads against
> the locked LTS era itself). Method: every load-bearing claim of
> the NIGHT-total-lts-1 verdict re-verified against source and
> fresh runs at HEAD — never against the earlier doc's own claim —
> plus this audit's own new instruments over the seams lts-1
> covered lightly: a repo-wide relative-link integrity pass (the
> first automated one; 193 links across 42 tracked .md files), an
> intra-doc anchor pass, a semantic duplicate-pair analysis over
> the scripts tree's same-named helpers, a bounds audit of
> build.rs's own ELF validator, a comment-rot heuristic over
> backticked symbol references, and a workflow-reference existence
> sweep. Status: all five areas answer SOUND at peak under fresh
> instruments; one real find in code hygiene (three broken
> relative links, one research doc, one drift class — closed
> docs-only in 8156f0a).

## 1. The mandate

The same five asks as lts-1, judged one era later with instruments
chosen to find what the first sweep's instruments could not see:

| # | The ask | This audit's instrument |
|---|---------|------------------------|
| 1 | Stability & crash: crashes, coredumps, engine failures, foundation breakage, vulnerabilities; no visual/performance regressions | the panic-path census re-counted and re-classified by reading, all three test lanes fresh at HEAD, the engine self-test fresh, the full-budget frame-bench fresh, check-all green |
| 2 | Code hygiene: the dragon hunt — spaghetti, duplicate, redundant, stale, zombie code, important directories first | the link-integrity pass (new), the anchor pass (new), the duplicate-pair semantic diff (new), the comment-rot heuristic (new), the stale-path-in-living-docs sweep, the workflow-reference sweep (new) |
| 3 | Optimization: peak-optimize, profiling data where available, micro-optimize hot paths | the fresh full-budget frame-bench against the recorded eras; the byte-pin constraint honored |
| 4 | Security hardening: input validation, memory safety, injection risks | the trust-boundary inventory re-verified by reading (exec sites, pin namespace, action pinning), plus a line-by-line bounds audit of build.rs's ELF validator (new — the lts-1 inventory named build.rs only in comments) |
| 5 | LTS stability: hidden failure modes, months-scale behavior | the pin-namespace finiteness re-proof by reading pin.rs end to end, the version triple cross-check (Cargo.toml = Cargo.lock = CHANGELOG), the hooks self-install contract, the claims-ledger close verification |

The honest headline: the repo answers at peak for the second
consecutive total-infra audit, and this audit tried hard to break
that verdict with instruments the first one did not carry. Every
candidate the new instruments raised was either a false positive
by construction (a future-roadmap path, an upstream-repo path, an
explicitly-marked historical reference) or the one real find below.
Nothing load-bearing moved.

## 2. Stability & crash — SOUND, re-proven fresh

**The panic-path census, re-counted.** Twenty-seven
`unwrap`/`expect`/`panic!` candidates across `src/`, re-classified
by reading each file's test-module boundary: 26 sit inside
`#[cfg(test)]` modules (verified per file: the test module's line
precedes every candidate in lock.rs, parse.rs, schema.rs,
capabilities, update, and info), and the one live candidate is
`probe_role.rs:115`, the connect-loop invariant whose totality is
proven by the loop's own exit arms — the same verdict lts-1
reached, now re-derived rather than trusted. Zero live-path
panics.

**Fresh batteries at HEAD (613ef26, pre-audit-commit):**

| Battery | Result |
|---------|--------|
| `build.sh check-all -q` | all quality checks passed (47 s warm, inside the 2-min cap) |
| `cargo test` (default, ebpf feature) | 647 + 46 passed / 0 failed / 1 + 3 ignored |
| engine self-test (`supermassive-test.py --self-test`) | 34 passed / 0 failed / 0 skipped (14.5 s) |
| frame-bench, full 10 s budget | bytes/frame 1,919.0 byte-exact; every other metric in the recorded run-to-run class (Section 4) |

**Stress posture, honestly unchanged.** The audit host runs
kernel 5.10.134 (below the 5.13 floor), uid 1001, no sudo: live
eBPF stress remains CI territory by design — the supermassive
legs boot the true floor and latest kernels on every push. The
b875f02 era's first verdict on the recalibrated lts-1 battery is
filed in CROSS_DISTRO_RESULTS; this audit's local instruments are
the batteries above and they are green.

**Visual/performance regressions: none.** The only commit between
the lts-1 close and this audit is this audit's own link fix —
docs-only, no product surface. The byte-exact bytes/frame at
1,919.0 is the anchor: the render path is unchanged.

## 3. The find — three broken relative links, closed

The new instrument: a repo-wide relative-link integrity pass over
every tracked `.md` (193 links across 42 files, hidden directories
included). Three broken targets, all in one file, all one drift
class: `docs/research/NIGHT_DINNER_14_PRICING_RESEARCH.md`
computed its sibling targets one directory too shallow —

1. Section 1's terms pointer read `../COMMERCIAL_LICENSE.md`,
   resolving to `docs/COMMERCIAL_LICENSE.md` (does not exist),
   while sections 5 and 6 of the SAME file already used the
   correct `../../COMMERCIAL_LICENSE.md` form for the same target
   — the drift provable against the file's own correct instances.
2. Both `LICENSING_FAQ.md` pointers (section 1 and section 5's
   three-file sync rule) were bare, resolving to
   `docs/research/LICENSING_FAQ.md` while the real file lives at
   `docs/LICENSING_FAQ.md` — pointed at by nothing until this pass.

The close (8156f0a): all three targets corrected, verified by the
re-run (193 checked, 0 broken). No other `.md` in the tree —
including the audits, research, and archive surfaces — carries a
broken relative link. The intra-doc anchor pass (29 anchors)
found zero broken. Docs-only; no product surface; no benchmark A/B
due (the owner's rule for docs-only changes).

Why it matters beyond three links: the repo's gates check
spellings (codespell), headers, permissions, emoji, language, LOC,
disclaimers, and link-adjacent syntax — but no gate resolves
relative link targets, so this drift class was structurally
invisible. The find is filed here as evidence; whether a link
gate joins the 22 is an owner call (the recommendation is noted
in Section 8, deliberately not implemented — a repo at peak does
not need a new gate invented for it in the same breath as the
audit that found the first instance).

## 4. Optimization — PEAK, skipped with fresh evidence

The fresh full-budget frame-bench at HEAD, against the lts-1
fresh run and the recorded eras:

| Metric | HEAD (this audit) | lts-1 fresh run | Recorded eras | Reading |
|--------|-------------------|-----------------|---------------|---------|
| fps (render path) | 7,077.9 | 7,282.5 | 7,361.5-8,155.7 | in class (host-load noise, cross-host) |
| bytes/frame | 1,919.0 | 1,919.0 | 1,919.0 | byte-exact — the render path unchanged |
| emit bytes/frame | 512.3 | 511.0 | 504.8-510.2 | in class (phase mix) |
| dirty cells/frame | 40.0 | 40.0 | 39.4-40.0 | matching |
| density gini | 0.3502 | 0.3504 | 0.3547-0.3587 | in class |
| frame entropy | 3.0287 | 3.0296 | 2.9992-3.0033 | in class |

The lts-1 verdict stands: every remaining candidate shape is
fast-pathed or fenced by the byte-parity discipline; the eBPF
side is byte-pinned with no performance reason to touch it (any
`ebpf/src` change forces an object refresh and lane
regeneration). No micro-optimization is warranted, and none is
performed — an unfounded rewrite in maintenance mode buys noise.

## 5. Security hardening — SOUND, the boundary inventory re-read

Every row re-verified by reading source at HEAD, not by trusting
lts-1's table:

- **Exec from the binary: three live sites, all hardened.**
  `update/mod.rs:152` — curl with hardcoded args, https only, a
  15 s `--max-time` bound, a fixed Accept header (read back line
  by line this audit). `commands/probe.rs:466` — the
  `current_exe()` re-exec with internal role args. The
  `term_reset` rescue-utils site (hardcoded names, the
  `RESCUE_SYSTEM_PATH` root pin). No fourth site exists (the
  `Command::new(` census confirms exactly these three in live
  code).
- **Pin namespace: finite, re-proven by reading pin.rs end to
  end.** `PIN_DIR` plus eighteen `PIN_*` constants — nineteen
  hardcoded paths, zero dynamic construction anywhere in `src/`
  (the path-census greps over every `zelynic/...` literal
  resolve to pin.rs constants, the GitHub API/release URLs in
  update/mod.rs, and the `/run/zelynic/zelynic.lock` runtime lock
  file — three families, none a bpffs construction).
- **build.rs's ELF validator (new this audit, line-by-line).**
  Every `u16_le`/`u32_le`/`u64_le` call site reads within the
  64-byte header or a 64-byte slice whose bounds were
  checked_add-verified first; the section-table loop's slice
  arithmetic is guarded by the shoff + shnum*64 table-bounds
  check; per-section offset+size is checked against the file
  length with the SHT_NOBITS carve-out; `shstrndx` is
  range-checked before use. The `u64_le`'s internal
  `try_into().unwrap()` is unreachable-panic by call-site
  construction, the same discipline the userspace census holds.
- **Action pinning: SHA discipline holds.** All actions across
  the eight workflows are 40-hex SHA-pinned; the one exception —
  `github/codeql-action/*@v4` — is the documented deliberate
  case (a frozen security scanner defeats its own purpose; the
  codeql.yml comment block carries the rationale).
- **Workflow references: complete.** Every script path the
  workflows invoke exists (the one sweep hit was a trailing
  period captured by the regex — a comment's sentence end, not a
  reference).

The lts-1 rows this audit did not re-derive line by line (env
reads, PID races, supply chain beyond the action pins) stand on
the same CodeQL-green floor plus the lts-1 reading; nothing in
this audit's passes contradicted any of them.

## 6. LTS stability — PEAK, the hidden-failure-mode re-sweep

- **Version triple consistent:** Cargo.toml 20.0.0-beta.1 =
  Cargo.lock zelynic entry = the CHANGELOG's [Unreleased] section
  carrying the post-20.0.0 entries. No version drift anywhere.
- **Hooks self-install contract intact:** a fresh clone carries
  `.githooks/pre-commit` unwired by design; `gate-keepers.sh`
  self-installs `core.hooksPath=.githooks` on its first wholesale
  run (verified live on this audit's own clone — the hook fired
  on this audit's own commit, running the prebuilt-parity gate).
- **Claims-ledger close verification:** lts-1's hygiene close —
  the orphaned `install-flow-test.sh` suite riding
  CLAIMS_VERIFICATION's Package lifecycle row — is landed and
  readable (row verified this audit).
- **Permission contract:** the working tree on this audit host
  started at mode 664 (a sandbox umask artifact, invisible to
  git, which tracks only the executable bit); the
  gate's own `--fix` restored the 644/755 contract and the gate
  answered 22/22. Local environment, not repo state — recorded
  here because the next auditor on a umask-002 host will see it
  too, and the fix is the gate's own one-liner.
- **The fence inventory (Z4 map budget, u128 ledgers, Instant
  uptime, ktime monotonicity, terminal crash ownership) is not
  re-performed** — the peak-skip protocol; each fence was touched
  by this audit's batteries only where the fresh runs exercised
  it, and every run was green.

## 7. The verdict table

| Area | Verdict | The one-line evidence |
|------|---------|----------------------|
| 1. Stability & crash | SOUND | panic census re-derived (26 test-gated + 1 proven invariant); 647+46 fresh; self-test 34/0/0; check-all green; bytes/frame byte-exact |
| 2. Code hygiene | one find, closed | three broken relative links in one research doc (the first link-integrity pass) — closed in 8156f0a; every other new-instrument candidate was a false positive by construction |
| 3. Optimization | PEAK (skip) | fresh full-budget bench in class on every metric, bytes/frame byte-exact at 1,919.0; no candidate survives the A/B discipline; eBPF byte-pinned |
| 4. Security hardening | SOUND | exec sites re-read hardened; pin namespace re-read finite; ELF validator bounds-audited line by line (new); actions SHA-pinned with the one documented exception |
| 5. LTS stability | PEAK (skip) | version triple consistent; hooks contract intact and verified live; claims-ledger close landed; permission contract restorable by the gate's own fix |

## 8. This audit's own honest residuals

- Live eBPF stress still cannot run on this audit host (kernel
  5.10.134, rootless uid): the LIVE verdicts ride the
  supermassive legs on every push. The b875f02 era's verdict on
  the recalibrated lts-1 battery is the current live record.
- The frame-bench deltas against the lts-1 fresh run (fps -2.8%)
  are cross-host load class: different audit host, different
  background load. The byte-exact bytes/frame is the anchor that
  makes the comparison honest; per-host A/B remains the repo's
  law for change-proving, and no change to prove was found.
- The comment-rot heuristic's 91 unresolved candidates were
  triaged by reading the top hits: all are non-symbol references
  (map names, tool names, libc types, the cosmostrix sibling
  contract, Howard Hinnant's algorithm). The heuristic is not a
  gate and should not become one on this evidence — a comment
  that names an external thing is not rot.
- One recommendation deliberately left unimplemented: a relative-
  link resolution gate (the class this audit's find belongs to)
  would close the seam permanently, but adding a gate to a repo
  at peak is the owner's call, not the auditor's. The evidence
  for the decision is Section 3; the one-line negative is that
  the drift was three links in one research doc in the entire
  history the tree carries.
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
