<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-zen-lts-2 audit — the all-infra pass at the v35 tree

> Audit date: 2026-11-18 (night-zen-lts-2). Scope: all
> infrastructure — the 17-workflow CI estate, the 35-job runtime
> cap surface, the 27-gate local battery, the four-lockfile supply
> chain, the scripts tree, and the docs estate's cross-references —
> audited at the night-zen-lts-1 tree plus this round's fixes.
> Method: every standing instrument re-run live in this seat (the
> wholesale battery, check-all, the four advisory scans, the deny
> doors, the parity lane), every cron and cap re-censused from the
> YAML, the delta since the last all-infra audit cross-checked
> against the docs that describe it. The honest boundary, stated
> once: this seat's GitHub credential authenticates git-HTTP but is
> rejected by the REST API (401 both schemes), so the runner's
> verdicts are taken from the public commit-checks pages — the same
> records, fetched without auth; the API-rate-limit split is a seat
> fact, not a repo defect.

## 1. The evidence run (live, this seat)

| Instrument | Verdict |
|---|---|
| `scripts/gate-keepers.sh` (wholesale) | **27 passed, 0 failed, 0 skipped** — the shell quad (bash -n, shellcheck, shfmt, source resolution), yamllint, actionlint, TOML, codespell, markdownlint, SPDX headers, permission guard, LOC caps, parity, index coverage, runtime caps, and the rest all green; the audit's first run showed 3 skips (shellcheck/shfmt/actionlint "not installed") that were a PATH artifact — the tools live under `~/.local/bin` and the full battery closed all three |
| `scripts/build.sh check-all -q` | exit 0 — clippy `-D warnings` over the workspace (the [lints] deny riding every invocation), the repository policy checks, the version-anti-pattern sweep over 153 source files |
| `cargo test --features ebpf --locked` | **1,158 passed + 74 integration, 0 failed** (1,232 green; 4 ignored by design) |
| `proofs/` suite | 23 passed, 0 failed |
| `cargo audit` × 4 lockfiles | clean — root 51, `proofs/` 51, `fuzz/` 12, `ebpf/` 28 crate dependencies, exit 0 on all four |
| `cargo deny check` | advisories ok, bans ok, licenses ok, sources ok — the 14-ban wall (5 policy + the nine-name supply tripwire) intact |
| prebuilt parity | green on the refreshed lane (the tree pin counts comments; see the sibling audit's find) |

## 2. The CI estate — censused from the YAML, not remembered

17 workflows; **35 jobs, every one capped, none below the
10-minute floor** (the runtime-caps gate's own verdict, re-verified
from the YAML by the gate). **17/17 top-level `permissions:`**
blocks, **17/17 `concurrency:`** groups. **7/7 scheduled lanes on
the one clock** (`7 3 * * dow` = 03:07 UTC = 10:07 WIB —
supermassive-verify daily, proofs-night daily, maintenance/audit/
fuzz/codeql Monday, miri Sunday): the night-consistent-1 clock
uniformity holds at HEAD. Every `uses:` is SHA-pinned with ONE
documented exception — codeql-action rides its moving tag on
purpose (codeql.yml's own comment: tracking the current analyzers
IS the scanner's value; "Every other action in this repo is
SHA-pinned" is that comment's claim, and §3's find 3 is what made
it true again). The checkouts carry `persist-credentials: false`
and the harden-dns composite rides the networked jobs. The pins
health gate (upstream currency, advisory mode) ran green in the
battery.

## 3. The finds — three stale references, all fixed here

1. **The quota-saver's schema pin spoke v30 in the present tense**
   (docs/QUOTA_SAVER_PHYSICS.md, the "The schemas" evidence bullet):
   "`SCHEMA_VERSION` 30 and the contract history" — five versions
   behind HEAD's 35, the v31-v35 run (measured-RTT retune, sk-storage
   hint, measured-srtt telemetry, the depth histogram pair) having
   landed after the page was written. Fixed: the bullet now says 35
   at this writing and names the v31-v35 run, with the whole walk's
   canonical record pointed at `ebpf/src/schema_ledger.rs` (tell it
   once).
2. **The maintenance table's audit row predates the supply-1 scan
   expansion** (docs/MAINTENANCE.md): "cargo audit + cargo deny over
   the locked tree" — the advisory scan has run over ALL FOUR
   committed lockfiles since night-supply-1; the row's scope phrase
   was the one surface that didn't catch up. Fixed: the row now
   names the four lockfiles and keeps deny's root-tree scope
   accurate.
3. **One checkout rode a moving tag against the repo's own law**
   (.github/workflows/supermassive-verify.yml:74):
   `actions/checkout@v4` — the only unpinned `uses:` outside
   codeql's documented exception, contradicting the codeql comment's
   "every other action is SHA-pinned" one workflow over. Fixed: the
   same SHA pin every sibling checkout carries
   (`3d3c42e5aac5ba805825da76410c181273ba90b1`, v7, NIGHT-hunt-20),
   `persist-credentials: false` already in place.

## 4. The peak-skips — named, with the reason each holds

- **Dependency chain**: 6 direct dependencies (anyhow, aya, blake3,
  clap, libc, nix) for the whole tool, 51 lockfile crates, zero git
  dependencies, zero [patch] sections, the deny wall and the four
  advisory scans standing. Nothing to trim, nothing to pin tighter.
  PEAK.
- **Schedule estate**: the one-clock law holds everywhere it is
  spoken (7/7 crons, the maintenance table's rows, DEPENDENCY_AUDIT's
  cadence note, CROSS_DISTRO's dispatch note); the retired-schedule
  mentions that name old clocks (supermassive.yml's NIGHT-reject-1
  retirement record) are records, not claims. PEAK.
- **Docs index coverage**: gate-enforced both halves (every tracked
  audits/ doc and every docs-tree page must carry its row — the
  gate ran green in the battery). The stale-reference class is the
  audits' instrument (this round's three finds are exactly it);
  the coverage class is the gate's. PEAK.
- **Scripts tree**: ~150 shell/python files under the strict quad +
  ruff + codespell, all green in this seat. The delta's new scripts
  (provenance words generator, forensic sim, harness lib additions)
  pass the same gates they ride. PEAK.
- **Secrets posture**: the token resolution is runtime-only
  (`scripts/lib/github_token.sh`'s resolve chain), no standing
  secret in the tree, checkout persistence disabled, the pins
  health gate's own preflight documenting the token-rejection shape
  this seat actually met. PEAK.

## 5. The verdict table

| Area | Verdict | Note |
|---|---|---|
| Gate battery | GREEN, live | 27/27 in this seat, the three PATH skips closed |
| Build + clippy | GREEN, live | check-all exit 0, the deny lint riding |
| Tests | GREEN, live | 1,232 green (lib + integration), proofs 23 |
| Supply chain | GREEN, live | 4 lockfiles clean, 14 bans intact, deny 4 doors ok |
| CI estate shape | PEAK | caps, permissions, concurrency, one clock, SHA pins (one documented exception) |
| Stale references | 3 FOUND, FIXED | the schema pin, the audit row's scope, the one unpinned checkout |
| Dependency chain | PEAK | 6 direct / 51 crates / zero git / zero patch |
| Docs index | PEAK | gate-enforced coverage, both halves |
| Scripts tree | PEAK | quad + ruff + codespell green live |

The infra estate is at the masterclass bar after the fixes: every
instrument this seat can run ran green, and the three finds were
the documented class (words behind the tree), not behavior.

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
