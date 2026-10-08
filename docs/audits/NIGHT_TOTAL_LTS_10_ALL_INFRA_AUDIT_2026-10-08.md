<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-total-lts-10 depth audit — the all-infra pass, round three

> Audit date: 2026-10-08 (NIGHT-total-lts-10). Scope: the owner's ask
> — depth audit focused on all infra, total LTS, honest; cross-check
> the whole root repo, peak-skip and continue. Audited at 44abe20
> (lts-11's tree, post 9b2b1d6). Method: the infra delta since lts-8's
> read point (hunt-35's help masterclass CI surface, hunt-36's two
> live-lane closures, hunt-37's born-red needle + QUIC rootfs staging +
> capacity law + pressed-bucket law v2 + the under-band re-probe
> rider, hunt-38's pins) read fresh with the false-green lens — a CI
> estate's defect class is not "red" but "red that lies" — plus the
> empirical legs this host can reach: the live CI verdicts pulled
> from the runner itself, the matrix's self-test battery fresh, and
> the machine gates re-run. Status: ZERO new defects — but this
> round's value is the verification that closed the loop the audits
> only read before: the three born-red supermassive legs are GREEN
> ON THE RUNNER (all four workflows green at 9b2b1d6, the first
> post-fix tree), the self-test's 37 engine laws pass fresh (the
> pressed-bucket law included, with the exact a11b8b1 shapes as
> fixtures), and every machine gate stands. The instruments and the
> evidence are on the record.

## 1. The mandate

The owner's ask: all infra, total LTS, honest; cross-check the whole
root repo; peak-skip and continue. The instrument table:

| # | The ask | The instrument this audit used |
|---|---------|-------------------------------|
| 1 | Stability & crash | the CI verdicts pulled live from the runner (the GitHub Actions API, this session's own credential): Supermassive, Gate-keepers, Supermassive Container E2E, CI — all four completed `success` at 9b2b1d6, the first post-fix tree; the Rust battery green fresh at HEAD (837 + 53 / 0 failed, the lts-11 leg); check-all green locally; gate-keepers 17/17 after the working-tree permission artifact (the clone's umask 664) was corrected to the tree's own 644/755 law |
| 2 | Code hygiene across the root repo | the zombie-file hunt over the delta (every new file verified wired: check-audits-index.sh in gate-keepers, QUIC_SERVER_SCRIPT driving the lane, all three new test files `#[path]`-mounted); the link sweep (65 docs, zero broken markdown references, resolver relative to each doc); the backtick-path sweep (the eight newest audit docs, zero stale code paths); the audits index 42/42 machine-gated complete |
| 3 | Optimization | no infra hot path in the delta (the CI scripts run on the runner; the local gate-keepers pass sits at the minute scale it always has); the self-test battery fresh at 14.5 s — the matrix's own engine floor unchanged |
| 4 | Security hardening | the new python read with the injection lens: `spawn_bg_in_cgroup_path` passes argv as a list behind `exec "$@"` (quoted, no shell interpolation of argv; the script's only interpolated token is the internally-constructed cgroup path); the QUIC lane's TLS is a throwaway self-signed pair scoped to 127.0.0.1 inside the CI VM with `verify_mode` 0 documented in place ("proves attribution, not identity"); the rootfs staging law (a staging failure FAILS the leg; the import is verified twice — before and after pip's purge) |
| 5 | LTS stability | the pressed-bucket law's SKIP discipline read at the verdict level (every SKIP carries its numbers — contention named, never a silent green); the v3 headroom law rides the PRECISION_ADAPT_MARGIN family's own constant (one family, one constant, both sides self-test-pinned); the index-coverage gate now machine-enforces the institutional-memory map at every push |

## 2. The empirical leg — the born-red fix verified on the runner

The a11b8b1 incident's three red legs (the best-specs gnu/musl and
low-specs gnu supermassive runs) were hunt-37's charter; the rider
v2 (the pressed-bucket law) landed at 9b2b1d6. Every prior audit
READ the fix; this round pulled the runner's own verdict:

| Workflow | head 9b2b1d6 | Verdict |
|---|---|---|
| Dragon Guard - Supermassive | completed | success |
| Dragon Guard - Gate-keepers | completed | success |
| Dragon Guard - Supermassive Container E2E | completed | success |
| Dragon Guard - CI | completed | success |

All four green on the first post-fix tree — the fix's own CI run,
not a later coincidence. The 44abe20 (lts-11) runs were still in
progress at read time; its tree is docs-only against a green base
(the commit gate's prebuilt-parity check passed at commit time
locally, the same hook CI runs).

## 3. The false-green hunt — the CI estate's real defect class

A CI estate can lie in two directions: red that convicts the
innocent (the a11b8b1 class, closed) and green that certifies
nothing (the skip-that-hides class). This round read the new
verdict logic for the second class:

- **The pressed-bucket law** (`realnet_under_band_reprobe`): an
  under-band window whose arrivals never pressed the floor's scale
  SKIPs — but the SKIP is a RECORD with every number attached (the
  measured rate, the window's own arrivals, the floor's scale, the
  re-probe's verdict, the contention verdict named), never a silent
  stand-down. A PRESSED window keeps the FAIL when the path feeds
  (enforcement guilty), and the over-band side never re-probes at
  all. The law guards false-RED by design and cannot manufacture
  false-GREEN: the rows that prove enforcement (the loopback lanes,
  the drops proofs, the ledger budgets) never ride the realnet
  re-probe.
- **The QUIC connections row** (the hunt-36 residual, closed):
  five-gate verdict arithmetic — the ledger ceiling
  (`(N+1) x (live x rate + burst) x 1.08`), the scale floor 2.5
  (the cookie-collapsed lane caps at 1.60 — so the floor proves
  every CID its own bucket), the per-connection cap measured
  against EACH client's own handshake lag, the per-connection
  floor, and the span-bounds pathology check. Any client failure,
  any unreadable ledger, any staging failure FAILs the row; the
  lane without the client stack SKIPs with the pip hint — and the
  CI rootfs staging law makes that skip impossible on the runner
  (the import check runs inside the assembled rootfs, twice).
- **The v3 headroom law** (proof-claims.py): the certification
  demands the same 25% headroom the adaptation itself designs in
  (`PRECISION_ADAPT_MARGIN`, one family, one constant) — a
  converged-but-sagging fleet's line-touch (+2.4-2.6%) reads
  offer-limited, not enforced; both sides pinned by the self-test
  with the exact a11b8b1/bd8de0e shapes as fixtures.

The self-test battery, fresh: 37 passed, 0 failed, 0 skipped
(14.5 s) — including the pressed-bucket law's own engine rows (the
a11b8b1 legs' real numbers as fixtures: the three red legs' arrivals
never pressed, the floor's scale does).

## 4. The hygiene leg — the root repo cross-checked

- **Zombies**: every delta file verified wired (the gate script in
  gate-keepers, the QUIC server script driving its lane, the three
  new test files `#[path]`-mounted in their modules, the audit docs
  indexed). Zero orphans.
- **Stale references**: 65 docs swept, zero broken markdown links
  (the resolver runs relative to each doc's own directory); the
  eight newest audit docs swept for backtick code paths, zero
  stale.
- **The institutional memory**: the audits index 42/42 complete,
  machine-enforced by the coverage gate at every push (the lts-8
  recipe, now standing law).
- **Permissions**: the working tree's clone artifact (umask 664)
  corrected to the tree's own 644/755 law by the gate's own fixer —
  a working-tree correction only; git tracks the exec bit and the
  committed state never changed (the status verified clean before
  commit).

## 5. The verdict table

| Area | Verdict | Note |
|---|---|---|
| CI estate (the four workflows) | GREEN, verified live | the runner's own verdicts at 9b2b1d6; the born-red class closed on the record |
| The supermassive matrix's new verdict logic | SOUND, read whole | the false-green hunt above; every SKIP a record, every FAIL fast |
| The QUIC rootfs staging | SOUND | fail-fast on the runner, import verified twice, pip purged (the ~10 MB rides the cpio) |
| The gates (index coverage, permissions, commit gate) | GREEN | 17/17; the prebuilt parity lane passed at commit time |
| The python scripts' syntax/compile | CLEAN | py_compile on all three; bash -n on the shell gates |
| The self-test engine battery | GREEN | 37/0/0 fresh, 14.5 s |
| Docs estate | CLEAN | zero broken links, zero stale paths, index complete |
| The Rust battery | GREEN | 837 + 53 / 0 failed fresh at HEAD (the lts-11 leg) |

## 6. This audit's own honest residuals

- The live eBPF legs (crash-recovery, race, reload, endurance,
  limiter-depth, the VM matrix's enforcement rows) remain CI-owned
  — this rootless cgroup-v1 host cannot attach an observer or build
  the VM; the runner's green verdicts stand in as the empirical
  instrument, which is exactly the estate's own division of labor.
- The 44abe20 runs were in progress at read time; the docs-only
  delta against a green base plus the locally-passed commit hook
  (the same parity check CI re-runs) is the honest expectation, to
  be confirmed by the owner's next look at the runner.
- The actions-pin health check reported its standing skip (the API
  ceiling 60/h cannot cover the 70-call cold-sweep floor without a
  GITHUB_TOKEN export) — a known, documented residual of the commit
  gate, not a defect this round introduced or can close rootlessly.

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
