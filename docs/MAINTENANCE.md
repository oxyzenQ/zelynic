<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# Maintenance Playbook (owner)

The recurring work that keeps zelynic trustworthy as critical
infrastructure. Everything here is either already automated (this doc
tells you where the automation lives and what to do when it fires) or
is a short manual ritual with a fixed procedure. Nothing on this page
requires improvising — a maintenance task that needs a decision made
from scratch is a signal to write the decision down first and only
then act on it.

## 1. Secret inventory

Four secrets carry the pipeline. Each has a defined rotation path and
a blast radius; none should outlive its purpose.

| Secret | Where | Scope | Blast radius if leaked |
|--------|-------|-------|-----------------------|
| `GPG_PRIVATE_KEY` | repo Actions secrets | the release-signing identity (master `F532 4E09 67F1 04D5 8CE0 25F3 47A5 0AEF 4B65 AAC2`) | forged release artifacts — the highest-value target in the project |
| `GPG_PASSPHRASE` | repo Actions secrets | passphrase for the signing subkey | useless without the key; still rotate together with it |
| `CRATES_IO_TOKEN` | repo Actions secrets | crates.io **publish-update** scope (NIGHT-dinner-1) | a bad crate version upload; crates.io versions are permanent — yank, never re-upload |
| `GITHUB_TOKEN` | automatic per-job | per-workflow, scoped by each job's `permissions:` block | nothing to rotate; the least-privilege `permissions:` on every job is the control |

Rotation procedures:

- **GPG pair**: the master key generates a fresh signing subkey,
  publishes it to the keyserver, and the workflow secrets are updated.
  Signatures from the old subkey remain valid forever (see
  [VERIFY_RELEASE.md](VERIFY_RELEASE.md) § signing key expiry policy).
  The weekly `gpg-key-check` job in
  [`.github/workflows/maintenance.yml`](../.github/workflows/maintenance.yml)
  warns 30 days before any subkey lapses — treat that warning as the
  rotation trigger, not a suggestion.
- **CRATES_IO_TOKEN**: crates.io Account Settings → API Tokens →
  revoke + generate. Keep the **publish-update** scope (the crate name
  exists since 2026-09-27; publish-new rights would only widen the
  blast radius). Update the repo secret in the same sitting.

## 2. Scheduled guards (what fires when, and what to do)

| Workflow | Cadence | Watches | On failure |
|----------|---------|---------|------------|
| `audit.yml` — Dragon Guard - Security Audit | weekly (Mon) 00:00 UTC | `cargo audit` (RustSec) + `cargo deny` (licenses/advisories) over the locked tree | Observation-only by design: read the advisory, decide patch-vs-accept, record the decision in the audit trail. A weekly ping is information, not an emergency (NIGHT-improve-38: the cadence matches this table's clock) |
| `codeql.yml` — Dragon Guard - CodeQL | weekly (Mon) | CodeQL security analysis of the userspace tree | Triage the alert; a confirmed finding gets a dated audit doc + a fix commit in the same task |
| `maintenance.yml` — Dependency Maintenance | weekly (Mon) | GPG subkey expiry (30-day warning), stale dependencies | The GPG warning starts the §1 rotation; stale deps get a scheduled upgrade window |

Plus the push-time guards (not scheduled, but part of the posture):
`gate-keepers.yml` wholesale on every push and PR, `ci.yml`,
`supermassive.yml`, `supermassive-container.yml`, and the three-arm
prebuilt-parity enforcement
(NIGHT-dinner-1 — commit time, publish time, release time).

## 3. The prebuilt eBPF lane (the one ritual with a hard rule)

After **any** change under `ebpf/`, the same task must also refresh the
lane:

```bash
./scripts/release/refresh-prebuilt.sh   # rebuild + restage + manifest + parity gate
git add ebpf-prebuilt/                  # commit the lane with the sources
```

This is enforced three times (commit hook, wholesale CI gate, publish
job) so the rule here is not load-bearing — the automation catches the
mistake. The doc-level rule survives because the enforcement tells you
*that* something is stale; this procedure is *what to do about it*.
Full contract: [VERIFY_RELEASE.md](VERIFY_RELEASE.md) § keeping the
prebuilt objects fresh.

## 4. Release procedures

**Routine release** (the only path that should ever run): bump the
version in `Cargo.toml`, commit, tag `vX.Y.Z`, push the tag. The
Release workflow builds the four-legged matrix, signs, checksums,
publishes the GitHub Release; the crates.io workflow waits for both CI
lanes on the exact SHA and publishes the registry tarball. The asset
inventory tripwire (NIGHT-dinner-3) fails the release loudly if
`dist/` does not hold exactly 4 tarballs + 12 checksums + (0 or 4)
signatures — an asset-less release can no longer ship green.

**Recovering a broken release** (the incident classes that have
actually happened, with their procedures):

- *Asset-less or wrong-asset release* (beta.3/beta.4 class, see
  [audits/RELEASE_ASSET_REGRESSION_2026-09-27.md](audits/RELEASE_ASSET_REGRESSION_2026-09-27.md)):
  land the workflow fix on `main`, verify CI green, then move the tag
  to the fixed commit (`git tag -f vX.Y.Z <sha> && git push origin vX.Y.Z`).
  The Release workflow re-runs against the fixed YAML and **upserts**:
  same-named assets are replaced, the body regenerates. Precedent: the
  v11.0.0-alpha.1 re-tag. Never delete the release — the upsert keeps
  download URLs stable.
- *Bad crate version on the registry*: `cargo yank --vers X.Y.Z`
  immediately, then fix forward on a new version. crates.io never
  deletes versions and never accepts a re-upload of the same number —
  the yank is the whole remedy.
- *Compromised signing key*: rotate (§1), re-sign the current release
  via the re-tag procedure, and publish the fingerprint change in the
  release notes + the keyservers before anything else.

**After any re-tag**: re-run the full
[VERIFY_RELEASE.md](VERIFY_RELEASE.md) verification battery on the
healed release — checksums, GPG, `zelynic -V`, and `zelynic doctor`
(the `Build:` line must name the flavor and lane of the freshly built
binaries).

## 5. Toolchain and dependency upkeep

- The **eBPF nightly pin** (`EBPF_TOOLCHAIN` in `build.rs`,
  `nightly-2026-09-18` at the time of writing) and the **bpf-linker
  pin** (0.11.1) move deliberately, never on a whim: both are pinned
  because the object build must be reproducible (a forced rebuild on
  2026-09-27 produced byte-identical objects). Moving either is a
  refresh-prebuilt + full-matrix release event, not a maintenance
  commit. The reasoning lives in [STABILITY.md](STABILITY.md).
- `Cargo.lock` moves with every dependency change, `--locked`
  everywhere; `deny.toml` is policy, not documentation — a denied
  advisory needs either a patch or an explicit policy amendment.
- The pinned light tools that gate the repo locally (shellcheck,
  shfmt, yamllint, codespell, actionlint, ruff) re-pin via
  `scripts/gate-keepers.sh` — the wholesale run prints the pinned
  versions it expects.
- The **CI action pins** heal at commit time — the contract's one
  automatic seat (NIGHT-improve-39's final form, fixup 3): the
  weekly server-side lane (`self-heal.yml`) is retired together
  with its `SELF_HEAL_PAT` push credential, because a standing
  Workflows-write PAT is exactly the secret the owner refused to
  carry. `scripts/gates/check-actions-pins.sh` (NIGHT-improve-40),
  wired through the `.githooks/pre-commit` gate, reads the pins'
  freshness on every commit of a wired clone — advisory by default
  (a remote fact the network may not reach is never a block),
  verdict cached in `.git/zelynic/` keyed on the workflows'
  content with a 6h TTL, classifications MAJOR/MINOR/PATCH in the
  report, strict an opt-in (`git config
  zelynic.actionsHealthCheck strict`), and `auto` the one-step-
  further opt-in (NIGHT-improve-40 fixup 1): a current verdict
  exits with zero output, and a clean-behind verdict re-verifies
  cold (a cached behind is a read, not a write mandate), runs the
  sweep's `--apply` itself under `ZELYNIC_ACTIONS_HEAL_TIMEOUT`
  (default 60s), stages `.github/workflows/` into the index, and
  fails the commit once — review `git diff --cached`, re-commit,
  and the re-commit reads the healed pins as current and stays
  silent; no auto-amend, no push, and every failed or partial
  apply restores the tree from a pre-apply backup before falling
  back to the advisory table (the sweep's `guard_diff` cannot
  arbitrate a pre-commit heal by design — it compares the whole
  tree against HEAD and would flag the contributor's own staged
  work — so the auto path proves the same discipline with
  pre/post snapshots of what actually changed). The heal stays on
  demand and human-carried when wanted:
  `scripts/ci/actions-version-sweep.sh --dry-run`
  prints exactly what a heal would move, `--apply` performs it,
  and the healed pins are committed like any other change (the
  hook re-reads the healed tree; the push rides the contributor's
  own credentials). What the sweep refuses to touch (the
  `@stable` pins, pins ahead of latest, non-version refs) is
  listed in the script's header with the reason for each rule.
  The honest trade: a quiet repository's pins age until the next
  contributor commit — and they age loudly, not silently (a
  scheduled lane goes red on a truly broken pin; GitHub keeps old
  major tags working for years, so age is not rot).

## 6. Docs hygiene

The [README index](README.md) is the map; keeping it honest is cheap
and pays every long-break return. When a doc changes purpose or a new
doc lands, the index gets the same commit. The
[CLAIMS_VERIFICATION.md](CLAIMS_VERIFICATION.md) ledger is the deeper
discipline: any *claim* (a number, a "fastest", a "zero") that appears
in public-facing text must have a verifying mechanism recorded there —
a claim without a ledger entry is a bug in the docs.

## 7. Cadence summary

| Every | Do |
|-------|----|
| push | nothing manual — the gate battery runs itself |
| weekly (Mon) | read the CodeQL + security-audit + dependency-maintenance results; rotate the GPG subkey if the 30-day warning fired |
| monthly | skim `git log -- docs/` for purpose drift; re-run `./scripts/gate-keepers.sh` once on the dev machine (re-arms the commit hook if the clone moved) |
| per release | the §4 routine; the §3 ritual whenever `ebpf/` moved in the cycle |
| quarterly | full sandbox validation matrix ([SANDBOX.md](SANDBOX.md)), a fresh dated audit doc recording the state of the project, and a stale-secret review (§1) |
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
