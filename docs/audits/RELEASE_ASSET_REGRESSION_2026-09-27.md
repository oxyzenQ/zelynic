<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# Release Asset Regression — v11.0.0-beta.3 / v11.0.0-beta.4

> Incident date: 2026-09-27. Resolved same session (NIGHT-dinner-3).
> Status: fixed, healed, verified. The regression window is exactly
> the two tags; every release before beta.3 shipped its full asset
> set.

## 1. The report and the reality

The owner reported that the v11.0.0-beta.4 release page carried "only
2 files" — the auto-generated source archives — and no binary
packages. The live API confirmed worse: **both** v11.0.0-beta.3 and
v11.0.0-beta.4 had shipped with **zero assets**. The last healthy
release was v11.0.0-beta.2 (20 assets: 4 tarballs, 4 detached GPG
signatures, 12 checksum files across SHA-512 / BLAKE2b / SHAKE256).

Both "Dragon Guard - Release" workflow runs had concluded **green**
while attaching nothing. A green pipeline that ships an asset-less
release is the worst failure class a release workflow can have: every
downstream trust signal (the badge, the email, the tag push
notification) says healthy, and only a human opening the release page
finds the empty shelf.

## 2. Root cause (from the live logs, not from theory)

The beta.4 Create GitHub Release job log (run 36299494146), in order:

```
06:15:51.06  Found 4 artifact(s)
06:15:51.28  ... 4 × "Starting download of artifact to: .../dist"
06:15:52.03  Total of 4 artifact(s) downloaded
06:15:52.17  Deleting the contents of '/home/runner/work/zelynic/zelynic'
06:15:56.95  (release body generated)
06:15:57.06  [thinking-face emoji] Pattern 'dist/*' does not match any files.
06:15:58.94  [thinking-face emoji] dist/* does not include a valid file.
```

(The original log lines carry softprops' thinking-face emoji prefix;
the emoji is replaced here — the repo's emoji sweep gate applies to
docs quoting logs too.)

The step order in the release job was: **Download artifacts →
Checkout release tooling → Generate body → Create Release**. The
"Checkout release tooling" step (added by NIGHT-blade-11, which moved
the release body to `scripts/release/generate-release-notes.sh` via a
sparse checkout) runs `actions/checkout@v5` with its default
`clean: true` — and on a workspace that holds files but no `.git`,
checkout **deletes the workspace contents** before `git init`. The
wipe landed exactly on the freshly downloaded `dist/`: four artifacts,
each digest-verified by the download action seconds earlier, destroyed
before the publish step could see them.

`softprops/action-gh-release` then evaluated `files: dist/*`, matched
nothing, and logged its thinking-face warning lines **as warnings** —
the action's
documented behavior is to succeed without assets unless told
otherwise. The release published. The pipeline stayed green. Nobody
was told.

beta.2 never hit this because its release job had no checkout step at
all (the body was rendered inline); the regression entered with the
blade-11 step insertion and manifested on the next two tags.

## 3. The fix (three arms, one per escape route)

Landed in `.github/workflows/release.yml` (commit 75efe6b, same
session):

1. **Step order** — checkout now precedes the artifact download. The
   checkout wipes an *empty* workspace; `dist/` survives to publish.
2. **Inventory tripwire** — a new "Assert release asset inventory"
   step between download and publish asserts the exact legal shape:
   4 tarballs (the build matrix legs), each with its three checksum
   siblings, and GPG coverage that is either 0 (secret unconfigured)
   or 4 (all-or-nothing per the build job's signature tripwire). Each
   violation is named with the precise missing file. The workflow, not
   a third-party action, defines what "assets present" means.
3. **Seatbelt** — `fail_on_unmatched_files: true` on the publish
   action: the unmatched-glob-as-warning path is structurally
   unavailable even if someone later edits the glob.

Self-test battery (local, before push): happy path (4/4/12 verified),
the exact beta.3/beta.4 shape (empty `dist/` → loud failure), partial
GPG coverage (2/4 → loud failure), and missing-checksum (collected
with the GPG violation in one run, matching the gate-keepers
"collect both failures" discipline).

## 4. The heal (beta.4 re-tag)

Tag-triggered workflows read their YAML from the tag's commit, so
re-running the broken runs or dispatching on the old tag ref would
have re-run the broken pipeline. The only correct heal was moving the
tag to a commit carrying the fixed workflow:

- `v11.0.0-beta.4` re-pointed from `a27f49f` to `9ab5eb3` (precedent:
  the v11.0.0-alpha.1 re-tag). Same version, same `Cargo.toml`, same
  eBPF objects — the parity gate re-ran green inside every build leg.
- The Release workflow re-ran against the fixed YAML and **upserted**
  the existing release: 20 assets attached, body regenerated, release
  URLs stable.
- The crates.io lane re-triggered and its idempotency probe held:
  *"zelynic 11.0.0-beta.4 is already published on crates.io - nothing
  to do."* No double publish, by design.
- The re-created tag object is **unsigned** (the signing key is
  owner-only; CI secrets sign artifacts, not tags). Artifact
  authenticity rides on the CI-signed `.asc` files either way. The
  owner may re-sign at leisure:
  `git tag -sfa v11.0.0-beta.4 -m '<message>' && git push -f origin
  v11.0.0-beta.4` (idempotent: the workflow re-runs and the upsert
  replaces same-named assets).
- beta.3 was **not** healed: it is superseded by beta.4 hours later,
  and healing it would only churn the changelog boundary. The same
  re-tag procedure works if ever wanted.

## 5. Post-heal verification (the full battery, executed live)

Against the healed v11.0.0-beta.4 release, on a host with AVX2 and
AVX-512:

| Check | Result |
|-------|--------|
| Asset count | 20 of 20 (4 tarballs, 4 `.asc`, 12 checksums) |
| SHA-512 (`sha512sum -c`) | 4/4 OK |
| BLAKE2b (`b2sum -c`) | 4/4 OK |
| SHAKE256 (64-byte, Python) | 4/4 OK |
| GPG detached signatures | 4/4 **Good signature** — "Rezky Cahya Sahputra (cosmic dragon)", primary fingerprint `F532 4E09 67F1 04D5 8CE0 25F3 47A5 0AEF 4B65 AAC2` matches [VERIFY_RELEASE.md](../VERIFY_RELEASE.md) |
| Tarball invariant | flat 3-file layout (zelynic, LICENSE, README.md) 4/4 |
| v3-gnu execution | `zelynic -V` — Build: `linux-amd64-v3-gnu (9ab5eb3)`, eBPF objects: source-built |
| v4-gnu execution | ran **live on AVX-512** (a stronger proof than the CI leg, which verifies v4 without executing it) |
| v3-musl / v4-musl | `ldd`: statically linked; `doctor --print-json` well-formed |
| Doctor build flavor (NIGHT-dinner-3) | `Build: FULL-LIFE (eBPF objects: source-built)` on the text surface; `build_flavor: "full-life"`, `ebpf_lane: "source-built"` in JSON |
| crates.io | 11.0.0-beta.4 published 2026-09-27T06:19:29Z, not yanked; re-tag run skipped upload via probe |

## 6. What this incident teaches (the durable lessons)

1. **A green pipeline is a statement about steps, not outcomes.** The
   gap between "the workflow succeeded" and "the release has its
   assets" was exactly one warning line nobody read. Every
   publish-adjacent step needs an assertion of the *postcondition*,
   not just a zero exit code — the same philosophy as the tarball
   invariant and the signature-coverage tripwires already in the build
   jobs.
2. **Third-party actions need their sharp edges pinned down.**
   `softprops/action-gh-release`'s unmatched-glob warning is
   documented, friendly, and in this pipeline's shape, catastrophic.
   `fail_on_unmatched_files` existed the whole time.
3. **Step order in a shared workspace is a data-flow contract.**
   actions/checkout's workspace wipe is invisible in the YAML and
   total in effect. Download-after-checkout is now structural; the
   tripwire holds the line if order ever drifts again.
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
