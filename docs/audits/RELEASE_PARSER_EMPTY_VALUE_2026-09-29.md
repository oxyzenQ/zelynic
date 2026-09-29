<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# Release Body Parser Regression — the v11.0.0 stable publish

> Incident date: 2026-09-29. Resolved same session (NIGHT-dinner-26).
> Status: fixed, healed, verified. The regression window is exactly
> one run — the v11.0.0 stable publish (Dragon Guard - Release run
> 36586939180); every release before it, including rc.1/rc.2/rc.3
> hours earlier the same day, published normally.

## 1. The report and the reality

The owner reported that the v11.0.0 stable release — the first stable
cut after the whole v11.0.0 release candidate series — failed its
"Dragon Guard - Release" pipeline. The "Create GitHub Release" job
died eleven seconds in, at the release body step, with:

```
scripts/release/generate-release-notes.sh: line 115: 2: --since-stable needs a value
Error: Process completed with exit code 1.
```

No release was published, no artifacts were attached. The step had
passed its own guard milliseconds earlier — the generator's
`--self-test` answered `OK release-notes generator: classifier
battery + shape contract` and then the very next command in the same
step died. The battery was green while the pipeline was red: nothing
in the battery exercised the CLI parser, and the parser was the part
that was broken.

## 2. Root cause (from the live log, reproduced locally first)

The error line is the exact diagnostic shape of bash's `${2:?word}`
parameter expansion: `script: line N: 2: word`. That expansion kills
the script when the parameter is unset **or null** — a
present-but-empty string argument is rejected exactly as hard as a
missing one. All seven flags in the parser used it.

The workflow step (release.yml, "Generate release body") passes every
flag unconditionally with quoted `"${VAR}"` values — by design, the
same design that its own comment records for the tag filtering: "no
previous tag is a legal state, not an error". For a **stable**
release the computation is:

- `PREV_TAG` = nearest previous **stable** tag (pre-releases
  skipped),
- `LAST_STABLE` = the same filter — identical by construction,
- therefore `SINCE_STABLE` stays empty (its guard requires
  `LAST_STABLE != PREV_TAG`, and for a stable release they are the
  same tag).

So every stable release reaches the generator with
`--since-stable ""` — a legal state, the state that means "no
distance to render" — and the parser answered it with a usage error.
Reproduced locally byte-for-byte before any edit; the same
`${2:?}` rejection also kills two more legal states that simply have
not fired yet:

| CLI shape | Flags carried empty | Legal meaning | Verdict before the fix |
|---|---|---|---|
| Stable release (the v11.0.0 live incident) | `--since-stable` | LAST_STABLE == PREV_TAG, no distance line | dies, line 115 |
| Initial release (documented in USAGE) | `--compare-json`, `--prev-tag` | no compare API response, no previous tag | dies, line 103 |
| Pre-release cut before any stable tag | `--last-stable`, `--since-stable` | no stable tag exists yet | dies, line 111 |

The USAGE header of the generator itself already documented the
contract for one of these: `--compare-json ... Absent or empty =
initial release`. The parser contradicted the file's own documented
interface.

Why the whole rc series passed: a pre-release's `PREV_TAG` is the
nearest previous tag of **any** channel, which differs from
`LAST_STABLE` whenever a stable tag exists — so `SINCE_STABLE` was
always a real number through rc.1/rc.2/rc.3, the expansion never saw
an empty value, and the bug stayed invisible until the first stable
cut switched the code path.

## 3. The fix (a two-class value contract, parser-side only)

Landed in `scripts/release/generate-release-notes.sh`
(NIGHT-dinner-26, one commit with this audit):

1. **Parser contract.** The seven flags split into two classes.
   Required-value flags (`--tag`, `--prerelease`, `--repo-url`) keep
   the `${2:?}` guard — no legal empty tag, channel, or repository
   URL exists. The four boundary flags (`--compare-json`,
   `--prev-tag`, `--last-stable`, `--since-stable`) now require the
   value to **exist** (`[ $# -ge 2 ]`: an argument follows the flag)
   but accept an empty one; the empty value flows on to the render
   layer, which already treats it as "feature absent"
   (`render_body`'s guard chain renders no dual-range line without
   it, and the initial-release marker without a compare file).
   A missing value is still a usage error for all seven flags.
2. **Zero workflow changes.** The workflow's unconditional quoted
   flag passing is the intended design; the script is what honors
   its own documented contract now.
3. **Self-test pin (the coverage gap closed).** The battery's shape
   probe called `render_body` directly — bypassing the parser, which
   is exactly how the v11.0.0 stable publish fell through. A new
   parse-contract probe re-executes the script itself through the
   real CLI path with every optional flag present-but-empty (the
   initial-release shape), asserting exit 0 and the initial-release
   marker. The OK line now reads `classifier battery + shape +
   parse contracts`.

Local battery before push, all green after the fix: the exact
v11.0.0 stable shape (single range line, no since-stable), the
initial-release shape, the pre-release-without-stable shape, the
rc-series shape (dual range line still rendered — the path every
prior release took, kept as a regression probe), a genuinely missing
value (still a usage error), plus `bash -n`, shellcheck 0.10.0 and
shfmt 3.10.0 clean.

## 4. The heal (the v11.0.0 re-point)

Tag-triggered workflows read their YAML and their checked-out
tooling from the tag's commit, so neither re-running the red run nor
dispatching on the old tag ref would pick up the fixed script — the
same geometry the beta.4 heal recorded. (Dispatching on `main`
computes `TAG="main"` and fails tag validation instead.) The only
correct heal was moving the tag:

- `v11.0.0` re-pointed from `84dc100` (the release commit) to the
  NIGHT-dinner-26 fix commit — same version, same `Cargo.toml`,
  unchanged `src/` (the fix is release tooling only), so the
  validate/build legs re-run their contracts unchanged. Precedent:
  the v11.0.0-alpha.1 and v11.0.0-beta.4 re-tags.
- The push-triggered run carries the fixed generator in its sparse
  `scripts/release` checkout, and softprops/action-gh-release
  publishes (the earlier run failed before any release object was
  created, so this is a clean create, not an upsert).
- The fix commit itself lands in the v11.0.0 changelog range
  (PREV_TAG..TAG grew by one commit) — honest and visible, filed
  under its classifier verdict.

## 5. What this incident teaches (the durable lessons)

1. **A documented contract must be the enforced contract.** The
   generator's own USAGE said "Absent or empty = initial release"
   while the parser rejected empty as hard as missing. Any place
   where docs and code disagree is a latent red pipeline with a
   delay fuse — the fuse here was "the first stable cut".
2. **Test the boundary you expose, not the function you refactored.**
   The self-test pinned `render_body`'s output shape while the
   pipeline's real entry point was the CLI. A probe that runs the
   real invocation path (this fix's parse contract) costs one
   subshell and catches the class.
3. **`${var:?}` conflates "missing" with "empty".** For an interface
   whose legal states include empty values, presence and
   non-emptiness are two different assertions — `[ $# -ge 2 ]` is
   the presence assertion, and the empty value is a fact to hand
   downstream, not a usage error.
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
