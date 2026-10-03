<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# NIGHT-hunt-Z11: the release-body verification cap (2026-10-03)

The owner's ask, verbatim: "zelynic NIGHT-hunt-Z11. missing this on
release page both stable/pre-releases after release v20 rc.2" — followed
by the expected Verification block (the GPG recv-keys command, the
`gpg --verify` example, the expected `Good signature from "Rezky
Cahya Sahputra (cosmic dragon)"` line, and the link to
`docs/VERIFY_RELEASE.md`). The verdict up front, honestly: **the
Verification section was never "removed" — it was silently truncated
off the page by GitHub's release-body storage cap, on exactly the two
releases the owner named; the generator now budgets every body it
renders, and both pages are healed.**

## The incident (what the owner saw)

Every release page from `v11.0.0-beta.3` through `v11.0.0-rc.3` ends
with the Verification section — the page's GPG + checksum contract.
The next two pages do not: `v11.0.0` (the stable) and `v20.0.0-rc.2`
(the pre-release that followed it) simply end mid-changelog, with no
verification text anywhere. The section is not a decoration: it is
the only on-page instruction for importing the signing key and
checking an archive before trusting a downloaded binary, and the two
casualties are the most important pages in the list — the stable
release and the current pre-release.

## The evidence (why "missing" was the wrong word)

The stored release bodies, read straight from the releases API:

| release | stored body | shape |
|---------|-------------|-------|
| `v11.0.0-rc.3` | 12,491 chars | ends with the Verification section, 5/5 `<details>` closed |
| `v11.0.0` | **exactly 124,999 chars** | cut mid-URL inside the full-changelog listing, 7 `<details>` opened / 6 closed |
| `v20.0.0-rc.2` | **exactly 124,999 chars** | cut mid-sentence inside a category listing, 4 opened / 3 closed |

Two bodies at *exactly* the same stored length, both ending
mid-word, is not a template regression — it is a platform cut.
GitHub silently truncates a stored release body over its cap
(observed here at 124,999 characters; the documented limit is
125,000). The generator renders the Verification section LAST —
so on an over-cap body, the platform's silent cut eats exactly the
page's tail: the verification contract. The generator had no idea
this was happening; it emitted a complete body, the action uploaded
a complete body, and the platform stored 124,999 characters of it.
Every green pipeline checked "body published", and the page was
quietly losing its most safety-critical section.

Two independent inflation paths produced the over-cap bodies:

1. **The `v11.0.0` stable shape**: the compare API's listing cap
   (250 commits) rendered twice — once in the category buckets,
   once in the full changelog — at ~62 bytes of link overhead per
   bullet plus uncapped subjects.
2. **The `v20.0.0-rc.2` shape**: only 139 commits, but campaign
   subjects run to essay length (~1,900 characters in that range),
   so each bullet is a paragraph and 61 rendered bullets alone
   consumed the entire cap.

## The fix (three layers in the generator, one in the workflow)

`scripts/release/generate-release-notes.sh` — the single
implementation of the release body — now bounds every body it
renders:

- **Layer 1, per-subject display cap (`MAX_SUBJECT_CHARS=240`)**:
  subjects are capped at extraction time (jq slices on codepoint
  boundaries, so a multi-byte character is never split; the `...`
  marker names the trim; the commit page carries the full text).
  This keeps the category sections — which list every commit —
  inside the budget on their own, and it is the layer that
  actually heals the `v20.0.0-rc.2` shape.
- **Layer 2, whole-body budget (`MAX_BODY_CHARS=120000`)**:
  `render_body` composes in memory (the streaming render could
  never know its own size), and the full-changelog bullet listing
  is trimmed from its tail — whole lines only — until the projected
  FINAL body, Verification section included, fits. The trim states
  itself on the page ("N commits in range, K shown — the compare
  view carries every subject in full"), alongside the existing
  compare-API truncation note. The categories keep every commit;
  the listing is the redundant reading order, never the record.
- **Layer 3, the hard refusal**: `main()` exits nonzero on any
  body that still exceeds the budget. Unreachable by construction
  after layers 1-2, it exists so future drift fails the pipeline
  red and named instead of shipping a silently truncated page —
  the exact silence this hunt closed.
- **The workflow tripwire**: the "Generate release body" step in
  `.github/workflows/release.yml` independently refuses any
  `release-body.md` over 124,000 bytes — the platform guard on
  the exact file the publish step uploads, independent of the
  generator's own policy number.

The budget unit is BYTES (`LC_ALL=C wc -c`): a body under the
budget in bytes is under it in characters under every reading of
the platform cap — the observed 124,999-character truncation and
the documented 125,000-character limit both sit 4,000+ above it.

## The backfill (the two pages, healed through the same generator)

The two casualty bodies were regenerated through the fixed
generator with the exact boundary values their pages already
displayed (`v11.0.0`: 250 commits since `v10.0.0`, stable callout;
`v20.0.0-rc.2`: 139 commits since `v11.0.0-rc.3`, 137 since the
`v11.0.0` last stable, pre-release warning) and PATCHed onto the
releases through the API:

| release | before | after | verification |
|---------|--------|-------|--------------|
| `v11.0.0` | 124,999 chars, cut mid-URL, 6/7 details closed | 93,671 chars, 7/7 closed | present, page ends with the `docs/VERIFY_RELEASE.md` line |
| `v20.0.0-rc.2` | 124,999 chars, cut mid-sentence, 3/4 closed | 72,306 chars, 8/8 closed | present, same |

Both regenerated bodies fit the budget with no tail trim needed —
layer 1 alone deflates the essay subjects past the point where
layers 2-3 would engage — and every range line, category count,
and bullet the pages showed before is unchanged. Only the
truncation damage healed.

## The verification

- `generate-release-notes.sh --self-test` pins the incident: a
  new budget contract feeds a synthetic range with MORE commits
  than the compare API's own 250-commit listing cap AND
  essay-length subjects (both failure shapes at once) through the
  real CLI path, and asserts the rendered body stays inside the
  budget, carries the Verification section, and states any trim
  honestly. The pre-fix generator fails this probe (its render of
  that fixture exceeds 150,000 bytes); the fixed generator passes.
- The two healed pages were re-read from the API after the PATCH:
  both now end with the full Verification section, and the whole
  release list from `v11.0.0-beta.3` forward carries it.

## Reproducing the diagnosis

```bash
# the platform cut, visible in the stored bodies (before the backfill)
curl -s https://api.github.com/repos/oxyzenQ/zelynic/releases \
  | jq -r '.[] | [.tag_name, ((.body // "") | length)] | @tsv'
# both casualties read exactly 124999

# the budget contract, pinned in the generator
./scripts/release/generate-release-notes.sh --self-test
```
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
