<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# night-audit-3 — the structure depth audit: every file and folder held to the masterclass bar

Date: 2026-11-13. The owner's mandate, verbatim in shape: "end to end
total master hardening — depth audit for this project structure files
and folder to peak masterclass pro not spaghetti/noob." The question
is not whether the code compiles or the gates pass (the batteries own
those); the question is whether the TREE ITSELF — the shape a
maintainer meets on the first `ls`, the place every artifact lives,
the map that carries institutional memory — is the shape a
masterclass project carries, or the shape that drifts into a junk
drawer.

The audit ran as a census, not a vibe. Every sweep below is a
command run against the tracked tree at the night-total-hardening-1
head, and every number in this doc is the sweep's printed output,
not an estimate.

## Method: the six instruments

1. **The tracked-mode census.** `git ls-files -s` sorted by mode:
   613 tracked files, 530 at 100644 and 83 at 100755, every mode
   checked against the filesystem and against the owner's law
   (644 files, 755 folders and executables) that
   `scripts/gates/check-permissions.sh` already enforces at every
   push.
2. **The orphan-reachability sweep.** For every tracked
   `scripts/*.sh` and `scripts/*.py`, the basename grepped across
   the whole tree excluding the file itself and excluding the
   historical rows (CHANGELOG, docs/audits, docs/archive) — a script
   referenced only by its own history is an orphan with a paper
   trail. Result: zero orphans; every script is reachable from a
   caller, a gate, a workflow, or a doc that instructs a human.
3. **The artifact-policy walk.** Every tracked file that looks like
   build output (binaries, object files, tarballs, checksum
   manifests) traced to its owner document: is it deliberate,
   verified, and consumed by a script or gate — or is it debris?
4. **The map-coverage sweep.** Every tracked doc under docs/
   checked against docs/README.md, the file that calls itself the
   master index of all zelynic documentation — first by basename
   (the find), then by the canonical `](...md)` link shape the
   coverage gate reads (the proof).
5. **The mirror census.** src/ checked against test/ module for
   module: a src module with no test tree counterpart must carry
   inline `#[cfg(test)]` coverage or the gap is a find.
6. **The stale-pointer sweep.** Every path-like string in
   load-bearing metadata (.gitattributes, .gitignore, manifests,
   gate headers) resolved against the tracked tree: a reference to
   a path that does not exist is a lie the next reader pays for.

## Find 1: the .gitattributes pointer named a doc that does not exist

The archive-export comment — load-bearing metadata, read by every
`git archive` consumer and every maintainer auditing the export
contract — pointed at `legacy-for-test/README.md`. That path does
not exist; the vendored pair's provenance note is
`legacy-for-test/VENDOR.md` (it has been VENDOR.md since the
directory was named, and nothing else references the README shape).
The comment now names the real doc; the `export-ignore` line itself
is untouched. One line, but the class is the one lts-6's instrument
hunts everywhere else: a pointer in a metadata file had no eyes on
it because the stale-reference sweeps walk docs, not dotfiles.

## Find 2: the master index had never met the quota-saver physics page

`docs/QUOTA_SAVER_PHYSICS.md` is a living doc — the RECWN Layer 1
physics page, referenced by the root README, by USAGE, by the
tenant-design research page — and it had no row in docs/README.md,
the master index whose header line promises the whole map. A
new maintainer reading the index end to end would never learn the
page exists. The find is exactly the lts-8 class one directory over:
lts-8's gate taught the audits/ half of the map to never drift and
left the other halves ungated — and the ungated halves had drifted.

## Find 3: the archive section indexed one of its two archives

`docs/archive/CHANGELOG-V20-ERA.md` carried no row in the master
index's Archive section, while its sibling `CHANGELOG_PRE_V11.md`
did — the section's coverage of its own directory was half a
directory. The v20-era record is reachable from the changelog's
header links, so the page was not lost, but a map that covers its
territory in patches is a map that teaches readers to double-check
it — the opposite of what an index is for. The row now sits beside
its sibling with the provenance the wrapper itself carries (the
b743d9c blob, NIGHT-improve-43's split, the relocation).

## Find 4: the coverage gate now has eyes on every half of the map

The three finds above share one root cause: the
`scripts/gates/check-audits-index.sh` instrument — the recipe lts-8
recorded — owned COVERAGE for `docs/audits/*.md` only, and nothing
owned the living pages, the archive, or the research pages. The
recipe now extends unchanged to the whole tree the master index
maps: every tracked `docs/*.md` (the index file itself excepted),
`docs/archive/*.md`, `docs/research/*.md`, and
`docs/research-future/*.md` must carry a canonical `](...md)` link
row, checked at every push and before the commit (git ls-files sees
staged files, so an unindexed doc fails before it lands). Verified
both ways before the extension was trusted: green at the head
(85/85 audit records, 118/118 docs-tree pages — the globs that
reach the audit records are one set, one verdict) and red when a
staged unindexed doc was planted (the gate named the path loud and
exited 1, then the plant was removed). The audits half keeps its
own check and its own verdict line; gate-keepers section 20 and
MAINTENANCE section 6 carry the extended contract.

## The verdicts that needed no change (the honest part of the audit)

**The permission law holds everywhere.** 530 files at 644, 83 at
755, zero mismatches between git modes and the filesystem, and the
shebang parity holds. The four 644 shell/python files in
`scripts/lib/` (`github_token.sh`, `harness_lib.sh`, `miri.sh`,
`zelynic_harness_lib.py`) are sourced or imported, never executed —
644 is their correct mode by the repo's own contract, and the gate
that enforces the law knows the difference. The only executable
that is not a script or binary is `.githooks/pre-commit`, which is
exactly what it should be.

**There are no orphan scripts.** The reachability sweep walked all
62 shell and 23 python files under scripts/ and every one is named
by a caller outside its own file. The tree has no dead wood at the
leaf level.

**Every tracked binary is deliberate, owned, and consumed.** The
two eBPF objects in `ebpf-prebuilt/` are the shipped lane pinned by
`manifest.toml` and enforced at commit time by the auto-healing
prebuilt gate (and again at ship time in the release and
crates-io lanes). The 4.2 MB stripped static-PIE binary in
`scripts/labs-exp/` is the documented fixture of the forensic rig
(v80.2.0, the VERIFY_LOCAL_HARDENING_1.md table names it, and both
verify scripts default their `BIN` to it while honoring a
`ZELYNIC_BIN` override). The v11.0.0 tarball in `legacy-for-test/`
is the checksummed counterfactual the MMSPA contract is measured
against, excluded from archive exports. Nothing tracked is debris.

**The src/ to test/ mirror has no uncovered gap.** test/ mirrors
the top-level module layout (cli, commands, ebpf, json, output,
terminal, integration), and the two src/ebpf subtrees without a
test-tree counterpart carry their coverage inline instead
(`src/ebpf/connections`: fifteen test functions; `src/ebpf/loader`:
one). Different shape, same guarantee — the audit checked the
guarantee, not the cosmetics.

**The top level carries no strays.** Every root file is load-bearing:
the four lint configs (.codespellrc, .ruff.toml, .markdownlint.json,
.yamllint) are each wired into a gate or workflow, the four legal
files plus NOTICE and CLA are the license estate, and the three
agent/maintainer docs (AI_AGENTS_READ_THIS.md, CONTRIBUTING.md,
QA.md) are the front door for the audiences the project names. The
scripts/ subdirectories follow one naming grammar (lowercase,
one-word or hyphenated: bench, ci, depth, dev, gates, labs-exp,
lib, package, release, sandbox, supermassive), the docs/ tree
follows its own (UPPER_SNAKE living pages, dated NIGHT_* audit
records, the archive frozen), and neither grammar has an outlier.

**The changelog-era discipline is intact.** The split night-docs-1
recorded holds: the root CHANGELOG carries only the post-v20
record, the two era archives sit in docs/archive/ with their
wrapper headers, and — after this audit — both are on the map.

## Residuals

One, and it is an owner call, not a defect: the labs-exp fixture
rides git as a 4.2 MB blob, so each future fixed binary the
forensic rig accumulates adds its weight to every clone forever.
Today there is exactly one and the rig documents it; if the
labs-exp family ever grows past a handful, git-lfs or a
release-asset fetch is the lever — deliberately not pulled here,
because a lever pulled without need is its own kind of noise.

## The standing record

Four finds, all closed in four micro-commits the same session, none
touching a line of Rust or an eBPF byte: the structure was audited
and it holds the bar — the finds were drift in the map and the
metadata, not spaghetti in the tree. The instrument they exposed
(the ungated map halves) is now gated, so the class cannot quietly
return. The tree a maintainer meets on the first `ls` is the tree
the audits promised: every file owned, every binary deliberate,
every permission lawful, every doc on the map, and the map itself
unable to drift without the push failing loud.

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
