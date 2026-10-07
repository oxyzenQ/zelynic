#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# ZELYNIC AUDITS INDEX COMPLETENESS CHECK (NIGHT-total-lts-8 followup)
#
# lts-8's one find: the docs/README.md audits index stopped at the
# 2026-10-03 Z10 row — eighteen sessions shipped audit docs without
# indexing them and NOTHING failed, because no gate existed for
# index completeness. The stale-reference instrument lts-6 runs
# checks whether a doc's path references RESOLVE (every audits/
# path in the index did resolve), not whether the index COVERS the
# directory it maps — the two instruments see different halves of
# the same lie, and the coverage half had no eyes at all.
#
# This gate is the recipe lts-8 recorded, machine-enforced at every
# push (the owner approved lifting the gate-inventory freeze for
# exactly this check): every tracked docs/audits/*.md doc must
# carry a link row in the docs/README.md index —
# `git ls-files 'docs/audits/*.md'` minus the index's audits/ link
# set must be EMPTY. An audit doc that ships without a row fails
# the push, so the institutional-memory map can never drift behind
# the records again.
#
# Scope honesty (one contract, one place): this gate owns COVERAGE
# only. A dead index row — a link pointing at a path that no longer
# exists — is the stale-reference class lts-6's instrument hunts at
# audit time, and is deliberately not re-owned here.
#
# Usage: bash scripts/gates/check-audits-index.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

INDEX_FILE="docs/README.md"

# Not a git work tree (a bare export, say): the tracked-set half of
# the recipe has nothing to read. Skip with the warning — the
# wholesale battery's caller prints its own non-git warning for the
# same shape.
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	echo "audits-index: not a git work tree — skipping"
	exit 0
fi

# The tracked set (repo-root-relative, sorted). git ls-files sees
# staged-but-uncommitted files too, so the gate fails BEFORE the
# commit that would ship an unindexed doc, not only after.
TRACKED="$(git ls-files -- 'docs/audits/*.md' | sort)"
TRACKED_COUNT="$(git ls-files -- 'docs/audits/*.md' | wc -l | tr -d ' ')"

# No tracked audit docs at all: complete by vacuum (a fresh tree
# before its first audit). Nothing to compare, and the recipe's
# index-file half has nothing to protect yet.
if [ "$TRACKED_COUNT" -eq 0 ]; then
	echo "audits-index: no tracked audit docs — complete by vacuum"
	exit 0
fi

# The map itself missing is not an empty index, it is amnesia: every
# tracked audit doc would be unindexed at once. Fail loud.
if [ ! -f "$INDEX_FILE" ]; then
	echo "audits-index: $INDEX_FILE missing — the institutional-memory map itself is gone"
	exit 1
fi

# The indexed set: every markdown link target of the canonical row
# shape ](audits/....md) in the index, lifted to repo-root paths.
# A doc linked any OTHER way does not join the set, so it stays
# "missing" below — the gate fails closed on non-canonical rows
# instead of blessing them.
INDEXED="$(grep -o '](audits/[^)]*\.md)' "$INDEX_FILE" 2>/dev/null | sed -e 's|^](|docs/|' -e 's|)$||' | sort -u || true)"

# The recipe: tracked minus indexed must be empty.
MISSING="$(comm -23 <(printf '%s\n' "$TRACKED") <(printf '%s\n' "$INDEXED"))"

if [ -n "$MISSING" ]; then
	echo "audits-index: FAIL — tracked audit doc(s) missing from $INDEX_FILE:"
	while IFS= read -r doc; do
		[ -n "$doc" ] || continue
		echo "  - $doc (add its row to the audits index table)"
	done <<<"$MISSING"
	echo "audits-index: the institutional-memory map must cover every record"
	exit 1
fi

echo "audits-index: $TRACKED_COUNT/$TRACKED_COUNT tracked audit docs indexed — the map is complete"
