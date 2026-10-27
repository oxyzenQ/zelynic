#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# ZELYNIC SECRET NAME CONSISTENCY CHECK
#
# night-dragon-maintenance-4: the repo's CI secret surface is exactly four
# names, and it stays exactly four names:
#   GITHUB_TOKEN      — the automatic per-job token, scoped by permissions:
#   CRATES_IO_TOKEN   — the crates.io publish-update token. Never a
#                       CARGO_REGISTRY_TOKEN / CRATES_TOKEN / CARGO_TOKEN
#                       spelling at the secrets. layer: CARGO_REGISTRY_TOKEN
#                       is the cargo-side CONSUMPTION env var the workflow
#                       derives FROM the secret (the same derivation the
#                       zejtron sibling documents), not a secret name.
#   GPG_PRIVATE_KEY   — the release-signing identity
#   GPG_PASSPHRASE    — the signing subkey passphrase
#
# Why a gate and not a one-off audit: a rogue spelling is a SILENT no-op.
# An Actions run reads a differently-named secret as the empty string and
# either publishes unauthenticated or skips signing without anyone noticing
# the name drifted. One secret, one name, everywhere: the workflows, the
# docs that tell a maintainer what to configure, and docs/MAINTENANCE.md's
# rotation table must all agree, or the push fails here.
#
# Contracts held:
#   1. every secrets.X reference in ANY tracked file (workflows included)
#      resolves to the canonical inventory
#   2. the crates.io alias spellings are contained: CARGO_TOKEN and
#      CRATES_TOKEN have no legal use anywhere (cargo only reads
#      CARGO_REGISTRY_TOKEN); CARGO_REGISTRY_TOKEN is allowed ONLY under
#      .github/workflows/ — the consumption site
#   3. every non-builtin canonical secret is still referenced by at least
#      one workflow (documented-but-unused = retire it from the docs)
#   4. every non-builtin canonical secret is documented in
#      docs/MAINTENANCE.md's rotation table (docs drift = a maintainer
#      rotating the wrong thing or nothing at all)
#
# Usage: bash scripts/gates/check-secret-names.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# The canonical inventory. Order never matters; the set is the contract.
CANONICAL_SECRETS="GITHUB_TOKEN CRATES_IO_TOKEN GPG_PRIVATE_KEY GPG_PASSPHRASE"
# The non-builtin members — the ones a human configures and the docs must track.
MANAGED_SECRETS="CRATES_IO_TOKEN GPG_PRIVATE_KEY GPG_PASSPHRASE"

is_canonical() {
	local name="$1"
	local secret
	for secret in $CANONICAL_SECRETS; do
		if [ "$name" = "$secret" ]; then
			return 0
		fi
	done
	return 1
}

indent() {
	while IFS= read -r line; do
		printf '       %s\n' "$line"
	done
}

FAILED=0

# ── 1. Repo-wide secrets.X references are canonical ──────────────────────────
# git grep sees every tracked file — workflows, docs, scripts, comments.
# History (docs/archive) is scanned too on purpose: a living doc is the
# instruction surface, and an archive doc re-linked as guidance is exactly
# how drift re-enters. If the archive ever grows a historical secrets.X
# mention, this gate forces a conscious exclusion decision, not silence.
ALL_REFS=$(git grep -hoE 'secrets\.[A-Z_][A-Z0-9_]*' '--' ':!scripts/gates/check-secret-names.sh' ':!scripts/gate-keepers.sh' | sed 's/^secrets\.//' | sort -u)
REF_COUNT=$(git grep -oE 'secrets\.[A-Z_][A-Z0-9_]*' '--' ':!scripts/gates/check-secret-names.sh' ':!scripts/gate-keepers.sh' | wc -l | tr -d ' ')
while IFS= read -r name; do
	if [ -z "$name" ]; then
		continue
	fi
	if ! is_canonical "$name"; then
		echo "FAIL: secrets.$name is not in the canonical inventory ($CANONICAL_SECRETS). Referenced at:"
		git grep -nE "secrets\\.$name([^A-Z0-9_]|$)" | indent
		FAILED=$((FAILED + 1))
	fi
done <<<"$ALL_REFS"
if [ "$FAILED" -eq 0 ]; then
	echo "OK: all $REF_COUNT secrets.* reference(s) across tracked files are canonical"
fi

# ── 2. crates.io alias spellings are contained ───────────────────────────────
# CARGO_TOKEN / CRATES_TOKEN: no legal use anywhere in the repo.
# ':!scripts/gates/check-secret-names.sh' — the gate's own evidence
# strings name the aliases it forbids; a gate is not an instruction
# to misconfigure, it is the instrument.
ALIAS_HITS=$(git grep -nE '\b(CARGO_TOKEN|CRATES_TOKEN)\b' '--' ':!scripts/gates/check-secret-names.sh' ':!scripts/gate-keepers.sh' || true)
if [ -n "$ALIAS_HITS" ]; then
	echo "FAIL: forbidden crates.io token alias spelling(s) found (the secret is CRATES_IO_TOKEN):"
	echo "$ALIAS_HITS" | indent
	FAILED=$((FAILED + 1))
fi
# CARGO_REGISTRY_TOKEN: the consumption env var — legal only under
# .github/workflows/. Anywhere else it is an instruction to misconfigure.
REGISTRY_HITS=$(git grep -nE '\bCARGO_REGISTRY_TOKEN\b' -- ':!.github/workflows' ':!scripts/gates/check-secret-names.sh' ':!scripts/gate-keepers.sh' || true)
if [ -n "$REGISTRY_HITS" ]; then
	echo "FAIL: CARGO_REGISTRY_TOKEN outside .github/workflows/ (it is the workflow-side env var, not a secret name — docs and scripts say CRATES_IO_TOKEN):"
	echo "$REGISTRY_HITS" | indent
	FAILED=$((FAILED + 1))
fi
if [ -z "$ALIAS_HITS" ] && [ -z "$REGISTRY_HITS" ]; then
	echo "OK: crates.io alias spellings contained (CARGO_REGISTRY_TOKEN only at the workflow consumption site)"
fi

# ── 3. Liveness: every managed secret is still wired to a workflow ───────────
for secret in $MANAGED_SECRETS; do
	WF_HITS=0
	for wf in .github/workflows/*.yml; do
		[ -f "$wf" ] || continue
		if grep -qE "secrets\\.$secret([^A-Z0-9_]|$)" "$wf"; then
			WF_HITS=$((WF_HITS + 1))
		fi
	done
	if [ "$WF_HITS" -eq 0 ]; then
		echo "FAIL: $secret is in the canonical inventory but no workflow references it — retire it from docs/MAINTENANCE.md or wire it back"
		FAILED=$((FAILED + 1))
	else
		echo "OK: $secret referenced by $WF_HITS workflow(s)"
	fi
done

# ── 4. Docs parity: the rotation table documents every managed secret ────────
MAINTENANCE_DOC="docs/MAINTENANCE.md"
if [ ! -f "$MAINTENANCE_DOC" ]; then
	echo "FAIL: $MAINTENANCE_DOC not found — the rotation table is the docs contract"
	FAILED=$((FAILED + 1))
else
	for secret in $MANAGED_SECRETS; do
		if grep -qE "\`$secret\`" "$MAINTENANCE_DOC"; then
			echo "OK: $MAINTENANCE_DOC documents $secret"
		else
			echo "FAIL: $MAINTENANCE_DOC does not document $secret (the rotation table must carry every managed secret)"
			FAILED=$((FAILED + 1))
		fi
	done
fi

echo ""
if [ "$FAILED" -gt 0 ]; then
	echo "FAIL: $FAILED secret-name contract(s) violated — one secret, one name, everywhere"
	exit 1
else
	echo "OK: secret-name consistency holds (inventory: $CANONICAL_SECRETS)"
	exit 0
fi
