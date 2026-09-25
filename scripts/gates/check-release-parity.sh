#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# PLATFORM: UNIX-only (Linux). zelynic is a Linux-only tool.
#
# ZELYNIC RELEASE PARITY CHECK (NIGHT-lts-9)
#
# The release pipeline builds the four arch-baseline packages from
# .github/workflows/release.yml's matrix rustflags; the README tells
# owners a local `cargo pro-linux-amd64-<platform>` reproduces the
# release artifact's optimization tier BIT-FOR-BIT. Until now nothing
# compared the two flag sets: the aliases live in .cargo/config.toml,
# the matrix lives in release.yml, and a one-file edit would silently
# break the documented parity (a locally built "release shape" that is
# not the release shape — exactly the drift class a critical-infra
# release pipeline should not carry).
#
# This gate walks the four platforms and asserts, per platform, that
# the -C codegen tokens of the alias's rustflags equal the -C tokens
# of the release matrix's rustflags. The -D warnings lint token is
# deliberately OUT of scope: the release build adds it via matrix env
# (NIGHT-strict-2), the local alias deliberately does not (a local
# debug build has no business failing on warnings) — the parity
# contract is about the OPTIMIZATION tier, not the lint posture.
# release.yml's own "Verify arch-baseline inputs" step holds the
# canonical constant per platform; this gate holds the cross-file
# equality. The musl aliases set the rustflags at the target level
# (the SHADOW rule documented in .cargo/config.toml) — both shapes
# are understood.
#
# Usage: bash scripts/gates/check-release-parity.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

FAILED=0

# The four release platforms (the matrix ids release.yml owns).
PLATFORMS="linux-amd64-v3-gnu linux-amd64-v4-gnu linux-amd64-v3-musl linux-amd64-v4-musl"

for platform in $PLATFORMS; do
	# ── Matrix side: the rustflags line inside release.yml's matrix
	# entry for this platform. The matrix block shape is stable:
	#   - platform: <id>
	#     target: <triple>
	#     rustflags: "..."
	# awk grabs the first rustflags line at or after the platform id
	# line (the matrix include list is the only such block in the
	# workflow; the verify step's case statement is compared by the
	# workflow itself at run time).
	MATRIX_FLAGS="$(awk -v p="$platform" '
                $0 ~ "- platform: "p { in_entry = 1 }
                in_entry && /rustflags: "/ {
                        gsub(/.*rustflags: "|".*$/, "")
                        print
                        exit
                }
        ' .github/workflows/release.yml)"
	if [ -z "$MATRIX_FLAGS" ]; then
		echo "FAIL: no matrix rustflags found for $platform in .github/workflows/release.yml"
		FAILED=$((FAILED + 1))
		continue
	fi

	# Extract the -C codegen tokens from the matrix flags (drop the
	# -D warnings lint token): "a b -C c" -> "-C c", normalized.
	MATRIX_C="$(printf '%s\n' "$MATRIX_FLAGS" | tr ' ' '\n' | awk '/^-C$/ { getline tok; printf "%s,", tok }' | sed 's/,$//')"

	# ── Alias side: .cargo/config.toml's pro-<platform> alias. The
	# alias is a TOML array of cargo args carrying the rustflags via a
	# --config value; python3 + tomllib (the stdlib TOML parser, the
	# same tooling gate 4 already trusts) reassembles the flag string.
	ALIAS_C="$(
		python3 - "$platform" <<'PYEOF'
import sys
import tomllib

platform = sys.argv[1]
alias_name = f"pro-{platform}"

with open(".cargo/config.toml", "rb") as f:
    cfg = tomllib.load(f)

alias = cfg.get("alias", {}).get(alias_name)
if alias is None:
    print("MISSING-ALIAS")
    sys.exit(0)

# Walk the alias args; the rustflags ride a --config value shaped
# either build.rustflags=["-C","tok",...] or
# target.<triple>.rustflags=["-C","tok",...]. Both are the same
# "-C tok" token stream once unwrapped: strip the key, unbracket the
# value, split on commas, unquote the tokens.
flags = []
i = 0
while i < len(alias):
    arg = alias[i]
    if arg == "--config" and i + 1 < len(alias):
        kv = alias[i + 1]
        if ".rustflags=" in kv or kv.startswith("build.rustflags="):
            raw = kv.split("=", 1)[1].strip()
            vals = [v.strip().strip('"') for v in raw[1:-1].split(",") if v.strip()]
            flags.extend(vals)
            i += 2
            continue
    i += 1

# "-C","tok" pairs -> "-C tok" tokens.
tokens = []
i = 0
while i < len(flags):
    if flags[i] == "-C" and i + 1 < len(flags):
        tokens.append(flags[i + 1])
        i += 2
    else:
        i += 1
print(",".join(tokens))
PYEOF
	)"
	if [ "$ALIAS_C" = "MISSING-ALIAS" ]; then
		echo "FAIL: .cargo/config.toml has no pro-$platform alias"
		FAILED=$((FAILED + 1))
		continue
	fi

	# ── The verdict.
	if [ -z "$MATRIX_C" ]; then
		echo "FAIL: $platform matrix rustflags carry no -C tokens: '$MATRIX_FLAGS'"
		FAILED=$((FAILED + 1))
	elif [ -z "$ALIAS_C" ]; then
		echo "FAIL: pro-$platform alias carries no -C tokens in its rustflags"
		FAILED=$((FAILED + 1))
	elif [ "$MATRIX_C" != "$ALIAS_C" ]; then
		echo "FAIL: $platform -C token drift — release matrix: '$MATRIX_C' vs local alias: '$ALIAS_C'"
		echo "      a local pro-$platform build would NOT reproduce the release optimization tier"
		FAILED=$((FAILED + 1))
	else
		echo "OK: $platform parity — matrix and pro-$platform alias share -C tokens: '$MATRIX_C'"
	fi
done

echo ""
if [ "$FAILED" -gt 0 ]; then
	echo "FAIL: $FAILED platform(s) out of parity"
	exit 1
else
	echo "OK: all four release platforms in local-alias/matrix parity"
	exit 0
fi
