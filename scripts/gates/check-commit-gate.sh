#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# ZELYNIC COMMIT-TIME PREBUILT GATE (NIGHT-dinner-1)
#
# The commit-time arm of the prebuilt eBPF freshness contract. The
# contract has three arms now, one per place a stale lane could slip
# through:
#   - commit time: THIS gate, wired into git via .githooks/pre-commit
#     (core.hooksPath=.githooks, self-installed by gate-keepers.sh)
#   - push time:   gate-keepers.sh section 18 and the wholesale
#     Dragon Guard workflow, unfiltered on every push
#   - ship time:   the parity steps in crates-io.yml and release.yml,
#     the last line of defense before the registry upload and the
#     release binaries
#
# What it enforces at the moment a commit is created:
#   1. Prebuilt parity (delegated to check-prebuilt-parity.sh): the
#      ebpf/ tree hash must still match ebpf-prebuilt/manifest.toml's
#      pin — the "edited ebpf/, forgot the refresh" case. The tree
#      hash reads the git index (git ls-files), so a source file is
#      counted as soon as it is staged.
#   2. Pairing: a commit that stages ebpf/ must also stage
#      ebpf-prebuilt/ — the "refreshed but forgot git add" case: the
#      worktree lane is fresh while the commit would still ship the
#      old one.
#   3. CI actions-pin health (delegated to
#      check-actions-pins.sh, NIGHT-improve-40): the freshness of
#      every `uses:` pin against upstream, classified
#      MAJOR/MINOR/PATCH — the actions-pin health contract's one
#      automatic seat (NIGHT-improve-39's final form: the weekly
#      server-side lane is retired, contributors carry freshness).
#
# Two contract classes share this gate, and the split is the point:
# sections 1-2 fail closed because prebuilt parity is a LOCAL fact
# this machine can always prove; section 3 is advisory by default
# because pin freshness is a REMOTE fact that needs the network and
# the API's quota right now — a gate that blocks a commit on facts
# it cannot reach would be a dishonest gate. Strict contributors
# opt in with git config zelynic.actionsHealthCheck strict, and even
# then only a KNOWN-stale verdict blocks; every skip reason stays a
# skip. The full contract (cache, budget, honesty rules) lives in
# check-actions-pins.sh's header.
#
# Fail-closed on 1-2. The escape hatch is git's own: --no-verify
# skips any local hook (a git contract, not a hole here) — but the
# wholesale push gate and the ship-time parity steps still block the
# push and the publish, so --no-verify buys a local WIP commit,
# never a stale shipment.
#
# Usage:
#   bash scripts/gates/check-commit-gate.sh    # same checks, preview
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# ── 1. prebuilt parity (delegated — one implementation, one truth) ────────
# Run it with the failure collected, not fatal: the pairing check
# below must still report when BOTH mistakes were made in one commit
# (stale lane AND an unstaged refresh), so the owner sees every
# finding in one gate run instead of fixing them one commit at a
# time.
GATE_FAILED=0
if ! bash scripts/gates/check-prebuilt-parity.sh; then
	GATE_FAILED=1
fi

# ── 2. ebpf/ staged without ebpf-prebuilt/ ───────────────────────────────
if git diff --cached --name-only -- ebpf/ | grep -q .; then
	if ! git diff --cached --name-only -- ebpf-prebuilt/ | grep -q .; then
		echo "FAIL: ebpf/ changes are staged but ebpf-prebuilt/ is not."
		echo "      The commit would ship sources the prebuilt lane does"
		echo "      not pin. Run ./scripts/release/refresh-prebuilt.sh, then"
		echo "      stage the lane in the SAME commit:"
		echo "        git add ebpf-prebuilt"
		GATE_FAILED=1
	fi
fi

# ── 3. CI actions-pin health (advisory by default) ────────────────
# Runs LAST: the fail-closed lane checks above never wait behind a
# network probe. In strict mode a known-stale verdict joins
# GATE_FAILED; in auto mode a healed-and-staged pin set joins it
# ONCE (the re-commit reads the healed pins as current); in every
# other shape (current, warn, every skip reason) the check owns its
# own exit-zero and its own output.
if ! bash scripts/gates/check-actions-pins.sh; then
	GATE_FAILED=1
fi

if [ "${GATE_FAILED}" -ne 0 ]; then
	echo "FAIL: commit gate — the tree is not committable in this state"
	echo "      (sections 1-2 fail-closed on the prebuilt lane; section 3"
	echo "      blocks on a strict stale verdict or an auto-mode heal —"
	echo "      the once-only re-commit that carries the healed pins)"
	exit 1
fi

echo "OK: commit gate — prebuilt lane in parity, ebpf/ staged with its lane, actions-pin health reported"
