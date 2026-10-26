#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# ZELYNIC COMMIT-TIME PREBUILT GATE (NIGHT-dinner-1, auto-heal since
# night-dragon-maintenance-0)
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
#   1. Prebuilt parity (delegated to
#      scripts/release/refresh-prebuilt.sh's read-only --check
#      verdict, AUTO-HEALED since night-dragon-maintenance-0 — the
#      sibling zejtron commit-gate shape): the ebpf/ tree hash must
#      still match ebpf-prebuilt/manifest.toml's pin, each staged
#      object must still be the pinned bytes, and the toolchain pin
#      must still match ebpf/rust-toolchain.toml — the "edited ebpf/,
#      forgot the refresh" case. A stale verdict now HEALS instead of
#      failing: the one writer rebuilds the objects through the
#      repo's validated pipeline, rewrites the manifest, and the
#      refreshed lane is staged into THIS commit — "edit ebpf/,
#      commit" carries a fresh lane with no separate manual step
#      (the build-time arm, build.rs's check_prebuilt_lane_freshness,
#      announces the same staleness on every cargo build; it cannot
#      rewrite because the writer's root build would deadlock on the
#      outer cargo's target/ lock — see that function's doc comment).
#      The fail-closed arm remains for the heal's own failure mode —
#      missing prerequisites — because a gate that would ship a stale
#      lane silently is the dishonest gate.
#   2. Pairing: a commit that stages ebpf/ must also stage
#      ebpf-prebuilt/ — the "refreshed but forgot git add" case.
#      Auto-healed the same way: when the on-disk lane already
#      verifies (a regenerator ran earlier, the staging was
#      forgotten) the lane is staged into the commit; when it does
#      not, section 1's heal has already run and the fail-closed arm
#      names the fix.
#   3. CI actions-pin health (delegated to
#      check-actions-pins.sh, NIGHT-improve-40): the freshness of
#      every `uses:` pin against upstream, classified
#      MAJOR/MINOR/PATCH — the actions-pin health contract's one
#      automatic seat (NIGHT-improve-39's final form: the weekly
#      server-side lane is retired, contributors carry freshness).
#
# Two contract classes share this gate, and the split is the point:
# sections 1-2 fail closed (after their auto-heal) because prebuilt
# parity is a LOCAL fact this machine can always prove; section 3 is
# advisory by default because pin freshness is a REMOTE fact that
# needs the network and the API's quota right now — a gate that
# blocks a commit on facts it cannot reach would be a dishonest
# gate. Strict contributors opt in with git config
# zelynic.actionsHealthCheck strict, and even then only a KNOWN-stale
# verdict blocks; every skip reason stays a skip. The full contract
# (cache, budget, honesty rules) lives in check-actions-pins.sh's
# header.
#
# Fail-closed on 1-2 when the lane cannot be made fresh. The escape
# hatches are git's own --no-verify and the shared
# ZELYNIC_SKIP_PREBUILT_REGEN=1 (build.rs honors the same variable),
# which turns the auto-heal back into the fail-closed shape —
# but the wholesale push gate and the ship-time parity steps still
# block the push and the publish, so either hatch buys a local WIP
# commit, never a stale shipment.
#
# Usage:
#   bash scripts/gates/check-commit-gate.sh    # same checks, preview
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

WRITER="scripts/release/refresh-prebuilt.sh"
GATE_FAILED=0

# ── 1. prebuilt parity (auto-heal — one implementation, one truth) ────────
# The stale verdict heals through the one writer, the refreshed lane
# rides the commit, and the re-check must pass. The build-time arm
# (build.rs's check_prebuilt_lane_freshness) announces the same
# staleness on every cargo build. ZELYNIC_SKIP_PREBUILT_REGEN=1 is
# the shared escape hatch: under it the stale verdict fails closed
# again, the pre-heal shape.
if [ "${ZELYNIC_SKIP_PREBUILT_REGEN:-}" = "1" ]; then
	if ! bash "$WRITER" --check; then
		echo "      ZELYNIC_SKIP_PREBUILT_REGEN=1 skips the auto-heal; refresh by hand:"
		echo "        ./scripts/release/refresh-prebuilt.sh, then git add ebpf-prebuilt"
		GATE_FAILED=1
	fi
elif ! bash "$WRITER" --check; then
	echo "      prebuilt lane stale — regenerating through the one writer..."
	if bash "$WRITER"; then
		git add ebpf-prebuilt
		if bash "$WRITER" --check; then
			echo "      lane regenerated and staged into this commit."
		else
			echo "      the rewrite landed but the re-check still says stale."
			GATE_FAILED=1
		fi
	else
		echo "      the regeneration failed (missing prerequisites?) — install the pair:"
		echo "        ./scripts/dev/bootstrap-ebpf.sh, then commit again"
		GATE_FAILED=1
	fi
fi

# ── 2. ebpf/ staged without ebpf-prebuilt/ ───────────────────────────────
# The "refreshed but forgot git add" case. A fresh on-disk lane (the
# --check verdict above) is staged into the commit; a stale one was
# already healed or failed in section 1, so this arm only ever names
# the fix when the lane itself could not be made fresh.
if git diff --cached --name-only -- ebpf/ | grep -q .; then
	if ! git diff --cached --name-only -- ebpf-prebuilt/ | grep -q .; then
		if bash "$WRITER" --check; then
			git add ebpf-prebuilt
			echo "      ebpf-prebuilt was fresh but unstaged — staged it into this commit."
		else
			echo "FAIL: ebpf/ changes are staged but ebpf-prebuilt/ is neither staged nor fresh."
			echo "      The commit would ship sources the prebuilt lane does"
			echo "      not describe. Refresh and stage the lane:"
			echo "        ./scripts/release/refresh-prebuilt.sh, then"
			echo "          git add ebpf-prebuilt"
			GATE_FAILED=1
		fi
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
