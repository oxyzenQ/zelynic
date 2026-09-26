#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# PLATFORM: UNIX-only (Linux). Runs on GitHub-hosted ubuntu runners
#   (curl + jq are runner staples); not for Windows cmd.exe.
#
# NIGHT-ask-1: the CI gate for tag-triggered workflows
# (crates-io.yml). Ported from the cosmostrix reference's
# scripts/release/wait-for-ci.sh — the same collision class exists
# here: when the owner pushes the release commit and its tag together
# (git push origin main vX.Y.Z), the tag pipeline starts while the
# branch CI (Dragon Guard - CI) is still running on the same SHA —
# without this gate the crates.io publish ships with zero
# serialization, and a crates.io publish is IRREVERSIBLE (a bad
# version can only be yanked, never replaced). This script serializes
# the two: it polls the GitHub Actions API until the ci.yml push-run
# for the exact tagged SHA completes, then requires
# conclusion=success before the caller proceeds.
#
# Semantics:
#   - A ci.yml run for the SHA is queued/in_progress -> keep polling.
#   - The newest completed run must have conclusion=success:
#       success            -> gate PASSES.
#       failure/timed_out/
#       startup_failure    -> gate FAILS (publish blocked; the code
#                             the tag points at did not pass CI).
#       cancelled          -> gate FAILS with a recovery hint. A
#                             cancelled CI never verified the code (the
#                             usual cause: a newer main push cancelled
#                             it via ci.yml's cancel-in-progress). Re-run
#                             CI for the SHA, or re-push the tag.
#   - No ci.yml run exists after the grace period -> gate PASSES:
#       the commit touched nothing in ci.yml's Rust-surface `paths:`
#       filter (a docs-only release), so there is no run to wait for.
#       The unconditional gate-keepers.yml still covered that push
#       (it runs on EVERY push, unfiltered — see ci.yml's header for
#       the split contract).
#
# Env (all provided by GitHub Actions):
#   GITHUB_API_URL, GITHUB_REPOSITORY, GITHUB_SHA, GITHUB_TOKEN
# Optional overrides:
#   WAIT_TIMEOUT_SECS  (default 1800) total polling budget
#   WAIT_GRACE_SECS    (default  90)  window for a sibling branch-push
#                                      event to register its CI run
#   WAIT_POLL_SECS     (default  30)  poll interval
#   WAIT_WORKFLOW_PATH (default .github/workflows/ci.yml)
#
# Usage (from a workflow job carrying permissions: actions: read):
#   ./scripts/release/wait-for-ci.sh
set -euo pipefail

TIMEOUT_SECS="${WAIT_TIMEOUT_SECS:-1800}"
GRACE_SECS="${WAIT_GRACE_SECS:-90}"
POLL_SECS="${WAIT_POLL_SECS:-30}"
WORKFLOW_PATH="${WAIT_WORKFLOW_PATH:-.github/workflows/ci.yml}"

: "${GITHUB_API_URL:?GITHUB_API_URL is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${GITHUB_TOKEN:?GITHUB_TOKEN is required}"

deadline=$(($(date +%s) + TIMEOUT_SECS))
grace_until=$(($(date +%s) + GRACE_SECS))

# Newest ci.yml push-run for the tagged SHA, or "" when none exists.
# Output: "status|conclusion|html_url" (conclusion is "-" until the
# run completes). The run list is filtered to event=push + branch=main
# so pull_request-triggered runs of the same SHA never satisfy or fail
# the gate.
newest_run() {
	curl -fsSL \
		-H "Authorization: Bearer ${GITHUB_TOKEN}" \
		-H "Accept: application/vnd.github+json" \
		"${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/actions/runs?event=push&branch=main&head_sha=${GITHUB_SHA}&per_page=50" |
		jq -r '[.workflow_runs[] | select(.path == "'"${WORKFLOW_PATH}"'")]
		        | sort_by(.run_number)
		        | .[-1]
		        | if . == null then "" else "\(.status)|\(.conclusion // "-")|\(.html_url)" end'
}

echo "[ci-gate] workflow: ${WORKFLOW_PATH}"
echo "[ci-gate] sha:      ${GITHUB_SHA}"
echo "[ci-gate] budget:   ${TIMEOUT_SECS}s (grace ${GRACE_SECS}s, poll ${POLL_SECS}s)"

while :; do
	summary="$(newest_run)"

	if [[ -z "${summary}" ]]; then
		if (($(date +%s) >= grace_until)); then
			echo "[ci-gate] PASS: no ci.yml push-run exists for this SHA after the grace period."
			echo "[ci-gate] (ci.yml's paths filter skipped this commit — a docs-only release; the"
			echo "[ci-gate]  unconditional gate-keepers.yml workflow still covered the push.)"
			exit 0
		fi
		echo "[ci-gate] no ci.yml run visible yet (commit+tag pushed together?); polling..."
	elif [[ "${summary}" == completed\|* ]]; then
		IFS='|' read -r status conclusion url <<<"${summary}"
		if [[ "${conclusion}" == "success" ]]; then
			echo "[ci-gate] PASS: ci.yml completed with conclusion=success."
			echo "[ci-gate] run: ${url}"
			exit 0
		fi
		echo "::error::ci.yml concluded '${conclusion}' for the tagged SHA — the publish pipeline is blocked."
		echo "::error::run: ${url}"
		if [[ "${conclusion}" == "cancelled" ]]; then
			echo "::error::A cancelled CI never verified this code (a newer main push likely"
			echo "::error::cancelled it via ci.yml's cancel-in-progress). Re-run CI for the SHA"
			echo "::error::(Actions UI or: gh run rerun <run-id>), then re-run this gate job —"
			echo "::error::or re-push the tag."
		fi
		exit 1
	else
		IFS='|' read -r status conclusion url <<<"${summary}"
		echo "[ci-gate] ci.yml run is ${status} (conclusion so far: ${conclusion}); waiting ${POLL_SECS}s..."
	fi

	if (($(date +%s) + POLL_SECS > deadline)); then
		echo "::error::ci-gate timed out after ${TIMEOUT_SECS}s waiting for ci.yml on ${GITHUB_SHA}."
		echo "::error::Re-run this gate job once CI finishes, or push the tag again."
		exit 1
	fi
	sleep "${POLL_SECS}"
done
