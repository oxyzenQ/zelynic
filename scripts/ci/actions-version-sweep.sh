#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# NIGHT-improve-39: the CI actions version sweep — the engine of
# the actions-pin health contract. The owner's LTS ask: every
# `uses:` reference in the CI estate upgrades itself — major,
# minor, or patch — so the workflows never rot on stale action
# pins. The final form is contributor-carried: pins are read on
# every commit (scripts/gates/check-actions-pins.sh,
# NIGHT-improve-40) and healed on demand (--apply, then a normal
# human commit) — no server-side healer, no standing push
# credential (the retired weekly lane's SELF_HEAL_PAT secret was
# exactly the standing-credential hassle the owner refused).
#
# The sweep contract, per uses: reference:
#   - SHA pins with a version comment (the estate's NIGHT-hunt-20
#     shape, "# v5, <lineage note>") heal to the latest stable
#     release's commit SHA. The comment's version token moves with a
#     major bump (v5 -> v7) and keeps the author's chosen form: a
#     major-only token stays major-only, an exact token goes exact.
#   - A pin already sitting on the release commit is CURRENT: the
#     SHA is the pin's identity, and the comment token keeps the
#     author's chosen form (a major-only "v7" beside latest v7.0.1
#     is a label, never a version behind).
#   - Tag pins (@v4) bump to the latest major tag when a newer major
#     exists; the moving major tag already carries minor/patch.
#
# What the sweep never touches — the honesty rules:
#   - local actions (./...), docker:// refs, branch pins: not
#     version pins, out of scope by construction;
#   - a pin AHEAD of the latest release: a deliberate pin wins over
#     the sweep (reported, left alone);
#   - a repo with neither a latest release nor semver tags (the
#     dtolnay/rust-toolchain @stable shape): reported as SKIP,
#     healed by a human decision, never by a guess;
#   - a SHA pin whose comment carries no version token: the pin
#     cannot be compared without guessing, so it is reported as
#     SKIP with the reason (add the "# vN" token to enlist it);
#   - anything outside .github/workflows/: the diff guard fails the
#     heal before the tree can be committed (maintenance.yml's
#     dependency-only-diff discipline, applied to the CI surface).
#
# Version truth: GitHub releases/latest (stable releases only, no
# prereleases) with a /tags fallback for release-less repos. The
# release tag's commit SHA is resolved through the git refs API with
# annotated-tag peeling, so a healed SHA pin always names the commit
# the release tag names — the SHA-pinning security posture the
# estate adopted in NIGHT-hunt-20 is kept, never traded for a
# moving tag.
#
# Usage:
#   scripts/ci/actions-version-sweep.sh --dry-run   # report only
#   scripts/ci/actions-version-sweep.sh --apply     # edit workflows
#
# --apply heals the workflow files in place and then proves, via
# guard_diff, that the heal only ever touched .github/workflows/.
# What happens next is deliberately manual: the maintainer
# reviews, stages, and commits the healed pins like any other
# change — the commit-time hook re-reads the healed tree, and the
# push rides the contributor's own credentials (the owner's
# NIGHT-improve-39 final form: healing carried by contributors,
# never by a standing token a machine holds).
#
# Environment:
#   GITHUB_TOKEN      optional; authenticated API reads (1000
#                     req/h). Unauthenticated works (60 req/h) but
#                     a shared egress IP can exhaust that mid-sweep
#                     (check-actions-pins.sh picks the variable up
#                     too).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

API_ROOT="https://api.github.com"
MODE="dry-run"

# ── reporting ─────────────────────────────────────────────────────────────

HEALED=0
KEPT=0
SKIPPED=0

note() { echo "SWEEP: $*"; }
keep() { echo "KEEP:  $*"; }
skip() { echo "SKIP:  $*"; }

usage() {
	cat <<'EOF'
scripts/ci/actions-version-sweep.sh — the CI actions version sweep
(NIGHT-improve-39; the full design notes live in this file's
header).

modes:
  --dry-run   report the verdict table, change nothing
  --apply     heal the workflow files in place (no git ops)
EOF
}

# ── GitHub API helpers ────────────────────────────────────────────────────

API_STATUS="000"

# api_get <path> <out_var> — GET $API_ROOT<path>, storing the body
# in the NAMED variable and the HTTP status in API_STATUS (000
# means the call never completed — a network failure, distinct from
# any server answer). The body rides a printf -v instead of stdout
# so the status global survives: an api_get inside a $( ) subshell
# would silently eat the API_STATUS assignment, and every caller
# here reads the status right after the call.
api_get() {
	local path="$1" outvar="$2" raw status
	local args=(
		-sS --retry 3 --retry-all-errors --retry-delay 5
		--connect-timeout 15 --max-time 60
		-w '\n%{http_code}' "${API_ROOT}${path}"
	)
	if [ -n "${GITHUB_TOKEN:-}" ]; then
		args+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
	fi
	raw="$(curl "${args[@]}" 2>/dev/null || true)"
	status="${raw##*$'\n'}"
	API_STATUS="${status:-000}"
	printf -v "$outvar" '%s' "${raw%$'\n'*}"
}

# resolve_tag_sha <repo> <tag> — the commit SHA the tag names, with
# annotated tags peeled through the git objects API (a lightweight
# tag's ref already points at the commit; an annotated tag's ref
# points at the tag object, whose own record names the commit).
resolve_tag_sha() {
	local repo="$1" tag="$2" ref obj_sha obj_type tagobj
	api_get "/repos/${repo}/git/ref/tags/${tag}" ref
	[ "$API_STATUS" = "200" ] || return 1
	obj_sha="$(printf '%s' "$ref" | jq -r '.object.sha // empty')"
	obj_type="$(printf '%s' "$ref" | jq -r '.object.type // empty')"
	if [ "$obj_type" = "tag" ]; then
		api_get "/repos/${repo}/git/tags/${obj_sha}" tagobj
		[ "$API_STATUS" = "200" ] || return 1
		jq -r '.object.sha // empty' <<<"$tagobj"
	else
		printf '%s\n' "$obj_sha"
	fi
}

# Per-repo caches: the latest stable version tag, its commit SHA,
# and a verdict for repos the sweep cannot size up.
declare -A LATEST_TAG=()
declare -A LATEST_SHA=()
declare -A REPO_VERDICT=()

# query_repo <repo> — fill LATEST_TAG (or REPO_VERDICT with the
# honest reason it stayed empty). releases/latest is primary; the
# newest semver tag is the fallback for release-less repos.
query_repo() {
	local repo="$1" body tag
	if [ -n "${LATEST_TAG[$repo]:-}" ] || [ -n "${REPO_VERDICT[$repo]:-}" ]; then
		return 0
	fi
	api_get "/repos/${repo}/releases/latest" body
	if [ "$API_STATUS" = "200" ]; then
		tag="$(printf '%s' "$body" | jq -r '.tag_name // empty')"
		if [ -n "$tag" ] && is_semver "$tag"; then
			LATEST_TAG[$repo]="$tag"
			return 0
		fi
	fi
	if [ "$API_STATUS" = "404" ] || [ "$API_STATUS" = "200" ]; then
		api_get "/repos/${repo}/tags?per_page=100" body
		if [ "$API_STATUS" = "200" ]; then
			tag="$(printf '%s' "$body" | jq -r '.[].name' |
				grep -E '^v?[0-9]+(\.[0-9]+)*$' |
				sort -V | tail -n 1 || true)"
			if [ -n "$tag" ]; then
				LATEST_TAG[$repo]="$tag"
				return 0
			fi
			REPO_VERDICT[$repo]="no releases and no semver tags"
			return 0
		fi
	fi
	REPO_VERDICT[$repo]="api unreachable (status ${API_STATUS})"
}

# ensure_latest_sha <repo> — resolve the latest tag's commit SHA.
ensure_latest_sha() {
	local repo="$1" sha
	[ -z "${LATEST_SHA[$repo]:-}" ] || return 0
	sha="$(resolve_tag_sha "$repo" "${LATEST_TAG[$repo]}")" || sha=""
	if [ -n "$sha" ]; then
		LATEST_SHA[$repo]="$sha"
	else
		REPO_VERDICT[$repo]="tag ${LATEST_TAG[$repo]} unresolvable"
	fi
}

# ── version math ──────────────────────────────────────────────────────────

is_semver() {
	printf '%s' "$1" | grep -Eq '^v?[0-9]+(\.[0-9]+)*$'
}

version_tuple() {
	local v="${1#v}"
	local maj min patch
	IFS='.' read -r maj min patch <<<"$v"
	printf '%s %s %s' "${maj:-0}" "${min:-0}" "${patch:-0}"
}

version_cmp() {
	local a_maj a_min a_pat b_maj b_min b_pat
	read -r a_maj a_min a_pat <<<"$(version_tuple "$1")"
	read -r b_maj b_min b_pat <<<"$(version_tuple "$2")"
	if [ "$a_maj" -lt "$b_maj" ]; then
		printf '%s\n' -1
	elif [ "$a_maj" -gt "$b_maj" ]; then
		printf '%s\n' 1
	elif [ "$a_min" -lt "$b_min" ]; then
		printf '%s\n' -1
	elif [ "$a_min" -gt "$b_min" ]; then
		printf '%s\n' 1
	elif [ "$a_pat" -lt "$b_pat" ]; then
		printf '%s\n' -1
	elif [ "$a_pat" -gt "$b_pat" ]; then
		printf '%s\n' 1
	else
		printf '%s\n' 0
	fi
}

major_of() {
	local maj _min _pat
	read -r maj _min _pat <<<"$(version_tuple "$1")"
	printf '%s' "$maj"
}

# ── the sweep ─────────────────────────────────────────────────────────────

declare -a EDIT_FILE=()
declare -a EDIT_LINE=()
declare -a EDIT_NEW=()

# The per-line edit ledger is grouped by file at apply time; every
# entry is a whole-line replacement built from the original line.
record_edit() {
	EDIT_FILE+=("$1")
	EDIT_LINE+=("$2")
	EDIT_NEW+=("$3")
}

sweep() {
	local file lineno content rest value action_part ref comment
	local owner name repo
	while IFS=: read -r file lineno content; do
		[ -n "${file:-}" ] || continue
		# Only `uses:` lines carry action references; the regex keeps
		# the optional list dash and captures the ref token plus the
		# trailing comment (which may carry the pin's version token).
		if ! [[ $content =~ ^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*([^[:space:]#]+)(.*)$ ]]; then
			continue
		fi
		value="${BASH_REMATCH[2]}"
		rest="${BASH_REMATCH[3]}"
		comment=""
		if [[ $rest =~ ^[[:space:]]*# ]]; then
			comment="$rest"
		fi
		action_part="${value%@*}"
		ref="${value##*@}"
		if [[ $action_part == .* || $action_part == docker:* ]]; then
			skip "${value} — local/docker reference, not a version pin"
			SKIPPED=$((SKIPPED + 1))
			continue
		fi
		IFS='/' read -r owner name _rest <<<"$action_part"
		repo="${owner}/${name}"
		if ! [[ $repo =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
			skip "${value} — unparsable action reference"
			SKIPPED=$((SKIPPED + 1))
			continue
		fi

		if [[ $ref =~ ^[0-9a-fA-F]{40}$ ]]; then
			sweep_sha_pin "$file" "$lineno" "$content" \
				"$repo" "$action_part" "$ref" "$value" "$comment"
		elif [[ $ref =~ ^v[0-9]+(\.[0-9]+)*$ ]]; then
			sweep_tag_pin "$file" "$lineno" "$content" \
				"$repo" "$action_part" "$ref" "$value"
		else
			skip "${repo}@${ref} — branch-style ref, not a version pin"
			SKIPPED=$((SKIPPED + 1))
		fi
	done < <(grep -nE '^[[:space:]]*(-[[:space:]]+)?uses:' .github/workflows/*.yml)
}

# sweep_sha_pin — the estate's own pin shape: 40-hex ref plus a
# "# vN" version token in the trailing comment.
sweep_sha_pin() {
	local file="$1" lineno="$2" content="$3" repo="$4" action_part="$5"
	local ref="$6" value="$7" comment="$8"
	local cur_ver token latest cmp new_line new_sha new_token

	token=""
	if [[ $comment =~ v[0-9]+(\.[0-9]+)* ]]; then
		token="${BASH_REMATCH[0]}"
	fi
	if [ -z "$token" ]; then
		skip "${repo} — no version token in the pin comment; add \"# vN\" to enlist it"
		SKIPPED=$((SKIPPED + 1))
		return 0
	fi
	cur_ver="$token"

	query_repo "$repo"
	if [ -n "${REPO_VERDICT[$repo]:-}" ]; then
		skip "${repo} — ${REPO_VERDICT[$repo]}"
		SKIPPED=$((SKIPPED + 1))
		return 0
	fi
	latest="${LATEST_TAG[$repo]}"
	ensure_latest_sha "$repo"
	if [ -n "${REPO_VERDICT[$repo]:-}" ]; then
		skip "${repo} — ${REPO_VERDICT[$repo]}"
		SKIPPED=$((SKIPPED + 1))
		return 0
	fi
	new_sha="${LATEST_SHA[$repo]}"
	cmp="$(version_cmp "$cur_ver" "$latest")"

	if [ "$cmp" = "1" ]; then
		keep "${repo} — pinned ${cur_ver} is ahead of latest release ${latest}"
		KEPT=$((KEPT + 1))
		return 0
	fi
	# The pin's identity is the SHA, not the comment's token: a pin
	# already sitting on the release commit is CURRENT in every form
	# its token takes (a major-only "v7" beside latest v7.0.1 is the
	# author's chosen label, never a version behind — the first live
	# dispatch reported 29 no-op "heals" on an already-healed tree
	# before this rule existed).
	if [ "$ref" = "$new_sha" ]; then
		keep "${repo} — ${cur_ver} pinned at the latest release commit"
		KEPT=$((KEPT + 1))
		return 0
	fi

	new_line="${content/${value}/${action_part}@${new_sha}}"
	if [ "$cmp" = "-1" ] && [ "$(major_of "$cur_ver")" != "$(major_of "$latest")" ]; then
		# Major moved: the comment's version token moves with it,
		# preserving the author's chosen form (major-only vs exact).
		if [ "$token" = "v$(major_of "$cur_ver")" ]; then
			new_token="v$(major_of "$latest")"
		else
			new_token="v${latest#v}"
		fi
		new_line="${new_line/${token}/${new_token}}"
	elif [ "$cmp" = "0" ]; then
		note "${repo} — pin drift: ${cur_ver} current but the SHA moved; re-pinning to the release commit"
	fi
	record_edit "$file" "$lineno" "$new_line"
	note "${repo} (${file#./}:${lineno}) — ${cur_ver} -> ${latest}, SHA ${ref:0:12} -> ${new_sha:0:12} HEAL"
	HEALED=$((HEALED + 1))
}

# sweep_tag_pin — a moving major tag (@v4). Minor and patch ride the
# tag; only a newer major needs the sweep's help.
sweep_tag_pin() {
	local file="$1" lineno="$2" content="$3" repo="$4" action_part="$5"
	local ref="$6" value="$7"
	local latest cmp new_ref new_line

	query_repo "$repo"
	if [ -n "${REPO_VERDICT[$repo]:-}" ]; then
		skip "${repo} — ${REPO_VERDICT[$repo]}"
		SKIPPED=$((SKIPPED + 1))
		return 0
	fi
	latest="${LATEST_TAG[$repo]}"
	cmp="$(version_cmp "$ref" "$latest")"
	if [ "$cmp" != "-1" ]; then
		keep "${repo}@${ref} — latest release ${latest} needs no tag move"
		KEPT=$((KEPT + 1))
		return 0
	fi
	if [ "$(major_of "$ref")" = "$(major_of "$latest")" ]; then
		keep "${repo}@${ref} — the moving tag already carries ${latest}"
		KEPT=$((KEPT + 1))
		return 0
	fi
	# Preserve the author's form: an exact tag pin goes exact, a
	# major-only tag pin goes major-only.
	if [[ $ref == *.* ]]; then
		new_ref="v${latest#v}"
	else
		new_ref="v$(major_of "$latest")"
	fi
	new_line="${content/${value}/${action_part}@${new_ref}}"
	record_edit "$file" "$lineno" "$new_line"
	note "${repo} (${file#./}:${lineno}) — ${ref} -> ${new_ref} HEAL (tag pin)"
	HEALED=$((HEALED + 1))
}

# ── apply / guard ────────────────────────────────────────────────

apply_edits() {
	local i j f idx lines
	declare -A seen=()
	for i in "${!EDIT_FILE[@]}"; do
		f="${EDIT_FILE[$i]}"
		[ -z "${seen[$f]:-}" ] || continue
		seen[$f]=1
		lines=()
		mapfile -t lines <"$f"
		for j in "${!EDIT_FILE[@]}"; do
			[ "${EDIT_FILE[$j]}" = "$f" ] || continue
			idx=$((EDIT_LINE[j] - 1))
			lines[idx]="${EDIT_NEW[$j]}"
		done
		printf '%s\n' "${lines[@]}" >"$f"
	done
}

# guard_diff — the sweep may only move workflow files. Any tracked
# change elsewhere means the sweep (or the tree) is not what this
# script believes it is; fail before a commit can exist. Tracked
# changes only, maintenance.yml's dependency-only-diff shape: an
# untracked file is never the sweep's doing (apply_edits writes
# only to workflow files), and a dirty local tree is its owner's
# business, not this guard's.
guard_diff() {
	local offender
	offender="$({
		git diff --name-only
		git diff --cached --name-only
	} |
		sort -u |
		grep -Ev '^\.github/workflows/[A-Za-z0-9_.-]+\.yml$' || true)"
	if [ -n "$offender" ]; then
		echo "FAIL: tracked files outside .github/workflows/ changed:"
		echo "$offender"
		exit 1
	fi
}

# ── main ──────────────────────────────────────────────────────────────────

case "${1:-}" in
--dry-run) MODE="dry-run" ;;
--apply) MODE="apply" ;;
-h | --help)
	usage
	exit 0
	;;
"") ;;
*)
	echo "unknown mode: $1" >&2
	usage >&2
	exit 2
	;;
esac

sweep
if [ "$MODE" != "dry-run" ] && [ "${#EDIT_FILE[@]}" -gt 0 ]; then
	apply_edits
fi

# The heal is proven sweep-only before the tree is handed to a
# human commit (the maintainer stages and commits it themselves).
if [ "$MODE" = "apply" ] && [ "${#EDIT_FILE[@]}" -gt 0 ]; then
	guard_diff
fi

echo ""
echo "sweep verdict: ${HEALED} healed, ${KEPT} kept, ${SKIPPED} skipped (mode: ${MODE})"
