#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# The supply-chain verdict (night-solid-defense-1): the Sunday
# maintenance lane audits every workspace lockfile against the RustSec
# advisory database and speaks the owner's two scenarios. The walk is
# the same walk the sweep script owns
# (scripts/ci/sweep-cargo-workspaces.sh — every committed Cargo.toml
# becomes its workspace's Cargo.lock), so every workspace rides the
# verdict (the audit lane's per-push scan already covers all four
# committed lockfiles — night-supply-1 — and this gate is the Sunday
# watch over the state that CHANGES between pushes: the advisory
# database and the registry, neither of which emits a commit event).
#
#   scenario A (fixable): the sweep cleared the finding. The advisory
#     was real, the auto-update took the clean version in the same
#     run, and the validated lane ships that fix. The job stays green
#     and the owner still reads a loud notice: without the Sunday
#     lane the tree would have carried the advisory for a week (this
#     dep must be updated ASAP; unpatched it endangers the project).
#
#   scenario B (unfixable): the finding survives the sweep - no fixed
#     version inside the current version requirements, or no fix
#     released at all. The job fails hard: the dep is dangerous and
#     no automatic update can take it - CALL OWNER. The commit job is
#     gated on the verdict, so nothing ships while the lane is red.
#
# Fail-closed law: a scanner that cannot run or cannot be parsed is a
# verdict failure, never a silent pass.
#
# Identity (night-solid-defense-1, the zejtron precedent): the verdict
# speaks under the owner's sentinel name - AXP1-ZnQ (Architect's eXecution Protocol 1).
# The banners, the
# annotations, and the step summary all sign as AXP1-ZnQ, so a red
# Sunday names its watcher and the run list reads like a sentinel on
# watch.
#
# Modes:
#   --pre   scan the as-committed lockfiles, store findings for the
#           post-pass diff
#   --post  scan the swept lockfiles, diff against the stored pre
#           findings, emit the verdict (exit 1 on scenario B)

set -Eeuo pipefail

mode="${1:-}"
case "$mode" in
--pre) ;;
--post) ;;
*)
	echo "usage: $0 --pre | --post" >&2
	exit 2
	;;
esac

for tool in cargo jq awk; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "error: $tool is missing - AXP1-ZnQ cannot scan (fail-closed)" >&2
		exit 1
	fi
done

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

state_dir="${RUNNER_TEMP:-/tmp}/supplychain-verdict"
pre_dir="$state_dir/pre"
post_dir="$state_dir/post"
mkdir -p "$pre_dir" "$post_dir"
pre_tsv="$state_dir/pre.tsv"
post_tsv="$state_dir/post.tsv"
cleared_tsv="$state_dir/cleared.tsv"
# The GitHub step summary (unset locally: the /dev/null fallback keeps
# the rendering law a no-op outside Actions).
summary_file="${GITHUB_STEP_SUMMARY:-/dev/null}"

# The deterministic lockfile walk: the same walk the sweep script owns
# (every committed workspace, target trees excluded, sorted - the same
# tree, the same order).
lockfiles="$(find . -name Cargo.lock -not -path '*/target/*' | sort)"
if [[ -z "$lockfiles" ]]; then
	echo "error: no Cargo.lock found under $repo_root - AXP1-ZnQ cannot scan (fail-closed)" >&2
	exit 1
fi

# One advisory row per line, TSV:
#   workspace | kind | id | package | version | severity | patched
# cargo-audit prints advisory-driven findings (vulnerabilities,
# unmaintained, unsound) and registry-only yanked entries in
# different shapes; the coalescing reads both, and the row count -
# not any one field - drives the verdict.
findings_for() {
	local lock="$1" workspace="$2" out="$3" dest="$4" json rc
	json="$out.json"
	rc=0
	cargo audit --json -f "$lock" >"$json" || rc=$?
	# cargo-audit exits 1 when findings exist - the JSON report is
	# still written and is the truth, so 0 and 1 both parse. Any
	# other exit is a scanner failure: fail-closed.
	case "$rc" in
	0 | 1) ;;
	*)
		echo "::error::AXP1-ZnQ: cargo audit failed (exit $rc) on $workspace ($lock) - a scanner that cannot run fails the lane, never passes it" >&2
		exit 1
		;;
	esac
	# A zero-document report (an empty or truncated file) is also a
	# scanner failure: type == "object" demands exactly the report
	# shape, jq -e exits 4 when it never produced a result.
	if ! jq -e 'type == "object"' "$json" >/dev/null 2>&1; then
		echo "::error::AXP1-ZnQ: cargo audit output is not valid JSON for $workspace ($lock)" >&2
		exit 1
	fi
	# The live-measured cargo-audit 0.22.2 shapes (the fixture
	# battery caught the crash class): vulnerabilities and
	# informational arrive as objects with .list, the three warning
	# families (unmaintained, unsound, yanked) arrive as plain
	# arrays, and every family can be absent or null. One
	# normalizer reads all of it; a shape the coalescer cannot
	# read still fails closed (jq exits non-zero, the lane dies
	# loudly), never silently empty.
	jq -r '
		def items: (if type == "object" then (.list // []) else (. // []) end)[];
		def rows(kind):
			items |
			[kind,
			 (.advisory.id // .id // kind),
			 (.package.name // .crate // "?"),
			 (.package.version // .version // "?"),
			 (.advisory.metadata.severity // "unspecified"),
			 ((.versions.patched // []) | join(","))] | @tsv;
		(.vulnerabilities | rows("vulnerability")),
		(.warnings.unmaintained | rows("unmaintained")),
		(.warnings.unsound | rows("unsound")),
		(.warnings.yanked | rows("yanked")),
		(.informational | rows("informational"))
	' "$json" | awk -v ws="$workspace" 'BEGIN { OFS = "\t" } { print ws, $0 }' >>"$dest"
}

if [[ "$mode" == "--pre" ]]; then
	: >"$pre_tsv"
	while IFS= read -r lock; do
		dir="$(dirname "$lock")"
		dir="${dir#./}"
		[[ "$dir" == "." ]] && dir="root"
		findings_for "$lock" "$dir" "$pre_dir/$dir" "$pre_tsv"
	done <<<"$lockfiles"
	pre_count="$(grep -c . "$pre_tsv" || true)"
	echo "AXP1-ZnQ pre-pass: ${pre_count:-0} finding(s) stored across $(printf '%s\n' "$lockfiles" | wc -l) workspace(s)"
	exit 0
fi

# ── --post: scan the swept lane, then the verdict ────────────────────
: >"$post_tsv"
while IFS= read -r lock; do
	dir="$(dirname "$lock")"
	dir="${dir#./}"
	[[ "$dir" == "." ]] && dir="root"
	findings_for "$lock" "$dir" "$post_dir/$dir" "$post_tsv"
done <<<"$lockfiles"

# The scenario A diff: pre findings whose key is gone from the swept
# lane were cleared by the update. The key drops the version (an
# update fixes BY moving the version); yanked findings key on the
# version (the identity there is the exact yanked release).
#
# The join reads the COMPOSITE key, and the cleared rows print WHOLE:
# a workspace whose lane keeps one surviving finding must still report
# its cleared sibling (a workspace-granularity join would silently
# drop it), and the cleared banner + step-summary table must read the
# same seven columns every other table reads (a prefix-stripped keyed
# line would shift them - the fixture run proved the garble live).
tab="$(printf '\t')"
key_of() {
	awk -F "$tab" -v OFS="$tab" '{
		if ($2 == "yanked") print $1, $2, $4, $5
		else print $1, $2, $3, $4
	}' "$1"
}
key_of "$post_tsv" >"$state_dir/keyed-post.tsv"
# File-order walk (the determinism law): cleared in pre order. The
# FILENAME guard keeps the join correct even when the swept lane is
# empty (an empty first file breaks the classic FNR == NR trick).
awk -F "$tab" 'FILENAME == ARGV[1] { seen[$0] = 1; next }
	{
		key = ($2 == "yanked") ? $1 FS $2 FS $4 FS $5 : $1 FS $2 FS $3 FS $4
		if (!(key in seen)) print
	}' \
	"$state_dir/keyed-post.tsv" "$pre_tsv" >"$cleared_tsv"

still_bad="$(awk -F "$tab" '$2 == "vulnerability" || $2 == "unmaintained" || $2 == "unsound" || $2 == "yanked"' "$post_tsv" || true)"
still_info="$(awk -F "$tab" '$2 == "informational"' "$post_tsv" || true)"
bad_count="$(printf '%s' "$still_bad" | grep -c . || true)"
info_count="$(printf '%s' "$still_info" | grep -c . || true)"
cleared_count="$(grep -c . "$cleared_tsv" || true)"
ws_count="$(printf '%s\n' "$lockfiles" | wc -l)"
: "${bad_count:=0}"
: "${info_count:=0}"
: "${cleared_count:=0}"

# ── The loud layer: annotations + step summary + the banner ─────────
summarize() {
	local title="$1" rows="$2" verdict="$3"
	{
		echo ""
		echo "### AXP1-ZnQ verdict: $title"
		echo ""
		echo "| workspace | kind | id | package | version | severity | patched | verdict |"
		echo "| --- | --- | --- | --- | --- | --- | --- | --- |"
		while IFS="$tab" read -r ws kind id pkg ver sev patched; do
			[[ -n "$ws" ]] || continue
			echo "| $ws | $kind | $id | $pkg | $ver | $sev | ${patched:-none} | $verdict |"
		done <"$rows"
	} >>"$summary_file" 2>/dev/null || true
}

printf '%s\n' "$still_bad" >"$state_dir/still-bad.tsv"
printf '%s\n' "$still_info" >"$state_dir/still-info.tsv"

if [[ "$summary_file" != "/dev/null" ]] && [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
	{
		echo "### AXP1-ZnQ supply-chain verdict (night-solid-defense-1)"
		echo ""
		echo "workspaces scanned: $ws_count | pre-sweep findings: $(grep -c . "$pre_tsv" 2>/dev/null || true) | cleared by the sweep: $cleared_count | still present (hard): $bad_count | informational: $info_count"
	} >>"$GITHUB_STEP_SUMMARY"
	[[ "$cleared_count" -gt 0 ]] && summarize "cleared by the sweep (scenario A)" "$cleared_tsv" "cleared - fix ships in this run"
	[[ "$bad_count" -gt 0 ]] && summarize "still present after the sweep (scenario B - CALL OWNER)" "$state_dir/still-bad.tsv" "STILL PRESENT - call owner"
	[[ "$info_count" -gt 0 ]] && summarize "informational" "$state_dir/still-info.tsv" "notice"
fi

if [[ "$cleared_count" -gt 0 ]]; then
	echo "=================================================================="
	echo "  AXP1-ZnQ: vulnerable dependency cleared by this run"
	echo "=================================================================="
	while IFS="$tab" read -r ws kind id pkg ver sev patched; do
		[[ -n "$ws" ]] || continue
		echo "  - $ws | $kind $id | $pkg $ver | severity $sev | now patched: ${patched:-yes}"
		echo "    the Sunday sweep took the fix; without this lane the tree"
		echo "    would have carried the advisory for a week"
		echo "::warning title=AXP1-ZnQ notice::$ws $kind $id ($pkg $ver) was present and the sweep cleared it - the fix ships in this run; without the weekly lane the tree would have carried it"
	done <"$cleared_tsv"
	echo "=================================================================="
fi

if [[ "$bad_count" -gt 0 ]]; then
	echo "=================================================================="
	echo "  AXP1-ZnQ SUPPLY-CHAIN VERDICT: FAIL - CALL OWNER"
	echo "=================================================================="
	while IFS="$tab" read -r ws kind id pkg ver sev patched; do
		[[ -n "$ws" ]] || continue
		if [[ -n "$patched" ]]; then
			fix="fixed in ${patched} - outside the current version requirement, cargo update cannot take it"
		else
			fix="no fixed version released - no automatic update path exists"
		fi
		echo "  - $ws | $kind $id | $pkg $ver | severity $sev"
		echo "    $fix"
		echo "::error::AXP1-ZnQ: $ws $kind $id ($pkg $ver, severity $sev) survives the sweep ($fix) - dangerous dep, cannot be auto-updated; CALL OWNER"
	done <<<"$still_bad"
	echo "=================================================================="
	echo "  AXP1-ZNQ HOLDS THE LANE: the deps above are dangerous and"
	echo "  cannot be auto-updated. CALL THE OWNER - the commit lane is"
	echo "  gated on this verdict, nothing ships while the advisory"
	echo "  survives the sweep."
	echo "=================================================================="
	echo "still present: $bad_count hard finding(s), $info_count informational, $cleared_count cleared by the sweep"
	exit 1
fi

if [[ "$info_count" -gt 0 ]]; then
	awk -F "$tab" '{ printf "  notice: %s | %s | %s %s (informational)\n", $1, $3, $4, $5 }' "$state_dir/still-info.tsv"
fi

echo "AXP1-ZnQ verdict: PASS - $ws_count workspace(s) scanned, $bad_count hard finding(s), $cleared_count cleared by the sweep, $info_count informational"
exit 0
