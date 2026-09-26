#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# PLATFORM: UNIX-only (Linux). zelynic is a Linux-only tool.
#
# ─────────────────────────────────────────────────────────────────────────────
# zelynic Release Note Generator — the cosmostrix release-page style
# (NIGHT-blade-11), single source of truth for the release body.
#
# Called by .github/workflows/release.yml ("Generate release body" step).
# Output: GitHub-flavored Markdown to stdout, designed for the body of a
# GitHub Release (softprops/action-gh-release body_path).
#
# Aesthetic (the mature cosmostrix releases page, owner-approved
# 2026-08-23): cold, silent, cosmic dragon. Zero emoji. GitHub alerts
# are the only native color mechanism — [!WARNING] for pre-releases,
# [!TIP] for stable. Every category count is a clickable <details>
# toggle that expands the per-commit changelog; every commit hash
# links to its GitHub commit page; the full changelog rides a collapsed
# details block with the compare link; the verification section (GPG +
# checksum policy) lives here so the release body has exactly one
# implementation.
#
# ARCHITECTURE (the zelynic difference): this port renders from the
# GitHub compare API JSON, not `git log` — the release job carries no
# repository history by design (NIGHT-improve-20: no fetch-depth 0
# clone; API ordering beats `git tag --sort=-creatordate` on re-pointed
# tags). The tradeoff is recorded here honestly: the cosmostrix
# classifier's stage 1 (diff-stat ground truth: a commit whose changed
# files are all *.md is docs work) needs per-commit file lists the
# compare API does not carry, so this port classifies from subjects
# alone (a guarded keyword scan). The <details> categories are
# navigational, the full changelog below them is complete — a misfiled
# commit is never a hidden commit.
#
# COMMIT CLASSIFICATION (zelynic subject shapes):
#   1. "Internal research: NIGHT-<word>-<num> — description" — the
#      repo's primary convention. The NIGHT-* task marker is stripped
#      for classification (it names the task, not the change type) and
#      KEPT for display (the markers are the campaign's identity).
#      Optional "- zelynic" task-marker prefixes are stripped both
#      ways. What remains is keyword-scanned (first 10 words, cleaned):
#        fix  > test > docs > feat > chore  (priority order)
#      anything else -> others.
#   2. Conventional commits "type(scope)!: subject" — type mapped
#      directly; the scope is bolded for display.
#   3. Bare subjects -> others.
#
# USAGE:
#   ./scripts/release/generate-release-notes.sh \
#       --tag v11.0.0-beta.3 --prerelease true \
#       --compare-json compare.json --prev-tag v11.0.0-beta.2 \
#       [--last-stable v10.0.0 --since-stable 42] \
#       [--repo-url https://github.com/oxyzenQ/zelynic]
#
#   --compare-json   the saved compare API response for
#                    PREV_TAG...TAG. Absent or empty = initial
#                    release (no previous tag).
#   --prev-tag       previous tag — any channel for pre-releases, the
#                    last stable tag for stable releases (the workflow
#                    computes both boundaries).
#   --last-stable    last STABLE tag. With --since-stable, renders the
#                    dual range line pre-release testers get in the
#                    cosmostrix style: "N commits since previous
#                    build · M commits since last stable".
#   --since-stable   commits in LAST_STABLE..TAG (the workflow counts
#                    them via a second compare call; API total_commits
#                    semantics, merge commits included).
#   --self-test      run the pinned classifier + shape battery, no
#                    network, no jq input, exit nonzero on any drift.
#
# Dependencies: bash 4+, jq (the GitHub runner image carries both;
# the workflow step already depended on jq before this script existed).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

TAG=""
IS_PRERELEASE="false"
COMPARE_JSON=""
PREV_TAG=""
LAST_STABLE=""
SINCE_STABLE=""
REPO_URL="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-oxyzenQ/zelynic}"
SELF_TEST=0

usage() {
	echo "Usage: $0 --tag TAG --prerelease true|false [--compare-json PATH]" >&2
	echo "            [--prev-tag TAG] [--last-stable TAG] [--since-stable N]" >&2
	echo "            [--repo-url URL] [--self-test]" >&2
}

while [ $# -gt 0 ]; do
	case "$1" in
	--tag)
		TAG="${2:?--tag needs a value}"
		shift 2
		;;
	--prerelease)
		IS_PRERELEASE="${2:?--prerelease needs a value}"
		shift 2
		;;
	--compare-json)
		COMPARE_JSON="${2:?--compare-json needs a value}"
		shift 2
		;;
	--prev-tag)
		PREV_TAG="${2:?--prev-tag needs a value}"
		shift 2
		;;
	--last-stable)
		LAST_STABLE="${2:?--last-stable needs a value}"
		shift 2
		;;
	--since-stable)
		SINCE_STABLE="${2:?--since-stable needs a value}"
		shift 2
		;;
	--repo-url)
		REPO_URL="${2:?--repo-url needs a value}"
		shift 2
		;;
	--self-test)
		SELF_TEST=1
		shift
		;;
	*)
		echo "unknown flag: $1" >&2
		usage
		exit 1
		;;
	esac
done

# ── Section order (the owner's release-note mockup: fix first) ────────
declare -A SECTION_ORDER
SECTION_ORDER[fix]=1
SECTION_ORDER[feat]=2
SECTION_ORDER[perf]=3
SECTION_ORDER[refactor]=4
SECTION_ORDER[docs]=5
SECTION_ORDER[test]=6
SECTION_ORDER[ci]=7
SECTION_ORDER[build]=8
SECTION_ORDER[chore]=9
SECTION_ORDER[_others]=99

# ── Keyword tables (zelynic-tuned against the real v10.0.0..beta.2
#    range subjects; see --self-test for the pinned battery) ──────────
FIX_KW='fix|fixes|fixed|repair|repairs|heal|healed|resurrect|resurrected|refuse|refuses|close|closes|plug|dedup|restore|restored|harden|hardened|guard|guards|kill|killed|hang|hangs|deadlock|race|corrupt|regression|revert|stale|dead|miscount|undercount|drift|broken|breaks|crash|crashes|bypass|compiles|compiled'
TEST_KW='battery|harness|stresstest|self-test|e2e|endurance|prove|proves|proof|pins|pinning'
DOCS_KW='docs|doc|document|documents|changelog|record|audit|sweep|research|study|verdict|verify|verified|honest|notes|readme|usage|examples|benchmark'
FEAT_KW='add|adds|added|implement|introduce|introduces|extend|extends|port|ports|create|embed|merge|merged|unify|sharpen|enable|support|apply|applies|alias'
CHORE_KW='bump|pin|pinned|trim|trimmed|deps|dependencies|cleanup|tidy|version|rename|renamed|retire|retired|refresh|release|releases'

# Clean a subject for keyword scanning: strip the repo prefix, the
# optional "- zelynic" marker, and the NIGHT-* task token (its
# "research"/"hunt"/"boost" words would fire the docs/feat tables on
# every commit), lowercase, drop parentheticals (finding IDs and hash
# mentions live there) and path-like tokens ("PERFORMANCE.md" would
# match "docs" without this; "arch-baseline" and "A/B record" carry
# their own separators and leave the same way; NOTE the class is
# [./-] not the reference's [./:-] — a colon here eats "audit:" and
# "hardened:", the exact keyword tokens this campaign's subjects put
# right before their clause colons, and URLs still leave via the
# slash), then keep the first
# 10 words — secondary clauses ("... and add X") far out must not
# reclassify the commit, but 10 not 8: this campaign's subjects lead
# with long noun phrases (the diff engine and cosmic dragon engine
# depth AUDIT — the signal word is #10; the cosmostrix 8-word window
# would lose it).
scan_text() {
	printf '%s' "$1" |
		sed -E 's/^[Ii]nternal [Rr]esearch:[[:space:]]*//' |
		sed -E 's/^-[[:space:]]*zelynic[[:space:]]+//' |
		tr '[:upper:]' '[:lower:]' |
		sed -E 's/^night-[a-z]+-[0-9]+[[:space:]]+//' |
		sed -E 's@^a/b record[[:space:]]+@@' |
		sed -E 's/\([^)]*\)//g' |
		sed -E 's/[^[:space:]]*[./-][^[:space:]]*//g' |
		tr -s '[:space:]' ' ' |
		cut -d' ' -f1-10
}

# Map a conventional-commit type to a section key.
ctype_to_section() {
	case "$1" in
	fix | revert) echo "fix" ;;
	feat) echo "feat" ;;
	perf) echo "perf" ;;
	refactor) echo "refactor" ;;
	docs) echo "docs" ;;
	test) echo "test" ;;
	ci) echo "ci" ;;
	build) echo "build" ;;
	chore | style | bump) echo "chore" ;;
	*) echo "_others" ;;
	esac
}

classify_subject() {
	local subject="$1"
	local scan

	# The repo's primary convention: "Internal research: ..." (prefix
	# matched case-tolerantly: the history writes "Internal research:").
	if printf '%s' "$subject" | grep -qE '^[Ii]nternal [Rr]esearch:[[:space:]]*[A-Za-z-]'; then
		scan="$(scan_text "$subject")"
		if printf '%s' "$scan" | grep -qwE "$FIX_KW"; then
			echo "fix"
			return
		fi
		if printf '%s' "$scan" | grep -qwE "$TEST_KW"; then
			echo "test"
			return
		fi
		if printf '%s' "$scan" | grep -qwE "$DOCS_KW"; then
			echo "docs"
			return
		fi
		if printf '%s' "$scan" | grep -qwE "$FEAT_KW"; then
			echo "feat"
			return
		fi
		if printf '%s' "$scan" | grep -qwE "$CHORE_KW"; then
			echo "chore"
			return
		fi
		echo "_others"
		return
	fi

	# Conventional commit: type(scope)!: subject
	if printf '%s' "$subject" | grep -qE '^[a-zA-Z]+(\([^)]*\))?!?: .+'; then
		ctype_to_section "$(printf '%s' "$subject" | sed -E 's/^([a-zA-Z]+)(\([^)]*\))?!?: .*/\1/' | tr '[:upper:]' '[:lower:]')"
		return
	fi

	# Bare subject.
	echo "_others"
}

# Entry display text: strip process prefixes, keep the human part (the
# NIGHT-* task marker stays — it is the campaign's identity, exactly
# as the cosmostrix release page keeps its markers).
display_text() {
	local subject="$1"
	local scope desc
	if printf '%s' "$subject" | grep -qE '^[Ii]nternal [Rr]esearch:[[:space:]]*'; then
		printf '%s' "$subject" |
			sed -E 's/^[Ii]nternal [Rr]esearch:[[:space:]]*//' |
			sed -E 's/^-[[:space:]]*zelynic[[:space:]]+//'
		return
	fi
	if printf '%s' "$subject" | grep -qE '^[a-zA-Z]+(\([^)]*\))?!?: .+'; then
		scope="$(printf '%s' "$subject" | sed -nE 's/^[a-zA-Z]+\(([^)]*)\)!?: .+/\1/p')"
		desc="$(printf '%s' "$subject" | sed -E 's/^[a-zA-Z]+(\([^)]*\))?!?: //')"
		if [ -n "$scope" ]; then
			printf '**%s**: %s' "$scope" "$desc"
		else
			printf '%s' "$desc"
		fi
		return
	fi
	printf '%s' "$subject"
}

# ── The self-test: pinned classifier battery + shape contract ────────
# Every pinned subject below is a real shape from this repo's history
# (or a boundary probe for the grammar). If a future edit to the tables
# or the strip chain moves a verdict, this battery fails — the release
# page style is a contract now, not a coincidence. Two pinned verdicts
# are honest fuzz (noted inline): the priority order fix > test means
# kill/race fix-words win over battery/harness test-words — the
# categories are navigational, the full changelog is complete.
self_test() {
	local failures=0

	t_case() {
		local subject="$1"
		local expected="$2"
		local got
		got="$(classify_subject "$subject")"
		if [ "$got" != "$expected" ]; then
			echo "  FAIL classify: '$subject'" >&2
			echo "       expected '$expected' got '$got'" >&2
			failures=$((failures + 1))
		fi
	}

	# Real subjects from the v10.0.0..v11.0.0-beta.2 range and this
	# campaign (verdicts verified by hand against the actual diffs).
	t_case "Internal research: NIGHT-hunt-33 - the release musl build compiles again, statfs f_type is a u64 on musl and an i64 on glibc" fix
	t_case "Internal research: NIGHT-improve-20 - the release pipeline hardened: musl compiled on every push, lean single-commit clones, an API-rendered changelog, and a re-tag concurrency guard" fix
	t_case "Internal research: NIGHT-improve-21 - the brutal battery: kill, race, and re-prove" fix
	t_case "Internal research: NIGHT-improve-22 - arch-baseline releases only: v3 and v4, gnu and musl, locally reproducible" chore
	t_case "Internal research: NIGHT-boost-1 - eagle-eyes: observe + top merged into one unified live monitor" feat
	t_case "Internal research: - zelynic NIGHT-boost-4 help examples: notes above, commands green" docs
	t_case "Internal research: NIGHT-boost-1 A/B record - eagle-eyes merge benchmark appended to PERFORMANCE.md" docs
	t_case "Internal research: NIGHT-master-4 - the stale-data sweep across cross docs and commented code: the two stale spots removed" docs
	t_case "Internal research: NIGHT-blade-14 - the all-scripts audit under the no-sudo sandbox: one dead suite resurrected, and the shell gate becomes a quad" fix
	t_case "Internal research: NIGHT-blade-16 - the diff engine and cosmic dragon engine depth audit against the mature cosmostrix reference: per-frame allocations retired" docs
	# Conventional shapes from the pre-v11 history.
	t_case "docs: update PERFORMANCE.md with final v10 benchmark + test results" docs
	t_case "fix(release): update script list in release.yml - deleted scripts" fix
	t_case "chore: update deps" chore
	t_case "feat: block-multi + block-all + rename all-limit to limit-all" feat
	# Boundary probes: bare subjects (version marker, no prefix).
	t_case "v10.0.0 - peak optimization + maintenance mode begins" "_others"
	t_case "Internal research: - zelynic NIGHT-boost-2 CI estate: Gnu Dynamic named, plain release retired for the pro profiles" chore

	# Shape contract on a synthetic initial-release render: the
	# stability callout, the initial-release marker, and the
	# verification section must all appear.
	local out
	out="$(render_body "" "" "" "" "")"
	local want
	for want in "> [!TIP]" "Initial release." "## Verification" "recv-keys F5324E0967F104D58CE025F347A50AEF4B65AAC2"; do
		if ! printf '%s' "$out" | grep -qF "$want"; then
			echo "  FAIL shape: body render is missing '$want'" >&2
			failures=$((failures + 1))
		fi
	done

	if [ "$failures" -eq 0 ]; then
		echo "  OK release-notes generator: classifier battery + shape contract"
		return 0
	fi
	echo "  self-test: ${failures} failure(s)" >&2
	return 1
}

# ── Render ────────────────────────────────────────────────────────────
# Reads the compare JSON (if any), buckets the commits, and prints the
# body. Split from main() so --self-test can exercise the shape with
# zero commits (the initial-release path) without a JSON fixture.
render_body() {
	local compare_json="$1" # may be empty = initial release
	local tag="$2"
	local prev_tag="$3"
	local last_stable="$4"
	local since_stable="$5"

	local commits=""
	local total=0
	local listed=0
	if [ -n "$compare_json" ] && [ -s "$compare_json" ]; then
		# ASCII unit separator (\x1f) between hash and subject — a
		# subject may contain any byte except newline, including the
		# pipes and tabs a naive delimiter would break on.
		commits="$(jq -r '
			.commits // []
			| .[]
			| select((.parents | length) <= 1)
			| (.sha[0:7]) + "\u001f" + (.commit.message | split("\n")[0])
		' "$compare_json")"
		total="$(jq -r '.total_commits // 0' "$compare_json")"
		listed="$(jq -r '(.commits // []) | length' "$compare_json")"
	fi

	echo "## What's Changed"
	echo ""

	if [ "${IS_PRERELEASE}" = "true" ]; then
		echo "> [!WARNING]"
		echo "> **Pre-release build — not a stable release. Expect bugs.**"
	else
		echo "> [!TIP]"
		echo "> **Stable release.**"
	fi
	echo ""

	if [ -z "$commits" ]; then
		echo "Initial release."
		echo ""
	fi

	# Range summary line (single or dual, the cosmostrix convention).
	local commit_count
	commit_count="$(printf '%s\n' "$commits" | grep -c . || true)"
	if [ "$commit_count" -gt 0 ]; then
		if [ -n "$last_stable" ] && [ -n "$since_stable" ] && [ "$last_stable" != "$prev_tag" ]; then
			echo "**${commit_count} commits** since \`${prev_tag}\` (previous build) · **${since_stable} commits** since \`${last_stable}\` (last stable)"
		else
			echo "**${commit_count} commits** since \`${prev_tag}\`"
		fi
		echo ""
	fi

	# Bucket commits by classification.
	declare -A BUCKET
	declare -A COUNT
	local ALL_SECTIONS=()
	local line hash subject key entry
	while IFS= read -r line; do
		[ -z "$line" ] && continue
		hash="$(printf '%s' "$line" | cut -d$'\x1f' -f1)"
		subject="$(printf '%s' "$line" | cut -d$'\x1f' -f2-)"
		key="$(classify_subject "$subject")"
		entry="- [\`${hash}\`](${REPO_URL}/commit/${hash}) $(display_text "$subject")"
		if [ -z "${BUCKET[$key]+x}" ]; then
			BUCKET["$key"]="$entry"
			ALL_SECTIONS+=("$key")
			COUNT["$key"]=1
		else
			BUCKET["$key"]="${BUCKET[$key]}
${entry}"
			COUNT["$key"]=$((COUNT[$key] + 1))
		fi
	done <<<"$commits"

	# Total achievements: per-category clickable details.
	if [ "$commit_count" -gt 0 ]; then
		echo "> [!NOTE]"
		echo "> **Total achievements** — click a category to expand its changelog."
		echo ""

		local sorted_sections section_key
		sorted_sections="$(for section_key in "${ALL_SECTIONS[@]}"; do
			echo "${SECTION_ORDER[$section_key]}|${section_key}"
		done | sort -t'|' -k1,1n | cut -d'|' -f2-)"

		while IFS= read -r section_key; do
			[ -z "$section_key" ] && continue
			echo "<details>"
			echo "<summary><strong>${section_key/_others/others} × ${COUNT[$section_key]}</strong></summary>"
			echo ""
			echo "${BUCKET[$section_key]}"
			echo ""
			echo "</details>"
			echo ""
		done <<<"$sorted_sections"

		# Full changelog with the compare link. The compare API caps
		# the commit list at 250 — an honest truncation note rides the
		# block when the range is bigger than the listing.
		echo "<details>"
		local compare_url="${REPO_URL}/compare/${prev_tag}...${tag}"
		echo "<summary><strong>Full changelog</strong> · ${commit_count} commits · <a href=\"${compare_url}\" rel=\"noopener\">compare view</a></summary>"
		echo ""
		printf '%s\n' "$commits" | while IFS= read -r line; do
			[ -z "$line" ] && continue
			hash="$(printf '%s' "$line" | cut -d$'\x1f' -f1)"
			subject="$(printf '%s' "$line" | cut -d$'\x1f' -f2-)"
			echo "- [\`${hash}\`](${REPO_URL}/commit/${hash}) $(display_text "$subject")"
		done
		if [ "$total" -gt "$listed" ]; then
			echo ""
			echo "- *(listing truncated by the compare API: ${total} commits in range, ${listed} shown)*"
		fi
		echo ""
		echo "</details>"
		echo ""
	fi

	# Verification (GPG + checksum policy — one implementation, here).
	echo "## Verification"
	echo ""
	echo "Every archive includes a GPG detached signature (\`.asc\`) and three checksum files (SHA-512, BLAKE2b, SHAKE256)."
	echo ""
	echo "### GPG signature"
	echo ""
	echo '```bash'
	echo "gpg --keyserver keyserver.ubuntu.com --recv-keys F5324E0967F104D58CE025F347A50AEF4B65AAC2"
	echo "gpg --verify zelynic-${tag}-linux-amd64-v3-gnu.tar.gz.asc"
	echo '```'
	echo ""
	echo "Expected: \`Good signature from \"Rezky Cahya Sahputra (cosmic dragon)\"\`"
	echo ""
	echo "Full verification instructions: [docs/VERIFY_RELEASE.md](docs/VERIFY_RELEASE.md)"
}

if [ "$SELF_TEST" -eq 1 ]; then
	if ! self_test; then
		exit 1
	fi
	# Self-test healthy: nothing else to do.
	exit 0
fi

if [ -z "$TAG" ]; then
	echo "--tag is required (or pass --self-test)" >&2
	usage
	exit 1
fi

render_body "$COMPARE_JSON" "$TAG" "$PREV_TAG" "$LAST_STABLE" "$SINCE_STABLE"
