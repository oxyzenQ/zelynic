#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
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
# implementation — and (NIGHT-hunt-Z11) the body budget guarantees it
# survives to the STORED page: GitHub silently truncates a release body
# over its cap (observed 124,999 characters; the documented limit is
# 125,000), and an over-budget body loses exactly its last section —
# the verification contract. Subjects display-cap, the full-changelog
# listing is trimmed from its tail under the budget, and main() refuses any
# body that still exceeds it.
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
# navigational and list every commit (subjects display-capped at
# MAX_SUBJECT_CHARS — the hash link carries the full text); the full
# changelog below them is the redundant reading order and is trimmed
# from its tail under the body budget with the state named on the page — a
# misfiled commit is never a hidden commit, and neither is a trimmed
# one.
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
#                    semantics, merge commits included). Legal-empty:
#                    a stable release carries no distance (LAST_STABLE
#                    == PREV_TAG by construction) and an initial
#                    release has no stable tag yet.
#   --self-test      run the pinned classifier + shape + parse
#                    battery, no network, no jq input, exit nonzero on
#                    any drift.
#
#   Value contract: --tag, --prerelease, and --repo-url must carry a
#   non-empty value; the four boundary flags above accept an empty
#   value (their "not applicable" states) while still requiring the
#   argument to exist. The parser section below enforces both classes.
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

# ── Release body budget (NIGHT-hunt-Z11) ─────────────────────────────
# GitHub silently truncates a stored release body over its cap —
# observed 124,999 characters on both Z11 casualties (the v11.0.0
# stable and v20.0.0-rc.2 pages both stored exactly that, cut
# mid-<details>, losing the Verification section that renders last;
# the documented limit is 125,000). The two numbers below bound every
# rendered body: the per-subject display cap keeps the category
# sections — which list every commit — inside the budget on their own
# (the v20.0.0-rc.2 shape: 139 commits with essay-length subjects),
# and the whole-body budget makes the full-changelog listing trim from
# its tail with an honest note instead of losing the page's tail to
# the platform's silent cut (the v11.0.0 shape: the compare API's
# 250-commit listing rendered twice). main() refuses (exit 1) any
# body that still exceeds the budget — drift fails red, never
# truncated-green.
MAX_BODY_CHARS=120000
MAX_SUBJECT_CHARS=240

usage() {
	echo "Usage: $0 --tag TAG --prerelease true|false [--compare-json PATH]" >&2
	echo "            [--prev-tag TAG] [--last-stable TAG] [--since-stable N]" >&2
	echo "            [--repo-url URL] [--self-test]" >&2
}

# ── CLI parsing (two value classes — a contract, not a style) ────────
# Required-value flags (--tag, --prerelease, --repo-url) keep the
# ${2:?} guard: no legal empty tag, channel, or repository URL
# exists, and an empty one must stay a usage error. The four boundary
# flags below are legal-empty instead: the USAGE block above says
# "Absent or empty = initial release", and the workflow step passes
# every flag unconditionally with quoted "${VAR}" values, so a
# stable release arrives with --since-stable "" (LAST_STABLE ==
# PREV_TAG by construction, no distance to render) exactly as an
# initial release arrives with --compare-json "" and --prev-tag
# "", and a pre-release cut before any stable tag arrives with
# --last-stable "". ${2:?} rejected a present-but-empty value as
# hard as a missing one, and that turned three legal states into red
# pipelines: the v11.0.0 stable publish died on --since-stable
# (Dragon Guard - Release run 36586939180, 11 seconds in; every rc
# before it passed only because pre-releases DO carry a
# since-stable distance), and the initial-release and
# first-pre-release shapes die on --compare-json / --last-stable the
# same way. The four flags now require the value to EXIST (an
# argument follows the flag, [ $# -ge 2 ]), not to be non-empty; the
# empty value flows on to the render layer, which already treats it
# as "feature absent" (the render_body guard chain) — the same
# philosophy as the workflow's own "no previous tag is a legal
# state, not an error".
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
	# Legal-empty: empty PATH = initial release (no compare API
	# response exists).
	--compare-json)
		if [ $# -lt 2 ]; then
			echo "--compare-json needs a value" >&2
			usage
			exit 1
		fi
		COMPARE_JSON="$2"
		shift 2
		;;
	# Legal-empty: empty TAG = initial release (no previous tag of
	# any channel).
	--prev-tag)
		if [ $# -lt 2 ]; then
			echo "--prev-tag needs a value" >&2
			usage
			exit 1
		fi
		PREV_TAG="$2"
		shift 2
		;;
	# Legal-empty: empty TAG = no stable release exists yet.
	--last-stable)
		if [ $# -lt 2 ]; then
			echo "--last-stable needs a value" >&2
			usage
			exit 1
		fi
		LAST_STABLE="$2"
		shift 2
		;;
	# Legal-empty: empty N = no distance to render (stable releases
	# carry none: LAST_STABLE == PREV_TAG; initial releases have no
	# stable tag yet).
	--since-stable)
		if [ $# -lt 2 ]; then
			echo "--since-stable needs a value" >&2
			usage
			exit 1
		fi
		SINCE_STABLE="$2"
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
# with long noun phrases (the diff engine and the cosmic dragon engine
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

# ── Byte length (the Z11 budget unit) ────────────────────────────────
# LC_ALL=C so wc counts BYTES, not display characters: a byte budget
# is the conservative reading of GitHub's storage cap — any body under
# it in bytes is under it in characters too, whichever unit the
# platform actually truncates at (NIGHT-hunt-Z11: the observed cap is
# 124,999 stored characters, the documented limit 125,000; the budget
# sits 5,000 under either reading).
body_bytes() {
	LC_ALL=C printf '%s' "$1" | wc -c | tr -d '[:space:]'
}

# The release page's verification contract (GPG + checksum policy) —
# one implementation, here. NIGHT-hunt-Z11 factored the block out of
# render_body's tail into this function so the budget fit test can
# compose the FINAL body (this block included) before deciding how
# many changelog bullets fit; the emitted text is byte-identical to
# the inline block it replaced. It renders last, and the budget
# layers above guarantee it survives to the STORED page.
verification_section() {
	local tag="$1"
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

# ── The self-test: pinned classifier + shape + parse contracts ───────
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

	# Parse contract (NIGHT-dinner-26, the v11.0.0 stable incident):
	# the four legal-empty flags must accept present-but-empty values
	# through the REAL CLI path — parser plus render, no fixture, no
	# network. The shape probe above calls render_body directly and
	# never touches the parser, which is exactly the gap the v11.0.0
	# stable publish fell through (the workflow passes --since-stable
	# "" for every stable release). One probe covers all four flags at
	# once: every optional value empty, the exact initial-release
	# shape, exit 0, and the initial-release marker rendered.
	local parse_out parse_rc=0
	parse_out="$("$0" \
		--tag v0.0.0-self-test \
		--prerelease false \
		--compare-json "" \
		--prev-tag "" \
		--last-stable "" \
		--since-stable "" 2>&1)" || parse_rc=$?
	if [ "$parse_rc" -ne 0 ] || ! printf '%s' "$parse_out" | grep -qF "Initial release."; then
		echo "  FAIL parse: legal-empty flag values rejected (rc=${parse_rc})" >&2
		failures=$((failures + 1))
	fi

	# NIGHT-hunt-Z11 budget contract (the v11.0.0 / v20.0.0-rc.2
	# incident, pinned): GitHub silently truncates a stored release
	# body at its cap (both casualty bodies stored exactly 124,999
	# characters, cut mid-<details>), and the Verification section
	# renders last — it was the casualty both times. This probe
	# reproduces BOTH failure shapes at once through the REAL CLI
	# path: more commits than the compare API's own 250-commit
	# listing cap (the v11.0.0 stable shape) AND essay-length
	# subjects (the v20.0.0-rc.2 shape — real subjects in that range
	# ran to ~1,900 characters). The rendered body must stay inside
	# the budget, carry the Verification section, and state the trim
	# honestly.
	local z11_json z11_out z11_rc=0 z11_len
	z11_json="$(mktemp)"
	jq -n '{
                total_commits: 260,
                commits: [
                        range(260) | {
                                sha: ("z11" + (. | tostring)),
                                parents: [],
                                commit: {
                                        message: ("NIGHT-hunt-Z11 synthetic subject " + (. | tostring) + " " + ("essay length subject text " * 18))
                                }
                        }
                ]
        }' >"$z11_json"
	z11_out="$("$0" \
		--tag v0.0.0-z11-budget \
		--prerelease true \
		--compare-json "$z11_json" \
		--prev-tag v0.0.0-z11-prev \
		--last-stable "" \
		--since-stable "" 2>&1)" || z11_rc=$?
	rm -f "$z11_json"
	z11_len="$(body_bytes "$z11_out")"
	if [ "$z11_rc" -ne 0 ]; then
		echo "  FAIL budget: over-cap fixture render exited ${z11_rc}" >&2
		failures=$((failures + 1))
	fi
	if [ "$z11_len" -gt "$MAX_BODY_CHARS" ]; then
		echo "  FAIL budget: rendered body ${z11_len} bytes exceeds the ${MAX_BODY_CHARS}-byte budget" >&2
		failures=$((failures + 1))
	fi
	for want in "## Verification" "recv-keys F5324E0967F104D58CE025F347A50AEF4B65AAC2" "listing trimmed to fit the release-body cap"; do
		if ! printf '%s' "$z11_out" | grep -qF "$want"; then
			echo "  FAIL budget: over-cap render is missing '$want'" >&2
			failures=$((failures + 1))
		fi
	done

	if [ "$failures" -eq 0 ]; then
		echo "  OK release-notes generator: classifier battery + shape + parse contracts"
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
		# pipes and tabs a naive delimiter would break on. The subject
		# takes its Z11 display cap here, at the source: a campaign
		# subject runs to essay length (the v20.0.0-rc.2 range carried
		# ~1,900-character subjects) and every commit renders twice
		# (its category bucket and the full changelog) — uncapped, one
		# long-winded range alone breaches the body budget. jq slices
		# on codepoint boundaries, so the cut never splits a multi-byte
		# character; the "..." marker names the trim and the commit
		# page (one click, the hash link) carries the full text.
		commits="$(jq -r --argjson cap "$MAX_SUBJECT_CHARS" '
                        .commits // []
                        | .[]
                        | select((.parents | length) <= 1)
                        | (.sha[0:7]) + "\u001f" +
                                (.commit.message | split("\n")[0] |
                                if (length) > $cap then (.[0:$cap] + "...") else . end)
                ' "$compare_json")"
		total="$(jq -r '.total_commits // 0' "$compare_json")"
		listed="$(jq -r '(.commits // []) | length' "$compare_json")"
	fi

	# NIGHT-hunt-Z11: the body composes in memory and prints once. The
	# stored GitHub release body silently truncates at the platform cap
	# (observed 124,999 characters — the v11.0.0 stable and v20.0.0-rc.2
	# pages both stored exactly that, cut mid-<details>, losing the
	# Verification section that renders last), so a streaming render can
	# never know its own size. Composing first makes the budget
	# arithmetic exact and the tail trim below possible; emit is the
	# single append point.
	local body=""
	emit() {
		body+="$1"$'\n'
	}

	# The Verification section, composed once: the budget fit test below
	# measures the FINAL body (this block included) before deciding how
	# many changelog bullets fit, and the emission at the end appends it
	# — byte-identical to the inline block it replaces (one
	# implementation, factored for measurement, not forked).
	local verification_block
	verification_block="$(verification_section "$tag")"

	emit "## What's Changed"
	emit ""

	if [ "${IS_PRERELEASE}" = "true" ]; then
		emit "> [!WARNING]"
		emit "> **Pre-release build — not a stable release. Expect bugs.**"
	else
		emit "> [!TIP]"
		emit "> **Stable release.**"
	fi
	emit ""

	if [ -z "$commits" ]; then
		emit "Initial release."
		emit ""
	fi

	# Range summary line (single or dual, the cosmostrix convention).
	local commit_count
	commit_count="$(printf '%s\n' "$commits" | grep -c . || true)"
	if [ "$commit_count" -gt 0 ]; then
		if [ -n "$last_stable" ] && [ -n "$since_stable" ] && [ "$last_stable" != "$prev_tag" ]; then
			emit "**${commit_count} commits** since \`${prev_tag}\` (previous build) · **${since_stable} commits** since \`${last_stable}\` (last stable)"
		else
			emit "**${commit_count} commits** since \`${prev_tag}\`"
		fi
		emit ""
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
		emit "> [!NOTE]"
		emit "> **Total achievements** — click a category to expand its changelog."
		emit ""

		local sorted_sections section_key
		sorted_sections="$(for section_key in "${ALL_SECTIONS[@]}"; do
			echo "${SECTION_ORDER[$section_key]}|${section_key}"
		done | sort -t'|' -k1,1n | cut -d'|' -f2-)"

		while IFS= read -r section_key; do
			[ -z "$section_key" ] && continue
			emit "<details>"
			emit "<summary><strong>${section_key/_others/others} × ${COUNT[$section_key]}</strong></summary>"
			emit ""
			emit "${BUCKET[$section_key]}"
			emit ""
			emit "</details>"
			emit ""
		done <<<"$sorted_sections"

		# Full changelog with the compare link. The compare API caps
		# the commit list at 250 — an honest truncation note rides the
		# block when the range is bigger than the listing. NIGHT-hunt-Z11
		# adds the second bound: the bullet listing itself is trimmed from
		# its tail, whole lines only (never mid-bullet, never mid-character),
		# while the composed body exceeds the budget. The categories
		# above keep every commit; this listing is the redundant reading
		# order, and the note below names exactly what was dropped and
		# where the complete record lives.
		emit "<details>"
		local compare_url="${REPO_URL}/compare/${prev_tag}...${tag}"
		emit "<summary><strong>Full changelog</strong> · ${commit_count} commits · <a href=\"${compare_url}\" rel=\"noopener\">compare view</a></summary>"
		emit ""

		# Compose the bullets in full first (the loop must not run in a
		# subshell — the trim below needs these in the current shell),
		# then drop bullets from the tail until the projected FINAL body
		# — head, categories, this listing, both notes, the closing tag,
		# the Verification section — fits the budget.
		local bullets="" shown=0
		while IFS= read -r line; do
			[ -z "$line" ] && continue
			hash="$(printf '%s' "$line" | cut -d$'\x1f' -f1)"
			subject="$(printf '%s' "$line" | cut -d$'\x1f' -f2-)"
			if [ -n "$bullets" ]; then
				bullets+=$'\n'
			fi
			bullets+="- [\`${hash}\`](${REPO_URL}/commit/${hash}) $(display_text "$subject")"
			shown=$((shown + 1))
		done <<<"$commits"

		local api_note=""
		if [ "$total" -gt "$listed" ]; then
			api_note="*(listing truncated by the compare API: ${total} commits in range, ${listed} shown)*"
		fi

		# The projected final body at the current trim level, in bytes
		# (the conservative unit: under by bytes is under by characters
		# under every reading of the platform cap). Dynamic scoping
		# carries the locals — the same discipline as self_test's t_case.
		projected_bytes() {
			local p="${body}${bullets}"
			if [ -n "$api_note" ]; then
				p+=$'\n'"- ${api_note}"
			fi
			if [ "$shown" -lt "$commit_count" ]; then
				p+=$'\n'"- *(listing trimmed to fit the release-body cap: ${commit_count} commits in range, ${shown} shown — the compare view carries every subject in full)*"
			fi
			p+=$'\n</details>'$'\n\n'"${verification_block}"
			body_bytes "$p"
		}

		while [ "$shown" -gt 0 ] && [ "$(projected_bytes)" -gt "$MAX_BODY_CHARS" ]; do
			case "$bullets" in
			*$'\n'*)
				bullets="${bullets%$'\n'*}"
				;;
			*)
				bullets=""
				;;
			esac
			shown=$((shown - 1))
		done

		if [ -n "$bullets" ]; then
			emit "$bullets"
		fi
		if [ -n "$api_note" ]; then
			emit ""
			emit "- ${api_note}"
		fi
		if [ "$shown" -lt "$commit_count" ]; then
			emit ""
			emit "- *(listing trimmed to fit the release-body cap: ${commit_count} commits in range, ${shown} shown — the compare view carries every subject in full)*"
		fi
		emit ""
		emit "</details>"
		emit ""
	fi

	# Verification (GPG + checksum policy — one implementation, in
	# verification_section above; budgeted to survive to the stored
	# page, rendered last per the cosmostrix convention).
	emit "${verification_block}"

	printf '%s' "$body"
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

release_body="$(render_body "$COMPARE_JSON" "$TAG" "$PREV_TAG" "$LAST_STABLE" "$SINCE_STABLE")"

# NIGHT-hunt-Z11 layer 3 — the hard refusal. The subject cap and the
# changelog trim make this unreachable by construction; it exists so
# any future drift (a budget bump past the platform cap, a new
# unbounded section, a regex eating the trim) fails the pipeline
# LOUDLY — red and named — instead of shipping a body GitHub silently
# truncates at its storage cap, which is exactly the silence that ate
# the Verification section off the v11.0.0 and v20.0.0-rc.2 pages.
release_body_bytes="$(body_bytes "$release_body")"
if [ "$release_body_bytes" -gt "$MAX_BODY_CHARS" ]; then
	echo "release body is ${release_body_bytes} bytes — over the ${MAX_BODY_CHARS}-byte budget; refusing to emit a body GitHub would silently truncate (NIGHT-hunt-Z11)" >&2
	exit 1
fi
printf '%s\n' "$release_body"
