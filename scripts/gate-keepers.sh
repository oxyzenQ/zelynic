#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# PLATFORM: UNIX-only (Linux). zelynic is a Linux-only tool.
#
# Pre-commit gatekeeper script for zelynic.
# Runs all non-code linters/checks before allowing a commit.
#
# Usage:
#   ./scripts/gate-keepers.sh           # Run all checks
#   ./scripts/gate-keepers.sh --fix    # Run with auto-fix where possible
#
# Checks performed (exclude Rust core code — use `cargo clippy` via
# ./scripts/build.sh check-all for that):
#   1.  Shell scripts (strict quad):
#         1a. bash -n   — syntax check (fast fail-fast pre-filter)
#         1b. shellcheck — static analysis (default rule set)
#         1c. shfmt -d  — canonical formatting (tabs, function braces
#             on own line, case branches expanded); --fix runs
#             `shfmt -w` to auto-canonicalize
#         1d. source resolution — every `source`/`.` target exists
#             (the literal path, not the directive; NIGHT-blade-14)
#   2.  yamllint on .github YAML (repo .yamllint config)
#   3.  actionlint on .github/workflows/*.yml
#   4.  TOML syntax validation (python3 tomllib)
#   5.  codespell on all text files (repo .codespellrc)
#   6.  SPDX license header check (scripts/gates/check-headers.sh — dual-line
#       contract across rs/c/h/py/sh/toml/yml/yaml/md; untracked files
#       included so new files fail BEFORE commit)
#   7.  File permission guard (owner rule — git-tracked files 644,
#       tracked executables and directories 755, shebang parity;
#       scripts/gates/check-permissions.sh, --fix chmods)
#   8.  Emoji sweep (owner rule — no emoji-class codepoints in ANY
#       tracked text file; cosmostrix fail blocks, strict detector,
#       exit 1 on hits)
#   9.  Rust source LOC cap (owner rule — scripts/gates/check-loc.sh, hard
#       limit 500 lines; // LOC_EXEMPT: marker = tracked migration debt)
#       + src/ root single-file policy (NIGHT-blade-15: only main.rs at
#       src/ root, every other module in a subsystem dir/mod.rs)
#  10.  Rust toolchain version sync (scripts/gates/check-rust-version-sync.sh —
#       rust-toolchain.toml pin == Cargo.toml MSRV == workflow RUST_VERSION)
#  11.  Documentation disclaimer (scripts/gates/inject-disclaimer.sh --check —
#       every living .md carries the stale-data warning; --fix injects)
#  12.  rustfmt on ebpf/ (the pure-Rust eBPF crate — CI parity with
#       the Gate-keepers workflow, which runs this same command on
#       every push; NIGHT-improve-1 phase 3 replaced the clang-format
#       gate on bpf/*.c when the C objects were deleted)
#  13.  Test-tree discipline (owner rule, NIGHT-hunt-17 — every .rs
#       test file lives under test/, cosmostrix Pattern C: no tests/
#       autodiscovery directory, no *_tests.rs/*_test.rs under src/,
#       every [[test]] target and src/ #[path] wiring resolves under
#       test/)
#  14.  Language discipline (owner rule, NIGHT-hunt-19 —
#       scripts/gates/check-language.sh: non-Latin scripts outside
#       NON_LATIN_FIXTURE-marked coverage files plus an Indonesian
#       vocabulary detector; the repo is English-only, the sibling of
#       the emoji sweep for everything that sweep cannot see)
#  15.  Python lint + format (ruff, NIGHT-improve-13 — cosmostrix
#       gate parity for the scripts/ tree: ruff check (explicit
#       rule set E4/E7/E9/F/I, .ruff.toml) + ruff format --check
#       (line-length 100, the scripts/ house style); --fix runs
#       ruff check --fix + ruff format. The EXE001 shebang parity
#       cosmostrix checks here is already owned by section 7, the
#       permission guard — one contract, one place)
#  16.  Scripts LOC cap (owner rule, NIGHT-lts-2 —
#       scripts/gates/check-scripts-loc.sh, hard limit 1000 lines
#       for every .sh/.py under scripts/; # LOC_EXEMPT: marker =
#       tracked migration debt — the scripts twin of section 9's
#       500-line Rust cap, doubled because a one-shot harness
#       legitimately bundles constants + stage table + verdict
#       plumbing, but no script grows unbounded)
#  17.  Release parity (NIGHT-lts-9 —
#       scripts/gates/check-release-parity.sh: the four arch-baseline
#       platforms' -C codegen tokens in .cargo/config.toml's
#       pro-linux-amd64-* aliases must equal the release workflow
#       matrix's rustflags, so a local alias build reproduces the
#       release optimization tier the README documents bit-for-bit;
#       a one-file edit can no longer silently break that contract)
#
# Missing tools are skipped with a warning so the gate stays usable
# on minimal development machines; CI runs this script WHOLESALE
# (the ci.yml gatekeepers job, full tool set installed, the
# NIGHT-hunt-23 class closure): every section, current and
# future, executes on every push — no gate can rot silently
# behind a missing CI mirror step again.
#
# Exit codes:
#   0 = all checks passed
#   1 = one or more checks failed

set -euo pipefail

# ── Colors ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS=0
FAIL=0
FIX_MODE=false

if [[ "${1:-}" == "--fix" || "${1:-}" == "--fix-all" ]]; then
	FIX_MODE=true
fi

info() { echo -e "${GREEN}[PASS]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
fail() {
	echo -e "${RED}[FAIL]${NC} $1"
	FAIL=$((FAIL + 1))
}
header() {
	echo ""
	echo "── $1 ──"
}

# ── 1. Shell scripts (strict quad: bash -n + shellcheck + shfmt -d + source resolution) ───────
# Resolve the .sh file list once and reuse across the three sub-checks.
# Excludes .git and target/ trees; .git is repo metadata, target/ is
# build output (vendor-generated scripts there are not our concern).
SHELL_FILES=$(find . -name '*.sh' -not -path './.git/*' -not -path './target/*' 2>/dev/null)

# ── 1a. bash -n (syntax check) ─────────────────────────────────────────────
# Fast-fail pre-filter: if bash itself rejects the syntax, there is no
# point running shellcheck or shfmt — the file is not parseable. This
# catches unbalanced quotes/braces/heredocs in milliseconds, before the
# slower static-analysis tools even start.
header "bash -n (syntax)"
if [ -n "$SHELL_FILES" ]; then
	BASHN_ERR=0
	# shellcheck disable=SC2086 # word splitting is intentional for file list
	for f in $SHELL_FILES; do
		if ! bash -n "$f" 2>&1; then
			fail "bash -n: syntax error in $f"
			BASHN_ERR=$((BASHN_ERR + 1))
		fi
	done
	if [ "$BASHN_ERR" -eq 0 ]; then
		info "bash -n: all .sh files syntax-clean"
		PASS=$((PASS + 1))
	fi
else
	info "bash -n: no .sh files found"
	PASS=$((PASS + 1))
fi

# ── 1b. shellcheck (static analysis) ───────────────────────────────────────
header "shellcheck"
if command -v shellcheck >/dev/null 2>&1; then
	if [ -n "$SHELL_FILES" ]; then
		# -x follows `source` targets: shared libs (harness_lib.sh,
		# NIGHT-hunt-21) are checked in the sourcing scripts' context
		# too, not only standalone. Directives carry repo-root-relative
		# paths, and the gate always runs from the repo root.
		# shellcheck disable=SC2086 # word splitting is intentional for file list
		if shellcheck -x ${SHELL_FILES} 2>&1; then
			info "shellcheck: all .sh files pass"
			PASS=$((PASS + 1))
		else
			fail "shellcheck: errors found in .sh files"
		fi
	else
		info "shellcheck: no .sh files found"
		PASS=$((PASS + 1))
	fi
else
	warn "shellcheck not installed — skipping"
fi

# ── 1c. shfmt -d (format check) ────────────────────────────────────────────
# Canonical style is shfmt's default: tab indent, function braces on
# their own line, case branches expanded. --fix runs `shfmt -w` to
# auto-canonicalize; the diff is then empty on the next run.
header "shfmt -d (format)"
if command -v shfmt >/dev/null 2>&1; then
	if [ -n "$SHELL_FILES" ]; then
		# shellcheck disable=SC2086 # word splitting is intentional for file list
		if shfmt -d ${SHELL_FILES} 2>&1; then
			info "shfmt: all .sh files formatted"
			PASS=$((PASS + 1))
		else
			if $FIX_MODE; then
				# shellcheck disable=SC2086 # word splitting is intentional for file list
				if shfmt -w ${SHELL_FILES} 2>&1; then
					info "shfmt: auto-canonicalized (review $(git diff))"
					PASS=$((PASS + 1))
				else
					fail "shfmt: auto-format failed (review errors above)"
				fi
			else
				fail "shfmt: .sh files not formatted (run with --fix to auto-format)"
			fi
		fi
	else
		info "shfmt: no .sh files found"
		PASS=$((PASS + 1))
	fi
else
	warn "shfmt not installed — skipping (https://github.com/mvdan/sh)"
fi

# ── 1d. source resolution (NIGHT-blade-14) ────────────────────
# The one gap the triad left open: nothing ever EXECUTED a source
# line. bash -n is syntax-only; shellcheck -x follows the source=
# DIRECTIVE, which can point at the right file while the literal
# path went stale — exactly how scripts/depth/reload-test.sh shipped
# broken through the NIGHT-refactor-1 lib move (its directive said
# scripts/lib/, its source line still said its own directory, and
# the suite died on an unbound variable for root and non-root
# alike). This check resolves every `source X` / `. X` line the way
# bash would and verifies the target exists. No script-authored
# code is evaluated: the repo's two idioms (the cd/pwd idiom
# anchored at BASH_SOURCE[0], and a plain path relative to the
# sourcing script's own directory — never the caller's CWD) are
# resolved by construction; any other shape fails loudly, and a new
# idiom must extend this translator (fail-closed, never fail-open).
header "source resolution"
SRC_BAD=0
SRC_RE='^[[:space:]]*(source|\.)[[:space:]]+"\$\(cd[[:space:]]+"\$\(dirname[[:space:]]+"\$\{BASH_SOURCE\[0\]\}"\)(/(\.\.)+)*"[[:space:]]+&&[[:space:]]+pwd\)/([^"]+)"$'
SRC_PLAIN='^[[:space:]]*(source|\.)[[:space:]]+([^"$][^[:space:]]*)[[:space:]]*$'
# shellcheck disable=SC2086 # word splitting is intentional for file list
for f in $SHELL_FILES; do
	fdir="$(dirname "$f")"
	while IFS= read -r line; do
		if [[ $line =~ $SRC_RE ]]; then
			climb="${BASH_REMATCH[2]}"
			target="${BASH_REMATCH[4]}"
			if [ ! -e "$fdir$climb/$target" ]; then
				fail "source resolution: $f: target missing: $line"
				SRC_BAD=$((SRC_BAD + 1))
			fi
		elif [[ $line =~ $SRC_PLAIN ]]; then
			rel="${BASH_REMATCH[2]}"
			if [ ! -e "$fdir/$rel" ]; then
				fail "source resolution: $f: target missing: $line"
				SRC_BAD=$((SRC_BAD + 1))
			fi
		else
			fail "source resolution: $f: unsupported idiom (extend the 1d translator): $line"
			SRC_BAD=$((SRC_BAD + 1))
		fi
	done < <(grep -E '^[[:space:]]*(source|\.)[[:space:]]' "$f" 2>/dev/null || true)
done
if [ "$SRC_BAD" -eq 0 ]; then
	info "source resolution: every source target resolves"
	PASS=$((PASS + 1))
fi

# ── 2. Yamllint ────────────────────────────────────────────────────────────
header "Yamllint"
if command -v yamllint >/dev/null 2>&1; then
	# CI parity: .github/** must pass the repo .yamllint config — the
	# same one the CI gatekeepers job enforces wholesale (line-length max
	# 120 included).
	GITHUB_YAML=$(find .github -name '*.yml' -o -name '*.yaml' 2>/dev/null)
	YAML_OK=0
	if [ -n "$GITHUB_YAML" ]; then
		# shellcheck disable=SC2086 # word splitting is intentional for file list
		yamllint -c .yamllint ${GITHUB_YAML} 2>&1 || YAML_OK=1
	fi
	if [ "$YAML_OK" -eq 0 ]; then
		info "yamllint: all .github YAML files pass (repo config)"
		PASS=$((PASS + 1))
	else
		fail "yamllint: errors found in YAML files"
	fi
else
	warn "yamllint not installed — skipping"
fi

# ── 3. Actionlint ──────────────────────────────────────────────────────────
header "Actionlint"
if command -v actionlint >/dev/null 2>&1; then
	if actionlint .github/workflows/*.yml 2>&1; then
		info "actionlint: all workflow files pass"
		PASS=$((PASS + 1))
	else
		fail "actionlint: errors found in workflow files"
	fi
else
	warn "actionlint not installed — skipping"
fi

# ── 4. TOML Syntax ─────────────────────────────────────────────────────────
header "TOML Syntax"
if command -v python3 >/dev/null 2>&1; then
	TOML_ERR=0
	while IFS= read -r -d '' f; do
		if ! python3 -c "import tomllib, sys; tomllib.load(open(sys.argv[1], 'rb'))" "$f" 2>/dev/null; then
			echo -e "${RED}INVALID TOML: ${f}${NC}"
			TOML_ERR=$((TOML_ERR + 1))
		fi
	done < <(find . -name '*.toml' -not -path './target/*' -not -path './.git/*' -print0 2>/dev/null)
	if [ "$TOML_ERR" -eq 0 ]; then
		info "TOML: all .toml files valid"
		PASS=$((PASS + 1))
	else
		fail "TOML: ${TOML_ERR} file(s) have syntax errors"
	fi
else
	warn "python3 not installed — skipping"
fi

# ── 5. Codespell ──────────────────────────────────────────────────────────
header "Codespell"
if command -v codespell >/dev/null 2>&1; then
	if codespell --config .codespellrc . 2>&1; then
		info "codespell: no spelling errors"
		PASS=$((PASS + 1))
	else
		# Deliberately NOT auto-fixed even under --fix: codespell -w
		# would rewrite identifiers, ASCII art, and URLs where apparent
		# misspellings are intentional (see .codespellrc ignore list).
		fail "codespell: spelling errors found (never auto-fixed - review manually)"
	fi
else
	warn "codespell not installed — skipping"
fi

# ── 6. SPDX License Headers (scripts/gates/check-headers.sh) ──────────────────
# Dual-line contract (Copyright + SPDX-License-Identifier) across
# rs/c/h/py/sh/toml/yml/yaml/md, including untracked-but-present files
# (pre-commit proxy parity). CHANGELOG.md is excluded as frozen history.
header "SPDX License Headers (check-headers.sh)"
if [ -f scripts/gates/check-headers.sh ]; then
	if bash scripts/gates/check-headers.sh 2>&1; then
		info "license headers: all source, config, and doc files carry the header"
		PASS=$((PASS + 1))
	else
		fail "license headers: violations found (no auto-fix - add the 2-line header)"
	fi
else
	warn "check-headers.sh not found — skipping"
fi

# ── 7. File Permission Guard (644/755 owner rule) ─────────────────────────
# Tracked files 644 (755 when executable), directories 755, shebang
# parity. --fix runs the guard with --fix (chmod in place; the
# 644/755 exec-bit flips are visible in git diff, the umask-level
# 664/775 repairs are invisible because git records only the exec bit).
header "Permission Guard (644/755)"
if [ -f scripts/gates/check-permissions.sh ]; then
	if $FIX_MODE; then
		if bash scripts/gates/check-permissions.sh --fix 2>&1; then
			info "permissions: violations auto-fixed (review git diff for exec-bit changes)"
			PASS=$((PASS + 1))
		else
			fail "permissions: violations not fully auto-fixable (review output above)"
		fi
	else
		if bash scripts/gates/check-permissions.sh 2>&1; then
			info "permissions: files 644, executables and directories 755"
			PASS=$((PASS + 1))
		else
			fail "permissions: violations found (auto-fixable via --fix)"
		fi
	fi
else
	warn "check-permissions.sh not found — skipping"
fi

# ── 8. Emoji Sweep (repo-wide) ─────────────────────────────────────────────
# Owner rule: the project carries no emoji anywhere — docs, source,
# scripts, configs alike. The detector scans anything that decodes as
# strict UTF-8, so file types cannot escape it by extension.
# Excluded: .git, target, the binary logo asset, lockfiles, and
# CHANGELOG.md + CHANGELOG-V11-ERA.md (frozen historical records —
# archive content is never rewritten, the same exclusion policy as
# the docs audit).
header "Emoji Sweep (repo-wide)"
if command -v python3 >/dev/null 2>&1; then
	EMOJI_RC=0
	python3 - <<'PYEOF' || EMOJI_RC=1
import sys
from pathlib import Path

# Emoji-class codepoint ranges (enough coverage for the sweep; the
# goal is to block emoji, not to enumerate every Unicode symbol).
RANGES = (
    (0x1F000, 0x1FFFF),  # astral emoji (incl. regional indicator flags)
    (0x2600, 0x27BF),   # Miscellaneous Symbols .. Dingbats
    (0x2300, 0x23FF),   # Misc Technical (clocks, media controls, key caps)
    (0x2B00, 0x2BFF),   # Misc Symbols and Arrows (stars, thick arrows)
    (0xFE0F, 0xFE0F),   # Variation Selector-16 (emoji presentation)
    (0xFE0E, 0xFE0E),   # Variation Selector-15 (text presentation)
    (0x200D, 0x200D),   # Zero-Width Joiner (emoji composition)
)

# Allowed non-ASCII (typographic house style, never flagged): prose
# arrows U+2190..21FF, box drawing + geometric U+2500..25FF, em/en dash,
# ellipsis, bullet, math operators. None of those ranges intersect the
# fail blocks, so the allowlist needs no carve-outs.

def is_emoji(cp: int) -> bool:
    return any(lo <= cp <= hi for lo, hi in RANGES)

SKIP_DIRS = {".git", "target"}
SKIP_FILES = {"CHANGELOG.md", "CHANGELOG-V11-ERA.md"}
SKIP_SUFFIXES = (".png", ".lock")
hits = []
for path in Path(".").rglob("*"):
    if any(part in SKIP_DIRS for part in path.parts):
        continue
    if path.name in SKIP_FILES or path.suffix in SKIP_SUFFIXES or not path.is_file():
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        continue
    for lineno, line in enumerate(text.splitlines(), 1):
        if any(is_emoji(ord(ch)) for ch in line):
            hits.append(f"{path}:{lineno}")

for h in hits[:20]:
    print(f"  emoji in: {h}")
if len(hits) > 20:
    print(f"  ... and {len(hits) - 20} more hit(s) not listed")

sys.exit(1 if hits else 0)
PYEOF
	if [ "$EMOJI_RC" -eq 0 ]; then
		info "emoji sweep: no emoji-class codepoints in tracked text files"
		PASS=$((PASS + 1))
	else
		fail "emoji sweep: emoji found (review the file:line list above)"
	fi
else
	warn "python3 not installed — skipping"
fi

# ── 9. Rust Source LOC Cap (owner rule: 500) ────────────────────────────────
# Hard limit from docs/RULES.md "Source file size cap". A file over the
# cap passes ONLY with a self-declared `// LOC_EXEMPT:` marker plus a
# one-line justification (tracked migration debt, not silent rot).
# NIGHT-blade-15: the same gate now also enforces the src/ root
# single-file policy (src/ root holds only main.rs; every other
# module lives in its subsystem directory as dir/mod.rs).
header "Rust LOC Cap + src Root Layout (check-loc.sh)"
if [ -f scripts/gates/check-loc.sh ]; then
	if bash scripts/gates/check-loc.sh 2>&1 | tail -20; then
		info "LOC cap + src root layout: all Rust files within policy"
		PASS=$((PASS + 1))
	else
		fail "LOC cap: file(s) over 500 lines without an exemption marker (split them or add // LOC_EXEMPT:)"
	fi
else
	warn "check-loc.sh not found — skipping"
fi

# ── 10. Rust Toolchain Version Sync ────────────────────────────────────────
# rust-toolchain.toml channel (authoritative pin) must agree with the
# Cargo.toml MSRV and every workflow RUST_VERSION env. Channel aliases
# (stable/beta/nightly) are rejected under the dormant-mode policy.
header "Rust Version Sync (check-rust-version-sync.sh)"
if [ -f scripts/gates/check-rust-version-sync.sh ]; then
	if bash scripts/gates/check-rust-version-sync.sh 2>&1; then
		info "rust version: toolchain pin, MSRV, and CI pins in sync"
		PASS=$((PASS + 1))
	else
		fail "rust version: sources out of sync (fix with ./scripts/dev/rust-version-to.sh <X.Y.Z>)"
	fi
else
	warn "check-rust-version-sync.sh not found — skipping"
fi

# ── 11. Documentation Disclaimer ──────────────────────────────────────────
# Every living .md file carries the stale-data disclaimer at the bottom
# (CHANGELOG.md excluded as frozen history). --fix auto-injects.
header "Documentation Disclaimer (inject-disclaimer.sh)"
if [ -f scripts/gates/inject-disclaimer.sh ]; then
	if bash scripts/gates/inject-disclaimer.sh --check 2>&1; then
		info "disclaimer: all living .md files carry the stale-data warning"
		PASS=$((PASS + 1))
	else
		if $FIX_MODE; then
			if bash scripts/gates/inject-disclaimer.sh >/dev/null 2>&1; then
				info "disclaimer: auto-injected (review git diff)"
				PASS=$((PASS + 1))
			else
				fail "disclaimer: auto-inject failed"
			fi
		else
			fail "disclaimer: .md file(s) missing the stale-data warning (auto-fixable via --fix)"
		fi
	fi
else
	warn "inject-disclaimer.sh not found — skipping"
fi

# ── 12. rustfmt (ebpf/ pure-Rust crate, exact CI parity) ──────────────────────
# The Gate-keepers workflow runs this exact command on every push
# (NIGHT-improve-13 moved the check wholesale here — one check, one
# place; the compile-carrying CI jobs build the crate with the same
# pinned nightly, NIGHT-improve-1 phase 3 retired the old
# clang-format gate with the C files). This check runs the CI
# command so a formatting regression cannot slip locally. The crate
# resolves its own toolchain from ebpf/rust-toolchain.toml.
header "rustfmt (ebpf/ crate, CI parity)"
if [ -d ebpf ]; then
	# Subshell: the cd must not leak into the gates below.
	if (cd ebpf && cargo fmt --all -- --check) 2>&1; then
		info "rustfmt: ebpf/ formatted (exact CI command)"
		PASS=$((PASS + 1))
	else
		fail "rustfmt: ebpf/ needs formatting (run: cd ebpf && cargo fmt)"
	fi
else
	warn "ebpf/ directory not found — skipping"
fi

# ── 13. Test-Tree Discipline (owner rule, NIGHT-hunt-17) ──────────────────
# Every .rs test file lives under the single top-level test/ tree
# (cosmostrix Pattern C): no Cargo tests/ autodiscovery directory
# (autotests = false keeps the old path inert), no *_tests.rs or
# *_test.rs module files under src/, every [[test]] target declared
# in Cargo.toml points under test/, and every #[path] module wiring
# inside src/ resolves into test/. Test code gets the same one-tree
# discipline as production code — one tree, one place.
header "Test-Tree Discipline (all .rs test files under test/)"
DISC_OK=true
if [ -d tests ]; then
	fail "test-tree: tests/ directory exists — its contents belong under test/ (autotests = false)"
	DISC_OK=false
fi
STRAY_TEST_FILES=$(find src -type f \( -name '*_tests.rs' -o -name '*_test.rs' \) 2>/dev/null)
if [ -n "$STRAY_TEST_FILES" ]; then
	fail "test-tree: test module files under src/ (they belong under test/):"
	echo "$STRAY_TEST_FILES"
	DISC_OK=false
fi
BAD_TEST_PATHS=$(sed -n '/^\[\[test\]\]/,/^\[/{s/^path[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p;}' Cargo.toml 2>/dev/null | grep -v '^test/' || true)
if [ -n "$BAD_TEST_PATHS" ]; then
	fail "test-tree: [[test]] target path(s) outside test/:"
	echo "$BAD_TEST_PATHS"
	DISC_OK=false
fi
BAD_MOD_PATHS=$(grep -rn '#\[path = ' src/ 2>/dev/null | grep -v '/test/' || true)
if [ -n "$BAD_MOD_PATHS" ]; then
	fail "test-tree: #[path] module wirings in src/ that do not resolve under test/:"
	echo "$BAD_MOD_PATHS"
	DISC_OK=false
fi
if $DISC_OK; then
	info "test-tree: disciplined (no tests/, no src/*_tests.rs, [[test]] and #[path] under test/)"
	PASS=$((PASS + 1))
fi

# ── 14. Language Discipline (owner rule, NIGHT-hunt-19) ─────────────
# The repo is English-only: comments, docs, script text, string
# literals (chat may be mixed-language; committed artifacts never
# are). Section 8 — the emoji sweep — blocks emoji codepoints; this
# gate blocks the two paths the sweep cannot see: non-Latin scripts
# (intentional Unicode coverage data self-declares via the
# NON_LATIN_FIXTURE: marker, the // LOC_EXEMPT discipline) and
# Indonesian vocabulary (the mixed-language directive quote leak).
header "Language Discipline (check-language.sh)"
if [ -f scripts/gates/check-language.sh ]; then
	if bash scripts/gates/check-language.sh 2>&1; then
		info "language: English-only discipline holds (no non-Latin prose, no Indonesian vocabulary)"
		PASS=$((PASS + 1))
	else
		fail "language: non-English content found (review the file:line list above)"
	fi
else
	warn "check-language.sh not found — skipping"
fi

# ── 15. Python lint + format (ruff, NIGHT-improve-13) ─────────────────────
# cosmostrix gate parity ("lint python"): the scripts/ tree (six
# python harnesses + helpers) gets the same lint+format gate the
# shell tree has had since the beginning. Rule set and line-length
# live in .ruff.toml — an EXPLICIT select (E4/E7/E9/F/I), never
# ruff's implicit defaults (those expand between releases; pinned
# findings only, the NIGHT-hunt-20 tool philosophy). The EXE001
# shebang/executable parity cosmostrix checks in its ruff section is
# deliberately NOT repeated here: section 7, the permission guard,
# already owns that contract repo-wide.
header "Python lint + format (ruff)"
PY_FILES=$(find scripts -name '*.py' -not -path '*/target/*' 2>/dev/null)
if [ -n "$PY_FILES" ]; then
	if command -v ruff >/dev/null 2>&1; then
		RUFF_OK=0
		# shellcheck disable=SC2086 # word splitting is intentional for file list
		if ! ruff check ${PY_FILES} 2>&1; then
			if $FIX_MODE; then
				# shellcheck disable=SC2086 # word splitting is intentional for file list
				if ruff check --fix ${PY_FILES} 2>&1; then
					info "ruff check: auto-fixed (review git diff)"
				else
					fail "ruff check: unfixable python lint errors remain (fix manually)"
					RUFF_OK=1
				fi
			else
				fail "ruff check: python lint errors found (auto-fixable via --fix)"
				RUFF_OK=1
			fi
		fi
		if $FIX_MODE; then
			# shellcheck disable=SC2086 # word splitting is intentional for file list
			ruff format ${PY_FILES} 2>&1
		else
			# shellcheck disable=SC2086 # word splitting is intentional for file list
			if ! ruff format --check ${PY_FILES} 2>&1; then
				fail "ruff format: python files not formatted (auto-fixable via --fix)"
				RUFF_OK=1
			fi
		fi
		if [ "$RUFF_OK" -eq 0 ]; then
			info "ruff: all python files lint-clean and formatted (.ruff.toml contract)"
			PASS=$((PASS + 1))
		fi
	else
		warn "ruff not installed — skipping (pip install ruff, or fetch the static binary from https://github.com/astral-sh/ruff/releases)"
	fi
else
	info "ruff: no .py files found"
	PASS=$((PASS + 1))
fi

# ── 16. Scripts LOC Cap (owner rule: 1000, NIGHT-lts-2) ───────────────────
# The scripts twin of section 9: every .sh/.py under scripts/
# (recursive) stays under the hard cap; a file over the cap passes
# ONLY with a self-declared `# LOC_EXEMPT:` marker plus a one-line
# justification (tracked migration debt, not silent rot). The three
# flagship harnesses carried their markers before this checker
# existed — this section is what turned those declarations into a
# live, every-push audit.
header "Scripts LOC Cap (check-scripts-loc.sh, limit 1000)"
if [ -f scripts/gates/check-scripts-loc.sh ]; then
	if bash scripts/gates/check-scripts-loc.sh 2>&1 | tail -25; then
		info "scripts LOC cap: all .sh/.py under scripts/ within policy (limit 1000)"
		PASS=$((PASS + 1))
	else
		fail "scripts LOC cap: script file(s) over 1000 lines without an exemption marker (split them or add # LOC_EXEMPT:)"
	fi
else
	warn "check-scripts-loc.sh not found — skipping"
fi

# ── 17. Release Parity (NIGHT-lts-9) ────────────────────────────────
# The four release platforms' local build aliases must carry the
# same -C codegen tokens as the release workflow's matrix rustflags
# (the optimization-tier parity the README documents). The lint token
# (-D warnings) is deliberately out of scope: the release build adds
# it via matrix env, the local alias deliberately does not — parity
# is about the codegen tier, not the lint posture. The workflow's own
# "Verify arch-baseline inputs" tripwire holds the canonical constant
# per platform at build time; this gate holds the cross-file equality
# at every push, before any tag is pushed.
header "Release Parity (check-release-parity.sh)"
if [ -f scripts/gates/check-release-parity.sh ]; then
	if bash scripts/gates/check-release-parity.sh 2>&1; then
		info "release parity: all four platforms' local aliases match the release matrix -C tokens"
		PASS=$((PASS + 1))
	else
		fail "release parity: platform -C token drift between .cargo/config.toml and release.yml (a local release-shape build would not be the release shape)"
	fi
else
	warn "check-release-parity.sh not found — skipping"
fi

# ── Summary ────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo -e "  Gatekeeper Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "═══════════════════════════════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
	echo -e "${RED}COMMIT BLOCKED: ${FAIL} check(s) failed.${NC}"
	if ! $FIX_MODE; then
		echo "Fix the issues above, or run: ./scripts/gate-keepers.sh --fix"
		echo "(codespell findings are never auto-fixed - review those manually)"
	else
		echo "Auto-fixes applied where possible; remaining findings need manual"
		echo "attention. Re-run plain ./scripts/gate-keepers.sh to confirm."
	fi
	exit 1
else
	echo -e "${GREEN}All checks passed — safe to commit.${NC}"
	exit 0
fi
