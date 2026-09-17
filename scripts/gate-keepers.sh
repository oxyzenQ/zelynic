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
#   1.  Shell scripts (strict triad):
#         1a. bash -n   — syntax check (fast fail-fast pre-filter)
#         1b. shellcheck — static analysis (default rule set)
#         1c. shfmt -d  — canonical formatting (tabs, function braces
#             on own line, case branches expanded); --fix runs
#             `shfmt -w` to auto-canonicalize
#   2.  yamllint on .github YAML (repo .yamllint config)
#   3.  actionlint on .github/workflows/*.yml
#   4.  TOML syntax validation (python3 tomllib)
#   5.  codespell on all text files (repo .codespellrc)
#   6.  SPDX license header check (scripts/check-headers.sh — dual-line
#       contract across rs/c/h/py/sh/toml/yml/yaml/md; untracked files
#       included so new files fail BEFORE commit)
#   7.  File permission guard (owner rule — git-tracked files 644,
#       tracked executables and directories 755, shebang parity;
#       scripts/check-permissions.sh, --fix chmods)
#   8.  Emoji sweep (owner rule — no emoji-class codepoints in ANY
#       tracked text file; cosmostrix fail blocks, strict detector,
#       exit 1 on hits)
#   9.  Rust source LOC cap (owner rule — scripts/check-loc.sh, hard
#       limit 500 lines; // LOC_EXEMPT: marker = tracked migration debt)
#  10.  Rust toolchain version sync (scripts/check-rust-version-sync.sh —
#       rust-toolchain.toml pin == Cargo.toml MSRV == workflow RUST_VERSION)
#  11.  Documentation disclaimer (scripts/inject-disclaimer.sh --check —
#       every living .md carries the stale-data warning; --fix injects)
#
# Missing tools are skipped with a warning so the gate stays usable
# on minimal development machines; CI enforces the full set.
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

# ── 1. Shell scripts (strict triad: bash -n + shellcheck + shfmt -d) ───────
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
		# shellcheck disable=SC2086 # word splitting is intentional for file list
		if shellcheck ${SHELL_FILES} 2>&1; then
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

# ── 2. Yamllint ────────────────────────────────────────────────────────────
header "Yamllint"
if command -v yamllint >/dev/null 2>&1; then
	# CI parity: .github/** must pass the repo .yamllint config — the
	# same one the CI workflow_quality job enforces (line-length max
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

# ── 6. SPDX License Headers (scripts/check-headers.sh) ──────────────────
# Dual-line contract (Copyright + SPDX-License-Identifier) across
# rs/c/h/py/sh/toml/yml/yaml/md, including untracked-but-present files
# (pre-commit proxy parity). CHANGELOG.md is excluded as frozen history.
header "SPDX License Headers (check-headers.sh)"
if [ -f scripts/check-headers.sh ]; then
	if bash scripts/check-headers.sh 2>&1; then
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
if [ -f scripts/check-permissions.sh ]; then
	if $FIX_MODE; then
		if bash scripts/check-permissions.sh --fix 2>&1; then
			info "permissions: violations auto-fixed (review git diff for exec-bit changes)"
			PASS=$((PASS + 1))
		else
			fail "permissions: violations not fully auto-fixable (review output above)"
		fi
	else
		if bash scripts/check-permissions.sh 2>&1; then
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
# CHANGELOG.md (frozen historical record — archive content is never
# rewritten, the same exclusion policy as the docs audit).
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
SKIP_FILES = {"CHANGELOG.md"}
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
header "Rust LOC Cap (check-loc.sh, limit 500)"
if [ -f scripts/check-loc.sh ]; then
	if bash scripts/check-loc.sh 2>&1 | tail -20; then
		info "LOC cap: all Rust files within policy (limit 500)"
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
if [ -f scripts/check-rust-version-sync.sh ]; then
	if bash scripts/check-rust-version-sync.sh 2>&1; then
		info "rust version: toolchain pin, MSRV, and CI pins in sync"
		PASS=$((PASS + 1))
	else
		fail "rust version: sources out of sync (fix with ./scripts/rust-version-to.sh <X.Y.Z>)"
	fi
else
	warn "check-rust-version-sync.sh not found — skipping"
fi

# ── 11. Documentation Disclaimer ──────────────────────────────────────────
# Every living .md file carries the stale-data disclaimer at the bottom
# (CHANGELOG.md excluded as frozen history). --fix auto-injects.
header "Documentation Disclaimer (inject-disclaimer.sh)"
if [ -f scripts/inject-disclaimer.sh ]; then
	if bash scripts/inject-disclaimer.sh --check 2>&1; then
		info "disclaimer: all living .md files carry the stale-data warning"
		PASS=$((PASS + 1))
	else
		if $FIX_MODE; then
			if bash scripts/inject-disclaimer.sh >/dev/null 2>&1; then
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
