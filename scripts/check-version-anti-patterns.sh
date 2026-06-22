#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# =============================================================================
# ZELYNIC VERSION-ANTI-PATTERN GUARD
# =============================================================================
# Fails if any source file re-introduces the hardcoded-version-string
# anti-pattern that previously broke CI on every version bump (13 tests
# failed when 3.1.0 -> 3.1.1 because tests asserted Cargo.toml contains
# the literal "3.1.0" string).
#
# Anti-pattern blocked:
#   - contains("version = \"X.Y.Z\"")  (Cargo.toml version tautology)
#   - Any contains() assertion on another test file's source code that
#     checks for a literal semver string (test-on-test meta-pattern)
#
# Correct pattern (allowed):
#   The current package version is verified by cargo metadata and by
#   tests/integration_test.rs::test_version (which uses the --version
#   CLI flag). No test should assert that Cargo.toml contains its own
#   version field — that is tautological (always true).
#
# Historical CHANGELOG assertions (e.g. contains("v3.0.1")) are NOT
# blocked — those verify a historical release entry exists and remain
# valid forever.
#
# Usage: bash scripts/check-version-anti-patterns.sh
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Patterns that indicate a hardcoded current-version assertion.
PATTERNS=(
    'contains("version = \\"[0-9]'
    'contains(r#"version = "[0-9]'
    'contains(r#"version = \\"[0-9]'
)

VIOLATIONS=0
FILES_CHECKED=0

while IFS= read -r -d '' file; do
    FILES_CHECKED=$((FILES_CHECKED + 1))
    for pattern in "${PATTERNS[@]}"; do
        if grep -nE -- "$pattern" "$file" >/dev/null 2>&1; then
            echo -e "${RED}VIOLATION: ${file}${NC}"
            grep -nE -- "$pattern" "$file" | head -5 | sed 's/^/    /'
            VIOLATIONS=$((VIOLATIONS + 1))
        fi
    done
done < <(
    find "$REPO_ROOT/src" \
        -name '*.rs' \
        -not -path '*/target/*' \
        -print0 2>/dev/null
)

# Also block the test-on-test meta-pattern: tests that include_str!() another
# test file and check it contains a literal semver string.
META_PATTERN='include_str!.*tests?\.rs.*\.contains\("[0-9]+\.[0-9]+\.[0-9]+"'
META_REPORTED=""
while IFS= read -r -d '' file; do
    basename_file="$(basename "$file")"
    # Skip if we already reported this file
    if [[ "$META_REPORTED" == *"$basename_file"* ]]; then
        continue
    fi
    if grep -nE -- "$META_PATTERN" "$file" >/dev/null 2>&1; then
        echo -e "${RED}VIOLATION (meta-test): ${file}${NC}"
        grep -nE -- "$META_PATTERN" "$file" | head -5 | sed 's/^/    /'
        VIOLATIONS=$((VIOLATIONS + 1))
        META_REPORTED="$META_REPORTED $basename_file"
    fi
done < <(
    find "$REPO_ROOT/src" \
        -name '*.rs' \
        -not -path '*/target/*' \
        -print0 2>/dev/null
)

if [[ "$VIOLATIONS" -eq 0 ]]; then
    echo "OK: $FILES_CHECKED source files checked, no version-anti-pattern violations"
    exit 0
else
    echo ""
    echo -e "${RED}FAIL: $VIOLATIONS file(s) contain hardcoded version assertions${NC}"
    echo ""
    echo "Fix: delete tautological version tests. The current package version"
    echo "is already verified by tests/integration_test.rs::test_version."
    echo ""
    echo "If you genuinely need to assert a version in a test, use:"
    echo '  const V: &str = env!("CARGO_PKG_VERSION");'
    echo '  assert!(cargo.contains(&format!("version = \"{}\"", V)));'
    exit 1
fi
