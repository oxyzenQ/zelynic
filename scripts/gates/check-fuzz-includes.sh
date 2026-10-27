#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux introspection tool; no other OS is supported.
#
# GATE 22: THE FUZZ INCLUDE LAW (night-dragon-maintenance-5, the
# zejtron estate's gate 18 ported to zelynic's fuzz lane)
#
# fuzz/fuzz_targets/*.rs path-include the parser sources and compile
# them STANDALONE (the contract documented in fuzz/Cargo.toml): the
# harness proves the same bytes the binary ships, which only holds
# while every included file is crate-import-free. One `crate::` path
# in an included file reds the cargo fuzz CI lane in seconds while
# every other gate stays green - the exact failure class the law
# exists to catch before the push. This gate is the local seat of the
# law the fuzz CI enforces the hard way.
#
# The law: every src/-rooted file the harness includes, plus every
# declared submodule of those files, must carry zero `crate::` paths
# in CODE - the sibling reach is `super::`, which resolves
# identically in the harness and in the crate. Comment lines are
# prose, not paths, and are stripped before the sweep.
#
# Fail closed: no targets, no src-rooted include, or a missing direct
# include is a failure, never a pass.

set -euo pipefail
cd "$(dirname "$0")/../.." || exit 1

if ! ls fuzz/fuzz_targets/*.rs >/dev/null 2>&1; then
	echo "fuzz include law: no fuzz targets found - fail closed" >&2
	exit 1
fi

# The src/-rooted includes, extracted from the targets' #[path]
# attributes. Test-file includes (../../test/...) are compiled out of
# the harness by cfg(test) and are not the law's subject.
includes="$(sed -n 's/^[[:space:]]*#\[path[[:space:]]*=[[:space:]]*"\.\.\/\.\.\/src\/\([^"]*\)".*/\1/p' \
	fuzz/fuzz_targets/*.rs | sort -u | sed 's|^|src/|')"
if [ -z "${includes}" ]; then
	echo "fuzz include law: no src-rooted include in fuzz_targets - fail closed" >&2
	exit 1
fi

# The declared submodules of the included files (a mod declaration
# whose file exists beside the includer is pulled into the harness
# too, exactly as the crate pulls it). A declared module whose file
# does not exist is a cfg(test)-gated decl pointing into test/ by
# convention - not part of the include.
all_includes="${includes}"
while IFS= read -r f; do
	[ -n "${f}" ] || continue
	dir="$(dirname "${f}")"
	while IFS= read -r m; do
		[ -n "${m}" ] || continue
		if [ -f "${dir}/${m}.rs" ]; then
			all_includes="${all_includes}
${dir}/${m}.rs"
		fi
	done < <(sed -n 's/^\(pub \)\{0,1\}mod[[:space:]]\{1,\}\([a-z_0-9]\{1,\}\);.*/\2/p' "${f}")
done <<<"${includes}"
all_includes="$(echo "${all_includes}" | sort -u)"

status=0
count=0
while IFS= read -r f; do
	[ -n "${f}" ] || continue
	count=$((count + 1))
	if [ ! -f "${f}" ]; then
		echo "fuzz include law: direct include ${f} is missing - fail closed" >&2
		status=1
		continue
	fi
	if sed 's|//.*$||' "${f}" | grep -q 'crate::'; then
		echo "fuzz include law: ${f} carries crate:: in code - the fuzz harness includes it standalone" >&2
		sed 's|//.*$||' "${f}" | grep -n 'crate::' >&2
		status=1
	fi
done <<<"${all_includes}"

if [ "${status}" -eq 0 ]; then
	echo "fuzz include law: ${count} included files are crate-import-free (compile standalone)"
fi
exit "${status}"
