#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# PLATFORM: UNIX-only (Linux). zelynic is a Linux-only tool.
#
# ZELYNIC NAME-CASE CHECK (NIGHT-dinner-22)
#
"""Check the lowercase project-name rule (docs/BRANDING.md 3.1).

The project name is lowercase `zelynic` in every context — prose,
titles, headings, code, CLI output, comments, commit subjects, and
file paths — the nginx/curl convention the owner mandated in
NIGHT-dinner-21. This gate scans EVERY tracked file and EVERY
tracked path (git ls-files: the .cargo/ and .github/ hidden trees
included — nothing excluded) and fails on any casing outside the
two legal families BRANDING 3.1 codified:

  1. lowercase — the name itself, always;
  2. the identifier family — the `ZELYNIC_*` environment variables
     and the `ZELYNIC-DISCLAIMER` marker (attached with `_` or `-`),
     plus the all-caps banner comment titles heading the scripts/
     gate files (a comment line opening with the all-caps name).

Every other casing — a capitalized first letter, internal capitals,
or all-caps prose — fails with file:line:token. The checker is
self-clean by construction: the all-caps form is built at runtime
from the lowercase name, so this file carries no literal it would
flag itself on.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NAME = "zelynic"
UPPER = NAME.upper()
IDENTIFIER_CHARS = ("_", "-")
BANNER_SUFFIXES = {".sh", ".py"}
BANNER_RE = re.compile(r"^\s*#\s*" + UPPER + r"(\s|$)")
MAX_REPORTED = 50


def tracked_paths() -> list[str]:
    """Every path in the index — nothing excluded."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        ).stdout
    except subprocess.CalledProcessError as exc:
        print("zelynic name-case check: FAIL")
        print(f"git ls-files failed (exit {exc.returncode}) — run from a repo checkout")
        raise SystemExit(1) from exc
    return sorted(p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p)


def banner_title(path: str, line: str) -> bool:
    """True when the line is a banner title heading a scripts/ gate file."""
    if not path.startswith("scripts/"):
        return False
    if Path(path).suffix not in BANNER_SUFFIXES:
        return False
    return BANNER_RE.match(line) is not None


def violation_reason(path: str, line: str, token: str, prev: str, nxt: str) -> str | None:
    """None when the occurrence is legal, else the failure reason."""
    if token == NAME:
        return None
    if token == UPPER:
        if nxt in IDENTIFIER_CHARS or prev in IDENTIFIER_CHARS:
            return None
        if banner_title(path, line):
            return None
        return "all-caps outside the identifier family (docs/BRANDING.md 3.1)"
    return "the name is lowercase in every context (docs/BRANDING.md 3.1)"


def main() -> int:
    failures: list[str] = []
    files = 0
    tokens = 0
    lowercase = 0
    family = 0

    for path in tracked_paths():
        files += 1

        lowered = path.lower()
        pos = lowered.find(NAME)
        while pos != -1:
            end = pos + len(NAME)
            if path[pos:end] != NAME:
                bad = path[pos:end]
                failures.append(f"FAIL PATH   {path} '{bad}' — path tokens must be lowercase")
            pos = lowered.find(NAME, end)

        target = ROOT / path
        if not target.is_file():
            continue
        try:
            text = target.read_bytes().decode("utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            lowered = line.lower()
            pos = lowered.find(NAME)
            while pos != -1:
                end = pos + len(NAME)
                token = line[pos:end]
                prev = line[pos - 1] if pos > 0 else ""
                nxt = line[end] if end < len(line) else ""
                tokens += 1
                reason = violation_reason(path, line, token, prev, nxt)
                if reason is None:
                    if token == NAME:
                        lowercase += 1
                    else:
                        family += 1
                else:
                    failures.append(f"FAIL CASE   {path}:{lineno} '{token}' — {reason}")
                pos = lowered.find(NAME, end)

    print("zelynic name-case check: " + ("FAIL" if failures else "PASS"))
    for failure in failures[:MAX_REPORTED]:
        print(failure)
    if len(failures) > MAX_REPORTED:
        print(f"... and {len(failures) - MAX_REPORTED} more violation(s) not listed")
    print(
        f"Checked {files} tracked file(s) and path(s), {tokens} name token(s): "
        f"{lowercase} lowercase, {family} identifier/banner family, "
        f"{len(failures)} violation(s)."
    )
    if failures:
        print("The rule (docs/BRANDING.md 3.1): the name is lowercase in every")
        print("context; the ZELYNIC_* / ZELYNIC-DISCLAIMER identifiers and the")
        print("scripts/ banner titles are the only uppercase survivors.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
