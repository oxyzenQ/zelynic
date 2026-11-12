#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
"""CI runtime caps (night-zen-2; docs/RULES.md "CI Runtime Caps" is
the rule's home).

Every workflow job must declare a timeout-minutes cap, and no cap may
sit below the sanctioned floor: an uncapped job hangs to the platform
default (hours) instead of failing loudly, and a too-tight cap kills
honest work on runner jitter rather than on real failures. The floor
governs only how tight a cap may never be; heavy lanes keep their
larger, deliberate ceilings (the supermassive batteries ride 40-60).

The parser is deliberately dependency-free (the estate's other
workflow gate, check-actions-pins.sh, reads the same files with plain
tools): jobs are the two-space indented keys under `jobs:`, each
job's block ends at the next two-space key or the first dedent, and
the cap is the job block's `timeout-minutes:` line. The tree's
yamllint config holds the workflows to that shape.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WF_DIR = ROOT / ".github" / "workflows"
MIN_CAP = 10

JOBS_RE = re.compile(r"^jobs:\s*$")
JOB_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
CAP_RE = re.compile(r"^\s+timeout-minutes:\s*(\d+)\s*$", re.MULTILINE)


def parse_jobs(text: str) -> dict[str, str]:
    """Return {job_id: job_block_text} for the keys under `jobs:`."""
    jobs: dict[str, str] = {}
    current: str | None = None
    block: list[str] = []
    in_jobs = False
    for line in text.splitlines():
        if JOBS_RE.match(line):
            in_jobs = True
            current = None
            block = []
            continue
        if not in_jobs:
            continue
        m = JOB_RE.match(line)
        if m:
            if current is not None:
                jobs[current] = "\n".join(block)
            current, block = m.group(1), []
        elif line and not line.startswith(" "):
            # dedent to column zero — the jobs: mapping is over
            if current is not None:
                jobs[current] = "\n".join(block)
            current, block, in_jobs = None, [], False
        elif current is not None:
            block.append(line)
    if current is not None:
        jobs[current] = "\n".join(block)
    return jobs


def main() -> int:
    failures: list[str] = []
    rows: list[str] = []
    for wf in sorted(WF_DIR.glob("*.yml")):
        jobs = parse_jobs(wf.read_text(encoding="utf-8"))
        if not jobs:
            failures.append(f"{wf.name}: no jobs parsed — parser evidence needed")
            continue
        for name in sorted(jobs):
            m = CAP_RE.search(jobs[name])
            if m is None:
                failures.append(f"{wf.name}: job '{name}' declares no timeout-minutes cap")
                continue
            cap = int(m.group(1))
            rows.append(f"  {wf.name}:{name}: {cap}m")
            if cap < MIN_CAP:
                failures.append(
                    f"{wf.name}: job '{name}' cap {cap}m sits below the sanctioned floor {MIN_CAP}m"
                )
    print("\n".join(rows))
    if failures:
        print(f"\nFAIL: {len(failures)} runtime-cap violation(s):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(
        f"\nOK: {len(rows)} jobs across the estate, every one capped, "
        f"no cap below the {MIN_CAP}-minute floor"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
