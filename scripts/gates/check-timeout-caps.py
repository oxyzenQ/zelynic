#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial
"""CI runtime law (night-zen-2 caps; night-fly-1 ceiling + schedule
law, 2026-11-22 — docs/RULES.md "CI Runtime Caps" is the rule's home).

Three laws, one gate:

1. Every workflow job must declare a timeout-minutes cap — an uncapped
   job hangs to the platform default (hours) instead of failing
   loudly.
2. No cap may sit below the sanctioned floor (a too-tight cap kills
   honest work on runner jitter rather than on real failures) or
   above the sanctioned ceiling (a job that runs past the ceiling is
   the hang shape the owner outlawed: the nightly kani tier burned
   its full 300-minute cap and died cancelled with zero verdicts).
   Publish- and maintenance-critical lanes are exempt from the
   ceiling by the law's own exception — they still carry the floor.
3. No test lane rides a schedule: every test is trigger-by-commit on
   main. Only the law's exception workflows (release, reproducible,
   maintenance, crates-io) may keep a `schedule:` trigger.

The parser is deliberately dependency-free (the estate's other
workflow gate, check-actions-pins.sh, reads the same files with plain
tools): jobs are the two-space indented keys under `jobs:`, each
job's block ends at the next two-space key or the first dedent, and
the cap is the job block's `timeout-minutes:` line; a schedule
trigger is the two-space `schedule:` key under `on:`. The tree's
yamllint config holds the workflows to that shape.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WF_DIR = ROOT / ".github" / "workflows"
MIN_CAP = 10
MAX_CAP = 15
# The night-fly-1 exception: publish- and maintenance-critical lanes
# keep their larger caps and (where they had one) their schedule.
EXEMPT_WORKFLOWS = {
    "release.yml",
    "reproducible.yml",
    "maintenance.yml",
    "crates-io.yml",
}

JOBS_RE = re.compile(r"^jobs:\s*$")
JOB_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
CAP_RE = re.compile(r"^\s+timeout-minutes:\s*(\d+)\s*$", re.MULTILINE)
SCHEDULE_RE = re.compile(r"^  schedule:\s*$", re.MULTILINE)


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
    schedule_rows: list[str] = []
    for wf in sorted(WF_DIR.glob("*.yml")):
        text = wf.read_text(encoding="utf-8")
        jobs = parse_jobs(text)
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
            elif cap > MAX_CAP and wf.name not in EXEMPT_WORKFLOWS:
                failures.append(
                    f"{wf.name}: job '{name}' cap {cap}m exceeds the sanctioned ceiling "
                    f"{MAX_CAP}m (the night-fly-1 law: micro-split the lane)"
                )
        if SCHEDULE_RE.search(text) and wf.name not in EXEMPT_WORKFLOWS:
            schedule_rows.append(f"  {wf.name}")
            failures.append(
                f"{wf.name}: a test lane rides a schedule — the night-fly-1 law "
                f"trigger-by-commit on main only (drop the schedule: block)"
            )
    print("\n".join(rows))
    if schedule_rows:
        print("\nscheduled workflows (the exempt set only):")
        print("\n".join(schedule_rows))
    if failures:
        print(f"\nFAIL: {len(failures)} runtime-law violation(s):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(
        f"\nOK: {len(rows)} jobs across the estate, every one capped, "
        f"no cap below the {MIN_CAP}-minute floor, no cap above the {MAX_CAP}-minute "
        f"ceiling outside the exempt set, no schedule on a test lane"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
