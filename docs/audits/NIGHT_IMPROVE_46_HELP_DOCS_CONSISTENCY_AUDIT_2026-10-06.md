<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-improve-46 depth audit — the help surface and the documents, verified against the source

> Audit date: 2026-10-06 (NIGHT-improve-46). Scope: the helpers'
> --help/-h output audited for complete match/consistency with the
> source code — and, per the owner's addendum, every other document
> and data surface too. Audited at 3becf5d..f7c55ce (v20.0.0), the
> built flagship binary as the rendered truth, src/cli/{root,surface}.rs
> as the source truth. Method: the two-way flag extraction (every
> source flag must appear in the help, every help flag must exist in
> the source), the empirical bounds walk (every numeric claim in the
> help tested against the binary's actual enforcement), the docs
> drift scan (every --flag mention in the live docs classified), and
> the command/alias census. Status: CONSISTENT — the help matches the
> source in both directions, every numeric claim tested is enforced
> exactly as printed, the live docs carry zero real drift, and the
> machine pins (help_pins.rs, 14 tests) hold the contract. Two
> presentational conventions verified as deliberate, one recurring
> tooling lesson re-confirmed.

## 1. The mandate

The owner's ask: depth-audit the helpers' --help/-h output for
complete match/consistency with the source code — honest,
transparent — and not just the help: every other document and data
surface too. The instrument table:

| # | The ask | The instrument this audit used |
|---|---|---|
| 1 | Help matches source, both directions | the two-way extraction: 22 source long flags (surface.rs + root.rs arg definitions) checked against the rendered help, and every --flag the help prints checked against the source set |
| 2 | The numeric claims are true | the empirical bounds walk: interval, focus, rate, during, bracket laws — each probed from both sides of its boundary on the built binary |
| 3 | The docs match the surface | the drift scan: every --flag mention in the live docs (434 across docs/ + README + QA, archives and audit records excluded as frozen history) classified as live / retired-documented / other-tool / payload-example |
| 4 | Commands and aliases complete | the 16-verb census + the 10 short aliases + the 2 shorthands against USAGE.md and README |
| 5 | The contract holds tomorrow | the machine pin inventory: help_pins.rs's 14 pins, including the 13-flag Pro mode drift pin and the subcommand -h refusal pin |

## 2. The two-way flag check

The source defines 22 long flags (the strict family's rate grammar:
during, floor, ceil and the four per-direction twins; force-this,
no-probe, per-socket; the monitor's interval, focus, depth; the
globals: help, version, verbose, print-json, color-mode,
check-update with its check-updated alias, reset-terminal; and the
per-direction download/upload pair). The rendered --help documents
every one of them:

- the globals in their own section,
- the rate grammar's -d/-u in every strict usage line and example,
- the thirteen advanced flags in the Pro mode section
  (improve-45), held by the 13-flag drift pin,
- the eagle-eyes trio in the monitor's own block and the Pro mode
  deep-inspection group.

The reverse direction: the help's only flag mentions with no
source definition are --info and --limit, and both are NEGATIVE
documentation — "the --info alias is retired, NIGHT-blade-4" and
"Rows follow the terminal height (no --limit)" — naming what does
NOT exist, on purpose. The hidden internal probe roles
(`__probe-server`, `__probe-client`) stay hidden by design: the
hidden-vocabulary contract's security posture, documented at the
improve-45 landing and re-verified here.

One presentational convention verified as deliberate, not drift:
the long spellings --download/--upload parse (they pass the gate;
clap registers them from the arg definitions) but the docs
present the interface as -d/-u — the source's own doc comment
says "Use -d/-u for per-direction", and no document ever names
the long spellings, so nothing is stale. The help's usage lines,
examples, and USAGE.md all carry the short forms consistently.

The subcommand -h/--help refusal (single-tier help surface,
NIGHT-improve-3) was probed on strict-single, eagle-eyes, and the
ss alias: every one refuses with the tip 'a similar argument
exists: zelynic --help' — the exact shape help_pins.rs's
test_subcommand_help_errors_with_suggestion pins.

## 3. The empirical bounds walk — every numeric claim tested

| The help's claim | The probe | The verdict |
|---|---|---|
| --interval: 1s to 60s | 90s refused ("must be between 1s and 60s"), 60s passes to the root gate | enforced exactly |
| --focus: 1s..30s, default 3s | 31s refused ("must be between 1s and 30s"), 30s passes | enforced exactly |
| Rate min: 1kb (1000 B/s decimal SI) | 500b refused with the SI wording and the --force-this redirect | enforced exactly |
| Rate max: 1tb | 1.5tb refused ("above maximum (1000000000000 B/s = 1 TB/s)") | enforced exactly |
| --during: 1s..10y, duration only | 11y and 500y refused ("the ceiling is 10y — a longer promise is a forever-limit wearing a date"); 30d passes; the removed window shape 09:00-17:00 refused BY NAME with the grammar tip | enforced exactly, including the removed-shape wording |
| The bracket ladder floor <= ceil <= rate | floor 200kb on rate 100kb refused (the over-subscription explanation); floor 50kb under ceil 20kb refused (the contradiction wording); the mixed spelling (--floor + --ceil-download) LEGAL, passes the gate; the double spelling (--floor + --floor-download) refused with the one-spelling law | enforced exactly, including the composition law improve-42 pinned |
| Dangerous target warning: 57 system processes | the blocklist counted at source: exactly 57; the help number is COMPUTED (DANGEROUS_TARGETS.len() formatted into the Safety section) — drift is structurally impossible | verified, and drift-proof by construction |
| Rate formats: lowercase only | 1MB refused with the lowercase tip (USAGE.md documents the tip; the pinned suite covers the fractional twins) | consistent with the docs |

## 4. The docs drift scan

434 --flag mentions across the live docs (docs/ tree, README,
QA; docs/archive/, docs/audits/, and the era changelogs excluded
as frozen history). Every mention classified:

- live surface flags, correctly spelled;
- documented RETIRED spellings (--help-all, --info, --live,
  --duration, --allow-dangerous, --force) — each named AS retired
  at its site (USAGE.md's "The CLI surface is frozen" section is
  the census; BRANDING.md names the --help-all merge; the
  retired spellings' refusal tips are pinned in the test tree,
  e.g. removed_help_all_flag_suggests_help);
- other tools' flags (cargo's --locked/--release/--features,
  gpg's --keyserver/--recv-keys/--verify, git's --short, curl's
  --max-time, docker's --privileged) — build/verify instructions,
  not the zelynic surface;
- the project's own script flags (--self-test, --quick, --json on
  the harnesses; --smoke/--endurance/--battery on the sandbox) —
  script surfaces, each documented at its own script;
- example payload text (a JSON document's "./cat-test --serve"
  cmdline, the depth report's field names) — data, not interface.

**Zero real drift.** No document names a flag the source does not
carry, no live flag is undocumented, and the retired vocabulary is
consistently marked retired everywhere it appears.

## 5. The command and alias census

All 16 verbs documented in USAGE.md (the strict family's three,
the block family's three, the unstrict family's three, recover,
snapshot, restore, status, list-apps, eagle-eyes, doctor); the 10
two-letter short aliases (ss sm sa bs bm ba us um ua ee) plus the
strict/unstrict shorthands documented as one block at USAGE.md's
command overview — the same `alias = canonical` pairing --help
prints; README's quick paths route through the same set. The
alias routing was probed live (ss parses to the strict-single
grammar — its missing-TARGET usage error names strict-single's
line, proving the route).

## 6. The machine pin inventory (tomorrow's consistency)

The drift contract is not this audit's prose — it is held by
help_pins.rs (14 tests, all green in the fresh battery): the
command census pin, the short-alias pairing pin, the verb-group
pin, the example-annotation pin, the unstrict synopsis pin, the
strict-single flags-complete pin, the quit-key contract pin, the
target-forms pin, the status-ledger pin, the bare-invocation pin,
the depth-mode pin, the subcommand-help-refusal pin, the Pro mode
13-flag drift pin, and the removed-help-all pin. A future flag
that ships hidden fails the battery the day it lands — the exact
regression class improve-45 closed.

## 7. The recurring tooling lesson

This audit's own reads hit the display-layer mangling twice more
(an apparent "1s to n" and an apparent "--ln" in tool output that
dissolved to the true bytes "1s to 60s" and "--interval" under
python repr) — the third occurrence this session after
depthbore-1's #[must_use] ghost, in the exact class the
long-horizon-1 audit documented. The discipline holds and must
stay: verify at the byte level before flagging, in audits and in
tools alike.

## 8. The verdict

**Consistent — the help surface matches the source in both
directions, every numeric claim tested is enforced exactly as
printed, and the live documents carry zero real drift.** The
honest notes are the two presentational conventions verified as
deliberate (the -d/-u short-form documentation choice; the
retired vocabulary named as retired), the computed-not-hardcoded
blocklist count (drift-proof by construction), and the recurring
display-mangling lesson (a tooling observation, not a project
defect). Nothing to fix; the correct entry for a consistency
audit whose subject already holds.
<!-- ZELYNIC-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every doc — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`, `ebpf/src/**/*.rs`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
