<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->

# night-dragon-fly-1: the end-to-end CLI UX audit manual

Date: 2026-11-27. Scope: the whole operator-visible CLI surface of the
zelynic binary — every command, flag, alias, retired spelling, error
lane, JSON contract, exit code, color law, and wording decision the
`zelynic --help` reference names. Source code is the truth this
manual is written from; the capture battery is the instrument that
proves the binary still tells it.

This audit is a two-step loop, by design:

1. This session produced the case catalog below and the capture
   battery `scripts/labs-exp/capture-cli-ux-e2e.sh`, every case's
   expected verdict derived from the source files cited inline.
2. The owner runs the battery on the real machine (the only place
   the true terminal, the true kernel, and the true privileges
   exist) and sends the log back; the next session diffs reality
   against this catalog and lands the fixes.

## How to run

```text
bash scripts/labs-exp/capture-cli-ux-e2e.sh > zelynic-ndf1-e2e.log 2>&1
```

The default run needs no privileges and touches no enforcement
state; its only network call is the single `--check-update` case
(safe offline — the error chain is itself audit material). The root
lane adds the enforcement smoke against a spawned `sleep` process
with full cleanup on exit:

```text
RUN_ROOT=1 bash scripts/labs-exp/capture-cli-ux-e2e.sh > zelynic-ndf1-e2e.log 2>&1
```

`ZELYNIC_BIN=/path/to/zelynic` overrides the binary under test. The
battery prints one block per case — `===== [ID] command =====`, the
exit code, then stdout and stderr separated — so every finding is
citable by ID. The BYHAND block at the log's end lists what the
battery refuses to automate (the screen-clearing terminal rescue,
the fleet sweeps, the live TUI frames) with the exact commands.

## Section map

| Section | Cases | Contract source |
|---------|-------|-----------------|
| E | environment, identity, `-V`, build facts | src/info/, src/commands/doctor.rs |
| A | `--help`, `-h`, no-args, `help` redirect, broken pipe, print-json honesty notes | src/main.rs:164-205, src/commands/help.rs, src/cli/ux.rs |
| B | the twelve per-verb help doors (exit 0, stdout) | src/cli/ux.rs:254-306, src/cli/surface.rs |
| C | the `--print-json` contract: honored surfaces, error object, ignored-note | src/cli/scope.rs, src/cli/json_error.rs, src/cli/argv.rs:210-237 |
| D | the rescue engine: redirect table, flag rescues, value tips, guards, bounds | src/cli/redirects.rs, src/cli/rescue.rs, src/cli/tips.rs, src/cli/suggestion.rs |
| F | the color/wrap/environment law: NO_COLOR, COLUMNS, TERM, mono lane | src/output/, src/cli/argv.rs:259-310 |
| G | determinism: help bytes, doctor JSON byte-stability | docs/USAGE.md (the stable v11 scripting API) |
| R | the root lane: doctor, sig, status, list-apps, recover, the enforcement smoke | src/commands/, the verbose law, the JSON-purity pin |

## The case catalog and its source-pinned expectations

### E — environment and identity

| ID | Command | Expected from source | Watching for |
|----|---------|---------------------|--------------|
| E01 | `command -v`, `-V` | Version banner with build facts (root.rs:62-72, info::print_version_report) | Banner content vs doctor's BUILD block drift |
| E02 | `--version` | Identical report to `-V` (same field, two spellings) | Any byte difference between the spellings |
| E03 | env facts | — | The env the audit ran under (TERM, COLORTERM, COLUMNS) |
| E04 | tool presence | — | python3 missing degrades the JSON shape checks honestly |

### A — help and metadata

| ID | Command | Expected | Watching for |
|----|---------|----------|--------------|
| A01/A02 | `--help`, `-h` | The curated end-to-end reference, stdout, exit 0 (main.rs:172-175, help.rs) | `-h` vs `--help` byte difference at the root (same field, same print) |
| A03 | bare `zelynic` | The same reference, exit 0 (commands/mod.rs:419-425) | Any difference vs A01 |
| A04 | `zelynic help` | Usage error exit 2, one tip: `to see the reference, run 'zelynic --help'` (redirects.rs:132-171) | A second (fuzzy) tip beside the redirect — the override must remove it |
| A05 | `--help \| head -3` | No panic; the writer swallows the broken pipe | Non-zero/141 exit surfacing from the pipe |
| A06-A09 | `--print-json` with `-h`/`-V`/bare | The stderr honesty note BEFORE the text surface; stdout untouched (main.rs:164-166, ux.rs:344-356) | The note landing on stdout, or the exit code moving |
| A10/A11 | `-V` after a subcommand | The banner prints, the command never runs (root.rs:64-72, global) — measured law since night-cafe-1's version door (`s -V` on a required-positional verb prints the report, exit 0; F7) | Any command execution before the banner |
| A12 | `--reset-terminal` | BYHAND only — silent, screen-clearing by design | — |

### B — the per-verb help doors

| ID | Command | Expected | Watching for |
|----|---------|----------|--------------|
| B01-B12 | `<verb> -h` / `<verb> --help` for strict, block, unstrict, eagle-eyes, status, list-apps, doctor, sig, recover | clap's local help on stdout, exit 0 (ux.rs:254-306); B02 (strict) speaks operator English with verbatim example rails since night-cafe-1's F10 (zero lineage codenames on the surface) | The local synopsis spelling `<TARGET> [RATE]` vs the curated reference's lowercase `<target> [rate]` (help.rs:120) — one grammar, two cases? |
| B13 | `strict -h --print-json` | The stderr note first, then the local help, exit 0 (ux.rs:344-356) | Note on stdout; exit code drift |

### C — the print-json contract

| ID | Command | Expected | Watching for |
|----|---------|----------|--------------|
| C01 | `doctor --print-json` | One compact JSON document, stdout, exit 0 | Parse failure; multi-line wrapping |
| C02/C03 | `status`/`list-apps --print-json` unpromoted | The runtime refusal as the JSON error object `{"error","tip"}`, stdout, exit 1 (main.rs:42-53) — or the documented degraded census for list-apps | Prose leaking onto the JSON lane; tip empty when advice exists |
| C04 | `ee --depth --print-json` without a target | Usage-class error as the JSON object (argv pre-parse scan, argv.rs:210-237) | The prose usage block leaking |
| C05 | `--print-json strictt` | `{"error":"unrecognized subcommand 'strictt'","tip":"some similar subcommands exist: 's', 'unstrict', 'strict'"}` exit 1 — the plural join (F4) | Tip content vs D01 — byte-parallel since night-cafe-1 |
| C06 | `--print-json snapshot` | The redirect rides since night-cafe-1 (H1 fixed): tip names the successor `status` — the same facts the prose render carries | Any drift re-appearing (the door moving back before the chain) |
| C07 | `--print-json __probe-serve` | The hidden-vocabulary filter runs BEFORE the JSON door (H2 fixed): tip `""`, the honest dead end | The probe pair surfacing in a machine tip — the regression class |
| C08 | `--print-json --verbos` | The JSON object carrying the rescue: tip names `--verbose` (H1 family fixed) | Tip vs D29 — parity |
| C09 | `--print-json s brave 1kb` | stderr note `--print-json ignored (JSON surface: ...)` + the prose refusal; stdout clean, exit untouched (scope.rs, commands/mod.rs:99-101) | Note on stdout; exit drift — see H4 |
| C10 | `--print-json sig` | Same note + the sig text report | Note wording listing sig as ignored |
| C11 | `--print-json --color-mode 99` | `{"error": <grammar reason>, "tip": ""}` exit 1 (main.rs:150-152) | Prose render leaking; empty-tip key absent |

### D — the rescue engine (the wording audit's core)

| ID | Command | Expected | Watching for |
|----|---------|----------|--------------|
| D01-D03 | `strictt`, `sttict`, `statuss` | Exit 2, clap's unrecognized-subcommand verdict; a fuzzy tip only when Jaro clears 0.7 | No-tip dead ends; double tips |
| D04-D28 | the full retired-spelling sweep: observe, top, eagle-eye, limit-all, la, strict-single, strict-multi, ss, sm, block-single, block-multi, bs, bm, unstrict-single, unstrict-multi, us, um, strict-all, sa, block-all, ba, unstrict-all, ua, snapshot, restore | Exit 2 with the redirect tip naming the successor verb or `verb --all` spelling (redirects.rs:45-89) | Any spelling whose tip names a dead or wrong successor |
| D29/D30 | `--verbos`, `--VERBOS` | Exit 2, one tip `a similar argument exists: '--verbose'` (case-insensitive rescue, suggestion.rs:85-164) | Two tips (the escape hatch must be dropped, ux.rs:151) |
| D31/D32 | `--json` at root and after `s` | The vocabulary rescue tip `--print-json` (rescue.rs:147) | Root-lane note: the flag itself is unknown; subcommand lane: same tip shape |
| D33 | `s brave 1kb --check-updat` | The shadowed-suggestion rescue: `--check-update` must beat `--ceil-upload` (rescue.rs:67-115); the usage line is the POST-chain form (F13: one usage per error class — byte-identical to D34's) | The subcommand pool shadowing the root flag — the improve-42 regression class |
| D34 | `s brave 1kb --check-updated` | The top-level authority tip `zelynic --check-update` (rescue.rs:32-39) | A bare `--check-update` tip pointing at a position where it still fails |
| D35 | `s brave 1kb --no-probe` | The vocabulary tip `--no-test` (rescue.rs:138-145) | Tip-less death (jaro 0.69 is under the bar by design) |
| D36 | `ee brave --info` | The vocabulary tip `--depth` (rescue.rs:129-137) | Tip-less death |
| D37 | `s brave 1mb --allow-dangerous` | The vocabulary tip `--force-this` (rescue.rs:127) — measured law since night-cafe-1's exact-spelling fence (clap's `--all` shadow, the D37 find, closed) | — |
| D38 | `s brave 550kb -- -V` | The escape hatch is HONEST here (the probe re-parses the spliced argv, argv.rs:70-81): the tip stays | A rescue tip and the hatch both printing |
| D39 | `s brave 550kb -- -i` | The hatch is DISHONEST (following it dies again): the tip must be dropped | The tip surviving — the boost-13 contract |
| D40 | `ee brave electron` | Exit 2 + the grammar tip `targets are ONE slash-separated argument` (ux.rs:201-235) | No tip; the flag rescues firing on a bare word |
| D41 | `ee brave/electron` | Parses; proceeds to the privilege or resolution rung | Parse rejection of the documented grammar |
| D42 | `--color-mode` (no value) | Exit 2, `a value is required for '--color-mode' but none was supplied` (json_error.rs:163-175 wording, prose twin) | `invalid value ''` — the machine-facing lie class |
| D43 | `--color-mode 99 doctor` | Exit 2 with the allowed grammar in the message AND exactly one canonical footer (F14 — the one fatal path that ended without it, closed) | The allowed list wording vs the help table |
| D44 | `--color-mode 0 doctor` | doctor in mono — zero ESC bytes (the one-color law, NIGHT-improve-73) | ESC bytes anywhere in stdout or stderr |
| D45-D47 | the 16-rung remap and the byte law | ESC bytes present, truecolor `38;2;` escapes ABSENT (clap_styles_16 remap, ux.rs:365-378) | RGB bytes surviving into the 16-rung render |
| D48-D51 | `1kib`, `10mbps`, `1MB`, `5.5xb` | Exit 2 + the unknown-unit verdict naming the crime (`unknown unit 'kib' — the ladder is b, kb, mb, gb, tb`, F6) + `tip: a similar value exists: '1kb'` / `'10mb'` / `'1mb'` / `'5.5kb'` (tips.rs:50-89, the fractional split) | The wrong-layer digit sentence re-appearing; comma-lane competition |
| D52 | `s brave 500b` | The min-rate guard refusal (< 1kb) | The guard's rung order vs privilege |
| D53 | `s brave 0.9kb` | The min-rate guard refusal (900 < 1000) | Rounding drift |
| D54 | `s brave 2tb` | The max-rate refusal (max 1tb) | The bound wording |
| D55 | `s brave 1000b` | Accepts — 1000 b/s IS 1kb (help_flags.rs:106) | Off-by-one at the boundary |
| D56 | `--during 3min` | Exit 2 + the duration tip `3m` | `mn` suggested for minutes — the trap below |
| D57 | `--during 0s` | The min-duration refusal (min 1s) | Bound wording |
| D58 | `--during 6y` | The max-duration refusal (max 5y) | Bound wording |
| D59 | `--during 30mn` | Accepts — 30mn is 30 MONTHS (~900d), not minutes | The acceptance echo naming the resolved window — see H3 |
| D60/D61 | `s`, `s brave` | Exit 2 (missing positional) / the rate-missing runtime wording | The lone-positional-is-RATE rule (surface.rs:38-40) colliding with the target-required rung |
| D62 | `s brave 1mb -d 2mb` | The both-rate + per-direction conflict refusal | Silent acceptance of one of the two |
| D63 | `s brave 1mb --floor 100kb --floor-download 50kb` | The refuse-together wording (surface.rs:138-144) | A clap conflict missing at parse time (no conflicts_with in the derive) — refusal must come from the runtime law, wording audited |
| D64 | `s --all 500kb --per-socket` | The sweep-lane refusal of per-socket — measured law since night-cafe-1's F12 (the flag rode nowhere: a silent no-op under root) | Silent acceptance |
| D65 | `s brave::steam::curl 1mb --per-socket` | The list-lane refusal (surface.rs:89-99) | Silent acceptance |
| D66 | `s "" 1kb` | The empty-target rung (the hardening-1 family) | A silent no-op |
| D67/D68 | `s cg:` / `s cg:abc` | The cgroup-grammar refusals at the privilege-free rung (F5 — measured law) | The display prefix round-trip law (help.rs:337-342) |
| D69 | `s docker://` | The container-grammar refusal at the privilege-free rung (F5 — measured law) | Empty-name handling |
| D70 | `ee ""` | The empty-targets rung | A live monitor launch on empty input |
| D71-D74 | `ee --interval 0s` / `61s`, `--focus 0s` / `31s` | The bounds refusals (1s..60s live, 1s..30s depth window, surface.rs:303-312) | The bound wording; `--focus` on the live monitor printing its one stderr note (D75) |
| D75 | `ee --focus 5s </dev/null` | The interactive gate's answer + the focus-ignored note | The note on stdout |
| D76 | `--check-update` unpromoted | The release check runs; offline shows the error chain | The refusal wording requires sudo (root.rs:74-89) — captured again at R01 |
| D77/D78 | `status` / `list-apps` unpromoted | The root-required refusal / the degraded census warning (help.rs:206) | The two rungs contradicting the reference |
| D79 | `s brave 1kb` unpromoted | The pre-privilege refusal rung | The enforcement touching state before privilege |

### F — the color, wrap and environment law

| ID | Command | Expected | Watching for |
|----|---------|----------|--------------|
| F01 | `NO_COLOR=1 --help` | Default-prose bytes (help_flags.rs:22-24) | Residual escapes |
| F02/F03 | `COLUMNS=40` / `COLUMNS=200` | The reference's fixed geometry does not reflow; long lines stay long | Wrap mangling the tier alignment |
| F04 | `TERM=dumb doctor` | The capability ladder's lowest honest rung | Color probes lying under dumb |
| F05 | `NO_COLOR=1 s brave 1kb` | The error block in plain bytes | — |
| F06 | `COLUMNS=40 --print-json doctor` | One-line JSON regardless of COLUMNS | The shared writer wrapping JSON |
| F07 | `LC_ALL=C --help` | Byte-identical text (no locale-dependent rendering) | Locale-shaped drift |

### G — determinism

| ID | Command | Expected | Watching for |
|----|---------|----------|--------------|
| G01 | `--help` twice, sha256 | Byte-identical | Any nondeterminism (clocks, map order) |
| G02 | doctor JSON twice, 1s apart | Byte-identical — the stable scripting API promise | Timestamps or counters leaking into the document |

### R — the root lane (RUN_ROOT=1)

| ID | Command | Expected | Watching for |
|----|---------|----------|--------------|
| R01 | `sudo --check-update` | The euid-0 refusal BEFORE any network I/O (root.rs:76-79) | A network call under sudo |
| R02/R03 | `sudo doctor`, `sudo sig` | The full capability report; sig exits 1 on any failed depth | sig's failed-depth exit honesty |
| R04-R08 | status, list-apps, recover, their JSON twins | The live counters; recover's clean-state no-op tail | JSON purity under root; recover's wording on a clean system |
| R09/R10 | `-v status` and `-v status --print-json` | The stderr trace; JSON stdout stays clean (root.rs:110-123) | Trace bytes on stdout |
| R11-R19 | the enforcement smoke on a spawned `sleep`: strict (verified verdict), status, ee --depth (+JSON), per-socket, unstrict, --during 30s row, the already-clean tail | Every verdict the reference promises (help.rs:129-176) | The cg: prefix echo, the VERIFIED wording, the expiry row, the honest tail |
| R20 | `sudo ee --focus 5s </dev/null` | The live gate + the focus-ignored note | Note placement |
| R99 | the exit trap | `unstrict --all` best-effort cleanup, sleep killed | State left behind |

## The hypothesis list (what the analyzer hunts first)

Each hypothesis is grounded at a source line; the battery case named
per hypothesis is the decisive evidence.

- **H1 — the JSON error lane never runs the rescue chain.** The
  contract door exited BEFORE the enrichment
  chain, but json_error.rs:24-25 promises "the same
  facts the prose render carries". Every retired spelling
  (C05/C06/C07 vs D04-D28), every flag rescue (C08 vs D29-D37), and
  the hidden-vocabulary filter rendered differently per lane.
  RESOLVED by night-cafe-1: the chain is one seam both lanes
  consume; the JSON door sits after it (the render and the footer
  stay prose furniture), C06/C08 carry the prose facts, and C07's
  tip is the honest empty.
- **H2 — the hidden probe roles can leak on the JSON lane.** The
  prose lane drops hidden subcommand suggestions (redirects.rs:174);
  the old JSON door exited before that
  filter. RESOLVED by night-cafe-1: the filter runs before the JSON
  door (one chain, both lanes), and `zelynic --print-json
  __probe-serve` answers the honest empty tip — C07 decided, the
  leak class stays closed on BOTH lanes.
- **H3 — the `mn` months trap has no runtime echo.** 30mn is 30
  months (help_flags.rs:176-178); nothing in the captured surface
  shows the resolved window being echoed back at acceptance time.
  Case D59 (and the R17 row shape) decides whether the acceptance
  output names the duration it resolved.
- **H4 — the ignored-note's lane purity.** The note must ride stderr
  only, stdout and exit codes untouched (scope.rs:21-25). C09/C10
  plus B13/A06-A09 decide.
- **H5 — one grammar, two casings.** The curated reference spells
  `<target> [rate]` (help.rs:120); clap's per-verb local help spells
  `<TARGET> [RATE]` from the value_name attributes (surface.rs:41,
  45). Both surfaces teach the same grammar in one binary. B01 vs
  A01 decides whether the drift is real on the rendered bytes.
- **H6 — the 1kb boundary and the fractional grammar.** 1000b must
  pass, 0.9kb must refuse, 5.5xb must suggest 5.5kb without slicing
  at the dot. D51-D55 decide; the message wording is audited against
  help_flags.rs:106.
- **H7 — doctor JSON byte-stability.** The "stable v11 scripting
  API" promise (root.rs:129) implies a diffable document. G02
  decides.
- **H8 — JSON ignores COLUMNS.** F06 decides.
- **H9 — exactly one footer on every error lane.** The bridge
  appends the canonical footer itself (ux.rs:67-69, 435); any lane
  rendering two footers is the NIGHT-improve-1 regression class.
  Every D-case's tail is the evidence.
- **H10 — the `help` redirect's one-tip contract.** A04 decides
  whether the fuzzy suggestion is fully removed by the redirect
  (redirects.rs:162-163).

## The wording watchlist (minor, cosmetic, LTS polish)

- W1: help_flags.rs:102 — "Color output is always on — set
  NO_COLOR=1 to disable" reads self-contradictory; "on by default"
  is the honest shape.
- W2: the `--color-mode` value hint is `M` in the flag table
  (help_flags.rs:91) but `MODE` in clap's local help
  (root.rs:152) — two placeholder spellings.
- W3: the eagle-eyes `--focus` range is spelled three ways across
  the surface: `1s-30s` (help.rs:253), `1s..30s`
  (help_flags.rs:271-272), `1s to 30s` (surface.rs:307).
- W4: help.rs:206 — "Needs root for the live counters — list-apps
  degrades without it" sits under the status synopsis; D77/D78
  verify the two rungs actually behave as the sentence promises.

## Method notes

- The catalog's expected verdicts were derived by reading the CLI
  modules end to end at commit 39a30e9 (the arc-gems-1 proof sync
  tree): src/cli/{root,surface,ux,argv,rescue,redirects,suggestion,
  tips,json_error,scope,styles,mod}.rs, src/commands/{help,
  help_flags,mod}.rs, src/main.rs — 106K total LOC scanned
  selectively, the CLI estate (about 3.3K lines) read whole.
- The battery is assert-light and capture-heavy on purpose: the
  analyzer (the next session) owns the verdict diff, so the battery
  never blocks on a judgment call and the log stays the single
  evidence artifact.
- The benchmark rule is honored by the letter: this task ships the
  battery, the manual, and the index row — no runtime code path
  changed — so no 10s A/B run is spent on it. The battery's own
  output becomes the A/B baseline for every CLI UX fix that lands
  after the audit.

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
