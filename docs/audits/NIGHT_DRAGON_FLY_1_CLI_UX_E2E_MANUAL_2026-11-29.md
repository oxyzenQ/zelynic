<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->

# night-dragon-fly-1: the copy-paste capture manual (rev 3, the help-surface walk)

Date: 2026-11-29. Tree under test: `main` at `b9a7766` (the source this
walk was written from). The owner asked for the audit manual as direct
copy-paste commands: every command, flag, alias, and example the
`zelynic --help` reference names, walked end to end on the real machine
(the only place the true terminal, kernel, and privileges exist), the
whole log sent back for the analyzer diff.

Two instruments, one audit:

1. The one-shot battery `scripts/labs-exp/capture-cli-ux-e2e.sh` (the
   fast path, 154 cases, section below).
2. THIS walk: the same surface as per-command paste blocks, every
   block tagged with the battery's own case ID (A/B/C/D/F/G/R) so the
   analyzer diff stays one namespace, plus two new series — the
   X-series (every example the reference teaches, captured unpromoted)
   and the S-series (this session's new hunts). The expected verdicts
   per case live in the case catalog
   (`NIGHT_DRAGON_FLY_1_CLI_UX_E2E_MANUAL_2026-11-27.md`, rev 2); this
   file owns the commands and the current-tree drift verdict.

## The safety contract (read first)

- Sections E through G and the X/S series run WITHOUT sudo. The
  unpromoted refusal (the root gate's own wording) is audit material;
  the apply lanes assume the gate closes them. The 2026-11-27 owner
  run measured a whole-fleet 500kb limit that outlived the battery
  because the apply cases ran under euid 0 — never repeat that shape.
- The root lane (R-series) is opt-in and owns its cleanup tail.
- `--reset-terminal` clears the screen by design — BYHAND only.

## Setup (paste once per shell)

The `cap` helper captures stdout, stderr, and the exit code of one
command under a citable ID — the same three axes the battery logs:

```sh
cap() { printf '\n===== [%s] %s =====\n' "$1" "$2"; eval "$2" >/tmp/zelynic-cap.out 2>/tmp/zelynic-cap.err; local rc=$?; printf -- '---- exit: %d ----\n---- stdout ----\n' "$rc"; cat /tmp/zelynic-cap.out; printf -- '---- stderr ----\n'; cat /tmp/zelynic-cap.err; }
```

Point the walk at the binary under test (the battery's
`ZELYNIC_BIN=/path/to/zelynic` override is the equivalent):

```sh
cap S00 'git -C "$(dirname "$(command -v zelynic)")" rev-parse HEAD 2>/dev/null; zelynic -V; uname -a'
```

## E — environment and identity

```sh
cap E01 'command -v zelynic; zelynic -V'
cap E02 'zelynic --version'
cap E03 'printf "TERM=%s COLORTERM=%s COLUMNS=%s LINES=%s\n" "${TERM:-unset}" "${COLORTERM:-unset}" "${COLUMNS:-unset}" "${LINES:-unset}"; printf "LANG=%s LC_ALL=%s NO_COLOR=%s\n" "${LANG:-unset}" "${LC_ALL:-unset}" "${NO_COLOR:-unset}"; printf "euid=%s\n" "$(id -u)"'
cap E04 'for t in python3 jq sha256sum curl; do command -v "$t" >/dev/null 2>&1 && echo "$t: present" || echo "$t: MISSING"; done'
```

## A — the help and metadata doors

```sh
cap A01 'zelynic --help'
cap A02 'zelynic -h'
cap A03 'zelynic'
cap A04 'zelynic help'
cap A05 'zelynic --help | head -3; printf "exit through the pipe: %s (broken-pipe law: no panic)\n" "${PIPESTATUS[0]}"'
cap A06 'zelynic --print-json --help'
cap A07 'zelynic --print-json -h'
cap A08 'zelynic --print-json -V'
cap A09 'zelynic --print-json'
cap A10 'zelynic s -V'
cap A11 'zelynic doctor -V'
```

BYHAND (A12): `zelynic --reset-terminal` — silent by design, clears
the screen; run by hand only when you actually want the reset.

## B — the per-verb local help doors (clap, exit 0)

```sh
cap B01 'zelynic strict -h'
cap B02 'zelynic strict --help'
cap B03 'zelynic s -h'
cap B04 'zelynic block -h'
cap B05 'zelynic unstrict -h'
cap B06 'zelynic eagle-eyes -h'
cap B07 'zelynic eagle-eyes --help'
cap B08 'zelynic status -h'
cap B09 'zelynic list-apps -h'
cap B10 'zelynic doctor -h'
cap B11 'zelynic sig -h'
cap B12 'zelynic recover -h'
cap B13 'zelynic strict -h --print-json'
```

## X — the reference walk: every example the --help surface teaches, unpromoted

This is the literal end-to-end sweep of the reference: every runnable
example line and every Pro mode example, typed exactly as `--help`
prints them (minus the `sudo` prefix), captured at the
privilege-free rung. A grammar or parse rejection here is a real
finding; the expected shape on the enforcement verbs is the root
refusal (exit 1), never a silent no-op.

```sh
cap X01 'zelynic strict brave 100kb'
cap X02 'zelynic strict brave -d 100kb'
cap X03 'zelynic strict firefox -d 1mb -u 500kb'
cap X04 'zelynic s nginx 500kb --per-socket'
cap X05 'zelynic s brave::curl::pacman 1mb'
cap X06 'zelynic s cg:1234::1245 100kb'
cap X07 'zelynic s docker://nginx 100kb'
cap X08 'zelynic s k8s://prod/web-abc 1mb'
cap X09 'zelynic s netns://sandbox 500kb'
cap X10 'zelynic s iface://red 2mb'
cap X11 'zelynic block brave'
cap X12 'zelynic b brave::curl::pacman'
cap X13 'zelynic unstrict brave'
cap X14 'zelynic u brave::curl::pacman'
cap X15 'zelynic recover'
cap X16 'zelynic status'
cap X17 'zelynic list-apps'
cap X18 'zelynic eagle-eyes </dev/null'
cap X19 'zelynic eagle-eyes brave </dev/null'
cap X20 'zelynic eagle-eyes 12345/brave/firefox </dev/null'
cap X21 'zelynic eagle-eyes --interval 3s </dev/null'
cap X22 'zelynic ee cg:1234 --depth'
cap X23 'zelynic ee cg:1234 --depth --focus 5s'
cap X24 'zelynic ee 12345 --depth --print-json'
cap X25 'zelynic ee --deep </dev/null'
cap X26 'zelynic doctor'
cap X27 'zelynic sig'
cap X28 'zelynic s --all 500kb'
cap X29 'zelynic s --all -d 1mb -u 500kb'
cap X30 'zelynic b --all'
cap X31 'zelynic u --all'
cap X32 'zelynic s brave 1mb --during 2h'
cap X33 'zelynic b brave::curl --during 30m'
cap X34 'zelynic s firefox 1mb --floor 100kb'
cap X35 'zelynic s curl 1mb --floor-download 50kb --ceil-upload 200kb'
cap X36 'zelynic s nginx 500kb --no-test'
cap X37 'zelynic s brave 100kb --force-this'
cap X38 'zelynic -v status'
cap X39 'zelynic status --print-json'
```

The live-monitor lanes ride `</dev/null` so the interactive gate
answers instead of waiting on a TTY (the D75 contract). The `--deep`
live lane and the `sig` provenance report are the two reference
surfaces the battery never probed unpromoted — their gate and refusal
wording are fresh capture material.

## C — the --print-json contract lanes

```sh
cap C01 'zelynic doctor --print-json'
cap C02 'zelynic status --print-json'
cap C03 'zelynic list-apps --print-json'
cap C04 'zelynic eagle-eyes --depth --print-json'
cap C05 'zelynic --print-json strictt'
cap C06 'zelynic --print-json snapshot'
cap C07 'zelynic --print-json __probe-serve'
cap C08 'zelynic --print-json --verbos'
cap C09 'zelynic --print-json s brave 1kb'
cap C10 'zelynic --print-json sig'
cap C11 'zelynic --print-json --color-mode 99'
```

## D — the rescue, suggestion and wording lanes

Retired spellings (the redirect table):

```sh
cap D01 'zelynic strictt'
cap D02 'zelynic sttict'
cap D03 'zelynic statuss'
cap D04 'zelynic observe'
cap D05 'zelynic top'
cap D06 'zelynic eagle-eye'
cap D07 'zelynic limit-all'
cap D08 'zelynic la'
cap D09 'zelynic strict-single'
cap D10 'zelynic strict-multi'
cap D11 'zelynic ss'
cap D12 'zelynic sm'
cap D13 'zelynic block-single'
cap D14 'zelynic block-multi'
cap D15 'zelynic bs'
cap D16 'zelynic bm'
cap D17 'zelynic unstrict-single'
cap D18 'zelynic unstrict-multi'
cap D19 'zelynic us'
cap D20 'zelynic um'
cap D21 'zelynic strict-all'
cap D22 'zelynic sa'
cap D23 'zelynic block-all'
cap D24 'zelynic ba'
cap D25 'zelynic unstrict-all'
cap D26 'zelynic ua'
cap D27 'zelynic snapshot'
cap D28 'zelynic restore'
```

Flag rescues and the escape hatch:

```sh
cap D29 'zelynic --verbos'
cap D30 'zelynic --VERBOS'
cap D31 'zelynic --json'
cap D32 'zelynic s brave 1kb --json'
cap D33 'zelynic s brave 1kb --check-updat'
cap D34 'zelynic s brave 1kb --check-updated'
cap D35 'zelynic s brave 1kb --no-probe'
cap D36 'zelynic ee brave --info'
cap D37 'zelynic s brave 1mb --allow-dangerous'
cap D38 'zelynic s brave 550kb -- -V'
cap D39 'zelynic s brave 550kb -- -i'
cap D40 'zelynic ee brave electron'
cap D41 'zelynic ee brave/electron'
```

The color-mode doors:

```sh
cap D42 'zelynic --color-mode'
cap D43 'zelynic --color-mode 99 doctor'
cap D44 'zelynic --color-mode 0 doctor'
cap D45 'zelynic --color-mode 16 --verbos'
cap D46 'c=$(zelynic --color-mode 0 --verbos 2>&1 | tr -cd "\033" | wc -c); printf "ESC bytes on the mono error lane: %s (expects 0)\n" "$c"'
cap D47 'c=$(zelynic --color-mode 16 --verbos 2>&1 | tr -cd "\033" | wc -c); printf "ESC bytes on the 16-rung error lane: %s (expects > 0)\n" "$c"; r=$(zelynic --color-mode 16 --verbos 2>&1 | tr -cd "\033" | grep -c "38;2;" || true); printf "truecolor RGB escapes (38;2;) on the 16-rung: %s (remap law expects 0)\n" "$r"'
```

The value lanes: rates, bounds, and the during grammar:

```sh
cap D48 'zelynic s brave 1kib'
cap D49 'zelynic s brave 10mbps'
cap D50 'zelynic s brave 1MB'
cap D51 'zelynic s brave 5.5xb'
cap D52 'zelynic s brave 500b'
cap D53 'zelynic s brave 0.9kb'
cap D54 'zelynic s brave 2tb'
cap D55 'zelynic s brave 1000b'
cap D56 'zelynic s brave 1kb --during 3min'
cap D57 'zelynic s brave 1kb --during 0s'
cap D58 'zelynic s brave 1kb --during 6y'
cap D59 'zelynic s brave 1kb --during 30mn'
cap D85 'zelynic s brave 1kb --during 1h30m'
cap D86 'zelynic s brave 1kb --during 2.5h'
```

Positional and grammar lanes:

```sh
cap D60 'zelynic s'
cap D61 'zelynic s brave'
cap D62 'zelynic s brave 1mb -d 2mb'
cap D63 'zelynic s brave 1mb --floor 100kb --floor-download 50kb'
cap D64 'zelynic s --all 500kb --per-socket'
cap D65 'zelynic s brave::steam::curl 1mb --per-socket'
cap D66 'zelynic s "" 1kb'
cap D67 'zelynic s cg: 1kb'
cap D68 'zelynic s cg:abc 1kb'
cap D69 'zelynic s docker:// 1kb'
cap D70 'zelynic ee ""'
cap D71 'zelynic ee --interval 0s'
cap D72 'zelynic ee --interval 61s'
cap D73 'zelynic ee --focus 0s'
cap D74 'zelynic ee --focus 31s'
cap D75 'zelynic ee --focus 5s </dev/null'
cap D76 'zelynic --check-update'
cap D77 'zelynic status'
cap D78 'zelynic list-apps'
cap D79 'zelynic s brave 1kb'
cap D80 'zelynic s k8s://prod/web 1kb'
cap D81 'zelynic s netns://sandbox 1kb'
cap D82 'zelynic s iface://red 1kb'
cap D83 'zelynic s brave::steam 100kb'
cap D84 'zelynic s cg:1234::1245 100kb'
```

## F — the color, wrap and environment law

```sh
cap F01 'NO_COLOR=1 zelynic --help | head -12'
cap F02 'COLUMNS=40 zelynic --help | head -24'
cap F03 'COLUMNS=200 zelynic --help | head -6'
cap F04 'TERM=dumb zelynic doctor | head -12'
cap F05 'NO_COLOR=1 zelynic s brave 1kb 2>&1 | head -6'
cap F06 'COLUMNS=40 zelynic --print-json doctor | wc -l; printf "line count above (contract expects 1)\n"'
cap F07 'LC_ALL=C zelynic --help | head -6'
```

## G — determinism

```sh
cap G01 'a=$(zelynic --help | sha256sum | cut -d" " -f1); b=$(zelynic --help | sha256sum | cut -d" " -f1); printf "run 1: %s\nrun 2: %s\n" "$a" "$b"; [ "$a" = "$b" ] && echo HELP-DETERMINISTIC || echo HELP-NONDETERMINISTIC'
cap G02 'zelynic doctor --print-json >/tmp/zg-a 2>/dev/null; sleep 1; zelynic doctor --print-json >/tmp/zg-b 2>/dev/null; diff /tmp/zg-a /tmp/zg-b >/dev/null && echo DOCTOR-JSON-DETERMINISTIC || { echo DOCTOR-JSON-DIFFERS; diff /tmp/zg-a /tmp/zg-b | head -20; }'
```

## S — the new hunts (this session, grounded in the current tree)

- S-H1: `zelynic s --all brave` — a word beside `--all` rides the
  rate slot (`commands/mod.rs` parks it in TARGET; the sweep
  reinterprets `rate.or(target)`), so the lane dies on the rate
  digit check (`parse.rs:298`) instead of the sweep's own stray
  refusal (`commands/mod.rs:159-164`, which needs BOTH slots
  filled). Expected today: exit 1,
  `expected digits before the decimal point, got 'brave'`, no tip
  (`tips.rs:74-78` returns None for a zero-digit prefix), nothing on
  the surface names the sweep lane or the stray target.
- S-H2: `zelynic s --all 500kb extra` — the both-slots refusal
  fires, and the tip names `drop '500kb'` (the TARGET slot's
  content) while the extra word rode the rate slot. Watching: which
  token the refusal names, and whether the sentence reads true.

```sh
cap S01 'zelynic s --all brave'
cap S02 'zelynic s --all'
cap S03 'zelynic --print-json s --all brave'
cap S04 'zelynic s --all 500kb extra'
```

S02 expected today: exit 1, `No rate specified. Use positional rate
or -d/-u options.` (`strict_all.rs:60-63`). S03 expected: the JSON
error object with the honest empty tip. S05 is paperwork, not a
command: the wording watchlist rides the A01 capture — W1
(`help_flags.rs:102`, "Color output is always on — set NO_COLOR=1 to
disable"), W2 (`--color-mode M` in the flag table at
`help_flags.rs:91` vs `MODE` in clap's local help at
`root.rs:152`), W3 (the `--focus` range spelled three ways:
`--focus <1s-30s>` at `help.rs:253`, `1s..30s` at
`help_flags.rs:271-272`, `1s to 30s` at `surface.rs:322`). All three
were still open on this tree when the manual was written.

## R — the root lane (opt-in, owns its cleanup)

Preferred shape: the battery's root lane, which arms its own exit
trap (`unstrict --all` best-effort + the spawned sleep killed):

```sh
sudo -v && RUN_ROOT=1 bash scripts/labs-exp/capture-cli-ux-e2e.sh > zelynic-ndf1-e2e-root.log 2>&1
```

If you walk it by hand instead, run `sudo -v` first, then:

```sh
sleep 300 & echo $! > /tmp/zelynic-smoke.pid
cap R01 'sudo zelynic --check-update'
cap R02 'sudo zelynic doctor'
cap R03 'sudo zelynic sig'
cap R04 'sudo zelynic status'
cap R05 'sudo zelynic status --print-json'
cap R06 'sudo zelynic list-apps'
cap R07 'sudo zelynic list-apps --print-json'
cap R08 'sudo zelynic recover'
cap R09 'sudo zelynic -v status'
cap R10 'sudo zelynic -v status --print-json'
cap R11 'sudo zelynic strict sleep 1mb'
cap R12 'sudo zelynic status'
cap R13 'sudo zelynic ee sleep --depth'
cap R14 'sudo zelynic ee sleep --depth --print-json'
cap R15 'sudo zelynic s sleep 1mb --per-socket'
cap R16 'sudo zelynic u sleep'
cap R17 'sudo zelynic s sleep 500kb --during 30s'
cap R18 'sudo zelynic u sleep'
cap R19 'sudo zelynic u sleep'
cap R20 'sudo zelynic ee --focus 5s </dev/null'
```

BYHAND (R21/R22): `sudo zelynic ee cg:<ID> --depth --focus 5s` (pick
the ID from R06) and the fleet sweep
`sudo zelynic s --all 500kb` then `sudo zelynic u --all` — run only
when you accept it. The cleanup tail (never skip):

```sh
kill "$(cat /tmp/zelynic-smoke.pid)" 2>/dev/null; sudo zelynic unstrict --all; unset sleep_pid
```

R17's expectation is the rev 5 window echo (`display_lines.rs:415`:
`window: lifts itself at <wall UTC> (<the operator's own spelling>)`)
and R05's the status JSON window object (`during` +
`expires_at_utc`, `display_json_window.rs`) — the pair the 11-28
audit landed and the battery has never yet caught at status time.

## What to send back

The whole log, one file: setup line S00 through the last S-series
block (and the root lane's log if it ran). The analyzer diffs it
against the case catalog's expected verdicts, the battery's own
154-case output, and the S-series hypotheses above — every finding
citable by ID.

## Method notes

- The walk was derived from the CLI estate read whole at `b9a7766`:
  `src/main.rs`, `src/cli/{root,surface,ux,argv,redirects,rescue,
  tips,suggestion,scope,json_error,styles,mod}.rs`,
  `src/commands/{help,help_flags,mod}.rs` (about 3.4K lines), plus
  the runtime anchors the catalog cites (`commands/mod.rs`,
  `commands/strict_all.rs`, `ebpf/limiter/parse.rs`,
  `ebpf/display_lines.rs`, `ebpf/display_json_window.rs`).
- Drift verdict of this pass: the rev-2 catalog's expectation cells
  still match this tree — the F7 version door (`ux.rs:387-399`), the
  one-chain JSON door (`ux.rs:414-438`), the F14 footer
  (`main.rs:160`), the D73/D74 grammar-first focus check
  (`commands/mod.rs:407-415`), the rev 5 window echo and the window
  object pair are all present. No expectation cell moved.
- The X-series and S-series are the growth edges: the reference's
  own example lines had never been captured unpromoted as a set, and
  the sweep lane's stray-word reinterpretation (S-H1/S-H2) is new.
- The benchmark rule is honored by the letter: this task ships
  documentation only — no runtime code path changed — so no 10s A/B
  run is spent on it. The capture log this walk produces becomes the
  A/B baseline for every CLI UX fix that lands after.

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
