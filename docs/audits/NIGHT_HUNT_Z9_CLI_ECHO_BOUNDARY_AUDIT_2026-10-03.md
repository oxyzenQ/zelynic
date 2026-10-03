<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# NIGHT-hunt-Z9: the CLI echo-boundary hardening audit (2026-10-03)

The owner's ask, verbatim: after NIGHT-hunt-Z7's audit and fixes,
all existing CLI surfaces are still suspected — harden totally to
close it; this is LTS production, not a rehearsal. Not just audit
and fix: a supermassive test with special focus on CLI usage, to
find potential bugs, tests, typos, and anything dangerous. Aim to
verify and be honest. This audit is that hunt: every CLI-facing
module read (the cli/ tree, the commands/ tree, the parse family,
the render boundary), every suspicion probed LIVE against the
debug binary before any fix was written, three finds closed, and
the rest of the sweep verified clean on the record.

## Find 1 (fixed): terminal injection through the CLI's own echo paths

The NIGHT-cybersecurity-1 audit sanitized the two untrusted input
classes it knew about: `/proc` comm labels (any unprivileged
process can `prctl(PR_SET_NAME)` 15 near-arbitrary bytes) and the
`--check-update` release tag (a network string through the
invoking user's proxy environment). The CLI's own echo paths
carried a third class neither covered: the user-supplied target,
rate, and duration strings embedded in the error and warn
messages the tool prints while REFUSING them.

Confirmed live, byte-level (od):

```
$ zelynic ss $'sshd\x1b]52;c;aGVsbG8=\x07' 1mb
error: 'sshd<ESC>]52;c;aGVsbG8=<BEL>' is a system process. ...
                                    ^ raw OSC-52 clipboard-write payload
```

The exact vector `sanitize_comm`'s own unit test documents,
printed raw by the tool refusing it. The same raw ESC survived
every pre-privilege echo path probed:

- the blocklist refusal (`ss <sshd-prefix-payload> 1mb`),
- the multi-segment grammar refusal
  (`sm brave<payload>/x 1mb` — "not a valid app name"),
- the invalid-rate echo (`ss brave 1<payload>kb`),
- the invalid-duration echo (`eagle-eyes --interval a<payload>b`).

Threat model, honestly stated: the command line is usually the
operator's own typing, and an operator attacking their own
terminal is not the case. The case is the paste-attack: a "fix
this by running: zelynic ss $'...'" block copied from a webpage or
issue comment carrying hidden escape bytes executes with the
operator's own intent — and every refusal echo bounced those bytes
back at the terminal raw. OSC 52 rewrites the clipboard in
terminals that honor it; newlines forge output lines that read as
zelynic's own (a fake verdict row); C1 8-bit controls corrupt
8-bit terminals.

The fix is ONE boundary, every path: `render_labeled_block`
(src/output/labeled.rs) — the single renderer every anyhow error
reaches (main's exit-adjacent choke point) and the warn channel
the guards use — now passes each line through `sanitize_comm`
BEFORE its semantic wrap. Control bytes become `?` before any
color code is added; the renderer's own branding (added after
sanitization) survives untouched. Verified live after the fix: the
same payloads render `sshd?]52;c;aGVsbG8=?` — the sequence is
dead text, and the clean part of every message is byte-identical.

Why not sanitize at each error-construction site: ~20 sites today,
and the LTS question is tomorrow's — a future error path built
forgetting the sanitization call would silently reopen the hole.
The render boundary makes every future path safe by construction,
the same doctrine the comm boundary owns. Success-path echoes were
audited and verified structurally unreachable with hostile bytes:
they print only MATCHED targets (a control-char name cannot match
a sanitized comm; a u32/cg: id cannot carry one; a container name
with control bytes never resolves). clap's own error contexts were
verified already clean — clap 4 strips control characters from the
contexts it renders.

## Find 2 (fixed): the shadowed positional rate — silent drop, unparsed

`resolve_rates`' documented priority (`-d`/`-u` flags over the
positional rate) had a hole exactly one flag wide, confirmed live:

```
$ zelynic ss brave not-a-rate -d 100kb
error: root required — eBPF operations need CAP_BPF     <- the typo sailed past
```

Two silent shapes:

1. **Unparsed garbage.** The positional was not even PARSED when a
   direction flag was present, so `not-a-rate` reached the root
   ask unexamined — the parse-before-execute ladder every strict
   handler documents ("a typo surfaces its did-you-mean tip before
   the root requirement") had exactly this shape missing.
2. **Unnamed drop.** A VALID positional (`ss brave 100kb -d 50kb`)
   vanished without a word — the silent-no-op class this CLI
   refuses everywhere else: `--print-json`, `--interval`, and
   `--focus` each print an ignored-input note on the same shape.

The fix (src/commands/rates.rs), verified live:

```
$ zelynic ss brave 1MB -d 100kb
error: Invalid rate '1MB'. Use lowercase: 1mb, 5.5mb, ...
  tip: a similar value exists: '1mb'          <- the ladder, restored

$ zelynic ss brave 100kb -d 50kb
! positional rate '100kb' ignored — -d/-u flags take priority (pass -d and -u together for both directions)
error: root required — ...                    <- the note, then the normal flow
```

Parse-only (no bounds check on the shadowed value — it applies
nowhere, so the 1kb floor is not its question; a typo is), and
stderr-only (stdout and exit codes untouched, so scripts that
legitimately pass both keep their behavior and learn nothing
they did not already know on stdout). All three strict verbs
(strict-single/multi/all) share the ladder through the one
`resolve_rates` call site.

## Find 3 (fixed): hidden internal roles leaked by the typo engine

clap's did-you-mean engine scores candidates from
`all_subcommand_names()` — hidden ones included. Confirmed live:

```
$ zelynic __probe-serve
error: unrecognized subcommand '__probe-serve'

  tip: some similar subcommands exist: '__probe-client', '__probe-server'
```

The vocabulary the help hides surfaced as a tip — teaching the
operator to run the internal probe server by hand: an
unauthenticated loopback data blast that accepts one connection
and writes zeros until the peer dies. The flag-side rescue in the
ux bridge already filtered `is_hide_set()` candidates (the same
NIGHT-improve-35 discipline the v4 battery's hidden stage
documents); the subcommand side had no twin.

The fix (src/cli/ux.rs): `drop_hidden_subcommand_suggestions`
filters the `SuggestedSubcommand` context — every candidate that
resolves (name or alias) to a hidden subcommand is dropped; a
trimmed list replaces the context when visible candidates remain,
and the context is removed entirely when none do (the
unrecognized-subcommand verdict, the usage line, and the footer
stay — the same honest dead end any no-candidate typo already
owns). Verified live after: `__probe-serve` answers with no
suggestion; `statu` still suggests `status` (and its other visible
candidates); `observe` still redirects to `eagle-eyes`.

## Verified clean (no change needed, this pass)

Honesty requires the clean list too — every suspicion probed,
none skipped:

- **Parse-family byte-safety:** every split in the rate/duration
  grammar is `split_once`/`strip_suffix` based — no byte-index
  slicing on user input anywhere in parse.rs.
- **Panic surface:** exactly one `expect()` across the CLI-facing
  modules (the probe client's connect-loop invariant, provably
  `Some` by the loop shape); no `unwrap()`, no `panic!`, no
  `unreachable!` reachable from CLI input.
- **Interval/focus bounds:** `--interval` (1s..60s) and `--focus`
  (1s..30s) refuse both edges with the bounds spelled out
  (`0s`, `61s`, `31s`, `3600s`, `1h` all probed); fractional
  seconds parse; the typo ladder fires (`100ms` -> `100s` tip).
- **The zero-rate lane:** `0` is the documented block verdict —
  accepted with and without `--force-this`, symmetric in the
  positional and `-d` slots; `0.4b`-style round-to-zero refuses.
- **Unicode digits:** Arabic-Indic and fullwidth digit rates get
  clean invalid-rate errors (no parse confusion).
- **Duplicate flags:** clap refuses (`-d 100kb -d 500kb` ->
  "cannot be used multiple times", exit 2).
- **Hidden roles' own validation:** mode checked (`dl`/`ul` only,
  exit 1), port bounds ride clap's u16 (70000 refused, exit 2),
  garbage addr errors exit 1 — all probed live.
- **Early-return precedence:** help > version > reset-terminal >
  check-update, deterministic; the order is the safe one (a
  broken terminal cannot read an update report; the rescue runs
  first).
- **Update surface:** static curl argv (no shell, no injection),
  the release tag sanitized, the hourly swarm bound, root refused
  before any network I/O.
- **Probe report family:** every line echoes measured figures and
  program-generated labels only — no user-supplied string reaches
  the verdict block (the failure error's target line flows through
  the render boundary anyway).
- **Escape-hatch probe paths:** `-- -V`, `-- -1s` answer with the
  probe's own honest verdicts (Z8's battery rows hold).

## The supermassive seat (v4 stage 9)

The owner's mandate — not just fix, but a supermassive test focused
on CLI usage — landed as the v4 battery's new stage 9, 32 rootless
rows (89 -> 121, all green):

- **The echo boundary:** five hostile payload families (OSC-52
  clipboard write, CSI color smuggle, newline forgery, C1 8-bit
  control, tab forgery) against four pre-root echo paths (the
  blocklist refusal, the multi grammar refusal, the rate parse,
  the duration parse) — every case asserts NO raw control byte in
  the output AND the refusal itself still firing (an unprintable
  target dodges no guard).
- **The shadowed positional:** six cases — garbage surfaces its
  refusal before the root ask, the uppercase typo carries its
  did-you-mean tip, the valid positional is named then the flags
  decide, the multi and all families share the ladder, and the
  unshadowed shape stays note-free (the rate applies).
- **The hidden vocabulary:** six cases — three leak shapes
  (`__probe-serve`, `__probe-clint`, `__probe` leak no role name)
  against three survivor shapes (`statu` -> `status`, `eagle-ey`
  -> `eagle-eyes`, `observe` -> the eagle-eyes redirect).

Plus 11 unit pins: the render boundary's OSC-52/CSI/clean-passthrough
family (output/labeled.rs), the shadowed-positional ladder
(test/cli/rates_shadow_tests.rs, new file), and the
hidden-vocabulary pins (test/cli/ux_tests.rs). The full suites:
677 unit + 47 integration green; the nonroot depth suite 90/90
(its own comm-spoof guards untouched — different boundary, same
byte-safety contract); v1/v2/v3 engine self-tests green.

## Declined investments (on the record)

- **Hard-erroring on the shadowed positional** (refusing
  `rate + -d/-u` as a contradiction): would break every script
  that legitimately passes both; the warn-and-continue shape keeps
  the LTS contract (stdout and exit codes unchanged) while the
  note closes the silence.
- **Sanitizing at the input boundary** (refusing control chars in
  targets outright): a control-char target already answers the
  no-match hard error after the root ask — an extra refusal lane
  would add a second grammar to maintain for a shape the render
  boundary already neutralizes, and the honest echo (`?`
  substitutions) carries MORE information than a refusal.
- **A second echo boundary for stdout** (success paths): verified
  structurally unreachable with hostile bytes (only matched
  targets print); adding a sanitize pass there would be
  defense against a shape that cannot exist.
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
