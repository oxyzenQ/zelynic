<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->

# night-dragon-fly-1: the end-to-end CLI UX audit verdict

Date: 2026-11-27. Input: the owner's captured battery logs, two full
runs on the real machine — the non-root lane (`RUN_ROOT=0`, 127 cases,
`BATTERY COMPLETE`) and the root lane (`RUN_ROOT=1`, 147 cases with
the enforcement smoke against a spawned `sleep`). Binary under test:
`v80.5.0-dragon.2`, build `local-pro-linux-amd64-v3-musl (de75d85)` —
byte-identical to this repository's HEAD at audit time. Terminal:
xterm-direct, truecolor, COLUMNS=88, kernel 6.18.65-1-cachyos-lts.
Every finding below names the case that exposes it and the source
file that owns the fix. Source code stayed the truth; the dump is the
reality check.

## Verdict

Not yet peak. The skeleton IS masterclass — the laws the reference
names hold under measurement, and several of them hold at a level
that is rare in the wild. But three findings land on the JSON
contract's own promise (machine-readability) and one lands on the
audit instrument itself, and an LTS that ships those is not the LTS
this project claims to be. All ten findings are surgical; none
touches the kernel lane.

## The laws that hold (measured, not assumed)

- **Determinism.** `G01` help sha256 stable across runs;
  `G02` doctor JSON byte-identical across runs; and the strongest
  evidence: 123 of the 127 shared cases are byte-identical between
  the two full battery runs. The 4 diffs are honest live state
  (`C03`/`D78` brave 24 -> 23 processes; `D76` the hourly
  check-update throttle; `G02` context noise).
- **Color law.** `D46` zero ESC bytes on the `--color-mode 0` error
  lane; `D47` 16 ESC bytes on the 16-rung and zero `38;2;` truecolor
  escapes — the remap law is real.
- **Stream discipline.** JSON on stdout, notes and verbose on stderr,
  everywhere. `R10` proves it accidentally: the battery's own broken
  printf swallowed the `---- stderr ----` header, and the verbose
  `[limiter]` line still sat exactly where the contract says it
  belongs — stderr — while stdout stayed one parseable document.
- **The rescue lanes.** 26 of 27 rescue cases landed the right
  successor: legacy verbs redirect exactly (`D21`-`D26` name the
  `--all` spelling to type), `observe`/`top` land on `eagle-eyes`
  (`D04`/`D05`), cross-tool vocabulary answers (`D31`/`D32` `--json`
  -> `--print-json`), `--no-probe` -> `--no-test` (`D35`), the
  two-positional eagle-eyes typo gets the slash-law tip (`D40`), and
  rate typos carry did-you-mean values (`D48`-`D51`). `D37` is the
  one miss — finding F2.
- **Honest bounds and honest math.** `D52`/`D53` name the minimum,
  offer `--force-this`, and redirect blocking intent to
  `zelynic block`; `D54` names the maximum; `D55` (1000b = exactly
  1kb) passes the guard and proceeds — the boundary is inclusive and
  exact. `R11`/`R15`/`R17` show the self-proving apply: the measured
  1.3 MB/s over a 1.0 MB/s target is not hidden, the budget line
  explains it (window + burst), the ledger closes the loop
  (4.0 MB admitted, 2.6 MB refused), and `R15`'s note names the
  carried-over token bucket ("spent by the target's own history") so
  a re-apply cannot be mistaken for a fresh bucket.
- **The no-match law.** `R19` exits 1 with live context ("94 other
  policies are still active") and routes to `status`/`recover`; the
  `--all`-on-clean exit-0 carve-out is documented and held.
- **Safety refuses privilege where privilege is wrong.** `R01`
  `--check-update` under sudo dies with "root refused — update check
  performs a network fetch, do not use sudo" — the inverse of the
  usual root gate, and exactly right.
- **Provenance does not flatter itself.** `C10`/`R03`: five depths
  pass, D5 fails honestly (commit not GPG-signed), verdict
  "SIGNATURE: UNSIGNED (5/6 depths verified)", exit 1, and the note
  says what an unsigned commit is and is not. Owner action: bind
  release commits/tags with GPG before the LTS cut.
- **The empty-tip law is deliberate.** `C11`'s `"tip": ""` is the
  contract's own no-fabrication clause (src/cli/json_error.rs:
  "the key stays present so a consumer can index both fields
  blindly") — verified against source, not a bug.

## Findings (ranked; every fix is surgical)

### F1 — HIGH: the display name cap leaks into the machine surface

`C03` and `C04`/`R07` (root, `census_complete:true`) both carry
`"process":"polkit-kde-authenticati…"`; `R05` carries the same
ellipsis inside `label`. The 24-column display cap
(`DISPLAY_NAME_MAX`, src/ebpf/identity/mod.rs, NIGHT-engrave-7) lands
on the one `comm` field every surface consumes — table, label, and
the `--print-json` document — so a script doing
`.apps[] | select(.process == "polkit-kde-authentication-agent-1")`
can never match, even with full root census. The display cap is a
good human law that must not govern the machine lane. Fix: carry the
uncapped enriched name beside the capped one in `ProcessIdentity`
and let the JSON writers emit it; the table and labels keep the cap.

### F2 — HIGH: the retired `--allow-dangerous` spelling suggests `--all`

`D37` (`zelynic s brave 1mb --allow-dangerous`) answers
"a similar argument exists: '--all'". The redirect entry exists
(src/cli/rescue.rs, `FLAG_VOCABULARY_RESCUES`:
`("allow-dangerous", "--force-this")`) but loses the score duel:
`rescue_shadowed_suggestion` keeps clap's fuzzy winner unless the
rescue scores strictly higher, and jaro_ci("allow-dangerous", "all")
(~0.73, the prefix) beats the vocabulary entry. The misdirection is
dangerous, not just unhelpful: `--all` is the fleet-wide flag, so a
user following the tip types a force-override and gets a whole-fleet
apply shape. Fix: exact-match vocabulary entries are authoritative —
override, never duel — the same law `REMOVED_SUBCOMMAND_REDIRECTS`
states ("a fuzzy suggestion for a removed name is overridden, never
supplemented — one tip, the right one").

### F3 — HIGH: the battery under-reports the binary's exit codes (and
two printf crashes)

The JSON-document cases eval `"$BIN" ... > file; cat file;
json_shape file` inside `run_sh`, so the captured `exit:` is
`json_shape`'s, not the binary's (`C01`-`C04`, `F06`, `G02`'s two
runs, `R05`, `R07`, `R10`, `R14`). Consequence: the JSON error
contract's exit-1 clause (src/cli/json_error.rs, "Exit 1 on this lane
is the contract's own clause") was NEVER measured — `C02`/`C04`'s
observed 0 is the validator's exit, not the CLI's. Same file, second
bug: `R10`'s inline `printf "---- stdout ----\n"` /
`printf "---- stderr ----\n"` die with `printf: --: invalid option`
(the helper at lines 79/81 already carries the `--` guard the inline
command lacks), so `R10`'s stderr section header vanished from the
log. Both fixed in this commit: every JSON-doc case now records and
prints `binary exit:` immediately after the binary, and `R10` uses
`printf --`.

### F4 — MEDIUM: the JSON tip lane repeats full sentences

`C05`'s JSON tip reads "a similar subcommand exists: 's'; a similar
subcommand exists: 'unstrict'; a similar subcommand exists: 'strict'"
where the prose lane (`D01`) says "some similar subcommands exist:
's', 'unstrict', 'strict'". Root: `clap_parts` (src/cli/json_error.rs)
formats every item of clap's `Strings` suggestion list with the
singular prefix, then joins. Fix: plural verdict once, quoted list
after — the prose lane's exact shape, contract-encoded.

### F5 — MEDIUM: the fail-fast ladder stops at the root gate for
strict's target grammar

`D67`-`D69` (`s cg: 1kb`, `s cg:abc 1kb`, `s docker:// 1kb`) reach
"root required" even though the target spec is pure grammar a
privilege-free parser could reject; eagle-eyes --depth already parses
its target spec BEFORE the root guard (src/commands/eagle.rs: "a
missing target and a spec that reduces to nothing both surface BEFORE
the root guard") while strict resolves its target after `ensure_root`
(src/commands/strict.rs, `Target::parse` past the root gate). One
family teaches the typo without sudo, the other asks for the password
first. Also: `D64` (`s --all 500kb --per-socket`) is a legal
combination the help is silent about (the per-socket line names the
single lane and the list refusal, not the sweep). Fix: strict's
single lane adopts the eagle parse-before-root ladder for the target
spec, and the help's per-socket line states the sweep's stance.

### F6 — MEDIUM: the rate parser blames the mantissa for unit typos

`D48` ('1kib') says "expected digits before the decimal point, got
'1kib'"; `D51` ('5.5xb') says "expected digits after the decimal
point". The crime is the unit — 'kib'/'xb' are not in the grammar —
and the did-you-mean tip already knows ('1kb'/'5.5kb'); only the
verdict sentence names the wrong layer. Root:
`parse_decimal_scaled` (src/ebpf/limiter/parse.rs) splits on the dot
before any unit awareness, so the trailing alpha lands in the digit
lanes. Fix: classify a trailing-alpha failure as an unknown-unit
verdict that names the grammar, keep the existing suggestion.

### F7 — LOW/MEDIUM: `-V` is not global in practice

`A11` `zelynic doctor -V` prints the banner exit 0; `A10`
`zelynic s -V` dies MissingRequiredArgument exit 2 — clap validates
strict's `required_unless_present = "all"` TARGET before the global
version flag fires. The reference lists `-V, --version` under Global
options; the practice breaks the claim exactly where a verb takes a
required positional. Fix: intercept `-V` the way `-h` is intercepted
(help_flags.rs door), or drop clap-level requiredness on TARGET/RATE
and let the manual validation the `--all` lane already needs own it.

### F8 — LOW: the status footer's fixed truncation swallows the
measured RTT

`R04`/`R12` at COLUMNS=88: "RECWN window: 40.0 KB (binding across 48
download policies; measured RTT …" — the ellipsis eats the measured
value the line exists to carry (src/ebpf/display_recwn.rs:229; the
honesty comment above it says the line names the measurement AND the
floor law precisely because the JSON already carries the raw sample).
The truncation budget sits under the terminal width and the payload
lands past the cut. Fix: shorten the line so the payload fits the
budget (e.g. "RECWN window: 40.0 KB · 48 policies · measured RTT
40ms (200ms floor)"), or widen the footer's budget to the terminal.

### F9 — LOW: contract edges to pin in documentation

Three edges the source knows and the docs do not: (a) the runtime
JSON surfaces' degraded error documents (`C02` status without root,
`C04` depth without target) — exit codes unmeasured because of F3;
pin them as degradation-exit-0 in the contract or route them through
`exit_json` — decide once, document, re-measure with the fixed
battery; (b) `rate_ring` is present only on rows with counters
(`R05`) — document-optional or always-emit; (c) `bypass_audit`
exposes raw shadow percentages (`R14` 19%/15%) without the
quiet-window floor context the human report carries (`R13` "quiet
window — under 1 MiB tx / 2 MiB rx floor") — one boolean field makes
the JSON as honest as the prose.

### F10 — INFO, owner's call: two voices on the long-help surface

The curated top-level reference (`A01`) speaks plain operator
English; the clap long help for strict (`B02`) carries the lineage
codenames (NIGHT-improve-53/54/30, charger-core-1-b/3b, improve-40,
improve-40-b, night-during schema v23) and collapses its bullet and
example rails into re-wrapped paragraphs — the source doc comment
(src/cli/surface.rs) has the real line structure; clap re-wraps
because the command lacks `verbatim_doc_comment` and the blocks lack
blank-line rails. `B07` (eagle-eyes) proves the house can do clean
prose with correct paragraphing on the same surface. Recommendation:
keep the lineage in code comments, docs, and tests; give the
operator-facing long help the eagle-eyes voice, and restore the
example rails (verbatim attribute or blank-line paragraphs).

## Non-issues verified

`A04` (`zelynic help`) dies with the correct pointer — a real `help`
subcommand would be convenience, not a defect. `D76`'s throttle
message is honest; "59 minute(s)" could drop the parenthetical one
day. `D62`'s "positional rate ignored" warning, `D73`-`D75`'s
--focus note, `R16`/`R18`'s unstrict accounting, `R20`'s TTY gate
with the `status --print-json` escape hatch — all match their
documented contracts. The install epilogue's active-pins note and
the `zelynic --help` reference's every claim checked out against the
captured behavior.

## The fix queue (suggested order)

1. F3 — the battery fixes land with this commit (done; re-run both
   lanes with the fixed battery to re-measure the JSON exits).
2. F2 — the vocabulary-rescue authority fix (one function, one law).
3. F4 — the JSON tip plural join (one function).
4. F1 — the uncapped name beside the capped one (identity + two
   writers).
5. F6 — the unknown-unit verdict (one parser branch).
6. F5 — strict's pre-root target-spec parse + the per-socket/help
   line.
7. F7 — the `-V` interception door.
8. F8 — the RECWN footer wording.
9. F9 — the three documentation pins.
10. F10 — the owner's voice decision on the long help.

Each queue item is one micro-commit with its own battery re-run of
the affected cases. The kernel lane stays untouched throughout; the
10s benchmark A/B is not meaningful for wording-level fixes (pure
display/parse strings) — the battery diff is the A/B for this lane.
