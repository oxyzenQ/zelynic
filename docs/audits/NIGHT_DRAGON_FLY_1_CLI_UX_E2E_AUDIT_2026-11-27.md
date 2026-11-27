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
touches the kernel lane. A same-day re-measurement with the fixed
battery (the section at the bottom) verified F3's fixes in the
field, resolved F9(a) by measurement, re-confirmed the eight
still-open findings, and raised four new ones (F11-F14) — one on
the instrument, one HIGH on the fleet sweep, two LOW wording laws.

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

## Re-measurement: the fixed battery on the real machine (same day, 12:18 run)

Input: the owner's third capture — the fixed battery (`4e97cbe`),
non-root lane, 127 cases, `BATTERY COMPLETE`, binary still
`v80.5.0-dragon.2 (de75d85)` (byte-identical to the first runs), now
under COLUMNS=95 (a second wrap width) and — the decisive accident —
invoked as `sudo ./capture-cli-ux-e2e.sh` without `RUN_ROOT=1`, so
every case ran as euid=0 while the battery believed it was
privilege-free. That accident is the audit's best teacher: it
measured the root rungs of the JSON contract AND exposed a battery
flaw of its own. Source stayed the truth; the new findings below
were each verified in the tree before being written down.

### What the re-measurement settled

- **F3 verified fixed.** `binary exit:` lines appear on every JSON
  document case: C01 0, C02 0, C03 0, C04 1, F06 0, G02 0/0. The
  exit-code clause of the JSON contract is measured law now, not a
  gap.
- **F9(a) resolved by measurement.** C04 (eagle-eyes --depth
  --print-json without a target) exits 1 with the error document —
  the degradation lanes honor the contract's exit-1 clause; C02's
  clean status exits 0. The remaining F9 items (rate_ring
  optionality, bypass_audit floors) need the root lane
  (`RUN_ROOT=1`), skipped in this run — the sudo invocation did NOT
  arm it, which is exactly the trap F11 names.
- **The eight still-open findings re-confirmed in the fresh dump:**
  F1 (C03 ships `"polkit-kde-authenticati…"` and
  `"drkonqi-coredump-proces…"` inside the machine document,
  `census_complete:true`), F2 (D37 still answers
  `--allow-dangerous` with `--all`), F4 (C05/C07 still repeat
  `a similar subcommand exists:` per item), F5 (D67-D69 — under
  root now, the grammar crimes surface as lookup-voice
  "No cgroup found" verdicts; the grammar rung is skipped even with
  the gate open), F6 (D48/D51 still blame the mantissa), F7 (A10
  still dies `Usage: zelynic strict --version <TARGET> [RATE]`
  while A11 prints the banner), F8 (D77 at COLUMNS=95 truncates the
  same footer — `measured RTT…` eaten; the budget is fixed, not
  terminal-relative), F10 (B02 still carries the lineage
  codenames and the collapsed example rails).
- **The laws that hold, again:** color law (D46 zero ESC bytes on
  mono, D47 sixteen ESC bytes / zero truecolor escapes on the
  16-rung), byte determinism (G01 help sha equal across runs; G02
  doctor JSON byte-identical across runs even while 45 policies of
  live enforcement state sat on the machine), stream discipline
  (every apply narrates on stderr and leaves stdout document-only —
  C09/D55/D59/D62/D64/D79/F05 all stdout-empty), the inclusive
  1000b boundary with honest ledger proof (D55), the min/max guards
  with their redirects (D52/D53/D54), the inverse privilege law
  (D76 refuses the update check under root), 26 of 27 rescue lanes
  landing the right successor (D01-D28, D31-D35, D40), the
  empty-tip no-fabrication clause (C11), and the system guard's
  honest skip note (D64: 25 system cgroups across 23 names named).

### F11 — CRITICAL (the audit instrument): the non-root battery under sudo enforces for real and never tears down

The owner's invocation (`sudo ./capture-cli-ux-e2e.sh`, no
`RUN_ROOT=1`) opened every root gate while the battery still ran its
non-root plan. The apply lanes crossed into live enforcement with no
cleanup: C09 (`--print-json s brave 1kb`), D55 (1kb), D59 (30mn),
D62 (2mb), D79 (1kb), F05 (1kb) each re-limited the live browser,
and D64 (`s --all 500kb --per-socket`) swept the whole fleet —
D77 measured 45 download + 45 upload policies on 45 user cgroups,
D44 saw the pin count go 0 -> 48 inside one battery, and nothing in
the non-root lane ever says `u --all` (the cleanup trap arms only
under `ROOT_ARMED=1`, i.e. RUN_ROOT=1). The battery's own safety
contract — "default run: zero enforcement state touched" — was
broken by the most natural invocation an eBPF tool invites. Fix
landed with this commit: an euid=0 / RUN_ROOT!=1 guard refuses the
run and names which lane owns which cleanup. Owner side note: the
state that run left behind is live until `sudo zelynic u --all`.

### F12 — HIGH (product): the fleet sweep silently swallows `--per-socket`

D64 (`s --all 500kb --per-socket`) exits 0, applies per-CGROUP
policies to the fleet, warns nothing, and its verify line renders
the per-cgroup shape — while the user asked for the per-connection
shape. Source: the sweep dispatch (src/commands/mod.rs, the
`handle_strict_all` call) never passes `per_socket`; the handler
(src/commands/strict_all.rs) has no such parameter and never
references it; the sweep's probe call hard-codes `false` (line
278). This violates the house's own printed law — "a target that
matches nothing is a hard error — never a silent no-op" — the same
sin class the retired-verb redirects exist to prevent, and the
list lane already refuses the flag with a tip (D65: "--per-socket
is the single-target lane"). Fix: refuse the combination on the
sweep with the D65-shaped tip (or implement the per-socket sweep —
owner's call), and let the help's per-socket line state the sweep's
stance, which also closes F5's help half.

### F13 — LOW (product): the rescue lane renders two usage shapes for one error class

D32/D34/D35/D36 render clap's usage-with-used
(`zelynic strict <TARGET> <RATE>`, `zelynic eagle-eyes <TARGETS>`)
while D33/D37/D38/D39 render the full regenerated form
(`zelynic strict [OPTIONS] [TARGET] [RATE]`) — and D33 vs D34 carry
the SAME tip (`zelynic --check-update`) under two different usage
lines. Mechanism verified in source (src/cli/ux.rs, the usage
context block + src/cli/argv.rs `failing_command_usage`): clap's
native usage is kept when it exists and was not narrowed; it is
regenerated when clap's own suggestion narrowed it (the suggested
flag reads as if required) or when the context is missing. The
mechanism is deliberate and documented — the operator-visible
result is still one error class wearing two shapes. Fix: one shape
law (always regenerate, or keep the native line and regenerate only
the narrowed case), pinned in the usage tests.

### F14 — LOW (product): the color-mode fatal lane exits bare, against the footer's own contract

D43 (`--color-mode 99 doctor`) prints the verdict line and exits 2
with no `For more information, try '--help'.` footer and no usage —
while src/cli/ux.rs's contract comment says every fatal CLI error
ends with exactly one footer. The exit-code asymmetry itself is
documented in source (src/main.rs:143-156: the JSON lane exits 1,
"the prose lane keeps its own 2" — C11 measured it), so only the
footer gap is a defect. Fix: append the canonical footer on that
lane, or scope the ux.rs comment to the clap bridge.

### The updated queue

1. F11 — battery guard (landed with this commit; the owner should
   also run `sudo zelynic u --all` once to clear the 12:18 run's
   live state).
2. F12 — the sweep's --per-socket refusal (or implementation).
3. F2 — the vocabulary-rescue authority fix (unchanged).
4. F4 — the JSON tip plural join (unchanged).
5. F1 — the uncapped name beside the capped one (unchanged).
6. F6 — the unknown-unit verdict (unchanged).
7. F5 — strict's pre-root target-spec parse + the per-socket/help
   line (now jointly with F12).
8. F7 — the `-V` interception door (unchanged).
9. F8 — the RECWN footer wording (unchanged).
10. F13/F14 — the two usage-shape law and the footer lane (new,
    one-liners each).
11. F9 — the remaining pins need a RUN_ROOT=1 run with the guarded
    battery; F10 — the owner's voice decision (unchanged).

Verdict after the re-measurement: unchanged in kind, sharper in
fact. The product's skeleton still holds every law it claims, the
JSON contract's exit clause is measured law now — and the fleet's
own polish queue grew by two product findings and one instrument
finding that only a real-machine accident could expose. Not yet
peak; the queue above is the remaining distance.

## The root-lane re-measurement: the run the queue asked for (12:43 run)

Input: the owner's fourth capture — the FULL root lane (`RUN_ROOT=1`,
147 cases, `BATTERY COMPLETE`, 46 s wall clock), binary
`v80.5.0-dragon.2`, build `local-pro-linux-amd64-v3-musl (edb43d0)` —
the same code as `de75d85` plus an empty `sign.txt` (the owner's
signed test build), so every shared case stays byte-comparable. The
invocation is exactly the one the queue asked for — and the one
F11's guard exists to protect.

### What this run settled

- **F3 verified fixed (again).** `binary exit:` on every JSON
  document case: C01 0, C02 0, C03 0, C04 1, F06 0, G02 0/0, R05 0,
  R07 0, R10 0, R14 0.
- **F9(a) holds by measurement at root:** C04 exits 1 with the error
  document; C02/C03 exit 0.
- **F9(b) measured for the first time.** At root, `rate_ring` rides
  ONLY the rows with counters: 8 of 46 rows in R05, the same 8 in
  R10; zero-traffic rows carry no key at all. The contract decision
  remains (document the presence rule or always-emit), but the rule
  itself is now measured fact, not inference.
- **F11's trap was dodged by hand, not by the guard.** The owner used
  the correct `RUN_ROOT=1` invocation — but the tree does NOT contain
  the guard yet (the verdict commit was still local when this run
  fired). The guard lands with the push of this document.
- **The state ledger, honest.** The 12:18 accident's 46 cgroup
  policies (92 total) were live through the whole run: doctor counted
  48 pins, recover said "Orphans: none (92 policies across 46
  cgroups, all live)" and named the lane, R19 counted "90 other
  policies are still active" after the smoke cleaned itself. The
  squeeze ate real traffic: brave 8106 allowed 49.3 MB / dropped
  14.2 MB, 904 CE-marked packets, 1.2 MB quota saved; python3 3442
  allowed 15.4 MB / dropped 4.4 MB. And RECWN's measured SRTT
  ballooned to 2,117,000 us — 10.6x the 200 ms floor. Owner action
  unchanged: `sudo zelynic u --all`.
- **The smoke is clean, measured.** R16/R18 removed what R11/R15/R17
  applied; R19 proves the zero state (exit 1, live context); the
  banner's "full cleanup at exit" is truth, not aspiration.
- **Determinism under the heaviest state yet.** G01 help sha
  `92d47851…` byte-identical twice; G02 doctor JSON byte-identical
  across a 1 s gap while 46 policies sat live. The byte law does not
  blink under enforcement state.
- **Stream discipline at root.** R10's stdout is one JSON document
  with a single stderr note; R11/R15/R17 narrate on stderr only; R13's
  focus note rides stderr; R20's TTY gate refuses piped stdout with
  the `status --print-json` escape hatch.
- **The self-proving apply holds at root:** R11 measured 3.9 MB in 3s
  (1.3 MB/s) against a 4.0 MB budget with the ledger closing the loop
  (3.9 MB admitted, 2.6 MB refused); R15 carried the token-bucket
  note ("147.928 KB spent by the target's own history"); R17's
  589.8 KB/s vs 500 KB/s stays inside the budget and says so; R13's
  accounting is exact to the second decimal (39.93%).

### The open findings, re-confirmed at edb43d0

F1 (R07 `"process":"polkit-kde-authenticati…"`, the same ellipsis in
R10/R14's `label`, with `census_complete:true`), F2 (D37 still tips
`'--all'` for `--allow-dangerous`), F4 (C05 still repeats the
singular clause three times), F5 (D67-D69 still reach the root-gate
voice before the grammar rung), F6 (D48/D51 still blame the
mantissa — with a correction to THIS document's own transcript: the
parser says `got '1ki'` and `got '5.5x'`, not `got '1kib'` /
`got '5.5xb'` as written above; dump 1 agrees byte-for-byte, the
paraphrase was the audit's slip), F7 (A10 still renders
`Usage: zelynic strict --version <TARGET> [RATE]`), F8 (four
truncations this run — D77, R05, R09, R12 — and the root instance
hides a diagnostic-grade value: "measured RTT 2…" was 2,117 ms),
F9(c) (R14's raw 13%/0% shadows vs R13's prose floor note), F12
(D64 re-enforced the fleet silently at 500kb under root — again),
F13 (D33/D34: the same tip under two usage shapes), F14 (D43 still
exits 2 bare, no footer).

### F15 — MEDIUM (product, owner's call): the apply epilogue never names what it resolved

R11 `strict sleep 1mb` resolved `sleep` to cg:8981 — the invoking
terminal's own cgroup (app-Alacritty@…, 9 processes: alacritty, zsh,
three sudos, bash, the battery's sleep, the probe itself) — limited
it, said "OK.", and named nothing. The blast radius surfaced only
because R13 inspected the target after the fact. unstrict DOES
speak: `[limiter] Unstrict: cg:8981 (sudo) — limits removed`
(src/ebpf/limiter/unstrict.rs:194). One family names the resolved
target, the other stays silent — and the silent one is the one that
CHANGES state. The pinned minimalism (src/commands/dispatch_common.rs,
NIGHT-improve-28: "the request echo lives in the shell history, the
enforced facts live in 'zelynic status'") explains the lean epilogue
but not the asymmetry: a name that resolves to a shared cgroup
(terminal, shell, session leader) shapes bystanders invisibly,
including the caller's own lane. Fix candidates: the verify block
names the resolved label ("resolved: cg:8981 (sudo) — 9 processes in
scope"), or the minimal version — a self-limit note when the
invoking process's own cgroup is the target. Owner's call on the
voice; the asymmetry itself is the defect.

### F16 — LOW (product): the depth census rss cell eats the unit

R13's census row: `11569 alacritty … 121.5 … 26m:51s` — the rss
column width is 7 (src/ebpf/render/report.rs:372, `widths[6]`) while
`format_bytes` renders eight characters at 100 MB and above
("121.5 MB"), so `pad_to_width` cuts the unit exactly when the
magnitude matters (MB or GB?). "11.9 MB" (seven chars) survives;
everything at 100 MB and above loses the unit. Fix: width 7 -> 8
(the `started` column next door proves the row has the room) or the
compact "121.5M" spelling.

### F17 — LOW (doc pin): '/' lives inside kernel-thread names too

R06 lists `napi/phy0-0` (cg:1, 232 processes) — a kernel thread whose
comm carries the eagle-eyes list separator. src/commands/eagle.rs:89
splits the TARGETS spec on every '/' and no spelling escapes it; the
cg: prefix is the only route to such a target. The help's Target
formats paragraph excuses the ':' collisions ("cannot collide with
the single ':' the cg: prefix and the container URIs own") but says
nothing about names that carry the monitor lane's own separator. One
help line closes it: names containing '/' (kernel threads) ride the
cg: prefix.

### The updated queue (after the third measurement)

1. F12 — the sweep's --per-socket refusal. This also unblocks the
   battery: D64 automates what R22's own BYHAND law calls
   destructive-by-definition; after the refusal lands, D64 is safe
   to automate.
2. F2 — the vocabulary-rescue authority fix.
3. F4 — the JSON tip plural join.
4. F1 — the uncapped name beside the capped one.
5. F6 — the unknown-unit verdict.
6. F5 — strict's pre-root target-spec parse + the per-socket help
   line (jointly with F12's help half).
7. F15 — the apply epilogue names the resolved target (owner's call
   on the shape).
8. F7 — the -V interception door.
9. F8 — the RECWN footer wording (now carrying root-lane evidence).
10. F16 — the rss cell width.
11. F13/F14 — the usage-shape law and the footer lane.
12. F17 — the help's separator-collision line.
13. F9 — the remaining pins (rate_ring presence rule now measured;
    bypass_audit floor context) — document or always-emit, once.
14. F10 — the owner's voice decision on the long help (unchanged).

### The verdict after the third measurement

Unchanged in kind, sharper again. Every law the product claims held
under the heaviest state this seat has measured — 46 live policies
under the battery, determinism byte-identical, stream discipline
intact at root, the smoke self-cleaning, the JSON exit clause
honored. The queue grew by one MEDIUM with a live demonstration
(the silent apply resolution), one display ambiguity, and one doc
pin — all surgical, none kernel. Not yet peak; this queue is the
remaining distance, and the owner's first step is one command:
`sudo zelynic u --all`.


## night-cafe-1: the approved queue verified and closed (same day)

The owner approved the finding list; this pass verified every item
against the current tree (source = truth), proved the open ones at
runtime on a fresh build, and closed them — one micro-commit per
finding, each with its own pins. Verdicts:

- **Already fixed before this pass (verified, not re-touched):**
  F3 (the battery records the BINARY's exit — `bin_rc` captured and
  printed before json_shape runs; R10's `printf --` lands the
  stderr headers) and F11 (the battery refuses euid=0 without
  RUN_ROOT=1, naming which lane owns which cleanup).
- **Closed this pass:** H1+H2 (one enrichment chain for both error
  lanes — the JSON door sits after it; the probe pair and the
  raw-fuzzy drift are gone from the machine lane; F13's one-usage
  law rides the same seam), F1 (the uncapped name beside the
  display-capped one; both JSON writers carry it; the resolution
  walk matches both spellings), F2 (the exact-spelling fence —
  D37 answers `--force-this`, never `--all`), F4 (the JSON tip
  renders the plural sentence once), F5 (the grammar rung refuses
  `cg:`-over-non-id and malformed container URIs before the root
  ask — single boundary and list grammar), F6 (the unknown-unit
  verdict names the crime on both the rate and duration lanes), F7
  (the version door — `s -V` prints the report, exit 0), F8 (the
  RECWN footer's compact voice fits the budget whole), F9(c)
  (`bypass_audit.quiet_window` — the floor gate as an additive
  boolean; F9(a)'s exit codes were already measured law and are now
  documented, F9(b)'s absence law was already documented), F10
  (B02 speaks operator English, verbatim example rails, zero
  codenames measured on the surface), F12 (the sweep refuses
  `--per-socket` at the routing rung; the help states the stance),
  F14 (the color-mode grammar error ends with exactly one footer),
  F15 (the apply epilogue names the resolved rows — `limited
  cg:8981 (alacritty)`), F16 (the census rss cell is 8 columns —
  the unit survives), F17 (the eagle-eyes slash collision gets its
  excuse on both surfaces).
- **The instruments:** 1,272 unit/integration pins green at every
  commit; every fix carries its own pins; the battery's case
  catalog (the MANUAL doc) re-pinned to the new expected verdicts
  and docs/USAGE.md re-synced (the JSON process field, the fatal
  exit-1 lane, bypass_audit's quiet_window, the per-socket sweep
  refusal, the -V door, the grammar rung, the epilogue's resolved
  line) so no doc pins a stale verdict. The next battery run diffs
  reality against the re-pinned catalog.
