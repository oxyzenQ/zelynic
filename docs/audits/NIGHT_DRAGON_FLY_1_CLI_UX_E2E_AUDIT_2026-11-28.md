<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->

# NIGHT-DRAGON-FLY-1 — CLI UX end-to-end audit verdict (capture of 2026-11-27)

<!-- rev 4b (2026-11-27): the owner re-ran the 154-case battery on
     d4b1a32 (build 17:47Z, kernel 6.18.65-1-cachyos-lts) and the
     diff came back clean — every Class A cell flipped to its
     documented expectation, every Class B fix verified live, and
     three of this record's own Class C claims proved stale (already
     closed before they were written; the re-measurement below owns
     the correction). -->

Source of truth: the owner's 154-case capture battery
(`scripts/labs-exp/capture-cli-ux-e2e.sh`, run at 23:07-23:08 local on
`nightpc`, kernel 6.18.65-1-cachyos-lts), diffed against the current
`main` source line by line. Every finding below was verified in the
source before it was classified — nothing is taken from the capture
alone.

## Verdict

**Not yet peak — one class of drift was live, and it is now landed.**
The CLI UX layer itself (help rails, suggestions, rescue lanes, exit
codes, determinism) survived a 154-case adversarial battery with zero
wrong-answer paths: every error names its crime and its repair, every
success round-trips its undo command, and the deterministic lanes are
byte-stable (G01/G02). What the battery exposed is a **version skew**:
the binary under test (`edb43d0`, built 05:42Z) predates the
night-cafe-1 F-series that landed on `main` (`fe22fe0`), so a large
slice of the captured defects is already fixed — and three defects
were live on `main` even after that series. Those three are landed in
rev 3.

**The re-measurement (rev 4b, the d4b1a32 capture of 00:47 local):
peak on every captured surface.** The owner rebuilt from current
`main` and re-ran the whole battery; every Class A cell now reads its
documented expectation — the machine docs carry the uncapped names
(C03/R07: `polkit-kde-authentication-agent-1` verbatim), the plural
tip collapses once (C05/C06), the unit ladder names the crime (D48:
`unknown unit 'kib'`, D51: `unknown unit 'xb'`), the RECWN footer
fits (D77/R04), `strict --help` keeps its paragraphs (B02), the
color-mode error carries the canonical footer (D43), the per-socket
refusals hold (D64/D65), both verify legs name the qualifier (R15:
`per socket, upload 1.0 MB/s per socket`), and the focus bounds refuse
hard (D73/D74). Determinism holds (G01/G02 byte-identical), the
broken-pipe law holds (A05), the honesty stack holds (D55/D79's ledger
proofs), the rescue lanes hold (R08/R19). What remains is exactly one
real design surface — the --during visibility gap (Class C item 1,
landed in rev 5) — plus the owner-side provenance action (D5: the
commit carries no GPG signature; sign releases) and the two deliberate
refusals below.

## Class A — stale-binary artifacts (already fixed on `main`, verify after rebuild)

The binary under test was built from `edb43d0`; the night-cafe-1
F-series and its pinned tests ride `fe22fe0`. Each captured defect
below was re-verified in the current source and is already closed:

| Capture | Artifact | Fixed by (verified in source) |
| --- | --- | --- |
| C03/R07 | `"process":"polkit-kde-authenticati…"` truncated inside the `list-apps --print-json` document | F1 — `list_apps.rs:204` rides `identity.full_name(id).unwrap_or(comm)` |
| C05/C06/C07 | JSON tip repeated per candidate: `a similar subcommand exists: 's'; a similar subcommand exists: ...` | F4 — `json_error.rs` plural collapse ("some similar subcommands exist: 's', 'unstrict', 'strict'") |
| D48/D51 | `'1kib'` / `'5.5xb'` misdiagnosed as digit crimes ("expected digits before the decimal point") | F6 — `parse.rs` names the unknown unit ("unknown unit 'kib' — the ladder is b, kb, mb, gb, tb") |
| D77/R04 | RECWN footer truncated past the measured RTT it exists to carry | F8 — `display_recwn.rs` compact voice, ≤76 columns worst case |
| B02 | `strict --help` long body flattened into one run-on paragraph | F10 — `surface.rs` `verbatim_doc_comment` + blank-line paragraphs |
| D43/C11 | The color-mode error ending without the canonical footer | F14 — `main.rs` appends `help_footer()` on the exit-2 lane |
| D64 | `s --all 500kb --per-socket` accepted by the sweep lane | F12 — `commands/mod.rs` refuses per-socket on the sweep lane (the flag rode nowhere) |
| R16 | Unstrict success answered in the reaper's voice (`[limiter] Unstrict: ...`) | The night-dragon-fly-6 announce-voice split + `cleanup.rs`'s naming law ("Removed N policies across M targets from '...'") |

Two more captures were verified as **pinned contracts, not defects**:
the empty `"tip": ""` on the JSON error object (the key stays present
so a consumer can index both fields blindly — `json_error.rs` header)
and the exit-code asymmetry on `--color-mode` (the JSON door exits 1,
the prose lane keeps its usage-class 2 — Night-netrunner-5, pinned in
`main.rs`).

**Action for the owner:** rebuild from current `main` and re-run the
battery; every Class A cell should flip to its documented expectation.

## Class B — live on `main`, landed in rev 3

Three defects survived the F-series and are fixed now, each with a
test pin and a micro-commit:

1. **The status JSON label was the surface F1 missed.**
   `display_json.rs` built `limits[].label` through
   `identity.status_label`, which rides the display-capped comm —
   `"cg:6126 (polkit-kde-authenticati…)"` inside a machine document.
   Fix: `status_label_full` (the byte-identical twin except for capped
   names) served only to the JSON lane; the human table keeps its cap.
   Landed in `1d5ac37`.

2. **The per-socket qualifier rode one leg of the verify line.**
   R15 read `(limit 1.0 MB/s per socket, upload 1.0 MB/s)` — the
   counter-direction clause appended its rate bare, so the report
   contradicted the enforcement shape it just verified. Fix: the
   qualifier rides both legs. Landed in `a630486`.

3. **The live monitor absorbed out-of-grammar `--focus` values.**
   D73/D74 walked `--focus 0s` and `--focus 31s` through the
   ignored-note — the only door in the tool where a typo'd value got
   the same treatment as a valid one, against the --interval law
   (D71/D72 refuse hard) and the --depth lane (parse.rs:151 refuses).
   Fix: the live lane grammar-checks through `parse_focus_window`
   before the note; in-grammar values keep the note contract
   byte-stable. Landed in `b679d70`.

## Class C — real gaps, owner decisions (not landed)

These are design surfaces, not bugs; schema and contract changes are
the owner's call. **The owner approved the queue on the rev 4b
re-measurement, and rev 5 landed the live ones — the record below
keeps the original classification with each item's outcome:**

1. **A `--during` limit is invisible in `status`.** The apply report
   (R17/D59) never echoes the window the user just asked for, and the
   status table (D77/R04) plus the status JSON document (R05) carry no
   window/expiry field — a user who limits for 30mn cannot see when
   the row lifts itself. **LANDED in rev 5** (the owner's signature
   arrived with the approval): the apply epilogue echoes the promise
   (the resolved wall instant plus the operator's own spelling — H3,
   the manual's acceptance-echo question, decided), and the status
   JSON window object gains `during` (the remaining lifetime,
   counting down) and `expires_at_utc` (ISO-8601). One correction the
   landing surfaced: the audit's "schema version bump (v34)" label was
   stale — the map schema had already reached v35 (night-frontier-Z1)
   when the proposal was written, and the visibility work touches no
   map byte, so no VERSION bump rides (an upgrade keeps every active
   limit alive). The human table's lifetime line
   (`window: until ... (X left)`, night-during schema v23) was
   already live — the captures never caught a windowed row at status
   time, which is why the gap read as table-wide.
2. **`ee --depth` census table truncates a mid-value.** The RSS cell
   rendered `115.9 …` at the terminal's budget (R13) — the value's
   unit was eaten by the ellipsis. The JSON document carries the full
   `rss_kb`, so machine truth is intact; the table wants one more
   column of headroom (or `115.9M` compact units). **ALREADY CLOSED —
   this claim was stale when written:** night-cafe-1's F16 widened the
   rss cell 7 → 8 columns (report.rs:368-374, `format_bytes`' own
   display ceiling `999.9 MB`) before this record was composed; the
   d4b1a32 capture's R13 renders every cell with its unit intact
   (`124.4 MB`, `11.5 MB`, …). The old capture's truncation was the
   pre-F16 binary.
3. **`s -V` is a missing-positional error while `doctor -V` prints the
   version** (A10 vs A11). Clap-derived (TARGET is
   `required_unless_present`), low priority, cosmetic asymmetry only.
   **ALREADY CLOSED — this claim was stale when written:**
   night-cafe-1's F7 version door treats a verbatim `-V`/`--version`
   riding a missing-positional death as a version REQUEST on every
   verb (ux.rs, the help door's twin); the d4b1a32 capture's A10 and
   A11 print the identical version report, exit 0.
4. **`zelynic help` is refused** (A04) — `disable_help_subcommand =
   true` is deliberate (`root.rs:42`); noted here so the choice stays
   a decision, not an accident. **Unchanged by design** — the d4b1a32
   capture confirms the refusal and the tip.
5. **Clap's did-you-mean suggests hidden internals** (`__probe-client`
   / `__probe-server` in C07). Harmless, but a private surface leaks
   through the suggestion lane; filtering hidden subcommands from
   `SuggestedSubcommand` is a one-spot change if the owner wants it.
   **ALREADY CLOSED — this claim was stale when written:** the
   hidden-vocabulary filter was hunt-Z9 (prose lane) and night-cafe-1
   H2 (the JSON door — one chain, both lanes); the old capture's C07
   leak was the pre-H2 binary (edb43d0). The d4b1a32 capture's C07
   answers the honest empty tip, the manual's own pinned expectation.
6. **`recwn_limits` appears in the status JSON only when the lane is
   planted** (absent in C02, present in R05). Deliberate
   (night-verify-final v33), but consumers should index it
   defensively; worth one sentence in docs/USAGE.md if the owner wants
   the contract spelled out. **LANDED in rev 5:** the USAGE.md RECWN
   section now spells the defensive-index contract (`has(...)` /
   `.recwn_limits // empty`) beside the absence law.

## What survived with distinction

The battery's adversarial lanes all passed on the binary under test —
these are the load-bearing walls the audit confirmed, not fixed:

- **Determinism:** `--help` is byte-identical across runs (G01) and
  `doctor --print-json` is byte-identical across runs (G02); the JSON
  contract holds one line even under `COLUMNS=40` (F06).
- **Broken-pipe law:** `--help | head -3` exits 0 through the pipe,
  no panic, no SIGPIPE kill (A05).
- **The suggestion ladder:** every typo'd subcommand and flag
  (D01-D46) names its nearest repair, including the round-trip forms
  (`strict-all` → `strict --all`); the `--no-probe` redirect and the
  `--allow-dangerous` merge both land on the modern spelling.
- **The atomic-group law:** `brave::steam` with one dead member
  applies NOTHING and says so, with the resolved/unresolved census
  (D83/D84) — never a partial limit wearing a success face.
- **The rate guards:** below-minimum refuses name the escape hatches
  (`--force-this`, or `block` for zero — D52/D53); the verifier's
  budget math is honest to the burst (D55's `2.474 KB of its 65.536 KB
  burst at window start`), and the ledger-refusal proof path states
  its basis when the flow check cannot offer one.
- **The probe's honesty stack:** the starvation note, the
  counter-direction clause, the multi-cgroup note and the per-window
  ledger (C09/D55/D79) — the verifier refuses to print VERIFIED
  without showing the arithmetic that earned it.
- **Rescue lanes:** `--check-update` refuses root with the reason
  (D76/R01), `recover` prints its census and the exact next command
  (R08), the double-unstrict answers with the fleet context
  ("86 other policies are still active" — R19).

## Next battery

Rebuild from current `main`, re-run
`sudo RUN_ROOT=1 ./scripts/labs-exp/capture-cli-ux-e2e.sh`, and expect
the Class A cells plus R05/R07 (full labels), R15 (both legs) and
D73/D74 (hard bounds refusals) to flip. **The d4b1a32 capture (rev
4b) confirmed every flip. The next battery's new expectation: R17/D59
carry the rev 5 window echo — `window: lifts itself at <wall UTC>
(<the operator's own spelling>)` between the resolved rows and the
follow-up — and the first status --print-json captured with a live
--during row shows the window object's `during` + `expires_at_utc`
pair (the capture battery has never yet caught a windowed row at
status time; that hole is the one blind spot the next run closes).**
The manual's D59 cell and H3 hypothesis ride the new law.

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
