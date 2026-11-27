# NIGHT-DRAGON-FLY-1 — CLI UX end-to-end audit verdict (capture of 2026-11-27)

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
the owner's call:

1. **A `--during` limit is invisible in `status`.** The apply report
   (R17/D59) never echoes the window the user just asked for, and the
   status table (D77/R04) plus the status JSON document (R05) carry no
   window/expiry field — a user who limits for 30mn cannot see when
   the row lifts itself. Proposal: add the window to the limit entry
   (`during` + `expires_at_utc`) and one status column; that is a
   schema version bump (v34), so it waits for the owner's signature.
2. **`ee --depth` census table truncates a mid-value.** The RSS cell
   rendered `115.9 …` at the terminal's budget (R13) — the value's
   unit was eaten by the ellipsis. The JSON document carries the full
   `rss_kb`, so machine truth is intact; the table wants one more
   column of headroom (or `115.9M` compact units).
3. **`s -V` is a missing-positional error while `doctor -V` prints the
   version** (A10 vs A11). Clap-derived (TARGET is
   `required_unless_present`), low priority, cosmetic asymmetry only.
4. **`zelynic help` is refused** (A04) — `disable_help_subcommand =
   true` is deliberate (`root.rs:42`); noted here so the choice stays
   a decision, not an accident.
5. **Clap's did-you-mean suggests hidden internals** (`__probe-client`
   / `__probe-server` in C07). Harmless, but a private surface leaks
   through the suggestion lane; filtering hidden subcommands from
   `SuggestedSubcommand` is a one-spot change if the owner wants it.
6. **`recwn_limits` appears in the status JSON only when the lane is
   planted** (absent in C02, present in R05). Deliberate
   (night-verify-final v33), but consumers should index it
   defensively; worth one sentence in docs/USAGE.md if the owner wants
   the contract spelled out.

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
D73/D74 (hard bounds refusals) to flip. The manual's D71-D74
expectation cell is already updated to the new law.
