<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Field Evidence (the standing sensor's log)

> The estate's two most valuable deferred items — the emit-on-change
> histogram and the bypass three-way reconciliation — wait on field
> evidence, not engineering: the first needs a corpus of real
> traffic-shape measurements before its threshold can be tuned
> honestly, the second needs a witnessed miss the interface-only
> delta cannot name. The owner's daily use IS the sensor that
> gathers both, and this log is where the harvest piles up — so the
> day a reopen trigger sounds, the evidence is already on record
> instead of "someday". No new code, no new instruments: the
> discipline is recording anomalies when they appear and
> occasionally running the harnesses the tree already ships.

## 1. Why this log exists (the someday/ready line)

A deferred item whose reopen condition reads "field measurements
exist" is either a someday or a ready, and the difference is
bookkeeping, not engineering. The sandbox cannot fabricate field
evidence — a KVM leg has no opinion about what a real browser
session does to a depth histogram, and a witnessed bypass miss is
by definition a surprise the lab did not script — so the only
honest source is the owner's own machine in daily use. Daily use
runs whether or not anyone records it; the sensor is free. What it
has never had is a ledger: the anomaly seen at 2 a.m. and fixed
(or shrugged off) leaves no entry behind, and the reopen
condition's corpus stays empty forever — not because the evidence
never arrived, but because it was never booked.

This document is that ledger. It is deliberately thin: a watch
table (what the sensor watches for), an entry format, the founding
entries backfilled from the record the tree already carries, and
the ritual that keeps the log alive. The two reopen conditions it
serves are quoted verbatim from their ledger rows
(docs/INNOVATIONS.md, Deferred by verdict) and never paraphrased
here — the deferred ledger owns the conditions; this log owns the
evidence that would satisfy them.

The precedent for the whole discipline is already on the record:
the 2026-11-09 live readings that retired two bookings (section 4,
entry E5) came from the owner's daily use — a `brave` session and
an `ss -tip` read — and no sandbox harness could have caught what
they caught. Daily use found a 36.8x over-claim that the estate's
own instruments had blessed. That is the sensor's calibration:
field evidence is not a nice-to-have beside the harnesses, it is
the instrument that has caught what the harnesses missed.

## 2. The watch targets (what the sensor watches for)

| Watch target | The reopen condition it serves (verbatim) | What the sensor records | The instrument to run |
|---|---|---|---|
| **Traffic-shape drift** (serves the emit-on-change histogram, -9000m) | "Reopens when: field measurements across real traffic shapes exist to tune the threshold honestly." | A representative session of a workload class (browser-heavy, sync/backup, streaming, bulk download, quiet background), its length, and the depth histogram's summary at session start and end — the bucket spread and its drift is the raw material a change-threshold must separate from sampling noise | `zelynic eagle-eyes --depth` (the `histogram:` line / `.targets[].histogram` block, schema v34-v35) read twice around the session; `scripts/bench/quota-saver-ab.sh` when the wire deltas of the workload class itself are wanted |
| **The witnessed miss** (serves the bypass three-way, D6 — the low rung) | "Reopens when: a user-reported bypass class lands that the interface-only delta demonstrably cannot see." | A session where traffic moved the wire but never booked an observer row the delta could name — a flagged or anomalous bypass-audit window with a workload explanation, or a live workload invisible to the session view | `zelynic eagle-eyes --depth` (the `bypass audit:` line — clean names its band or floor, flagged prints the full block with the triage commands); `ss -etu` / `lsof -i` for the mover when a window flags |

The trigger discipline is deliberately asymmetric: an entry that
does NOT match a watch target is still worth booking (the
found-incident class below proved that), and an entry that matches
one does not reopen anything by itself — graduation is section 5's
rule, and the reopen itself stays the owner's call, exactly as the
deferred ledger rows state.

## 3. The entry format

Every entry carries the five fields, in this order, one paragraph
each — short enough to write the same day, specific enough to be
evidence:

- **date** — the session date, ISO. The entry is written the same
  day or it names why not.
- **the observation** — what was seen, with the number. An
  observation without a figure or a paste is an anecdote, not an
  entry.
- **the instrument** — what read it: the surface (`--depth`'s
  histogram line, the bypass audit line, a status read) or the
  harness (`quota-saver-ab.sh`, `ee-resource-bench.sh`), by name.
- **the home** — where the durable record lives. A small anomaly
  lives only in this log; an anomaly that spawns work gets its
  audit doc or its physics-page section, and the entry degrades to
  a pointer (tell-once: the entry never restates what the home
  already says).
- **the disposition** — one of: `booked` (recorded, no action),
  `spawned <task>` (work followed), or `graduates <watch target>`
  (section 5).

Entries append; history is never edited. A wrong entry gets a
dated correction entry below it, the same discipline the audits
carry.

## 4. The founding entries (the harvest already on record)

The log is born 2026-11-24, backfilled from the record the tree
already carries — every number below is quoted from its home, and
the homes are linked. The backfill is the proof the format works:
this is the owner's daily-use evidence the estate has already
banked, in the order it arrived.

**E1 — 2026-10-07, the live bug-hunt session.** The owner ran the
flagship binary through its paces for eighty minutes and filed
four finds the way he always files them — an echo at the moment
the bug bit; four finds, four closures, zero declined, plus the
negative results the audit owed the record (the refusal wordings
and rate bounds that held). Instrument: the owner's own session
against the live binary. Home:
[audits/NIGHT_HUNT_30_OWNER_LIVE_SESSION_FINDS_2026-10-07.md](audits/NIGHT_HUNT_30_OWNER_LIVE_SESSION_FINDS_2026-10-07.md).
Disposition: spawned NIGHT-hunt-30. The class this entry teaches:
a live session on the owner's machine is a bug-hunt instrument no
synthetic battery replaces.

**E2 — 2026-10-28, the blocked teardown.** The owner's own
`rm -rfv zelynic` died on root-owned `__pycache__` bytecode the
sudo-run harnesses had left behind — the workspace incident class
that became the `sys.dont_write_bytecode` guard block in all
fourteen harness entry points. Instrument: the field report
itself (the exact failing paths quoted). Home:
[MAINTENANCE.md](MAINTENANCE.md) §7 (the root-owned `__pycache__`
class). Disposition: spawned the guard + the shell-layer second
wall. The class: field reports from daily use close failures the
clean-tree gates cannot even see.

**E3 — 2026-11-06, the bounded pair that saved nothing.** A
bounded 20 MB transfer run through the A/B harness measured ~0%
(enforced leg moved +1.21 MB download / +0.64 MB upload MORE than
the unenforced leg, against bookings of 82.58% / 75.85%) — the
workload condition of the entire quota-saver claim, discovered on
a real run: the saver prices an overrun that actually happens.
Instrument: `scripts/bench/quota-saver-ab.sh`. Home:
[QUOTA_SAVER_PHYSICS.md](QUOTA_SAVER_PHYSICS.md) §1 and §8.
Disposition: booked (the claim's conditions of validity carry it).

**E4 — 2026-11-07, the campaign day.** Three same-day harvests:
the five-rate A/B series on the home WiFi (94.9/95.9, 85.0/91.9,
79.7/86.7, 59.7/83.5, 40.3/72.3 — the measured curve, including
the 2.3pp run-to-run variance the two 100kb runs named); the
owner's 200kb-on-Brave session that forced the bypass audit's
clean verdict to name the band it cleared ("clean" beside a 22%
shadow figure had made the reader guess); and the live floor-bound
window (tx shadow 0% / rx shadow 100%) that taught the clean line
to say which gate held. Instruments: the A/B harness; the
`--depth` bypass audit line on the owner's session. Homes:
[QUOTA_SAVER_PHYSICS.md](QUOTA_SAVER_PHYSICS.md) §3/§7/§8;
[USAGE.md](USAGE.md) §eagle-eyes --depth (the bypass audit
paragraph);
`src/ebpf/render/bypass.rs`'s own record. Disposition: spawned
night-ux-1 / night-ux-3 (landed 2026-11-07). The class: the
surfaces' honesty laws were tuned by what the owner actually saw.

**E5 — 2026-11-09, the masterclass.** The owner's live readings
broke two bookings the estate's own instruments had blessed: a
`brave` at 500kb booked 744.6 MB against a 20 MB doc-formula
prediction (36.8x over) and a `python3` at 300kb booked 1.8x
over, killing the EDT counterfactual (schema v29); and the
`ss -tip` read — 48-78 KB autotuned rcv_wnd across 11 connections,
one at the clamp, the strict bound ~6.5 MB against the 165 MB
booked (~25x over) — killed the RECWN estimate (schema v30). Both
words stay at their offsets reading zero; both graves are kept.
Instrument: the owner's own `status` read and `ss -tip` — daily
use, nothing else. Home: [QUOTA_SAVER_PHYSICS.md](QUOTA_SAVER_PHYSICS.md) §2;
`ebpf/src/schema_ledger.rs` (v29/v30). Disposition: spawned
night-quota-audit / night-recvn-audit; this entry is also the
standing calibration of the whole log (section 1) and the founding
precedent of the booking law ([CLAIMS_VERIFICATION.md](CLAIMS_VERIFICATION.md),
the booking law).

## 5. The harvesting protocol (the ritual)

Three habits, none on a clock:

1. **Record the anomaly the day it appears.** Anything in daily
   use that surprises — a verdict band that reads oddly, a counter
   that disagrees with the wire, a session the surfaces cannot
   explain, a teardown that fails — gets an entry the same day,
   five fields, ten minutes. The bar is low on purpose: the
   expensive part of evidence is writing it down late or never.
2. **Run the harness when a workload class changes, not on a
   schedule.** When a new heavy app becomes routine, the link
   changes, or a sync client joins the machine: one
   `quota-saver-ab.sh` run (the wire shape of the class) and, for
   the monitor's own cost on the new load, one
   `ee-resource-bench.sh` run. Both refuse loudly when their
   prerequisites are missing; both clean up after themselves; a
   harness run that produced a surprising figure is itself an
   entry.
3. **Graduate by the ledger, not by enthusiasm.** An entry
   graduates a watch target when the target's reopen condition is
   satisfied by what the entries collectively show — and the
   graduation act is a dated update to the deferred item's ledger
   row in [INNOVATIONS.md](INNOVATIONS.md) naming the entries
   (the same dated-update pattern the Z14 mirror row carries).
   The reopen decision itself stays the owner's call; the log's
   job is that the call is made against a pile of evidence, not a
   memory.

## 6. The honesty rules

- An entry records what was seen, never what was hoped for. A
  watch target that never fires produces zero graduation entries,
  and that is the discipline working, not failing — most watches
  find nothing, and the finding of nothing is what keeps a
  deferred item honestly deferred.
- No entry edits history. Corrections are new, dated entries.
- A number in an entry is either read off an instrument or labeled
  an estimate — and an estimate errs low or it does not ship into
  any claim (the booking law,
  [CLAIMS_VERIFICATION.md](CLAIMS_VERIFICATION.md)).
- The log is not a backlog. An entry's disposition names what
  happened; it never becomes a promise that something will.

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
