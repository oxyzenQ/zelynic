<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-improve-74 audit — the 55h window that read 3d (the transcript's timezone, not the kernel's clock)

> Audit date: 2026-10-10 (night-improve-74, after night-improve-73).
> Scope: the owner's `--during` transcript and its AI analysis —
> `sudo zelynic s brave 200kb --during 55h` applied at the shell's
> 23:21 (the command's 2s timer), `status | grep -A5 brave` read back `window: until
> 2026-10-12 23:21:18 UTC (3d left)` three seconds later, and the
> analysis concluded "55h from now should land 13 Okt ~06:21 UTC, not
> 12 Okt — and 23:21 to 23:21 is 48h, but the UI says 3d left — likely
> a rounding bug or inclusive counting". Method: re-derive every
> number from the transcript, then read the three code surfaces the
> numbers flow through (the grammar parse, the monotonic translation,
> the status renderer), and pin the exact transcript shape so the
> question can never come back.

## 1. The 48h that was 55h (a local clock compared against a UTC stamp)

The transcript's two clocks were compared in two different timezones.
The shell's `23:21` (the 2s-timer timestamp) is the owner's wall clock (WIB, UTC+7); the
status line prints `until ... UTC` — `format_wall_utc` names its
timezone in the string. Re-derived in one zone (UTC): the apply ran at
2026-10-10 **16:21:18 UTC** (23:21:18 WIB), and the window end the
status read back is 2026-10-12 **23:21:18 UTC** — that is
16:21:18 + 55h **to the second** (48h lands on 12 Oct 16:21:18 UTC;
the remaining 7h carry it to 23:21:18). The seconds digit seals it:
`:18` on both sides is the apply instant's own seconds, preserved
through the translation. The analysis's "55h from now should land 13
Okt ~06:21 UTC" added 55h to 23:21 *as if it were UTC* — a 31-hour
error that is exactly the WIB/UTC gap applied twice. **The flag was
honored exactly; no clamp between 48h and 55h exists anywhere on the
path** (`DURING_MAX_NS` is 5y, night-improve-60's trim; 55h = 198,000s
parses clean through `during_parse::parse_duration`).

## 2. The 3d that is 2d6h59m (the improve-60 ceil law at a tier crossing)

The second suspicion — "(3d left)" beside a 48h-looking gap — is the
night-improve-60 contract working exactly as the owner mandated it
three days earlier for the same renderer: "a countdown never
understates what remains — every tier rounds UP to the unit it still
holds". At status time the remaining span was 54h59m57s, which sits
ABOVE the day-tier boundary (86,400s): the day tier's honest ceiling
of 2.29 days is 3d. The promise was spoken in hours, but the
countdown's one-unit display rounds into the unit the remainder still
holds — 54h59m57s still holds a third day, so it reads "3d", the same
law that makes 4h59m59s read "5h" (the owner's own 5h find that
started improve-60). The `until` stamp beside it carries the exact
promise; only the countdown's unit crossed. Both sides of the
hours-to-days boundary are now pinned in
`test/ebpf/display_tests.rs` (`55h - 3s → "3d"`, `1d - 1s → "24h"`,
`1d + 1h → "2d"`), so the crossing cannot silently move.

## 3. The clock discipline (why the end instant is trustworthy)

The row the apply wrote is a `WINDOW_KIND_SPAN` with
`start_mono_ns = bpf_ktime_now` and `end_mono_ns = start + 198e9`
(`during_to_window`): the KERNEL decides expiry off the monotonic
clock — NTP slews and a manual `date -s` cannot move the deadline
(the documented residue: suspend time does not count, so a sleeping
host's window outlives its wall-calendar promise by the slept time).
The status line reconstructs the wall instants through the offset
bridge (`wall_minus_mono`) and prints them in UTC — the timezone is
in the string, and the two clocks (the kernel's monotonic verdict,
the display's wall reconstruction) agree to the second in the
transcript. This is the drift-freedom the night-during design chose
over a daemon, and the transcript is a live confirmation.

## 4. The already-limited path (re-apply semantics, the "already limited" ask)

The transcript itself exercises the re-apply case: brave was already
limited (cg:89976 carried 255.7 MB of history when the fresh 200kb
landed), and the target spanned TWO cgroups (each with its own
bucket). The status read-back shows both cgroups re-stamped to the
SAME end instant — the improve-29 law in action: an apply WITH
`--during` writes a fresh window from the NEW apply instant
(replacing whatever window stood before), and an apply WITHOUT
`--during` removes any existing window entirely. Re-applying never
extends a deadline silently; it re-promises from now. The verify
note's two-bucket shape (the probe measured cg:90021, the ledger
reports both) is the per-cgroup bucket model, not a window split.

## 5. Verdict

No defect on any surface the transcript touched: the grammar parsed
55h exactly, the kernel window spans exactly 55h from the apply
instant, the UTC end stamp is correct to the second, the countdown
read is the owner's own ceil law at a tier crossing, and the
re-apply re-stamped both cgroups per the improve-29 contract. The
confusion was a local clock compared against a UTC stamp — the same
class of misread the improve-60 audit recorded from the other side
(a renderer that understated an honest window). Documentation is the
fix this time: this document, the tier-crossing pins in
`format_duration_compact_one_unit_ceiled`, and the existing
rootless grammar pins in `test/ebpf/limiter/during_user_tests.rs`
(`duration_parses_every_unit`, `duration_bounds_are_pinned`,
`duration_translates_to_a_running_span`) which already pin the
surfaces section 1-3 walk through.
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
