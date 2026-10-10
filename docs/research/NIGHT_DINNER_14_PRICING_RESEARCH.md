<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Pricing Research — Individual / Business / Company Tiers (NIGHT-dinner-14)

> The owner's ask, in his own words (translated; the repo is
> English-only): the top tiers currently look cheap for what they
> cover — a zero-to-hero, critical-infrastructure-grade tool built
> from scratch — and before any price moves, he wants the research
> on the table so HE decides what is worth approving. This document
> is that research. It changes no price, edits no license, and
> touches no user-facing file: it is the decision brief.
>
> Update 2026-09-28 (same day): the owner read the brief and made his
> call — the executed decision is recorded in section 7.

Research date: 2026-09-28. Prices are point-in-time snapshots from
public sources, each named with its date; competitor pricing moves,
so every number below should be re-verified at execution time.
Currency is USD as listed by the source.

## 1. What zelynic charges today

| Tier       | Price        | Target                                          |
| ---------- | ------------ | ----------------------------------------------- |
| Personal   | Free (GPL)   | Hobby, personal, non-commercial, contributions  |
| Individual | $99/year     | Solo devs, freelancers, revenue < $100K/year     |
| Business   | $1,000/year  | SMB, revenue $100K – $10M/year                  |
| Company    | $9,900/year | Enterprise (>$10M/year) OR redistribution rights |

The full terms live in [COMMERCIAL_LICENSE.md](../../COMMERCIAL_LICENSE.md)
and [LICENSING_FAQ.md](../LICENSING_FAQ.md). Tiers are self-declared in
good faith, paid in USD-pegged crypto, with an owner-discretion
multi-year discount (20% off 2 years, 30% off 3 years).

## 2. The market scan

### 2.1 Consumer per-app network control (the feature zelynic has)

These are the tools a home user finds when they search "limit app
bandwidth". None of them runs on Linux — that matters below.

| Product (platform)        | Price                                          | Model             | Source (date) |
| ------------------------- | ---------------------------------------------- | ----------------- | ------------- |
| NetLimiter 5 (Windows)    | $29.95 standard / $24.95 home                  | One-time, lifelong | itprc.com roundup (2026-06-25) |
| TripMode (macOS/Windows)  | $11.99–$17.99/year, or $39.99–$49.99 lifetime  | Subscription      | tripmode.ch Mac App Store terms; App Store listing (regional/plan variants, retrieved 2026-09-28) |
| Little Snitch (macOS)     | $59 single license                              | Perpetual + paid major upgrades | peakhour.app comparison (retrieved 2026-09-28; historically EUR 45, 2017) |
| GlassWire (Windows/Android) | Basic $2.99/mo, Pro $7.99/mo, Elite $15.99/mo | Subscription     | gappsy.com (2026-07-20); techradar (2025-04-23) |
| NetBalancer (Windows)     | Free tier exists; paid pricing not verifiable this pass | Mixed    | search pass 2026-09-28 — treat as unverified |

Read of the consumer band: **$12–$60/year effective at the low end,
$36–$192/year for subscription monitoring** (GlassWire's tiers).
One-time licenses cluster at $30–$59. These are mass-market
Windows/macOS products with large audiences and no copyleft
alternative behind them.

### 2.2 Commercial network monitoring / shaping (the budget zelynic's Business and Company tiers actually live in)

When a company budgets for network visibility and control, these
are the price anchors on the same invoice line:

| Product          | Price                                            | Source (date) |
| ---------------- | ------------------------------------------------ | ------------- |
| PRTG 500         | $2,149/year (TrustRadius 2026); $200/month paid annually = $2,400/yr (paessler.com) | both retrieved 2026-09-28 |
| PRTG 2500        | $8,099/year (TrustRadius 2026); $742/month paid annually = $8,904/yr (paessler.com) | both retrieved 2026-09-28 |
| PRTG (field report) | ~300% license increases reported 2025 — equivalent sensor counts now ~$10,000/year | Reddit r/sysadmin thread (2025) |
| InterMapper      | subscription starts ~$1,900/year                  | itechguides comparison (2026) |

Read of the commercial band: **entry ~$1,900–$2,400/year,
mid $8,000–$10,000/year**, and the trend line is upward. These
products are monitoring-first; zelynic is enforcement-plus-monitoring
at the host level — a stricter guarantee than a dashboard.

### 2.3 The Linux lane

The reason the consumer comparables are all Windows/macOS: **no
mainstream per-app limiter exists on Linux.** The free options
users actually find are monitor-only (nethogs, iftop, vnstat — they
watch the drain continue) or interface-level CLI shaping
(tc/htb/tbf — powerful, but per-link and per-class, not per-app,
and famously unfriendly). trickle (LD_PRELOAD per-process) is
effectively unmaintained. The user-pain evidence is public and
evergreen: "my brother's streaming is eating the bill, how do I cap
just him" is a standing genre of forum threads (e.g., the
superuser thread surfaced in this research pass, 2017 — still the
shape of the ask years later). zelynic's lane on Linux is
uncontested: per-cgroup, kernel-enforced, one static binary, no
daemon, no config file.

### 2.4 The mobile-data cost anchor (what the tool saves)

For the cost-saving story (documented in [QA.md](../../QA.md) Q6):
the global average price of mobile data is ~$2.59/GB across 237
countries (Cable.co.uk survey, reported by The Register, 2023-09-28);
the US sits around $5.62/GB (2022 survey data). A user whose
hotspot plan dies to background processes is losing $5+/day of
quota value at those rates — the save side of the pricing
conversation, and the cheapest marketing the tier structure has.

## 3. Analysis against the current tiers

- **Individual $99/year sits at the TOP of the consumer band, not
  under it.** NetLimiter is $30 once; TripMode is $12–18/year;
  Little Snitch is $59 once. Only GlassWire's Elite tier ($192/year)
  prices above it. The "looks cheap" feeling comes from comparing
  against enterprise tooling, not against what a home user pays for
  this feature class. Raising Individual is defensible only on the
  Linux-lane-monopoly argument (no alternative exists to buy), not
  on the comparables. Risk of a raise: $99 is already the price of
  "I trust this on my daily driver" for a solo dev; pushing to
  $149 invites the GPL path to be chosen instead (which costs
  nothing and is first-class by design).
- **Business $1,000/year is underpriced 2x+ against its own
  budget line.** PRTG's entry monitoring product is $2,149–$2,400/
  year — for dashboards. A business buying active enforcement
  (policer + monitor, kernel-enforced, one binary to deploy) is
  getting the harder half of the problem for half the entry price.
  $1,490–$2,490/year is supported by the anchors; $1,990 keeps the
  clean "under two thousand" read while doubling revenue per buyer.
- **Company $9,900/year carries redistribution rights and still
  sits mid-band.** PRTG's mid tier is $8,099–$8,904/year for
  monitoring alone; field reports put equivalent coverage at
  ~$10,000/year after the 2025 increases. OEM/redistribution
  licensing in infrastructure software conventionally starts in
  five figures — it is the right to embed and resell, not a seat.
  $14,900 stays under the psychological $15K while pricing the
  redistribution grant like one.

## 4. Options for the owner's decision

| Option | Individual | Business | Company | The bet |
| ------ | ---------- | -------- | ------- | ------- |
| A — hold Individual, lift the business end | $99 (hold) | $1,990 | $14,900 | The consumer anchor is honest where it is; the money is in the tiers businesses budget against |
| B — lift the whole ladder | $149 | $1,990 | $14,900 | The Linux lane is uncontested end to end; capture it before a competitor reads this research too |
| C — hold everything, sell the value | $99 (hold) | $1,000 (hold) | $9,900 (hold) | Ship the cost-saving story (QA.md Q6) first; re-price only after demand proves the story |

What NOT to do, regardless of option:

- **Do not jump any tier more than ~1.5x in one step.** There is no
  sales motion, no trials-to-conversion funnel, and no volume — a
  3x jump at zero friction just moves buyers to the GPL path (which
  is a fine outcome for adoption, a poor one for revenue).
- **Grandfather existing buyers.** The tiers are self-declared good
  faith; honoring the price someone already paid is the same
  contract in the other direction.
- **Keep the ladder legible.** 99 / 1,000 / 9,900 reads as a decade
  ladder; 149 / 1,990 / 14,900 keeps a clean ~13x / ~7.5x shape;
  uneven steps (e.g., 129 / 1,490 / 19,900) read like pricing
  experiments, not a structure.

## 5. Execution checklist (for whichever option is approved)

1. The tier table lives in THREE files and must move as one:
   [README.md](../../README.md) (Commercial Licensing section),
   [COMMERCIAL_LICENSE.md](../../COMMERCIAL_LICENSE.md) (section 3),
   and the revenue-tier guide in
   [LICENSING_FAQ.md](../LICENSING_FAQ.md). A price change that
   desyncs the three is worse than no change.
2. The multi-year discount note (20% / 30%) scales with the new
   prices automatically — no edit needed, but re-read it after.
3. Announce with a dated window (e.g., new prices effective from
   the next release tag), not retroactively.
4. Re-verify every number in section 2 against its source on the
   execution date; competitor pricing moves (PRTG demonstrably
   moved ~300% in one year).
5. This research document stays as the rationale record — the repo
   documents why, not just what.

## 6. Verdict

The research supports lifting the business end: **Business and
Company are underpriced against their own budget anchors (2x+
against PRTG entry, mid-band with redistribution rights included).
Individual is already at the top of its consumer band — the
stronger Individual play is the cost-saving value story (QA.md Q6),
not the price.** The choice between options A, B, and C is the
owner's call alone; this brief exists so that call is made from
evidence.

## 7. The owner's decision (executed 2026-09-28)

Option A, with one owner adjustment: **Business $1,990/year,
Company $14,990/year.** Company lands $90 above the researched
$14,900 anchor — still under the psychological $15K line the
analysis drew, and the owner's number, not the research's.
Individual holds at $99/year: section 3's read — it already sits
at the top of its consumer band, and its stronger play is the
cost-saving value story (QA.md Q6), not a raise. Effective from
the first release tag after 2026-09-28, announced in the
CHANGELOG rather than retroactively; buyers who paid before the
move are grandfathered at the price they bought, for the term
they bought (the what-NOT-to-do list honored). The three-file
sync (section 5, item 1) — README.md, COMMERCIAL_LICENSE.md,
LICENSING_FAQ.md — is the execution record. Same-day
re-verification: every section 2 source was checked 2026-09-28,
the same date as this execution — no source moved in between.

**Superseded 2026-09-30 (NIGHT-dinner-25):** the owner lifted the
business end of the ladder again — Business $2,199/year, Company
$20,199/year; Individual still holds at $99/year. The rationale
this time is the owner's, not the comparables': zelynic is a
masterpiece, and its value increases year by year — the price
follows the value. This section stays as the 2026-09-28 decision
record; the current price list lives in
[COMMERCIAL_LICENSE.md](../../COMMERCIAL_LICENSE.md).

**Superseded again 2026-10-10 (NIGHT-dinner-31):** the owner
lifted the business end once more — Business $5,199/year,
Company $110,199/year; Individual still holds at $99/year. Same
rationale, compounding: zelynic is a masterpiece, its value
increases year by year, and the price keeps tracking the value
upward. Grandfathering unchanged — buyers who paid before any
move keep the price they paid, for the term they bought. The
current price list lives in
[COMMERCIAL_LICENSE.md](../../COMMERCIAL_LICENSE.md).

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
