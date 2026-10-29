<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# zelynic Licensing FAQ

Short answers to the questions that reach the licensing inbox most.
The authoritative documents are [LICENSE](../LICENSE) (GPL-3.0-only),
[COMMERCIAL_LICENSE.md](../COMMERCIAL_LICENSE.md) (the commercial
offer), and [TRADEMARK.md](../TRADEMARK.md) (the Marks).

## Can I use this at my company for free?

Only if you comply with GPL-3.0 — which means, among its obligations,
open-sourcing your modifications and integrations and offering them
under GPL-3.0-only to anyone you distribute to. If that works for you,
use it for free with the project's blessing. If your company cannot or
will not meet the copyleft obligations, buy a commercial license —
that is exactly what it is for. See
[COMMERCIAL_LICENSE.md](../COMMERCIAL_LICENSE.md) for who needs one.

## Which tier do I need?

Tiers follow your total annual revenue:

| Your annual revenue                | Tier                                 |
| ---------------------------------- | ------------------------------------ |
| No commercial use (hobby/personal) | Personal (free, GPL-3.0)             |
| Solo dev / freelancer, < $100K     | Individual ($99/year)                |
| $100K – $10M                       | Business ($9,999/year)               |
| 5–19 nodes, internal use           | Enterprise Node ($2,499/node/year)   |
| > $10M, internal use only          | Enterprise Internal ($49,999/year)   |
| Embedding in a shipped product     | OEM / Redistribution ($149,999/year annual, or $249,999 one-time + 20%/year maintenance) |

Redistribution under your own terms is the OEM / Redistribution tier
regardless of revenue — it is the only tier that carries
redistribution rights.

## Isn't $149,999 for an OEM license too expensive for a rate limiter?

Compare it to what the license replaces, not to the CLI's length.
Reaching zelynic's enforcement depth in-house means senior
kernel-engineer months (the 3–6 months to reach half of it is an
estimate from the R&D shape, not a measurement), the R&D budget that
precedes the first production line, and kernel-side bug risk that
never leaves — the full framing lives in
[COMMERCIAL_LICENSE.md](../COMMERCIAL_LICENSE.md#why-just-a-rate-limiter-is-the-wrong-comparison).
Against commercial embedding benchmarks — large-OEM Qt Commercial
deals are commonly cited in the $500K–$2M range, Elastic OEM
agreements in the $250K–$2M range (ballpark figures, not quotes) —
$149,999/year for the redistribution rights sits on the low end of
the industry band. The perpetual path ($249,999 one-time +
20%/year maintenance) additionally caps the long-term cost: by year
3 it is already cheaper than three annual terms.

## Why is there a per-node tier? Enterprise Internal is already unlimited.

Because between 5 and 19 nodes, a $49,999 flat tier is hard to
justify internally, and the Individual/Business tiers do not fit an
enterprise deployment either. Enterprise Node prices that shape
honestly: $2,499/node/year, minimum 5 nodes, maximum 19 — a
10-node deployment pays $24,990, proportional and approvable. At
20 nodes the flat tier wins ($49,999 for unlimited nodes), so the
per-node tier is a bridge, not a destination: the tier you outgrow
on purpose.

## Can I mix annual and perpetual across different OEM products?

Yes — the two paths are per-product, and they can coexist in one
portfolio: Product A on the annual path, Product B on the perpetual
path. What a license does not do is span products: a perpetual
license for Product A does not cover Product B, and each embedded
product needs its own OEM license — its own tier, its own path, its
own license PDF.

## Do contributors need to sign anything?

Yes, in the lightweight DCO sense: every commit carries a
`Signed-off-by:` line (`git commit -s` appends it from your git
identity), and that line is the acceptance of the
[Contributor License Agreement](../CLA.md). The CLA grants the Owner
the right to relicense contributions — the legal foundation the
dual-license offer stands on, since a commercial license cannot
lawfully cover code the contributor did not allow to relicense —
while contributors keep full copyright of their own work. No separate
document to sign, no paperwork to mail; an agreeing comment on the
pull request works too.

## How do I pay?

Crypto, USD-pegged: Solana (SOL / USDT-SPL), Ethereum (ETH / USDT /
USDC), or Bitcoin (Taproot). You send the cryptocurrency equivalent of
the USD price at purchase time; the rate is verified via CoinGecko or
CoinMarketCap. Send the transaction hash to the licensing email and
the owner verifies it on-chain. Full instructions and QR codes:
[COMMERCIAL_LICENSE.md § Payment](../COMMERCIAL_LICENSE.md#5-payment).

## Do I need a license for hobby use?

No. GPL-3.0 covers personal, hobby, educational, and non-commercial
research use completely — no payment, no registration, no ask. The
free path is not a trial.

## Can I rebrand and sell it?

No. Two separate locks apply:

1. **Redistribution** of zelynic or a derivative under your own terms
   requires the OEM / Redistribution tier of the Commercial License —
   see [COMMERCIAL_LICENSE.md](../COMMERCIAL_LICENSE.md).
2. **The Marks** (name, logo, branding) are governed by
   [TRADEMARK.md](../TRADEMARK.md) and require separate trademark
   permission for any rebrand or relaunch — a commercial source
   license does not grant them.

Both locks must be opened to rebrand and sell: the OEM / Redistribution
tier **plus** trademark permission.

## What if I just take it — fork it illegally, close the source, and sell it?

Then you are the person the licensing docs warn about. Taking
zelynic's code — stealing it, forking it illegally, stripping the
license, or building a closed-source commercial product on it —
without contacting the owner (rezky_nightky / oxyzenQ) and paying
for the license is theft, not a gray area: a breach of GPL-3.0-only
and the Commercial License alike, and — in the owner's own words —
the mark of the worst kind of human, a rotten one. The honest
options are exactly two: open-source what you build under
GPL-3.0-only (free and first-class), or buy the tier your revenue
honestly matches. Closed source without a license is not a third
option — it is the one this warning exists for.

## More questions?

Email [with.rezky@gmail.com](mailto:with.rezky@gmail.com) or open an
issue on [GitHub](https://github.com/oxyzenQ/zelynic).

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
