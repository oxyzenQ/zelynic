<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Zelynic Licensing FAQ

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

| Your annual revenue                | Tier                     |
| ---------------------------------- | ------------------------ |
| No commercial use (hobby/personal) | Personal (free, GPL-3.0) |
| Solo dev / freelancer, < $100K     | Individual ($99/year)    |
| $100K – $10M                       | Business ($1,000/year)   |
| > $10M, or any redistribution      | Company ($9,900/year)    |

Redistribution under your own terms is the Company tier regardless of
revenue — it is the only tier that carries redistribution rights.

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
   requires the Company tier of the Commercial License — see
   [COMMERCIAL_LICENSE.md](../COMMERCIAL_LICENSE.md).
2. **The Marks** (name, logo, branding) are governed by
   [TRADEMARK.md](../TRADEMARK.md) and require separate trademark
   permission for any rebrand or relaunch — a commercial source
   license does not grant them.

Both locks must be opened to rebrand and sell: Company tier **plus**
trademark permission.

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
