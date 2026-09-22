<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Zelynic Trademark Policy

This document governs the use of the **Zelynic** name, logo, and associated branding assets. It supplements, but does not replace, the GPL-3.0-only license that covers the source code.

> **TL;DR** — Forking falls into two categories. **Contribution forks** (bug
> fixes, features, PRs back to upstream) are allowed without permission and
> may keep the "Zelynic" name and branding unchanged. **Non-contribution
> forks** (rebrand, relaunch, derivative product, commercial offering) must be
> discussed with the owner first and MUST rename away from "Zelynic".

---

## 1. Trademark Ownership

The name **"Zelynic"** and all associated logos, icons, artwork, and visual identifiers (collectively, the **"Marks"**) are trademarks of the project creator (`rezky_nightky (oxyzenQ)`). These Marks are **not** covered by the GPL-3.0-only license granted to the source code.

Use of the Marks is permitted only as described in this policy. All other uses require prior written consent.

---

## 2. Permitted Uses (No Approval Required)

The following uses are allowed without seeking explicit permission:

### 2.1. Attribution

You may use the Zelynic name and logo in a purely **attributive** manner to accurately identify the origin of the unmodified software. Examples:

- Crediting Zelynic in a "powered by" or "built with" section of your documentation or website.
- Referencing the original project by name in articles, reviews, or academic papers.
- Including the original name in source file headers as required by the GPL-3.0-only license attribution clause.

### 2.2. Non-commercial redistribution of unmodified copies

Distributing **unmodified** copies of the Zelynic binary or source code (including the original name, logo, and README) is permitted under the GPL-3.0-only license, provided that the license and copyright notices are preserved.

### 2.4. Contribution forks (the cosmostrix lineage)

Forking the source code under the terms of GPL-3.0-only for the purpose
of contributing back to zelynic (bug fixes, features, PRs) is allowed
without permission. Contribution forks may keep the Zelynic name, logo,
and branding unchanged — no rename or rebrand required — as long as the
fork is clearly labeled as a contribution fork (e.g. the fork description
says "WIP: <feature> for zelynic upstream") and the owner is notified via
a GitHub Issue or PR. The full contract lives in §4a.

### 2.5. Community and educational use

Using the name in community discussions, issue trackers, forums, educational materials, or presentations about the project is always welcome.

---

## 3. Uses That Require Approval

You **must** obtain prior written permission before using the Marks in any of the following ways:

### 3.1. Forks and derivatives that are NOT contributions

Forks intended for any purpose other than upstream contribution — rebrand,
relaunch, derivative product, commercial offering, or redistribution under
a different identity — require owner discussion BEFORE public release (see
§4b). These forks may **not** use the Zelynic name or Marks to identify or
market the derivative. This includes but is not limited to:

- Distributing a modified build under the name "Zelynic" or a confusingly similar name (e.g., "Zelynic Pro", "Zelynic Plus", "ZelynicX").
- Using the Zelynic logo or artwork on packaging, websites, or promotional materials for a derivative product.

### 3.2. Commercial use

Using the Zelynic name or Marks in any commercial context — including product names, company names, service names, domain names, social media handles, or advertising — requires prior written approval.

---

## 4. Forks & Derivatives

There are two fork categories with different rules (the cosmostrix
fork-policy lineage — same owner, same two doors):

### 4a. Contribution Forks (allowed without permission)

Forks whose sole purpose is to contribute back to the upstream zelynic
repository via Pull Requests. These forks:

- MAY keep the zelynic name, logo, and branding unchanged.
- MUST be clearly labeled as a contribution fork in the fork
  description (e.g. "WIP: fix for rate parser edge case").
- MUST NOT be published or distributed as a standalone product.
- MUST be offered back to the upstream via a PR or Issue before any
  external distribution.

No rename, no rebrand, no permission needed — just open a PR.

### 4b. Non-Contribution Forks (require owner discussion)

Forks intended for any purpose other than upstream contribution —
rebrand, relaunch, derivative product, commercial offering, or
redistribution under a different identity. These forks:

- MUST be discussed with the owner (rezky_nightky / oxyzenQ) BEFORE
  public release. Open a GitHub Issue or contact via the repository.
- MUST use a different project name (not "zelynic", and not a
  confusingly similar name — "Zelynic Pro", "Zelynic Plus",
  "ZelynicX" included).
- MUST use different branding (logo, color scheme, artwork).
- MUST preserve the GPL-3.0-only license and copyright notice.
- MUST clearly state that the fork is derived from zelynic but is
  NOT zelynic and is NOT endorsed by the owner.

A suggested attribution format:

```
This project is a fork of zelynic by rezky_nightky (oxyzenQ).
Original repository: https://github.com/oxyzenQ/zelynic
```

The owner reserves the right to decline non-contribution forks that
would compete with, dilute, or confuse the zelynic brand.

---

## 5. Enforcement Philosophy

The goal of this policy is to **prevent confusion**, not to restrict the open source community. The project creator reserves the right to:

- Request that a fork or derivative stop using the Zelynic Marks.
- Require a renamed fork to update its branding if it causes user confusion or misattribution.

Enforcement will always begin with a polite request before any formal action.

---

## 6. Contact

For trademark inquiries, permission requests, or clarifications, please open an issue on the [GitHub repository](https://github.com/oxyzenQ/zelynic) or contact the project creator at with dot rezky at gmail dot com.

---

*This policy may be updated at any time. The most current version is always available in the repository root.*
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
