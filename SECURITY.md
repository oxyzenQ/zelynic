<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Security Policy

zelynic runs as root and programs the kernel's datapath — security is
part of the product, not an afterthought. This file is the security
foundation: how to report, what we support, what counts as a
vulnerability, and where the audit trail lives.

## Supported versions

| Version | Branch | Status |
|---------|--------|--------|
| 11.x (main) | `main` | **supported** — active maintenance (bug fixes, kernel compatibility, hardening) |

Pre-release channels (`dev`, `nightly`, `alpha`, `beta`) are
development artifacts: reports against them are welcome and triaged,
but fixes land on `main` first.

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.**

Use GitHub's **private vulnerability reporting** on this repository:
*Security tab → "Report a vulnerability"*. If that button is disabled
on your view, open a **draft security advisory** instead
(*Security → Advisories → New draft security advisory*) — both routes
reach the maintainer privately.

Please include:

- the affected command/flag or code path (`zelynic -V` output helps),
- a minimal reproduction (commands, expected vs. observed),
- impact assessment — who can trigger it and what it costs.

You will get an acknowledgment within a reasonable window; fixes ship
as patch releases on `main` with credit in the changelog unless you
prefer to stay anonymous. Coordinated disclosure: we ask for up to
90 days before public disclosure, and we will not pursue anyone who
acts in good faith.

## Scope

In scope:

- The Rust CLI and everything it executes (`src/`), including the
  curl-backed `--check-update` surface.
- The eBPF loader and datapath (`src/ebpf/` userspace + the `ebpf/`
  pure-Rust BPF source) — privilege handling, map writes, pin
  lifecycle, raw-syscall wrappers.
- The release pipeline and artifacts: workflows (`.github/workflows/`),
  tarballs, checksums, install scripts.
- The security-relevant UX contract: privilege guards, error surfaces,
  the operation lock.

Out of scope (by design, not neglect):

- **Anything requiring the attacker to already be root.** The operator
  running zelynic owns the machine; the dangerous-target blocklist is a
  UX guard against foot-guns, not a containment boundary (renaming a
  binary to dodge it is not a vulnerability).
- **Rate-limit circumvention by design.** zelynic enforces at cgroup
  boundaries as documented (see the honest-limitations section of
  [docs/USAGE.md](docs/USAGE.md)); traffic that never crosses a
  limited cgroup is out of the enforcement model.
- **Denial of service by a user who can already run processes on the
  machine against their own session**, unless it degrades other users
  or the host (e.g., the pre-2026-09 lock-squatting class WAS in scope
  and is fixed).
- Unmaintained versions, and social-engineering/phishing.

## What we treat as a vulnerability

Concrete classes we care about, with the current posture of each:

| Class | Posture |
|-------|---------|
| Privilege confusion (root used where it is not needed, or the inverse) | Guarded — `--check-update` refuses root; eBPF surfaces require root and fail fast |
| Local DoS by an unprivileged user against the root tool or other users | In scope — the `/tmp` lock-squatting/symlink class was found and fixed (2026-09 audit) |
| Injection (command, path, format-string, CI script) | Audited — argv-array curl, kernel-generated paths only, env-isolated CI scripts |
| Memory safety in the kernel datapath | BPF verifier bounds-checks; C side reviewed per release |
| Panic surfaces reachable from user input | Pinned by the non-root depth suite (exit 101 asserted absent) |
| Supply chain (dependency compromise) | 7 direct deps, `cargo audit` + `cargo deny` in CI, chrono banned, every dep justified in [docs/DEPENDENCY_AUDIT.md](docs/DEPENDENCY_AUDIT.md) |
| Release artifact tampering | SHA-512 + BLAKE2b-512 + SHAKE256 checksums; verify per [docs/VERIFY_RELEASE.md](docs/VERIFY_RELEASE.md) |

The full audit trail — findings, verdicts, and accepted risks — lives
in [docs/SAFETY_ANALYSIS.md](docs/SAFETY_ANALYSIS.md) and is updated
with every security pass.

## Hardening posture (already shipped)

- Root is required only where the kernel demands it, refused where it
  is a hazard (privilege matrix in SAFETY_ANALYSIS.md).
- The operation lock lives in a root-only `/run/zelynic/` (0700) —
  never in world-writable directories.
- Fail-safe datapath: on any internal error the BPF programs allow the
  packet; enforcement never silently hard-blocks.
- CodeQL + dependency audit + policy gates run in CI on every change.
- No config files, no daemons, no background network surface: the
  binary makes exactly one outbound connection, in `--check-update`,
  time-boxed and root-refused. That one response is untrusted input
  too: the release tag it prints passes the same control-character
  sanitizer as `/proc` comm labels (NIGHT-cybersecurity-2) — a MITM'd
  or compromised proxy response cannot reach the admin's terminal as
  escape sequences (OSC 52 clipboard rewrites, output forging).
- Every string that crosses a trust boundary into the terminal is
  sanitized at the boundary: process names (the `pid_comm` boundary,
  NIGHT-cybersecurity-1), the update-check release tag
  (NIGHT-cybersecurity-2). Cgroup paths are resolved by inode and
  never rendered. The eBPF map values are treated as untrusted input
  on the kernel side (the burst/tokens/frac clamp triple, schema v6
  — see SAFETY_ANALYSIS.md's overflow audit).

## Easy to use, by construction

Security that costs usability gets switched off by users. zelynic keeps
the two aligned: no keys, no config, no new workflow steps — the
hardening is invisible (lock relocation, CI isolation, guards) and the
one behavioral rule that matters is a clear error message, not a
foot-gun (`--check-update` tells you to drop sudo instead of failing
cryptically).
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
