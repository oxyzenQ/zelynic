<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# night-dragon-maintenance-X1 — end-to-end maintenance audit (2026-11-02)

The owner mandate: a maintenance pass (night-dragon-maintenance-X1)
that lands the project on LTS production with proof — total-ban the
serde/json dependency family, audit the repo end to end at real usage
(every CLI surface, the JSON lane, the update check, the panic
surface, the test suite), sign the asset images against fakes, and
close the rate-limit failure class the shfmt-resolve incident named.
This document is the audit's standing record: what was run, what it
answered, what was found, what was fixed in the same session, and
what stays open on purpose.

Method note, stated honestly: the audit host is a rootless sandbox
(kernel 5.10, no cgroup v2, no BPF fs) running the dormant build lane
(`--no-default-features`, stable 1.98.1, cargo-deny 0.20.2 = the CI
pin). Every eBPF enforcement surface answers its honest refusal here
by design; the full-life lane stays CI-owned. Real usage therefore
exercises the complete dormant contract — the refusals, the JSON
report lane, the update check, the error paths — not the kernel
enforcement path, whose evidence rides the test suite and CI instead.

## Lane 1: the serde/json ban (root graph verified clean, widened, live-fire proven)

The S1 removal (night-dragon-maintenance-T1) already left the root
graph serde-free; this pass re-verified the fact live and closed the
one loophole the original ban list left open.

- The committed root `Cargo.lock` carries zero serde-family entries
  (grep over the lockfile: no serde, serde_json, serde_core,
  serde_derive).
- The deny.toml ban list widened from the two facade names to the
  full derive stack — `serde`, `serde_json`, `serde_core`,
  `serde_derive` — because a future dependency could legally depend
  on the derive crates directly and the facade-only ban would stay
  silent. Both extra names ship only inside the serde monorepo, so
  the widened ban cannot collide with a legitimate third-party use.
  itoa/ryu/memchr stay unbanned on purpose (generic crates with
  non-serde consumers elsewhere in the graph; memchr rides the
  committed lockfile through such a consumer).
- Live-fire proof (cargo-deny 0.20.2): the widened list passes
  `cargo deny check bans` clean; injecting `cargo add --dev serde`
  resolves serde 1.0.229 plus its serde_core companion and the check
  fails with `error[banned]: crate 'serde = 1.0.229' is explicitly
  banned` and the serde_core twin; reverting the tree restores
  `bans ok`. The B2 live-fire contract re-proven for the widened
  surface.
- Scope boundary, stated: the ebpf/ nested crate's build-time
  aya-build chain (the one documented serde consumer,
  docs/DEPENDENCY_AUDIT.md) is upstream framework design, build-time
  only, lockfile-committed, and outside the root `cargo deny check
  all` scan. Removing it means leaving aya; accepted risk, unchanged.

## Lane 2: the actions API reads pinned to the dated version header

The two scripts that read api.github.com (the actions version sweep,
the commit-time pin health check) already resolved their credential
from the machine's own sources and lifted the anonymous 60 req/h
per-IP pool to the authenticated 1,000 req/h, but neither pinned the
REST contract. Both api surfaces now send
`X-GitHub-Api-Version: 2022-11-28` on every read, both tiers. The
failure class closed is the shfmt-resolve incident's: an
unauthenticated resolve shares the 60 req/h pool, a busy pool
outlives any 300 s retry window, and the retry contract alone cannot
clear the failure. Verified live: the exact request shape (rate_limit
read, version header only, no token) answers HTTP 200 from this
host, and both scripts pass `bash -n`. Release-asset downloads stay
bare on purpose (CDN redirect; a forwarded Authorization header can
taint the signed asset URL). The repo-side sweep of the same class
found no other surface: gate-keepers.yml's tool installs are
hard-pinned release URLs (no API resolve at all), the release lane
reads via `gh` with the run's ephemeral token, and the crates.io
publish probe targets crates.io with its required User-Agent.

## Lane 3: the asset images signed (BLAKE3)

Every image under `assets/` — seven pngs: the two eagle-eyes
captures, the three qr codes, the two original-logo files — now
carries its b3sum digest in assets/signature-assets.md with the
machine-readable sidecar assets/signature-assets.b3sum in `b3sum -c`
format. Verified before landing: `b3sum -c` prints OK for all seven
and exits zero; the tamper contract was exercised live (one appended
byte to a signed image names the file FAILED; the restored tree
verifies clean). README's forking policy now points at the record,
turning "keep the branding unchanged" into a one-command check.
assets/tools.md stays outside the signed set (a doc, not an image).

## Lane 4: the end-to-end real-usage matrix (dormant lane)

Every public surface invoked for real on this host, exit codes
captured without pipe masking:

| Surface | Verdict |
|---------|---------|
| `--version` / `-V` | exit 0; full build facts; honest `eBPF dormant` signature on a local dormant build |
| bare invocation | exit 0; brand help |
| `--help`, `help strict` shape | top-level help exit 0; no `help` subcommand answers exit 2 with the pointer tip (contract) |
| `doctor` | exit 0; HALF-LIFE verdict + host facts (5.10 kernel, no cgroup v2, no bpf fs, no root) + four actionable warnings |
| `doctor --print-json` (both flag orders) | exit 0; one compact document, `jq -e .` valid |
| `status`, `list-apps`, `list-apps --print-json`, `strict`, `block --all`, `unstrict --all`, `recover`, `ee`, `ee cg:1 --depth`, `__probe-server` | exit 1 with the identical honest dormant refusal + the install tip — the whole enforcement family answers the same gate |
| `--print-json` on a text surface (`-V`, `status`) | stdout/exit untouched; one stderr note names the honoring surface (`doctor`) — the scripting contract holds |
| `--color-mode 0` / `--color-mode bogus` | mono renders exit 0; invalid value exit 2 naming the allowed set |
| `bogus`, `eagle-eye brave` | exit 2; did-you-mean tips (the removed singular alias redirects to `eagle-eyes`) |
| `strict` (missing target) | exit 2; clap usage |
| `--badflag` | exit 2; unexpected-argument error |
| `doctor --print-json` piped into `head -c 20` | no panic; broken pipe discarded; binary exit 0 (the `broken_pipe_errors_are_discarded` contract, live) |
| `--check-update` | exit 1, `error: GitHub API request was rate-limited or forbidden` — see the finding below; no crash, no hang, cooldown self-throttle armed |

## Findings

1. **The rate-limit failure class, observed live at runtime** — the
   `--check-update` probe answered HTTP 403 on this host's shared
   egress (the anonymous pool). The code handled it the way the
   contract says: curl bounded at 15 s, named error, exit 1, the
   1-hour cooldown stamp written only on a completed exchange so the
   storm throttles itself after one round trip, the tag sanitized
   against terminal injection, root refused outright. This is the
   runtime twin of the lane-2 CI class and it is handled; no fix
   needed, recorded as evidence.
2. **The dormant gate precedes input validation** —
   `strict brave nota-rate`, `strict brave 0kb`, `strict root 100kb`
   and `--during 99y` all answer the dormant refusal (exit 1) rather
   than a per-input error, because the whole verb is unavailable.
   Consistent by design; full-life builds validate the same inputs
   behind the gate and the test tree pins the wording. No action.
3. **Runtime panic surface: one site, provably safe** — 30 raw
   unwrap/expect/panic hits across src/, 29 inside `#[cfg(test)]`
   modules. The single runtime site (probe_role.rs, the probe
   client's `stream.expect("connect loop invariant")`) exits its
   loop only via `Some` or `bail!`, so the invariant holds by
   construction; the expect carries its own contract comment.
4. **The JSON escape law is correct per spec** —
   src/json/write.rs's single writer: quote/backslash two-char forms,
   the five named control bytes, other control bytes `\u00xx`, all
   UTF-8 passthrough (em-dash labels survive verbatim). This is the
   serde_json-equivalent table the S1 hand-write promised; the parse
   sibling's 128-frame depth cap and offset-naming errors ride the
   same test net.
5. **The suite is green on the audited bytes** — `cargo test
   --locked --no-default-features`: 161 unit + 65 integration, 226
   passed, 0 failed, 3 ignored (the root/eBPF-gated lanes). The
   json parse/print, output (broken pipe), cli ux (usage, footer)
   and help/surface pin suites all carried.

## What this audit did not run, on purpose

- The full-life enforcement path (root, cgroup v2, BPF fs): absent
  on this host by construction; CI's ebpf lanes own it, and the
  ebpf/ tree was untouched by every lane of this session (the
  prebuilt pin did not move).
- The frame A/B benchmark (scripts/bench/frame-bench.py): every
  X1 lane is policy, scripts, docs, or workflow-adjacent — no byte
  of the binary's render or engine path changed, so the benchmark
  is not applicable (the docs-only rule and its code twin).
- A full `check-all -q` and the wholesale gate-keepers battery ran
  after this document landed — their verdicts are the session's
  closing record, not part of this file.

## Verdict

The repo answers its maintenance mandate: the root dependency graph
is serde-family-free with the ban widened and live-fire proven, the
actions API reads are contract-pinned, the asset set is
signature-verifiable, the dormant CLI contract behaves exactly as
documented on every tested surface (honest refusals, correct exit
codes, valid JSON, working rescue tips), the update check survives a
hostile rate-limited egress gracefully, and the runtime panic
surface is one documented, provably-safe site. No bug or leak was
found that requires a code fix in this lane; the two hardening
fixes the audit did find landed in the same session (commits with
the lane-1 and lane-2 subjects). LTS-ready from this seat, with the
full-life lane CI-owned as always.

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
