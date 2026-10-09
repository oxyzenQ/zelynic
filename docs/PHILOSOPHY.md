<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# zelynic Design Philosophy

> zelynic is "boring and silent but killer" — a per-app network rate
> limiter and traffic monitor that does its work in the kernel, prints
> only what it verified, and never makes a claim it cannot back. The
> terminal speaks once, the datapath never speaks at all.

This document consolidates the architectural philosophy governing
zelynic's design decisions. It is the canonical reference for why
certain designs were chosen, why entire classes of features are
rejected, and what a contributor should feel in their gut before
proposing a change to the core. Where a rule here overlaps a hard
enforcement gate, the gate wins; this file explains the reasoning that
produced the gate.

## 1. The Cgroup Is the Unit

zelynic never sees processes the way a userspace tool does — it sees
cgroups. Every byte counted, every rate enforced, every verdict printed
is keyed by cgroup id, captured in the kernel with
`bpf_skb_cgroup_id(skb)` — the id of the **socket owner**, not the
current task. This matters more than it looks: TCP packets are
processed in softirq context, far from the process that sent them, so
task-based attribution is structurally wrong for network accounting.
The cgroup lens is the only lens that is correct at line rate.

The consequence is a deliberate refusal: applications stay black
boxes. zelynic does not trace function calls, does not parse
application protocols, and does not care what language an app is
written in. A browser, a container, a build job, a VPN tunnel — each
is a cgroup with a rate and a verdict. Anything finer-grained belongs
to a profiler; anything that requires cooperation from the application
belongs to a different product category. This boundary is what keeps
the datapath small enough to audit line by line.

## 2. Pure eBPF, Pure Rust, One Binary

The entire kernel-side program is written in Rust against the aya
framework — no C, no libbpf bindings, no system LLVM dependency
(docs/PURE_RUST_EVALUATION.md records the full migration). The linked
objects are embedded into the single static-ish binary at build time,
so a release tarball is three files and an install is one copy. There
is no daemon waiting to be started, no unit file to misconfigure, and
no runtime object loading from disk paths that can drift.

The supply chain is treated as architecture, not paperwork: the three
distribution lanes — source builds, the crates.io registry lane
(`ebpf-prebuilt/`), and GitHub Release binaries — ship **identical
object bytes by construction**, and parity gates fail the build when
they diverge (docs/VERIFY_RELEASE.md). A user who verifies a checksum
is verifying the same bytes a from-source builder produced. Freshness
of the prebuilt lane is enforced at commit time, publish time, and
release time (NIGHT-dinner-1), because stale objects flowing through a
green pipeline is the quietest failure class this project can imagine.

## 3. Observation Before Enforcement

The monitor shipped before the limiter earned trust, and the ordering
is a principle, not history. `eagle-eyes` answers what a cgroup is
doing; the limiter answers what a cgroup may do — and the limiter's
verdicts are printed from probes of the real pinned state, never from
assumptions about it (the NIGHT-master-4 hardening retired the last
fabricated-clean verdict class). When nothing is pinned, status says
**unlimited**, plainly, because that is the truth of the machine.

The same discipline governs diagnostics: `zelynic doctor` probes
capabilities and names its own build flavor (full-life vs half-life)
rather than trusting that the binary in front of you is the binary you
think it is. A tool that sits on the enforcement path of real machines
does not get to guess.

## 4. The Frozen CLI Grammar

The v11 verb surface is frozen: verbs are named once and never renamed
(docs/RULES.md). Expansion arrives as planning, not as churn — a flag
that changes meaning is a silent breaking change wearing a familiar
name, which is worse than a new flag. Scripts written against a zelynic
release keep working across the line because the grammar holds still.
When the surface must grow, it grows the way `--depth` did: one verb,
one honest report, no aliases multiplying behind it.

## 5. Local-First, No Telemetry

Nothing leaves the host unless the operator pipes it there. There is
no analytics path, no beacon, and no phone-home — the only network
gesture zelynic makes on its own behalf is `--check-update`, which is
explicit, user-invoked, and refuses to run under root privileges
because a version check never needs the enforcement uid. Observation
data is answered from local BPF maps and printed to the local
terminal or JSON; what happens after that is the operator's business.

## 6. Boring Output, Capability-Aware

The brand prints in purple, at whatever depth the terminal actually
supports — and there is no `--no-color` escape hatch, because branding
is not a preference (docs/BRANDING.md, NIGHT-hunt-5 owner mandate).
Everything else about the output is aggressively boring: deterministic
layouts, terminal state restored through layered reset contracts with
an emergency five-layer `--reset-terminal` behind them, and no
animation on paths an operator might script. The live monitor holds
the same line from the other side (NIGHT-dinner-29, re-cut by
night-improve-58): it is no BLOAT TUI, because a bloat TUI is an
interactive application — menus, cursor navigation, screens inside
the screen — and zelynic refuses the genre; the monitor simply
shows the data, it is not a game the operator plays (the whole
interactive surface is six keys — `q`, `t`, and the four arrows
that scroll the focused section and switch it, the minimal TUI
focus monitoring earns; acting on what the frame shows is another
CLI verb, never an in-app gesture). Terminal corruption is the one bug class a
monitoring tool cannot apologize its way out of.

## 7. Gates Are the Culture

Every rule above that can be automated is automated:
scripts/gate-keepers.sh runs the wholesale battery on every push, the
pre-commit hook enforces prebuilt freshness before a commit lands, and
CI re-runs what the hook checked because `--no-verify` only postpones
the verdict. Docs carry disclaimers that say the source is truth;
claims map to verifying mechanisms in docs/CLAIMS_VERIFICATION.md; and
audits are dated, immutable records (docs/audits/). Philosophy that is
not enforced by a gate is a wish — zelynic keeps its wishes short and
its gates long.
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
