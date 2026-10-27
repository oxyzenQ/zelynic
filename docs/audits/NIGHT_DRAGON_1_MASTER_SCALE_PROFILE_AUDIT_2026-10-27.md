<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-dragon-1 audit — where zelynic lives at ultra-massive scale

> Audit date: 2026-10-27 (night-dragon-1, the owner's master-depth
> question). Scope: the project's usage profile taken to the
> ultra-massive-scale limit — is zelynic best used on a SERVER, a
> DESKTOP, or a HYBRID estate — answered from the mechanisms on disk,
> the limits the project states about itself, and one live probe run
> during this audit. Every number below is documented in the repo or
> measured here; nothing is projected. Audited at b64629d.

## 1. What the tool is, in enforcement terms

zelynic limits **cgroups**, not processes or interfaces. Two eBPF
`cgroup_skb` programs attach at the cgroup-v2 root — one ingress, one
egress — and every packet crossing any cgroup boundary is classified
by its cgroup ID and checked against a rate policy in a BPF map. The
kernel IS the rate limiter: no proxy, no `tc`, no `LD_PRELOAD`, no
userspace hop, and — the property everything else follows from —
**no daemon**. The command writes rules into pinned BPF maps and
exits; enforcement lives in the kernel from that instant
(`fire-and-forget`, pinned under `/sys/fs/bpf/zelynic/`, surviving
process exit). That single design decision is the axis the whole
server/desktop/hybrid question turns on, because the "service" role
a fleet manager would normally provision is already played by the
kernel itself.

## 2. The scale ledger — what compounds at massive scale

Read the mechanism against four scale axes, honestly:

**Per-host packet path (the vertical axis).** Per packet, the data
path costs a map lookup keyed by cgroup ID plus the SMP-safe token
bucket's atomic operations (BPF_ATOMIC fetch-add/cmpxchg, compiled at
cpu v3 — kernel 5.12+ ISA on a 5.13 verified floor). The cost is
O(1) in the packet and **independent of how many apps, containers, or
processes the host runs** — adding the ten-thousandth workload costs
the same per-packet work as the first. No packet is ever copied to
userspace and back; there is no context switch in the enforcement
path at all. This is the same mechanical class datacenter eBPF
policers use, and it is the axis where zelynic does not degrade as
the estate grows. The hot loops ride the x86-64 v3/v4 vector paths
the release baselines are built around.

**Per-host population (the policy axis).** One policy row per cgroup
per direction; subtrees resolve under one budget (MMSPA) with the
kernel resolving the covering root **per packet** — descendants born
hours after the limit share it with zero control-plane work. The
fair-share lane (DRR with the learned-share draw) is measured, not
asserted: the position ratio lands 1.34 at 6 leaves and 1.18 at 24
under the battery's load shapes, inside the 1.75x + one-quantum
bound the rootless simulation battery pins. The honest ceiling is
printed in USAGE: below ~656 KB/s the fairness granularity coarsens
(the 64 KiB GSO admit law floors the quantum), a cgroup_skb hot path
cannot iterate leaves (bounded-share fair, never a formal round-
robin guarantee), and a hierarchy deeper than 32 levels resolves
unlimited — no real deployment reaches a third of that.

**Fleet scale (the horizontal axis).** There is deliberately no
controller, no central state, no cluster mode: zelynic is a
single-host control plane, N hosts means N independent binaries, and
the integration surface is the CLI, the documented JSON reference,
and the documented exit codes. Persistence is the same story —
limits do not survive reboot (bpffs wipes; cgroup IDs re-assign), the
`snapshot`/`restore` lane was retired on purpose (NIGHT-improve-55:
"a dump you must remember to run is a workflow your own script
already owns; a unit file calling the strict family IS the desired
state"), and re-apply after boot is explicitly the orchestrator's
decision. At massive scale this is not a gap; it is the composition
model — the tool provides per-host kernel enforcement and gets
composed by whatever the estate already runs for desired state.

**Operator scale (the human axis).** Discovery is `eagle-eyes` (live,
ranked, diff-rendered — one write syscall per frame, idle frames
cost zero I/O — with `--depth` one-shot inspection of who/what is
inside a cgroup); triage is `doctor` (kernel support answered with
the exact reason, plus the binary's own FULL-LIFE/HALF-LIFE build
identity); automation is the JSON reference and exit codes; limits
self-expire kernel-side (`--during 20d`) with no cron and no drift.

## 3. The live probe — the floor law answers for itself

Run on the audit host during this round: `zelynic doctor` on a
kernel 5.10.134 host without cgroup v2. The binary answers FULL-LIFE
(objects embedded, source-built, v80.0.0 — the build stamp names its
exact commit, the checkout state the flagship was built at), then
reports the kernel and the cgroup v2
verdict and honestly refuses the enforcement surfaces rather than
degrading silently — the exact behavior a fleet health-check wants
at 10,000 hosts: the floor (5.13, cgroup v2, root) is checked by the
tool, in one command, exit-coded. The probe doubles as the install
path's proof: the binary was built and landed on PATH by the 2f
round's `install-on-my-machine.sh` earlier in this same session.

## 4. The scoring — server, desktop, hybrid

| Dimension | Server | Desktop | Basis |
|-----------|--------|---------|-------|
| Enforcement model | **Ideal** | Works | kernel-resident, fire-and-forget, zero-daemon — the "service" already lives in the kernel; nothing to babysit on a headless host |
| Resource posture | **Ideal** | Ideal | static musl binary, no runtime deps (7 direct deps), nothing running in the background burning CPU/RAM/IO — measured by the proof harness, not asserted |
| Automation surface | **Ideal** | Unused | JSON reference, documented exit codes, `--during` self-expiry, `doctor` exit-coded — designed for scripts and orchestration |
| Interactivity | Sufficient | **Ideal** | eagle-eyes TUI, depth focus, rootless CLI parse — the discovery loop is a terminal experience |
| Privilege model | Normal | Friction | root (or CAP-class equivalent) for every enforcement command — normal on servers, a `sudo` tax on a laptop |
| State model | Composable | Friction | reboot-wipes-by-design + re-apply = orchestration's job on a fleet, a manual step on a desktop |
| Release payloads | **Ideal** | Fine | x86-64 v3/v4 static musl — servers and laptops both, no libc question exists |

The honest read of the table: **zelynic is a server-first, single-
host enforcement tool with full desktop capability, and the hybrid
question resolves into "one binary, two postures."** There is no
desktop edition or server edition — the same static artifact serves
both, and the mechanisms that make it excellent at fleet scale
(kernel-resident state, statelessness, automation surface) are
exactly the ones that make it unobtrusive on a workstation. It is
not a consumer desktop application (root-gated, terminal-only), and
it is not a cluster product (no controller, no state sync — by
documented design, not omission).

## 5. The verdicts

| Surface | Verdict | Basis |
|---------|---------|-------|
| Best use at ultra-massive scale | **SERVER** — per-host enforcement composed by external orchestration | O(1) per-packet kernel path independent of workload count; fire-and-forget control plane; JSON/exit-code automation; `--during` removes the cron class; doctor scales as fleet triage |
| Desktop role | **CAPABLE COCKPIT** — the operator's discovery station | eagle-eyes/depth are terminal-native; zero-daemon means zero battery drain; the friction is privilege and re-apply, both workflow-shaped |
| Hybrid estate | **ONE BINARY, TWO POSTURES** — not a product split | same static musl artifact, same kernel contract; no editions exist to reconcile |
| Fleet layer | **OUT OF SCOPE, DELIBERATELY** | no controller/state-sync shipped; composition via existing orchestration is the documented model (NIGHT-improve-55's unit-file verdict) |
| Where it breaks at scale | PRINTED, NOT HIDDEN | sub-656 KB/s fairness coarsening, bounded-share (not formal RR), 32-level depth bound, snapshot targets (new top-level apps need the re-sweep), reboot re-apply |

## 6. Deployment postures (the recipes the verdict implies)

- **Server fleet**: bake the static binary into the image, let the
  orchestrator own desired state (`systemd` unit or timer calling the
  strict family — the project's own named answer), let the kernel
  enforce between runs, triage with `doctor` and the JSON `status`.
- **Desktop workstation**: install once (user shape),
  `eagle-eyes` for discovery, `strict`/`unstrict` per session, accept
  the `sudo` tax as the price of kernel authority.
- **Container lane**: the container-shaped test lane exists
  (supermassive-container) and the micro-VM CI legs prove the kernel
  span 5.13 -> latest per push — but cgroup v2 delegation is the
  container's own prerequisite, and the 32-level/parent-cgroup rules
  apply unchanged.

## 7. Honest residuals

- Every fairness number above is the battery's measured shape
  (6/24-leaf positions, the 2:1 adversarial K=2 bound, the RTO
  backoff window) — behavior beyond those measured shapes is
  unmeasured, and this audit does not project it.
- Map capacity ceilings (max policy rows) are bounded by the BPF map
  definitions; this audit did not re-derive the per-map maximums and
  does not quote one — the source is the single authority.
- The audit host's live probe proves the floor law and the install
  path, not enforcement: this host is below the kernel floor, so the
  live-eBPF legs remain CI-owned (the standing boundary of the
  series, unchanged).
- "Ultra massive" is answered per-host and per-fleet-posture, not as
  a load-test campaign — the repo's own scale evidence is the
  supermassive matrix (dynamic low/best envelopes, the kernel-span
  micro-VMs); no number here comes from a projection.

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
