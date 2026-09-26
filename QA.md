<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# zelynic Q&A Record

Ask-mode sessions (the NIGHT-ask series): the owner asks, the answer
is researched against the source tree before it is written. Every
claim below was verified against the code at the time of writing, and
each answer names the file it came from — this record is evidence,
not opinion. Questions arrive in the owner's own words (translated;
the repo is English-only) and are kept focused: one question, one
honest answer, no padding.

---

## Q1 — What does "2.5K packets + 16 cgroups" in the eagle eyes footer mean?

It is the **session census line** — the footer's own scale note, not
a rate and not a per-second figure
(`src/ebpf/render/footer.rs`, `FooterCensus::gather` + the census
render):

- **`2.5K packets`** — packets accumulated **since the session
  started** (monitor launch), summed across every cgroup on the
  current board, with saturating adds. The horizon deliberately
  matches the footer's grand-total bytes row: the two figures can
  never disagree about when counting began (NIGHT-engrave-4). The
  number is humanized by `format_count`
  (`src/ebpf/limiter/format.rs`): 24 packets stays `24`, 2,500-ish
  reads `2.5K`, an eight-hour 2,244,843 reads `2.2M` — no raw u64 is
  allowed to explode the line (NIGHT-boost-16 counter hardening).
- **`16 cgroups`** — how many cgroups the frame's **board** carries,
  i.e. `board.len()`. In eagle eyes mode the board is the watched set:
  the 16 cgroups your filter matched. The doc contract is explicit —
  "filtered frames count their filtered board" — and the census counts
  every candidate on the board, not just the rows the window budget
  happened to show (NIGHT-hunt-15 footer honesty: a 16-cgroup board in
  a 10-row window still says 16).

So the line reads as: *since this session started, the 16 cgroups on
the watched board have moved about 2,500 packets between them.* If
that number looks small, that is the honest answer — the board is
scoped to what you asked eagle eyes to watch, not the whole machine.

---

## Q2 — Is zelynic suitable for a crates.io release?

**Yes — publishable today, and the release support landed with this
task.** The name was unregistered (registry API answered 404 for
`zelynic` at 2026-09-27), the manifest metadata is complete
(description, license, repository, keywords, categories, MSRV), and
`11.0.0-beta.2` is a valid registry pre-release. What this task added:
the curated `include` ship set in `Cargo.toml`, the tag-triggered
`.github/workflows/crates-io.yml` (CI-gated, idempotent, `--locked`),
the commit-sha chain in `build.rs` so a registry build's `-V` reports
the real source revision via `.cargo_vcs_info.json`, the registry
preflight below, and the full owner manual in
[docs/VERIFY_RELEASE.md](docs/VERIFY_RELEASE.md) section 4.

**One structural fact shapes the channel**: cargo's package walk
auto-excludes nested packages — any directory with its own
`Cargo.toml` — so the detached `ebpf/` workspace cannot ride a
registry tarball. This was verified live twice on this manifest,
including with `ebpf/*` entries in `include` (they are silently
dropped; `include` does not override the rule). The published crate
is therefore the **dormant lane**: `cargo install zelynic` builds the
stable-toolchain binary with eBPF surfaces disabled, and
`--features ebpf` from a registry source fails fast in `build.rs`
with the two real remedies (git checkout, or the GitHub Release
binary) instead of a cryptic nested-build error. The flagship
monitor/limiter binary stays the release tarball or a source build.

**The owner's first publish, in short** (full detail in
[docs/VERIFY_RELEASE.md](docs/VERIFY_RELEASE.md)): create the
crates.io account (GitHub sign-in, email confirmed, 2FA on) →
generate a `publish-new` API token → then either add it as the
`CRATES_IO_TOKEN` repo secret and push the `v*` tag (the workflow
publishes, gated on branch CI), or do the manual first publish from
the tagged commit: `cargo login` → `cargo publish --locked --dry-run`
→ `cargo publish --locked`. Verify with the registry API answering
200 and a clean-environment `cargo install zelynic --locked`. A bad
version is `cargo yank` — the registry never deletes, so the
tag/version check and the CI gate run before every upload.

*Parked, not hidden*: shipping prebuilt BPF objects inside the crate
would flip `cargo install zelynic` to the full-featured binary with
no nightly toolchain on the user side — but it changes the build
architecture (objects are built fresh and validated by contract, and
the tree bans tracked `*.o` artifacts). That is an owner decision for
another day, recorded here so it is not silently lost.

---

## Q3 — Why is zelynic so sharp for monitoring and limiting?

Because every number is **the kernel's own accounting, taken at the
exact point of truth** — not a userspace reconstruction of it:

- **Counting**: the eBPF observer hooks the cgroup v2 datapath
  itself. Every packet is counted by the kernel as it moves; there is
  no interface polling, no pcap parsing, no sampling window where
  traffic can hide. What the footer reports is what the kernel
  charged, byte for byte and packet for packet.
- **Enforcement**: the limiter is the datapath too — rate math in
  exact u128 arithmetic, drops enforced by the kernel at the asked
  rate. It is not userspace throttling after traffic already landed;
  the ceiling holds while the process is idle and the numbers stay
  consistent between what the BPF side charged and what the client
  measured (the depth batteries pin that agreement).
- **Attribution**: per-cgroup identity with per-socket resolution —
  the footer's "top consumer is curl" is the busiest process inside
  the champion cgroup, not a guess from a process list.
- **No observer tax**: the render loop is zero-alloc (reused buffers
  through the diff engine), so watching stays cheap under load — the
  measurement does not distort the thing measured.

The honest ceiling: this sharpness is bought with constraints —
Linux-only, a modern kernel, and root/capabilities to program the
datapath (see [docs/KERNEL_COMPATIBILITY.md](docs/KERNEL_COMPATIBILITY.md)).
A cross-platform tool cannot have this exactness; zelynic chose
exactness.

---

## Q4 — Why does zelynic exist?

Frustration with complicated tools — the owner's own words — and the
discipline that followed from it. The existing landscape asked for
daemons, config files, service managers, and dependency stacks to
answer one question: *what is this app doing with my network, and how
do I cap it?* zelynic is the answer built the other way around:
**simple masterclass, silent but killer.**

The shape that philosophy produced, concretely:

- **One static binary.** The release payload is one file — the eBPF
  objects are embedded in it. No clang, no cargo, no installer on the
  target machine; uninstall is `rm`.
- **No config file, no daemon, no service.** Every setting is a
  command-line flag, every command is immediate, nothing resident
  survives the process.
- **Silent by default.** Enforcement does its job without noise; the
  monitor is the one interactive surface, and it is designed to be
  read at a glance.
- **Boring where it counts.** The Cargo description says it outright —
  "Boring and silent but killer" — boring in the operational sense:
  predictable, stable, nothing to babysit.

The rule the frustration left behind: every piece of friction that
survives in the tool has to justify its existence, or it gets hunted
out. That rule is why the tool feels different from the tools that
caused the frustration.

---

## Q5 — Why are the quality standards different from other projects?

Because the goal was never "a project like the others" — it was
**zero to hero for the owner's own daily machine and servers**, built
as pure internal research from the owner's own head, not from
surveying how other projects do it. Three consequences, stated
honestly:

- **Stricter where it hurts the owner, narrower where it doesn't.**
  The standard that matters is "never breaks on me, at 3 a.m., on a
  server" — so stability, crash discipline, and leak hygiene are held
  to a critical-infrastructure bar (the NIGHT audit trail in
  [docs/STABILITY.md](docs/STABILITY.md) is the evidence). Surface
  breadth, plugin ecosystems, and cross-platform reach are
  deliberately not goals.
- **The repo is the research record.** With no external template to
  copy, every decision had to be derived and then written down — the
  comment headers, the hunt narratives, and this Q&A record are the
  methodology. The upside is traceability: nothing in the tree is
  unexplained. The trade is real: no external contributor base yet
  means no diversity of environments — the 6-distro validation
  matrix ([docs/CROSS_DISTRO_RESULTS.md](docs/CROSS_DISTRO_RESULTS.md))
  compensates deliberately, and imperfectly.
- **Honesty is the non-negotiable.** A one-person standard can drift
  into self-congratulation; the countermeasure is the standing rule
  that limitations get documented, claims get verified, and verdicts
  refuse to inflate (see the "honest" sections across the docs and
  the peak-skip verdicts in the audit record). Different standards,
  yes — never lower ones where truth is involved.
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
