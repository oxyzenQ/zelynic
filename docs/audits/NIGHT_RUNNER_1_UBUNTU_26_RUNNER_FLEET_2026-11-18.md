<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-runner-1 record — the runner fleet meets Ubuntu 26.04

> Task date: 2026-11-18 (night-runner-1). Scope: the whole runner
> estate — every runs-on site in the 17-workflow CI fleet — against
> GitHub's ubuntu-latest → Ubuntu 26.04 migration (the changelog of
> 2026-09-17 and actions/runner-images#14748: rollout between
> 2026-10-19 and 2026-11-19, complete by November 19). Method: the
> announcement read first, then a full census of the fleet's runner
> labels from the YAML, then an exposure analysis of every
> runner-OS-sensitive surface (apt, toolchains, kernel fetches,
> python, docker, QEMU/KVM, the artifact libc shape), then the work
> split into the two halves the estate's own history prescribes.
> Honesty note: the phase-2 verdict cells in §6 stay "pending" until
> the cutover push's own check runs fill them — this record never
> speaks a green verdict before the evidence exists.

## 1. The census (from the YAML, not from memory)

- 17 workflows, 35 runs-on sites. Of the 35: 32 x64 label sites
  (30 plain `ubuntu-24.04` runs-on lines plus 2 matrix arrays —
  ci.yml's musl and ebpf-host legs) and 3 `ubuntu-24.04-arm` sites
  (the musl-arm64 twin and the two supermassive-e2e sites, one of
  them the arm64 ternary). The 2 `${{ matrix.os }}` references
  resolve into those arrays.
- Zero `ubuntu-latest`. The floating label never touches this fleet:
  NIGHT-hunt-26 (commit b90c895a) froze all runners on 24.04 in
  direct response to this same #14748 announcement, with a pin
  rationale on each workflow's first pinned job.

## 2. The failure mode the freeze leaves behind (why this task exists)

The freeze was the right call for the migration window, and the
window is closing (2026-11-19, tomorrow at this writing). But a
runner pin is not a terminal state — GitHub retires old images on a
documented cadence, and this estate has already lived one: the
ubuntu-22.04 image's retirement is what NIGHT-blade-3 answered by
retiring the old-OS matrix leg. When the 24.04 image retires, the
same shape repeats, bigger: all 35 sites fail at once — the push
lanes, the release lane, and the 7 scheduled lanes (miri, audit,
maintenance, codeql, fuzz, proofs-night, supermassive-verify) that
run even with no push. That is the definition of a calendar-triggered
surprise, and this task's directive is the opposite: zero-touch —
the estate stays green with nobody at the laptop.

hunt-26's own body names the escape: "a future Ubuntu 26 move is a
deliberate matrix-first upgrade, not a calendar-triggered surprise."

## 3. The exposure analysis (what a 24.04 → 26.04 move can touch here)

| Surface | Finding | Verdict |
|---|---|---|
| Shipped artifacts' libc | musl is the ONLY libc shape (night-dragon-maintenance-6, release.yml: the gnu pair retired, zero glibc/GLIBC packages ship); all packages are static musl (v3/v4 x86_64, arm64) | The build host's glibc cannot move the artifacts' floor — the classic runner-upgrade regression does not apply |
| eBPF toolchain | bpf-linker installs as the prebuilt static musl binary (one pin, the NIGHT-improve-11 lineage); rust toolchains come from rust-toolchain.toml pins | No runner clang/LLVM dependency; host kernel 7.0 vs 6.17 changes nothing for the compile |
| Runner apt surface | b3sum (with the `|| cargo install b3sum --locked` fallback), cpio, qemu-system-x86, kmod; python3-pip only inside containers | All four host names exist in 26.04's universe; the fallback guards the one name with package-drift history (crates-io.yml's comment documents that lesson) |
| Kernel deb fetches | jammy floor + latest-head fetched via dedicated `/etc/apt/sources.list.d/*.list` files with `Dir::Etc::sourcelist` overrides | Runner-OS-agnostic by construction — the sources are written explicitly, never inherited from the image |
| Lint toolchain | shellcheck 0.10.0 / shfmt / actionlint installed from pinned release binaries; yamllint==1.38.0 / codespell==2.4.3 / ruff==0.16.8 via `python3 -m pip install --user` | Static binaries are OS-agnostic; the pip shape already works on the 24.04 image and the exact pins hold on the newer python |
| Runner python | stdlib only on the host (tomllib is 3.11+, http.server, json); the aioquic installs happen inside containers | Version bump harmless |
| Docker | buildx is the same version on both images (the #14748 table); the container lanes stage the ubuntu containers they drive | Guest digests unchanged |
| KVM micro-VM pair | the x86 lanes boot under KVM (`/dev/kvm` asserted per run — "a GitHub runner guarantee", e2e:630; the arm fleet is host-native, no /dev/kvm, e2e:50); guests are the jammy floor, the 24.04 cloudimg, and the latest head, fetched per run | The HOST kernel moves 6.17 → 7.0 under unchanged guests — exactly what CI re-proves per push; the guest pins are untouched |
| Live BPF host | supermassive-verify loads the real objects on the runner itself (root-capable, cgroup v2 unified, /sys/fs/bpf mounted) | The ONE surface that changes meaningfully — and it changes in the estate's favor: the live runtime proof extends to the newest LTS kernel (7.0) on the nightly clock |
| ARM | ubuntu-26.04-arm is GA per #14747 | The 3 arm pins move with the fleet |
| Workflow lint | the pinned actionlint 1.7.7's embedded label DB predates 26.04's GA; the newest release (1.7.12, 2026-03-30) carries no 26.04 labels either — proved live in this seat with both binaries against the probe leg | Remedied in-tree: actionlint.yaml's self-hosted-runner allowlist (the tool's own documented shape) + the explicit `-config-file` at the single invocation site (gate-keepers.sh, shared by the local seat and CI); revisit on a future actionlint release |
| Path/OS conditionals | census: no RUNNER_OS branches, no hardcoded distro paths in the estate | Nothing to migrate |

## 4. The plan (the estate's own documented path, two halves)

- Phase 1 (this commit): ci.yml's two matrix jobs — the musl static
  twin and the eBPF host lane — run BOTH legs, `os: [ubuntu-24.04,
  ubuntu-26.04]`. The known-green floor stays; the probe proves the
  estate's two heaviest compile surfaces on kernel 7.0 / new glibc /
  new python while everything else is still frozen. This is
  hunt-26's "matrix-first" half, verbatim. The estate's own lint is
  part of the probe: the pinned actionlint (1.7.7, and even the
  newest 1.7.12) predates the 26.04 GA and would reject the real
  label, so actionlint.yaml carries the self-hosted-runner label
  allowlist and the wholesale gate passes the config explicitly at
  its one invocation site — the flag keeps the local seat and CI on
  the one contract.
- Phase 2 (the next commit): the cutover half — all 35 sites move to
  the 26.04 family (the 32 x64 sites, the 3 arm sites, the two
  matrix arrays retire the 24.04 leg per blade-3's latest-LTS-only
  rule), the pin rationales and every present-tense runner comment
  refreshed (the hunt-26 four-line blocks in release/maintenance/
  audit/codeql, supermassive.yml's LTS note and its b3sum apt note,
  supermassive-verify.yml's runner description, the arm64 comments
  in ci.yml and supermassive-e2e.yml), the docs rows updated
  (KERNEL_COMPATIBILITY's distro table, README's CI-leg sentence),
  and the CHANGELOG carries the cutover. The words-behind-the-tree
  hygiene law applies to the pin comments the same way zen-lts-2
  applied it to stale references.

## 5. Peak-skips and rejections, with reasons

- NOT adopting `ubuntu-latest` anywhere: the floating label is the
  estate's anti-lottery contract (hunt-26) — determinism beats
  convenience, and the LTS move is made deliberately once per LTS,
  not continuously per rollout.
- NOT keeping a permanent 24.04 matrix leg after the cutover:
  blade-3's rule (latest LTS only) stands; the kernel span is the
  supermassive VM pair's contract, and a duplicate hosted leg buys
  runner-minutes, not coverage.
- NOT changing timeouts/caps/concurrency: the job shapes are
  unchanged; the probe legs inherit their jobs' existing caps (the
  40-minute musl twin and 30-minute eBPF host caps already hold the
  heaviest shapes).
- NOT touching `supermassive-server.yml`'s
  `ubuntu-24.04-server-cloudimg-amd64.img`: that is a QEMU GUEST
  image (a deliberate pinned guest), not a runner label — the same
  class as the jammy floor kernel, and it stays.
- NOT refreshing the dated records (CROSS_DISTRO_RESULTS's addenda,
  the "compiled on Ubuntu 24.04" evidence lines): they are frozen
  historical records and keep the language of their time (the
  docs/README.md rule); only present-tense claims follow the fleet.

## 6. The evidence ledger (filled as the phases land)

| Phase | Claim | Evidence | Verdict |
|---|---|---|---|
| 1 | ci.yml carries both legs | `os: [ubuntu-24.04, ubuntu-26.04]` ×2 (musl:248, ebpf-host:510 at this writing) | in tree |
| 1 | actionlint accepts the 26.04 labels | the config schema proved with `-config-file` on the CI-pinned 1.7.7 (exit 0, no findings); both 1.7.7 and 1.7.12 without the config reject the label — the find is real, not cosmetic | this seat |
| 1 | Local gates on the changed workflow | yamllint + actionlint (+ the wholesale battery) | PASS — the wholesale battery 27/27, re-run live in the runner-2 seat (2026-11-18) before the cutover |
| 1 | The 26.04 probe legs green on CI | this push's check runs (Musl Static Twin (ubuntu-26.04), eBPF Host (ubuntu-26.04)) | GREEN — both legs success on the runner-1 push's 42-check-run ledger (7bc37653), read from the API in the runner-2 seat |
| 2 | All 35 sites on the 26.04 family | the phase-2 census | DONE — night-runner-2's census: 30 plain pins + 2 arm pins + the ternary + 2 arrays on the 26.04 family, zero non-26.04 hosted labels, zero `ubuntu-latest` (see NIGHT_RUNNER_2_UBUNTU_26_CUTOVER_2026-11-18.md §1) |
| 2 | Fleet green on 26.04 end to end | the cutover push's check runs | GREEN — 40/40 check runs success on the cutover push (0c234712), both 26.04 legs success, read from the API in the runner-3 seat (2026-11-18) |

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
