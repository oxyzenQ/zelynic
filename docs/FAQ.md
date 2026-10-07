<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# zelynic FAQ — Q/A

Answers to recurring setup and behavior questions, written once so the
answer never drifts. Each entry names the doc or source file that
implements it — source code is the single source of truth; if a doc and
the code disagree, the doc is wrong.

Index:

- [Root & privileges](#root--privileges)
- [Kernel & distro support](#kernel--distro-support)
- [Limits & the "unlimited" verdict](#limits--the-unlimited-verdict)
- [Where the eBPF objects come from](#where-the-ebpf-objects-come-from)
- [full-life vs half-life](#full-life-vs-half-life)
- [Privacy & telemetry](#privacy--telemetry)
- [Colors](#colors)
- [Verifying a release](#verifying-a-release)

## Root & privileges

### Q: Why does zelynic need root?

A: Loading and attaching BPF programs requires `CAP_BPF` or root —
that is the kernel's requirement, not zelynic's choice
(docs/KERNEL_COMPATIBILITY.md; the loader lives in `src/ebpf/`).
zelynic does not ask for any privilege beyond that: no setuid install,
no daemon holding root between invocations, and `--check-update`
refuses to run under root at all (`src/cli/mod.rs`). To experiment
without touching a real host, use the sandbox
(docs/SANDBOX.md).

## Kernel & distro support

### Q: Which kernels and distros work?

A: Kernel 5.13+ is the floor of the verified matrix, 6.6 LTS+ is
recommended; cgroup v2 is required (the hooks are `cgroup_skb/egress`

- `ingress`) and BPF fs must be mounted at `/sys/fs/bpf` for pinning
(docs/KERNEL_COMPATIBILITY.md). The tested distro/kernel matrix lives
in docs/CROSS_DISTRO_RESULTS.md, and `zelynic doctor` probes the
running kernel and reports what it actually found rather than assuming
support.

## Limits & the "unlimited" verdict

### Q: My app shows "unlimited" — is the limit broken?

A: No: **unlimited is the honest verdict when nothing is pinned**.
`strict <app> <rate>` pins the enforcement (download AND
upload), `unstrict` removes it, and `block` cuts access entirely
(docs/USAGE.md). Status output is printed from probes of the real
pinned state, never from assumptions (NIGHT-master-4) — so "unlimited"
means the machine currently has no limit for that target, which is
exactly what you want to be told.

## Where the eBPF objects come from

### Q: Does zelynic compile eBPF at install time? Do I need nightly?

A: It depends on the lane, and the binary tells you which one you got:
a source build compiles the objects with the dated nightly pin;
`cargo install zelynic` ships the maintainer-built objects from
`ebpf-prebuilt/` and compiles only the userspace on stable
(NIGHT-ask-2); GitHub Release binaries embed the same bytes. All three
lanes carry **identical object bytes by construction**, enforced by
parity gates (docs/VERIFY_RELEASE.md). `zelynic doctor` names the lane
and the build flavor — no guessing from release notes.

## full-life vs half-life

### Q: What do "full-life" and "half-life" mean in doctor output?

A: It is the build flavor: a **full-life** binary compiled with the
`ebpf` feature and can load and pin programs; a **half-life** binary
was built without it (the explicit `--no-default-features` opt-out)
and cannot enforce anything — doctor says so, carries the reinstall
warning, and gates the "Ready" hint on the full-life verdict
(NIGHT-dinner-3). If you are looking at a half-life binary on a
machine that should enforce, reinstall from the default lane.

## Privacy & telemetry

### Q: Does zelynic phone home or send my traffic data anywhere?

A: No. Observation is local-first: rates are answered from local BPF
maps and printed to your terminal or JSON; there is no analytics path
and no beacon. The only network gesture zelynic makes on its own
behalf is `--check-update`, which is explicit, user-invoked, and
refuses to run under root. Anything beyond that is you piping output
somewhere — your business, not the tool's.

## Colors

### Q: Can I turn the purple off?

A: No, and that is deliberate: branding has no opt-out
(docs/BRANDING.md, NIGHT-hunt-5 owner mandate). What IS capability-
aware is the depth: TrueColor, 256-color, 16-color, and mono each get
the correct encoding for the terminal actually present, and the
standard environment variables (`NO_COLOR`, `CLICOLOR`) remain the
only control surface — exactly the cosmostrix output contract.

## Verifying a release

### Q: How do I verify a downloaded binary?

A: Every release ships SHA-512, BLAKE2b-512, and SHAKE256 checksum
siblings for each tarball, plus GPG signatures: download the checksum
next to the tarball, run `sha512sum -c`, and check the signature
against the fingerprint recorded in docs/VERIFY_RELEASE.md. The
registry lane (crates.io) and the release binaries carry the same
embedded object bytes, so verifying one lane verifies the objects.
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
