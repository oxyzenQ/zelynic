<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-dragon-lts-2f audit — the missing install tool restored

> Audit date: 2026-10-27 (night-dragon-lts-2f, the owner's find).
> Scope: `scripts/package/` carried `uninstall.sh` and nothing else —
> the install side of the pair existed only as a manual `cp` the
> README and the setup.sh menu prescribed. The sibling zejtron ships
> the packaged install tool; the shape is now ported as
> `scripts/package/install-on-my-machine.sh`. Audited and executed at
> 571f06d. The sibling reference stays zejtron.

## 1. The mandate

The owner found the gap: the package directory holds a teardown tool
with no install twin. The repo's own words proved the hole — build.sh
("land it on PATH yourself (cp ... — the release payload is that one
file; the uninstall tool stays: ./scripts/package/uninstall.sh)"),
setup.sh's menu (a literal `cp ... ~/.local/bin/ (or /usr/local/bin)`
line), and README's install-from-source paragraph (a plain `cp`
sentence). The mandate is the port and nothing more: one script, the
two prescribing spots re-pointed at it, no build or packaging
behavior changed.

## 2. The contract — uninstall.sh's law, install side

The script mirrors its twin line for line where the laws transfer:

- **One file, no payload drift**: the phase-3 flagship
  (`target/x86_64-unknown-linux-musl/pro-native-musl/zelynic`, eBPF
  objects embedded) is the whole install — no `/usr/lib` lane, no
  service, no man page; the legacy loose-objects dirs stay
  uninstall-only.
- **Run WITHOUT sudo, escalate internally**: root shell already holds
  the privilege (the NIGHT-blade-8 law); non-root gets the sudo
  prefix on `/usr/bin` paths only.
- **Modes mirror the twin**: `--system` (/usr/bin, sudo-sanctioned),
  `--user` (~/.local/bin, rootless), and the default is the twin's
  scan reversed — where an older zelynic lives is where the upgrade
  lands, both found means both refreshed (an upgrade never leaves a
  stale copy), nothing found means the rootless user shape setup.sh
  suggests first.
- **Never silent, honest postconditions** (the NIGHT-improve-15 law,
  install side): every destination must exist, be executable, and
  answer `-V` with `zelynic: v*` — the exact verdict contract
  uninstall.sh demands before it uses a binary — before the script
  claims success; failures count into the exit status.
- **Kernel state is never touched**: pins under
  `/sys/fs/bpf/zelynic` are reported (unreadable leans present, the
  NIGHT-hunt-32 posture) with the upgrade-safety note — enforcement
  continues from the pinned maps and the new binary manages them;
  the removal-under-live-pins trap stays uninstall.sh's guard.
- **The debian13 lesson respected** (NIGHT-improve-16): a user
  install only lands "on PATH" if `~/.local/bin` is on PATH — the
  exact export line prints, plus the one command that persists it.

Two install-side additions complete the shape: a missing flagship
runs `scripts/dev/bootstrap-ebpf.sh` first (the canonical builder,
idempotent — "install on my machine" ends with a working binary, not
a build lecture), and a binary that will not answer `-V` is a hard
stop with the arch explanation named (the flagship alias is
x86_64-only; `.cargo/config.toml` carries the aarch64 note) — a
cross-built artifact can never be installed silently.

## 3. The wiring — the two prescribing spots re-pointed

- `scripts/setup.sh`'s next-steps menu: the manual `cp` line now
  offers `./scripts/package/install-on-my-machine.sh` (with the
  uninstall twin named beside it). Text only; the pipeline phases are
  untouched.
- `README.md`'s install-from-source paragraph: the plain `cp`
  sentence now names the install tool and its twin, with the
  build-when-missing and verdict-verification behavior summarized.
  Prose only.

## 4. The verification stack — run for real, on this host

The script was exercised end to end on the audit host, both paths:

- **Fresh path**: no flagship in the tree, no install on the machine
  — the script ran the bootstrap itself (flagship built in 1m15s,
  `zelynic: v80.0.0`), resolved the auto-detect default (user shape),
  installed to `~/.local/bin/zelynic` via `install -Dm755`, and
  verified the verdict at the destination. Exit 0.
- **Re-run path**: idempotent — the existing flagship was reused (no
  rebuild), the existing user destination refreshed, verdicts green,
  exit 0.
- The installed binary answers for itself: `zelynic doctor` reports
  FULL-LIFE (source-built objects), v80.0.0, the commit of this
  session, and honestly refuses the enforcement surfaces on this
  host (kernel 5.10 below the verified 5.13 floor, cgroup v2 absent)
  — the honest-refusal design the dormant-lane tests pin.
- Static gates on the new file: `bash -n`, `shellcheck` (default
  rules), `shfmt -d` — all first-pass clean; mode 755 with shebang
  (the permission guard's executable rule); SPDX dual-line header;
  English-only comments; well under the scripts LOC cap.
- No `ebpf/` or Rust source changed: the prebuilt pin, the suite
  (975/0/4), both fmts, and the kernel-clippy verdict carry; the
  battery re-runs clean with the new script in scope at closure.

## 5. The verdicts

| Surface | Verdict | Basis |
|---------|---------|-------|
| scripts/package/ pair | COMPLETE | install-on-my-machine.sh + uninstall.sh — both directions of the one-file payload now tooled |
| Fresh-install path | PROVEN | run for real: bootstrap, build, user install, verdict verified, exit 0 |
| Upgrade path | PROVEN | idempotent re-run: no rebuild, destination refreshed, verdicts green |
| Documentation drift | CLOSED | build.sh's help already named the script's job; setup.sh menu and README now point at the tool instead of the manual cp |
| Kernel safety | UNMOVED | install never touches pins; note printed when they exist; teardown guard stays in uninstall.sh |

## 6. Honest residuals

- The script installs from THIS checkout by design — release-tarball
  and crates.io installs keep their documented one-liners untouched;
  a download-then-install wrapper is a different tool and stays
  unrequested.
- `--all` is not offered: uninstall's `--all` is its default
  (a scan), and install's default already refreshes every found
  destination — a flag that installs the same file twice would be
  ceremony, not contract.
- The aarch64 host story is the config note's, restated not fixed:
  the flagship alias is x86_64-only, the script refuses cleanly, and
  a static aarch64 native build remains a mirror-the-block decision
  for the owner.
- The GitHub Actions lanes (release.yml's packaged payloads) keep
  their own assembly: this script is the host-side tool, and CI's
  release shape is already gated by its own parity steps.

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
