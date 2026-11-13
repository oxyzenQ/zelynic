<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# night-total-hardening-1 — the fixed CLI, vendored for local verification

Package date: 2026-11-13. Source commit: 81353a8 (the session's HEAD) plus the
re-verification record 371fd39. This lab directory vendors the session's
verification package so a fresh clone verifies the fixed CLI with zero
manual download steps — the same zero-friction posture the vendored
`legacy-for-test/` pair owns (see legacy-for-test/VENDOR.md for that lane's
precedent).

## What is in this directory

| File | Purpose |
| --- | --- |
| `zelynic-fixed-cli-hardening-1.gz` | The fixed CLI binary, v80.2.0, static musl, x86_64 — the gz package (raw binaries are never tracked, night-cafe-1) |
| `zelynic-fixed-cli-hardening-1.b3sum` | BLAKE3 sidecar over the package bytes |
| `verify-cli-ux.sh` | The 17-case non-root verification battery — auto-extracts the package and sha256-pins the bytes when the raw binary is absent (ZELYNIC_BIN names another build) |
| `verify-root-lane.sh` | The root-lane battery: the seven Step 2 shapes automated, probe-cgroup isolated, `--apply-row` for the forensic rig's once-per-process apply row — the same package bootstrap as its sibling |
| `VERIFY_LOCAL_HARDENING_1.md` | This guide |

Binary integrity:

```
b3sum -c scripts/labs-exp/zelynic-fixed-cli-hardening-1.b3sum

sha256: 7556c6272eb114709afc3059820c434302708c7033ce2e88d041b7b4d9b2fc66
```

`b3sum` is the official BLAKE3 utility (the `b3sum` package on
Ubuntu 24.04+, the same lane docs/VERIFY_RELEASE.md prescribes); the
sha256 pins the extracted binary bytes, the same value both
batteries verify before running a case.

Provenance and the staleness contract (no silent substitutions, the
from-source law held):

- Built from the exact 81353a8 tree via the documented host path
  (`scripts/dev/bootstrap-ebpf.sh`): nightly-2026-09-18 + rust-src +
  rustfmt, bpf-linker 0.11.1 prebuilt static-musl.
- Userspace: stable 1.98.1, `cargo build --profile release --features ebpf
  --target x86_64-unknown-linux-musl`, `+crt-static`, NO `target-cpu` pin —
  a generic-baseline build that runs on any x86_64 Linux. Build label
  `local-generic-musl`; `zelynic doctor` answers FULL-LIFE with
  `eBPF objects: source-built`.
- The binary is a SNAPSHOT of the 81353a8 fixes, not a living build
  product: as the tree moves, rebuild from source instead of trusting
  the vendored bytes. `b3sum -c` on arrival, then either battery (each
  extracts the package and verifies the sha256 pin itself), or, for a
  bare version probe:

```
gunzip -c scripts/labs-exp/zelynic-fixed-cli-hardening-1.gz > /tmp/zelynic-fixed-cli && chmod 755 /tmp/zelynic-fixed-cli
/tmp/zelynic-fixed-cli -V   # expect v80.2.0, commit 81353a8
```

- Rebuild contract, three commands:

```
git clone https://github.com/oxyzenQ/zelynic && cd zelynic
./scripts/dev/bootstrap-ebpf.sh
```

## Step 1 — the non-root battery (any machine, no privileges)

```
./scripts/labs-exp/verify-cli-ux.sh
```

## Why the binary ships packaged (night-cafe-1)

Raw binaries are never tracked in this repository — the vendored
counterfactual lane set the precedent: `legacy-for-test/` ships its
release tarball with checksum sidecars and the raw extraction product
rides .gitignore (`/legacy/zelynic`). The night-total-hardening-1
vendored CLI obeys the same law: the tracked lane is the `.gz`
package plus its `.b3sum` sidecar, the raw binary stays a local
extraction product, and both batteries carry the bootstrap — absent
a raw binary, they extract the package into a private temp dir,
verify the pinned sha256, run the cases against the extracted copy,
and tear the temp dir down on exit. The zero-friction posture is
unchanged: a fresh clone still verifies with zero manual download
steps.

Expected: `battery: 17 passed, 0 failed`. The battery pins, on the binary
itself:

1. The 32-bit numeric-boundary refusal at the input boundary — bare digits
   (`s 100000000000000000 1mb`), the `cg:` spelling, and the `'::'` list lane
   naming the offending member. The bound is named: "the kernel numbers them
   inside 32 bits", with the `list-apps` tip.
2. The `u32::MAX` edge: `4294967295` is inside the id space and must NOT be
   refused at the boundary (it flows to the privilege ladder as an id).
3. The empty-target rung (`s "" 1mb` refuses before the privilege ask).
4. The danger guard firing before the privilege ask: `s sshd 1mb` refuses
   with the "system process" wording and the `--force-this` tip.
5. The JSON door: `ee --depth --print-json --focus` (valueless flag) renders
   the prose lane's own verdict —
   `{"error": "a value is required for '--focus <SECONDS>' but none was supplied", "tip": ""}`
   with exit 1, never the old `invalid value ''` lie. A genuine non-empty
   value error keeps its own verdict (`Invalid focus window '0': must be
   between 1s and 30s`).
6. The help tiers: `ee -h` is compact (13 lines, zero NIGHT-* lineage), the
   detail tier points at `docs/USAGE.md`, and the root `-h` reference lists
   the full command surface.

## Step 2 — the root-lane shapes (needs root + cgroup v2 + the eBPF floor)

These fixes live post-privilege by design; verify them on a machine that
meets the floor (kernel >= 5.15, cgroup v2, bpffs mounted, root). The
battery automates all seven shapes with its own probe-cgroup isolation —
nothing outside its own `/sys/fs/cgroup/zelynic-root-lane-battery` is
touched, and the EXIT trap tears the probe down even on Ctrl-C:

```
sudo ./scripts/labs-exp/verify-root-lane.sh
```

The table below keeps the audit's original shapes; the battery rides
machine-independent spellings of the same verdicts (a dead id just
under u32::MAX, the probe cgroup as the resolvable member, the root id
discovered per machine):

| Command | Old (buggy) behavior | Fixed behavior |
| --- | --- | --- |
| `sudo zelynic s 889111 100kb` | blind `OK.` for a dead id, reaped by the next sweep | the apply-side liveness gate proves the id against the cgroupfs census; the no-match hard error names the dead target, exit 1, nothing limited |
| `sudo zelynic b 1011::11` | the same blind OK through a list | the atomic refusal: "target '1011' resolved to no cgroup — the list apply is atomic, nothing was blocked", naming the miss beside the resolvable remainder |
| `sudo zelynic s zylaxion::brave::noexist 1mb` | the resolvable half enforced, the miss vanished | the pre-flight marks the dead segment a MISS; "nothing was limited (2 of 3 targets were resolvable, 0 applied)" |
| `sudo zelynic u zylaxion::kate::noexist` | "Removed N policies across 7 targets" claiming members that matched nothing | the success line counts only targets that actually had limits removed; a grey tail names every member that had none |
| `sudo zelynic s <root-ino> 1mb --no-test --force-this` | the identical root catch-all warning printed twice | warned ONCE per process (the second guard rung stays silent); the apply lands, so this is the battery's opt-in `--apply-row` |
| `sudo zelynic ee zylaxion::brave` | the no-match error left the user guessing the separator | the tip names it: "eagle-eyes targets separate with '/' — e.g. 'zelynic ee brave/electron'" |
| `sudo zelynic b zylaxion::noexist` | the abort line said "limited" for the block family | the verb carries the family: "nothing was blocked", never "limited" |

Two command notes the table packs tight: the root id in row 5 is the
cgroupfs mount's own inode — discover it with
`stat -c %i /sys/fs/cgroup` (often 1, never assumed), and the rate rides
the command — without one the parse-before-execute ladder answers
"No rate specified" before any guard rung fires.

Honest-behavior notes (by design, not bugs): the sweep family (`s brave
--all`, `b --all`) keeps its best-effort admission — a fleet snapshot must
not abort on one dead app; a missing/inconclusive cgroupfs census keeps the
old fail-open posture; the monitor's digit targets resolve after the
privilege gate (the multi-user /proc law), so a past-u32 digit spec for
`ee` reaches the ladder as an eventual named miss.

## Step 3 — the full E2E forensic rig (the mandate's own vehicle)

```
git clone https://github.com/oxyzenQ/zelynic && cd zelynic
./scripts/dev/bootstrap-ebpf.sh                   # toolchain + bpf-linker + flagship build
sudo ./scripts/supermassive/supermassive-test.sh  # the supermassive battery
```

The session's rig: `scripts/sandbox/forensic-critical-sim.sh` (one
FORENSIC-RESULT row per claim — 30/30 green in the micro-VM; the
`netrunner-night-C77` CI lane runs the same simulation per push and holds
the `FORENSIC-VERDICT: PASS` sentinel as the authority). The non-root depth
battery: 107/107.

## Building your own native flagship instead

The vendored binary is generic-baseline on purpose (portable across x86_64
hosts). For a host-CPU-optimized flagship, build locally:

```
./scripts/dev/bootstrap-ebpf.sh   # then, already on PATH:
cargo pro-native-musl             # lands in target/x86_64-unknown-linux-musl/pro-native-musl/
```

(arm64 machines: `cargo pro-native-arm64-musl`. Point the battery at any
build with `ZELYNIC_BIN=<path> ./scripts/labs-exp/verify-cli-ux.sh`.)

## Version note

The vendored binary ships v80.2.0 — the manifest version is the owner's
call and was not touched.

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
