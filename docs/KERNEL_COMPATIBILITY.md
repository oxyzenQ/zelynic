<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Kernel Compatibility

> Requirements for running zelynic (the cosmic dragon architecture).

## Minimum Requirements

| Component | Minimum | Recommended | Why |
|-----------|---------|-------------|-----|
| **Kernel** | 5.13+ | 6.6 LTS+ | `bpf_skb_cgroup_id()` (4.18+), `bpf_skb_ancestor_cgroup_id()` (present in the 5.13 floor, exposed to cgroup_skb via `cg_skb_func_proto` — the AMMSP walk's helper, verified against v5.13 and master source, NIGHT-private-research-2), `bpf_get_socket_cookie()` (cgroup_skb-legal across the whole verified matrix — the observer's per-endpoint join since NIGHT-boost-26; the LIMITER joined it at charger-core-3b for the `--per-socket` lane and again at schema v20 for the CAKE-shaped flow-isolation lane inside the DRR leaf, so both objects ride the same proven helper), `bpf_link` (5.7+) — 5.13 is the oldest kernel in the verified matrix. The observer's events ringbuf (previously the 5.8+ floor item) is gone since NIGHT-boost-34 — see the 6.8 helper wall below |
| **cgroup** | v2 only | v2 only | zelynic uses `cgroup_skb/egress` + `ingress` hooks |
| **BPF fs** | Mounted at `/sys/fs/bpf` | Mounted | Required for map + link pinning (fire-and-forget mode) |
| **Root** | Required | Required | BPF program load + attach requires `CAP_BPF` or root |
| **rustup nightly pin** | `nightly-2026-09-18` | same | BUILD-time only (source builds): the aya-ebpf crate cross-builds on the dated nightly pin — host install: `./scripts/dev/bootstrap-ebpf.sh`. A crates.io install needs NO nightly: the registry tarball ships the maintainer-built objects (`ebpf-prebuilt/`, NIGHT-ask-2) and compiles the userspace on stable |
| **bpf-linker** | 0.11.1 | 0.11.1 | Links the bpfel-unknown-none objects (prebuilt static musl binary — no system LLVM). Build-time only, same as the nightly pin above; the registry lane embeds already-linked objects |

## Kernel Feature Dependencies

### `bpf_skb_cgroup_id(skb)` — kernel 4.18+

Returns the cgroup ID of the **socket owner** (not current task). This is critical
for correct attribution — TCP packets are processed in softirq context, not the
originating process. Available since kernel 4.18 (2018).

### Cgroup ID resolution — `stat(2)` inode (every cgroup v2 kernel)

There is no `cgroup.id` file in any mainline kernel (NIGHT-hunt-31
removed that phantom from the resolver and both test harnesses). The
cgroup ID is the kernfs inode number of the cgroup directory:
`bpf_skb_cgroup_id()` returns `cgrp->kn->id`, and kernfs publishes that
same node id as `st_ino` — so `stat(2)` is the whole resolution, and it
is the numbering every verified kernel in the matrix ran on.

### `bpf_link_create` + `BPF_OBJ_PIN` — kernel 5.7+

zelynic uses `bpf_link` (fd-based attachment) instead of legacy
`bpf_prog_attach`. Links are pinned to bpffs so enforcement survives
process exit. Aya's public API (0.13 through 0.14, verified against
the 0.14.0 source) does not expose link pinning for
`CgroupSkb`, so zelynic uses raw `bpf()` syscalls. Requires kernel 5.7+
for `bpf_link_create`.

### `BPF_ATOMIC` RMW (`fetch_add` / `cmpxchg`) — kernel 5.12+

The limiter's token bucket is SMP-safe since NIGHT-boost-38 (schema
v7): every refill-window ownership, token deduction, and stats
increment is an atomic read-modify-write, so two CPUs enforcing the
same cgroup can no longer lose updates and over-allow 130-146% of
budget under concurrent flows (the E2E strict-multi / curl-burst
reds of 2026-09-24). NIGHT-improve-29 brought the OBSERVER onto the
same ISA for the same reason: its four counter maps (two per-cgroup,
two per-socket) were plain `+=` on shared map values, so two CPUs
carrying one cgroup's or one socket's traffic lost increments and
the eagle-eyes rates read LOW under exactly the concurrent traffic
the monitor exists to measure — every observer update is now a
fetch_add, and first-packet inserts are `BPF_NOEXIST` so a
concurrent initializer is never clobbered (ebpf/src/stats.rs, pinned
by test/ebpf/stats_smp_tests.rs under real thread contention). The
instructions are 64-bit `BPF_ATOMIC`
fetch-add and compare-exchange — kernel 5.12+; the verified floor
(5.13) sits above it, so the minimum moves nothing. The BPF build
itself rides a repo-local clone of the `bpfel-unknown-none` target
spec (`ebpf/bpfel-unknown-none.json`) with `atomic-cas` enabled —
the rustc builtin still carries the pre-5.12 `atomic-cas: false`
legacy — plus `-C target-cpu=v3` (alu32, kernel 5.1+; see
docs/PURE_RUST_EVALUATION.md and build.rs's
`force_bpf_v3_rustflags`).

### `bpf_skb_ecn_set_ce(skb)` — kernel 5.1+

The ECN-first policing lane (NIGHT-private-research-4, schema v19):
when a budgeted lane's verdict would drop a packet, the datapath
first asks the kernel to set the ECN CE codepoint on the packet's
IP header — an ECT-capable packet is then delivered CE-marked and
charges the `ecn_debt_dl/ul` word instead of dying (the budget law
lives in ebpf/src/ecn.rs). Schema v21 (the per-socket convergence
closure) extended the contract to the per-socket lane: the debt
word lives inside the connection's own bucket there, charged and
paid by the same helper's marks — every budgeted lane is now
ECN-first. The helper handles IPv4 AND IPv6, updates
the header checksums itself, refuses cloned-not-writable and
non-linear-header packets, and is `gpl_only = false`; it entered the
kernel in v5.1 (verified against v5.1's net/core/filter.c —
`cg_skb_func_proto` carries it under `CONFIG_INET`; absent in v5.0)
and the call rides the helper-ID call-immediate convention the
aya-ebpf-bindings crates generate (ID 97, pinned against
include/uapi/linux/bpf.h's `FN(skb_ecn_set_ce, 97)` and aya-obj
0.3's parser table). The verified floor (5.13) sits two minors
above the helper's introduction, so the minimum moves nothing. A
non-ECT packet (the RFC 3168 majority) is refused by the helper and
drops exactly as the legacy policer dropped it — hosts without
CONFIG_INET lose only the rescue, never the enforcement.

### `bpf_skb_load_bytes(skb, offset, buf, len)` — kernel 4.1+

The QUIC-aware attribution lane (NIGHT-private-research-4
candidate, schema v22): the two header reads the cookie-to-
connection-key refinement needs — a bounded 40-byte IP-header
window, then a bounded 56-byte L4 window rebased to the UDP header
the first read's parse located (night-audit-1's two-read split;
the combined 96 bytes per call site match the v22 single window's
stack budget, and the rebase is what makes every pure-core read a
compile-time-constant stack offset). The pure core
(ebpf/src/quic.rs) parses both windows. aya-ebpf 0.2.1 wraps the
helper as `SkBuffContext::load_bytes` (helper 26, the
bpf_skb_load_bytes proto every skb program family has carried
since v4.1 — long before the 5.13 verified floor). Both reads are
data-relative (skb->data = the network header at both cgroup_skb
hooks); a helper refusal (truncated head, non-linear skb) hands
the packet back the raw socket key, exactly the pre-v22 verdict —
the parse is self-protecting by shape, never load-bearing for
enforcement.

THE 5.13 VERIFIER LAW this lane now documents (night-audit-1, the
load failure the supermassive 5.13 floor caught at runs 187+): a
variable-offset STACK read — a load whose address carries a
runtime term, which re-sliced subslices and loop indices produce —
is bounded by the verifier's scalar range tracking, and kernels
before the 5.14 precision rework lose the range through spills
and compound offsets, refusing the whole program with EACCES. The
two-read split plus the unrolled byte collectors keep the object
at ZERO variable-offset stack reads, so the oldest verifier in
the matrix proves every load on sight — the property the
supermassive 5.13 micro-VM keeps pinned on every push.

### `BPF_MAP_TYPE_ARRAY` + `BPF_MAP_TYPE_HASH` — kernel 4.18+

Standard BPF map types. Used for:

- `watchdog_deadline` (ARRAY, 1 entry)
- `schema_version` (ARRAY, 1 entry)
- `cgroup_policy_dl/ul` (HASH, 1024 entries)
- `cgroup_bucket_dl/ul` (HASH, 1024 entries)
- `group_bucket_dl/ul` (HASH, 256 entries)
- `cgroup_limiter_stats` (HASH, 1024 entries)

### cgroup v2 — kernel 4.5+ (practical: 5.0+)

zelynic requires cgroup v2 (unified hierarchy). cgroup v1 is NOT supported.

Check: `stat -fc %T /sys/fs/cgroup` should return `cgroup2fs`.

## Distro Compatibility

| Distro | Kernel | Status | Notes |
|--------|--------|--------|-------|
| **Arch Linux** | 6.18+ | Verified | Dev machine (CachyOS 6.18) — all tests pass |
| **Ubuntu 24.04 LTS** | 6.8 | Build-verified | CI build matrix — compiles + unit tests pass (no runtime record) |
| **Ubuntu 22.04 LTS** | 5.15 | Build-verified | CI build matrix — compiles + unit tests pass (no runtime record) |
| **Fedora 44** | 6.19 | Verified | Real enforcement tested (firefox 100kb → 690 Kbps) |
| **Debian 13** | 6.12 | Verified | Real enforcement tested (firefox-esr 900kb → 7.0 Mbps) |
| **Ubuntu 21.10** | 5.13 | Verified | Minimum kernel — MUSL binary, all tests pass |
| **CachyOS VM** | 7.1 | Verified | MUSL binary, chromium 360kb → 3.0 Mbps (98%) |
| **openSUSE Tumbleweed** | 6.x | Should work | Not yet tested |
| **CentOS Stream 9** | 5.14 | Should work | Edge case (5.14 > 5.13 minimum) |
| **Alpine** | 6.x | Should work | musl libc — may need testing |

## Testing Matrix

### Kernels — verified PASS where recorded

- [x] 5.13 (minimum — Ubuntu 21.10, MUSL binary)
- [x] 6.12 (Debian 13)
- [x] 6.18 (Arch Linux — dev machine)
- [x] 6.19 (Fedora 44)
- [x] 7.0 (Ubuntu 26.04)
- [x] 7.1 (CachyOS VM)
- [ ] 6.1 LTS (pending — no runtime record)
- [ ] 6.6 LTS (pending — no runtime record)
- [ ] 6.8 (Ubuntu 24.04 — CI build matrix only, no runtime record)

### Hardware

- [x] AMD (dev machine — Ryzen 7 5800HS, verified)
- [ ] Intel (not yet tested)
- [ ] ARM64 (future — no cross-compile yet)

### Network

- [x] WiFi (dev machine — verified, wlp1s0)
- [ ] Ethernet (not yet tested)
- [ ] Multiple interfaces (not yet tested)

### Binary types

- [x] GNU (glibc, dynamic) — Arch, Ubuntu, Fedora, Debian
- [x] MUSL (static) — Ubuntu 21.10, CachyOS VM, Debian 13

### Test coverage

Depth/leak/enforcement results per distro are recorded once in
[CROSS_DISTRO_RESULTS.md](CROSS_DISTRO_RESULTS.md) — the harness
commands to reproduce them are in the README's Test Results section.

## Known Limitations

1. **cgroup v1 systems**: Not supported. zelynic will error on attach.
2. **Kernel < 5.7**: no `bpf_link` (5.7+), so neither object can
   attach. Kernels below 5.13 are outside the verified matrix (5.13
   is the oldest kernel tested). The depth harness reports the span
   for you (NIGHT-boost-27): `limiter-depth-test.sh` emits a
   kernel-span verdict family — the 5.13+ floor gate (FAIL below
   it), the capability rung the running kernel rides at (5.7 links,
   the 5.13 verified floor, the 6.x LTS lines), and the LTS
   placement — so a verdict from any machine, 5.13 hardware to the
   latest release, names the kernel generation it rode on. (The
   observer's events ringbuf — the old 5.8 rung — was dropped at
   NIGHT-boost-34; the 6.8 note below is the reason.)
3. **No BPF fs mounted**: Fire-and-forget mode (pin maps) will fail.
   Fix: `sudo mount -t bpf bpf /sys/fs/bpf`
4. **Non-root**: BPF operations require root. Use `sudo`.
5. **Container environments**: May need `--privileged` or specific capabilities.

## Troubleshooting

### "cgroup v2 not found at /sys/fs/cgroup"

Your system uses cgroup v1. Check:

```bash
stat -fc %T /sys/fs/cgroup
# Should output: cgroup2fs
```

### "the pinned nightly toolchain ... is not installed" or "bpf-linker is not on PATH" (build time)

The BPF objects build inside the binary now (NIGHT-improve-1 phase
3); the build.rs preflight (NIGHT-host-1) names the exact missing
prerequisite before any compile time is spent. One command fixes
both — and finishes the whole host setup by also building the
flagship binary (NIGHT-improve-16), so the next command is the
test, not a build:

```bash
./scripts/dev/bootstrap-ebpf.sh
```

Manual alternative:

```bash
rustup toolchain install nightly-2026-09-18 --component rust-src --component rustfmt
# bpf-linker 0.11.1: https://github.com/aya-rs/bpf-linker/releases
```

A failure that instead reads "the pure-Rust eBPF build failed with
prerequisites present" is a real compile error — the nested cargo
output above it is the diagnosis. The former "BPF object file not
found" error class is gone — the objects are embedded, never
discovered on disk.

### "Failed to pin map"

BPF filesystem not mounted:

```bash
sudo mkdir -p /sys/fs/bpf
sudo mount -t bpf bpf /sys/fs/bpf
```

### BPF verifier rejects program

Check kernel version — `bpf_skb_cgroup_id()` requires 4.18+.
Some older kernels have stricter verifier. Check dmesg for verifier log.

### eagle-eyes load fails with EINVAL on kernel 6.8 (NIGHT-boost-34, closed)

Kernel 6.8 moved `bpf_get_current_pid_tgid` / `bpf_get_current_uid_gid` /
`bpf_get_current_comm` out of `bpf_base_func_proto` into the new
`cgroup_current_func_proto`, and the cgroup_skb dispatch never calls
the latter — so a cgroup_skb program using those helpers fails
program load with EINVAL ("program of this type cannot use helper").
The old observer's 1-in-100 event branch used all three (feeding the
events ringbuf no zelynic code ever read); 6.8 hosts — including the
6.8-azure CI pool — rejected the load, 6.17 restored the helpers
quietly, and stock 5.13/5.15 never had the wall. The fix dropped the
event branch and the ringbuf entirely (the phase-2 hunt decision,
forced by the kernel): the observer's helper set is now
`bpf_map_lookup_elem`, `bpf_map_update_elem`,
`bpf_skb_cgroup_id`, `bpf_get_socket_cookie` — each allowed for
cgroup_skb on every kernel from 5.13 through 6.17+.
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
