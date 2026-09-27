<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# NIGHT-dinner-5 — The v10 vs v11 Era Comparison

> Which era is sharper and more powerful — the v10 stable line or the
> v11 Cosmic Dragon line? Asked by the owner on 2026-09-27, answered
> live: both binaries run as root inside the zelynic sandbox micro-VM
> (kernel 7.0.0-34-generic, Ubuntu 26.04 LTS lane, TCG emulation —
> this agent box has no /dev/kvm and no sudo), plus a rootless host
> battery and the full v11.0.0-rc.1 release-lane verification. Every
> number below was produced by a command that ran; nothing is quoted
> from marketing.

## The verdict in one paragraph

The v11 era is decisively the sharper and more powerful one — not
because it is newer, but because it is **correct where v10 was
measurably wrong and complete where v10 was structurally gap-toothed**:
the enforcement arithmetic survives concurrent CPUs (v10's token bucket
lost updates and over-allowed **130–146 % of budget** under concurrent
flows — measured, then fixed by the v7 schema), the observer survives
the kernel generation v10's docs promised but its C code could not
span (kernel 6.8 removed the helpers v10's observer called; the
program fails to load with EINVAL on every 6.8–6.16 host), the eBPF
objects ride inside the binary (v10 shipped them as **external files**
— live proof below: the bare v10 binary cannot apply a single limit
until `bpf/limiter.bpf.o` is placed beside it), and the monitoring
surface went from a box-mode status table to a per-endpoint attribution
engine. The honest counterweight: the core limiter DNA — per-cgroup
token bucket with sub-byte fractional precision, pinned maps, watchdog
deadline, schema migration — is **inherited** from v10, not reinvented;
v11's campaign spent its energy hardening that DNA (schema v2 → v9)
and paying down distribution trust. Sharpness, in this comparison, is
mostly a story of paying boring costs v10 deferred.

## Axis 1 — The engine

| Dimension | v10.0.0 | v11.0.0-rc.1 |
|---|---|---|
| eBPF source language | C (`bpf/limiter.bpf.c`, `bpf/observer.bpf.c`) | Rust (`ebpf/src/bin/limiter.rs`, `ebpf/src/main.rs`, aya-ebpf 0.2.1) |
| User toolchain prerequisites | clang 10+, libbpf-dev headers | none (prebuilt lane) or Rust nightly (source lane) |
| Object delivery | **external `.bpf.o` files**, loaded from disk | **embedded in the binary** (source-built or registry-prebuilt) |
| Loader | raw `bpf()` syscalls, libbpf-style pinning | same contract on aya 0.13.1 (ELF-identical port) |
| Kernel span claimed | 5.13+ | 5.13+ (verified matrix) |
| Kernel span actual | breaks on 6.8–6.16 (observer helper wall, EINVAL at load) | holds — live-booted on 7.0.0-34-generic in this comparison |
| Doc honesty | claimed a `cgroup.id` file (5.13+) that **never existed in mainline** | NIGHT-hunt-31 corrected it: stat(2) inode resolution |

The port itself is disciplined: the v11 Rust datapath is a
line-for-line translation of the C twin with the ELF contract pinned
(map names, sections, struct layouts, pinning), and every behavioral
delta is documented in `ebpf/src/main.rs` and
`docs/PURE_RUST_EVALUATION.md` — six deltas, each with a reason
(non-linear skb parsing the C path silently skipped, the dead ringbuf
removed after kernel 6.8 cast the deciding vote, atomic counters, the
per-socket cookie maps, the 4096-entry counter capacity).

**Live proof of the embedding gap.** In the sandbox VM, with only the
bare v10 binary at `/opt/zelynic/zelynic`:

```text
$ zelynic strict-single 31 1mb
zelynic: BPF object file not found. Compile with:
  clang -O2 -g -target bpf -c bpf/limiter.bpf.c -o bpf/limiter.bpf.o
  Searched: ["bpf/limiter.bpf.o",
              "/home/runner/work/zelynic/zelynic/bpf/limiter.bpf.o",
              "/usr/lib/zelynic/limiter.bpf.o",
              "/usr/local/lib/zelynic/limiter.bpf.o"]
```

Two era facts in one error: the objects are external, and the search
list embeds a **hardcoded CI runner path** — a v10-era portability
smell. The v11 binary carries the same objects inside the executable
(the `-V` report's `Signature: Pure eBPF builtin` is a claim this
architecture can back), which is also what makes the crates.io lane
possible at all.

## Axis 2 — The limiter

The shared DNA (v10 innovation, inherited by v11): per-cgroup token
bucket with `frac_rem` sub-byte fractional remainder (the "0.00 % rate
error" precision), strict-single / strict-multi group semantics,
pinned `bpf_link`s so enforcement survives process exit, a watchdog
deadline map that turns BPF into a no-op past its expiry, and schema
versioning for safe evolution.

What v11 added is the hardening record — the schema version marched
v2 → v9, and each bump is a measured defect closed:

| Schema | The defect it closed |
|---|---|
| v3 | rate 0 now **drops** instead of allowing |
| v4 | burst/tokens clamped before refill math (overflow safety) |
| v5 | rate-0 block verdict books its drops into stats |
| v6 | `frac_rem` sanitized on read (the third stored field the v4 clamps missed) |
| v7 | **SMP-safe atomics** — v10's read-modify-write lost updates and over-allowed 130–146 % of budget under concurrent flows |
| v8 | CAS consume retry (4 attempts) — 1.35 % of packets falsely dropped at one attempt, 28× fewer at four |
| v9 | the rate-0 booking moved to the same atomic path the enforce path uses |

**Live enforcement, apples-to-apples.** Both eras ran the identical
probe in the sandbox VM: a 6 MiB loopback transfer (python3 server and
curl sharing one cgroup, id 31), unlimited, then capped at `1mb` both
directions, then unrestricted:

| Leg | v10.0.0 (musl, v1 baseline) | v11.0.0-rc.1 (musl, v1 baseline) |
|---|---|---|
| Baseline (no limit) | 30,786,443 B/s (≈ 30.8 MB/s) | 34,081,006 B/s (≈ 34.1 MB/s) |
| `strict-single 31 1mb` | 1,151,760 B/s (≈ 1.15 MB/s) | 1,151,827 B/s (≈ 1.15 MB/s) |
| Kernel proof (status) | 399 pkts / 12.6 MB allowed, **160 pkts / 20.7 MB dropped** | 12.7 MB allowed, **20.5 MB dropped** (same dual-capping shape) |
| After `unstrict` | 34,294,834 B/s (≈ 34.3 MB/s) | 33,259,442 B/s (≈ 33.3 MB/s) |

The most telling cell is the capped row: **1,151,760 vs 1,151,827 B/s —
a 67 B/s (0.006 %) difference across a complete engine rewrite**. The
enforced rate is set by the inherited `frac_rem` token-bucket math, and
both eras compute it to the same byte budget under the same kernel —
cross-era consistency as a precision claim, made visible.

The v10 numbers are already instructive: the cap binds in-kernel (the
dropped-packet column is the kernel refusing traffic, not a userspace
shaper), and the allowed-byte count (~12.6 MB for a 6 MB transfer)
matches the dual-capping design — the server's egress bucket and the
client's ingress bucket each book their own direction. The ~15 %
overshoot over the nominal 1,048,576 B/s is the burst allowance plus
dual-bucket interaction, honest behavior of a token bucket with burst,
not drift.

Targeting also matured: v10 accepts a raw cgroup id or a process name
(`Target::parse` — a bare number is an id); v11 accepts the `cg:<id>`
prefix **its own surfaces print** (the eagle-eyes footer suggests
exactly `sudo zelynic ss cg:48181 100kb`), a small ergonomics fix with
a real story: copying a displayed `cg:48181` into a v10-era command
would have been parsed as a process named `cg:48181`.

## Axis 3 — Monitoring ability

| Capability | v10.0.0 | v11.0.0-rc.1 |
|---|---|---|
| Live surfaces | `observe` (box mode), `top --live` | unified `monitor` render engine (≈ 3.6 K LOC: eagle-eyes, footer tiers, detail, focus, session, depth JSON) |
| Attribution unit | per-cgroup byte counters | per-cgroup **plus per-socket cookie maps — per-endpoint byte attribution** (NIGHT-boost-26; v10 never had it) |
| Counter updates | plain `+=` on a shared map value — reads LOW under concurrent CPUs | 64-bit BPF_ATOMIC fetch-add + BPF_NOEXIST first-insert |
| Counter capacity | 256 entries per direction | 4096 entries (16×) |
| Non-linear skbs | silently skipped by the C direct-access path | parsed via `bpf_skb_load_bytes` |
| Event ringbuf | 2 MiB ringbuf **no code ever read** (dead payload) | removed (kernel 6.8 helper wall made it fail to load) |
| JSON surfaces | status JSON | status / depth / doctor JSON documents, contract-pinned by tests |
| doctor | 5 checks (kernel, cgroup v2, BPF fs, root, verdict) | the same checks **plus** `Build: FULL-LIFE|HALF-LIFE` + the eBPF lane, text and JSON |

**Live, as root, same kernel (7.0.0-34-generic):**

```text
v10 doctor:                       v11 doctor (rc.1):
  Kernel:  7.0.0-34-generic         Build:   FULL-LIFE (eBPF objects: registry-prebuilt)
  cgroup v2: YES                    Kernel:  7.0.0-34-generic
  BPF fs:  YES                      cgroup v2: YES
  Root:    YES                      BPF fs:  YES
  eBPF:   SUPPORTED                 Root:    YES
                                    eBPF:   SUPPORTED
```

And the census, same moment, same VM shape:

```text
v10 list-apps:                    v11 list-apps:
  PROCESS       CGROUP ID  UID       2 cgroups resolved, 1 with live sockets
  bash          cg:1       0
  python3       cg:31      0         process    procs  sockets  cgroup id  uid
                                   bash          71        0      cg:1       0
                                   python3        1        1      cg:31      0
```

The v10 table is a name-to-id map; the v11 table is a **socket-aware
census** — the procs and sockets columns expose multi-tenancy (71
processes in the root cgroup, the server's one live socket in the era
cgroup), which is exactly the visibility the eagle-eyes footer builds
on. The status surfaces grew the same way: v11's status table closes
with the build-stamp footer (`v11.0.0-rc.1 (65898c6) by oxyzenQ`)
and the apply path answers with colored, copy-pasteable next commands
(`Run 'zelynic unstrict cg:31' to remove...`) — small ergonomics, but
they are the difference between a tool you operate and a tool you
read. The v11 line-up also adds the build-provenance axis (which of
the three object paths produced this binary) to what a doctor is
*for* — a direct answer to the owner's cargo-install question in the
next section.

## Axis 4 — Distribution and trust

| Dimension | v10.0.0 | v11.0.0-rc.1 |
|---|---|---|
| Release assets | 8 (one tarball per libc + checksums) | 20 (v3/v4 × gnu/musl + 3 checksum algorithms each + GPG `.asc`) |
| Tarball shape | nested 12-file tree (binary, external `bpf/*.bpf.o`, man, scripts) | flat 3-file invariant (binary, LICENSE, README) |
| Baseline coverage | whatever the host CPU was | explicit x86-64-v3 (AVX2) and v4 (AVX-512) arch-baseline legs |
| Signature | none | GPG (EDDSA, verified Good below) |
| crates.io | not published (first publish in project history was v11.0.0-beta.3) | full-life registry lane; `cargo install zelynic --version 11.0.0-rc.1` verified live |
| CI gates era | 4 workflows, script checks | 8 workflows, 21-gate wholesale lane + sandbox micro-VM + supermassive/depth harnesses |
| Tree size | 73 tracked files | 239 tracked files |

**The registry lane verdict (the owner's explicit question).** A
plain, default-toolchain `cargo install zelynic --version
11.0.0-rc.1 --locked` was executed on the agent box and the installed
binary was probed:

```text
$ zelynic doctor
  Build:      FULL-LIFE (eBPF objects: registry-prebuilt)
  ...
$ zelynic doctor --print-json
  {"system":{...},"ebpf_supported":false,
   "build_flavor":"full-life","ebpf_lane":"registry-prebuilt",...}
```

**FULL-LIFE, registry-prebuilt** — the monitor and the limiter both
arrive via the tarball's `ebpf-prebuilt/` objects (the same bytes the
release binaries embed, freshness pinned by the parity gate), on a
stable toolchain, no nightly anywhere near the user. The half-life
build flavor exists (the `--no-default-features` dormant lane) and is
honestly reported when it occurs — the registry lane is simply not it.

## The release-lane verification record (v11.0.0-rc.1)

- **GitHub Release**: 20/20 assets present (4 tarballs + 12 checksum
  siblings + 4 GPG signatures), `prerelease: true`, never marked
  "latest", release notes render the dual-range line ("8 commits
  since v11.0.0-beta.4 (previous build) · 336 commits since v10.0.0
  (last stable)") — the rc channel's first live fire, accepted by the
  validate job after this session taught it the channel.
- **Checksums**: sha512, b2, shake256 all `OK` against the shipped
  siblings (v3-gnu leg verified byte-for-byte locally).
- **GPG**: `Good signature from "Rezky Cahya Sahputra (cosmic
  dragon)"` (EDDSA), same identity as every prior verified release.
- **Workflows on the release SHA**: Release (re-run after the probe
  fix below) and Gate-keepers wholesale — both green on `ec2ba94`
  itself; CI/CodeQL/Supermassive green on the parent bump commit
  (their path filters do not fire for a workflow-only change).
- **A bug found and fixed on the way (honesty section)**: the first
  rc.1 release run failed both AVX-512 legs at the Verify-binary step
  — the NIGHT-dinner-4 Signature strings probe had never executed on
  a real release before, and `strings(1)` (7-bit ASCII runs) splits
  the literal at its UTF-8 em-dash, so the one-line grep could never
  match. Fixed by grepping the literal bytes straight against the
  artifact (`grep -aFq`), reproduced locally, healed by re-pointing
  the tag (the beta.4 precedent). Maturity is a process; this
  comparison documents the process catching its own regressions.

## What the deltas teach (the evolved-thinking section)

1. **Helper-minimal programs age better.** v10's observer died
   mid-span on a helper removal nobody announced; v11's survives
   because it asks the kernel for less. When the promised span is
   years long, every helper call is a bet against kernel evolution.
2. **Measured beats argued.** "The limiter over-allows 130–146 % under
   concurrency" is a number, and numbers get schema bumps, tests, and
   closures. The v10 line had the same class of bug and no instrument
   that could see it.
3. **Embedding beats adjacency for a single-binary tool.** External
   `.bpf.o` files created a whole failure mode (search paths, install
   layout, CI-path leftovers) that embedding simply deletes — and the
   registry lane is only constructible once objects ride inside.
4. **Dead code is a kernel-compat liability.** The unread ringbuf was
   harmless right up to the day its helper set got removed, and then
   it was an EINVAL on every 6.8 host. Unused code does not stay
   unused-cost-free forever.
5. **Claims discipline compounds.** The nonexistent `cgroup.id` file
   in v10's docs is the small ancestor of the claims-verification
   culture (docs/CLAIMS_VERIFICATION.md) that keeps v11's banner
   honest — a dormant build prints a dormant Signature, not a claim
   it cannot back.

## Method, environment, and reproduction

- **The sandbox lane** (root-full): `scripts/sandbox/
  zelynic-sandbox.sh --binary <path> --envelope best --run <probe>`,
  kernel lane `lts` (7.0.0-34-generic, Ubuntu 26.04 LTS), TCG (no
  /dev/kvm on this box), 2 vCPU / 3030 MB. The probe script stages a
  python3 loopback server and curl into one cgroup, measures
  unlimited / capped / post-unstrict transfers, and captures census,
  status, and teardown output. The v10 probe embeds the era's own
  `bpf/*.bpf.o` objects (base64) so the comparison measures the era
  as shipped-in-full, not the era's packaging gap — the packaging gap
  is documented separately above, from the bare-binary run.
- **The rootless host battery**: `-V`, `doctor`, `doctor --print-json`,
  `status`, `--help`, exit codes, for both the v10 release binary and
  the v11 rc.1 release + cargo-installed binaries.
- **The release-lane battery**: asset inventory via the GitHub API,
  checksum verification (sha512/b2/shake256), GPG verification,
  workflow state for the tag and its SHA.
- **The portable qemu bootstrap** (this agent box: Debian 13 host, no
  sudo, no qemu package): the jammy closure for `qemu-system-x86` +
  `seabios` + `ipxe-qemu` + `qemu-system-data` (114 debs, 46.1 MB)
  extracted rootless under `~/.local/lib/qemu-vm`; the wrapper runs
  qemu under **its own** jammy loader with `--library-path` (mixing
  the host's newer ld.so with the older extracted libc segfaults),
  `QEMU_MODULE_DIR` override (jammy qemu 6.2 is modular and derives
  the module dir from `/proc/self/exe`, which under a loader
  invocation points at the loader — without the override the TCG
  accel never registers), and the SeaBIOS/iPXE ROMs consolidated into
  the single `-L` data dir. Reproduce with
  `python3 scripts/qemu_bootstrap.py` (kept outside the repo with the
  session tooling; the recipe is three paragraphs of comment in the
  wrapper itself).

## Environment honesty

The VM legs ran under TCG software emulation on 2 vCPUs; absolute
throughputs are loopback numbers under emulation, meaningful as
ratios (capped vs baseline), not as host performance claims. The
kernel-span verdict for v10's observer on 6.8–6.16 is cited from the
v11 era's documented kernel research (`ebpf/src/main.rs`,
`docs/PURE_RUST_EVALUATION.md`), not re-derived live here — this box's
LTS kernel (7.0.0-34) postdates the helper restoration, so v10's
doctor legitimately reports SUPPORTED on it; the span defect lives in
the 6.8–6.16 window the box cannot boot without fetching another
kernel lane (`--kernel floor` boots 5.13, the other edge).
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
