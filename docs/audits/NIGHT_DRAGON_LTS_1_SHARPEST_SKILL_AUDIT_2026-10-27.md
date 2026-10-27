<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-dragon-lts-1 audit — the sharpest skill pass

> Audit date: 2026-10-27 (night-dragon-lts-1). Scope: the sharpest
> skill — the per-packet kernel enforcement core (`ebpf/src`, 6,645
> lines across 23 files) and its userspace half (`src/ebpf` loader,
> pin, capabilities, lock) — audited against the LTS five: stability
> and crash, hygiene, optimization, security hardening, and hidden
> failure modes. Audited at 1eab6ca, the tree whose full CI round
> (9/9 workflows) verified the session's six harness commits. Method:
> the perstage probe discipline — the crash classes (panic family,
> division provenance, parser bounds, cast truncation), full reads of
> the three most attack-relevant files (`enforce.rs`, the `quic.rs`
> parse core, `pin.rs`), the spawn-injection census, and a fresh
> mechanical re-verification of the standing memory-safety claim
> LTS-14 carries. The sibling reference stays zejtron.

## 1. The mandate

The sharpest skill is the code that runs per packet on every host
that polices traffic: one lookup miss there is a per-packet tax
forever, one panic there is a verifier reject or a kernel-side trap,
one unguarded divisor is an enforcement stall, one unbounded parser
read is a remote attacker's lever. The audit asked the LTS five of
exactly that code and accepted nothing but mechanical evidence —
every claim re-derived at HEAD, nothing inherited from a prior
record's say-so.

## 2. Stability and crash — the kernel object

The panic family census (unwrap, expect, panic, unreachable, todo,
unimplemented) across `ebpf/src` outside the test tree: **zero
hits**. The kernel object cannot panic by construction — the claims
SAFETY_ANALYSIS makes are true at HEAD, not just at the record that
wrote them.

The division census found every runtime divisor and traced each to
its guard: the three drawees denominators (`epoch_allowance`,
`flow_leaf_budget`, `flow_allowance`) all early-return under the
`< 2` law before the divide; `share_epoch_ns()` and
`1000 / DRR_WINDOW_MS` are constants (100 ms window); `NS_PER_DAY`
and `NS_PER_SEC` are constants; the rate ring's `RING_WINDOW_NS` and
`RING_SLOTS` are constants. Not one unguarded divisor remains.

The packet-parsing surface (`quic.rs` 541 lines, `quic_l4`,
`socket_flow`, `quic_flow`) rides the 5.13 floor law end to end:
`pack8_bounded` and `flow_key_bounded` collect bytes through the
buffer's own base pointer at compile-time-constant offsets gated by
a scalar length, `scid_len_byte` extracts the runtime-positioned
length byte as a shift-and-mask of packed registers (pure ALU, zero
variable-offset memory reads), and a window past the buffer reads as
zero so the caller's span check turns it into the honest refusal.
The oldest verifier in the matrix proves every load on sight — the
supermassive lane boots that verifier on every push.

The epoch field in the DRR share state packs 28 bits of
`now / DRR_WINDOW_MS` — an 8.5-year horizon whose single wrap is
documented benign (the first asker of the post-wrap epoch is capped
at `quantum/(K+1)` like every other drawer). The u32 truncation at
the callers is the packing itself, not a loss the state misreads.

## 3. Stability and crash — the userspace half

The 28 unwrap/expect hits in `src/ebpf` and `src/capabilities` all
sit inside `#[cfg(test)]` test modules. The non-test remainder is
checked-then-expect (the schema-version consistency pin that must
die loudly at build time if the ebpf schema declaration drifts) or
`strip_suffix` after an explicit suffix check. The `unsafe fn`
sites (3 in `src`, 1 in `ebpf/src`) carry `# Safety` contracts and
ride clippy's default `missing_safety_doc`, which the CI's
`clippy -D warnings` enforces on every push.

The process-spawn census found exactly three `Command::new` sites in
the binary, each pinned: `probe.rs` spawns `current_exe()` (its own
binary, no user string), `term_reset`'s rescue utility pins
`RESCUE_SYSTEM_PATH` for root spawns (the documented defense against
a user PATH sliding a binary under a root-run rescue), and
`update/mod.rs` invokes `curl` with a constant argument array
against a constant URL — no user input reaches any argv. The update
path is check-only, root-refused before any network I/O, hourly
throttled, and curl-timeout bounded (15 s).

## 4. Security hardening — the kernel-mode read

`enforce.rs` (read in full) carries the hardening generations
stacked: the unlimited fast path first (NIGHT-lts-2 — an unpolicied
packet pays two map lookups, never the watchdog read or the
timestamp), the security-3 trust boundary that clamps the stored
burst before any consumer derives a bound from it, the schema-v9
atomic booked drop (a blocked cgroup's drops are visible on every
CPU), the lts-7 degrade-not-fail-open when a group bucket cannot
materialize, and the TOCTOU belt that answers a policy vanished
mid-walk with allow — never a drop on a map race.

`pin.rs` (read in full) removals are verified, not assumed
(NIGHT-master-4): the unlink return values are not the verdict, the
re-read-empty verification pass is; a raced-away entry counts as
neither removed nor leftover; a foreign nested directory fails
EISDIR into the survivor error; the bpffs root is kernel-owned, so
the symlink-following class has no unprivileged foothold to stand
on.

## 5. The one find — the memory-safety claim does not survive a mechanical re-check

LTS-14's verdict table carries the memory-safety row as
"100% SAFETY-annotated; undocumented-unsafe clippy at zero". Fresh
verification at HEAD found the claim is (a) not wired as a standing
property and (b) not reproducible under the lint's own rule:

- No `clippy.toml`, no `[lints]` table in `Cargo.toml`, no crate
  attribute, and no flag in any clippy invocation (CI's
  `cargo clippy ... -- -D warnings` and `build.sh`'s twin run the
  default groups only) enables `clippy::undocumented_unsafe_blocks`
  — a restriction-group lint that `-D warnings` does not turn on.
  The at-zero was a one-time manual measurement inside the lts-14
  audit; a new undocumented unsafe block would pass every standing
  gate today.
- A static census mirroring the lint's positional rule (a comment
  mentioning safety within the 3 lines above the block) counts
  120 unsafe block openers in the tree (`src` 61 + `ebpf/src` 59)
  and finds 78 with no safety-mentioning comment in the window.
  Spot checks confirm the census is not a false-positive engine:
  the rationale genuinely lives at the function- and module-doc
  level (the house convention — `enforce.rs`'s trust-boundary and
  TOCTOU paragraphs are exactly that), which the mechanical lint
  does not read. The house convention and the lint's rule are two
  different instruments; the claim as written names the lint's
  rule.

Honest caveats on the census: the exact accepted-comment semantics
of the lint (inside-block first-statement comments, distance
edge cases) are approximated by the static rule, so the precise
count under a real clippy run may move by a few sites — but the
direction (78 uncovered sites, not zero) is far outside any
epsilon. The one-command reproduction for the owner's toolchain:

    cargo clippy --all-targets --all-features -- \
      -W clippy::undocumented_unsafe_blocks

Resolution path left to the owner (the gate-inventory freeze
governs standing-lint wiring, and annotating 78 sites is a
multi-hour diff this audit will not ship unverified — no Rust
toolchain exists on the audit host to prove the deny would not go
red): either wire the lint as a standing lane and annotate the
census's uncovered sites, or re-spell the LTS-14 row's basis to the
convention the tree actually holds (doc-level safety rationale,
zero production unwraps, default-group clippy clean). Both are
recorded as the honest state; neither was imposed from here.

## 6. Hygiene, optimization, LTS failure modes — the peak-skips

- Hygiene: the kernel and userspace trees sit under the 600-line
  cap with zero files over (the gate counts 273 .rs files, all
  green), headers 464/464, no TODO/FIXME debt, and the module
  splits (`drr_flow_*`, `enforce_helpers`, `quic_l4`) are cohesion
  splits through their module roots, not function bisections. The
  dup census found no copy-paste pair across the parse cores — the
  `pack8_bounded`/`flow_key_bounded`/`scid_len_byte` family is
  shared, not duplicated. PEAK — nothing to hunt.
- Optimization: the hot path already carries the law (the
  NIGHT-lts-2 reorder saved a timestamp and a map read per
  unpolicied packet — the majority), `MAX_ENFORCABLE_BURST` bounds
  the arithmetic, and the release profile is maxed (opt-level 3,
  fat LTO, one codegen unit). Any further micro-opt on the render
  side would be unverifiable on this host (no toolchain, no frame
  A/B possible), and unverifiable optimization claims are exactly
  what the honesty rule forbids. PEAK — skipped with reason.
- LTS failure modes: the `--during` comparator is a totality law
  (`saturating_mul` / `wrapping_sub` / `% NS_PER_DAY` — no panic,
  no hang, no domain escape from any u64 input), the margin law
  biases under-enforcement (a clock accident may briefly
  under-limit, never lock a host out), the wall-offset bridge is
  re-stamped by every enforcement command's attach-reuse (the CLI
  visit is the refresh channel — a documented trade), and the
  update-cooldown stamp fails open on a missing or broken stamp.
  The cgroup-id u32 keying truncation is a design constant applied
  identically by the kernel reader and the userspace writer — the
  alias horizon is the kernfs inode counter, not a live-host risk.
  PEAK — every horizon found already has its doc.

## 7. The verdict summary

| Dimension | Verdict | Evidence |
|-----------|---------|----------|
| Kernel stability and crash | PEAK | zero panic family; every divisor guarded or constant; the 5.13 floor law end to end; the wrap horizons documented |
| Userspace stability | PEAK | test-only unwraps; checked-then-expect pins; the spawn census all pinned |
| Kernel security | PEAK | the trust-boundary clamp, the TOCTOU belt, the atomic booked drop, the verified-removal pin discipline |
| Hygiene | PEAK | cap green, headers green, cohesion splits, zero dup pairs in the parse cores |
| Optimization | PEAK, skipped with reason | the reorder law already landed; further micro-opts unverifiable without a toolchain and frame A/B |
| LTS failure modes | PEAK | the totality law, the margin bias, the refresh channel, the fail-open stamps |
| Memory-safety claim (LTS-14 row) | FINDING, owner-call | the claim's lint has no standing wiring and the mechanical census counts 78 uncovered of 120; the audit-doc record is the correction vehicle |

The one find is a claims-versus-instrument gap, not a memory-safety
defect: the unsafe sites carry their rationale at the doc level and
every other crash class held. The audit shipped zero code changes —
the sharpest skill held on every dimension the mandate named, and
the record's value is the evidence plus the one claim now honestly
priced.

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
