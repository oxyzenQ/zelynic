<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-reliable-lts-1 audit — is this software ready to be trusted for a decade?

> Audit date: 2026-11-08 (night-reliable-lts-1, the owner's LTS closure
> task). Scope: ONE question — is zelynic ready to be trusted by a
> stranger who downloads it in 2030, on a kernel that does not exist
> yet, with no owner alive to patch it? This is a VERIFY task under
> the peak-skip protocol: a surface that is already LTS-ready gets
> "LTS-ready, skipped" with proof; a future break risk gets its
> failure mode and its minimum mitigation. No feature work. Audited
> at 5e7337d (the clone the audit read; the report itself lands as
> this task's single `research:` commit). Method: the record was read
> first (STABILITY, SAFETY_ANALYSIS, KERNEL_COMPATIBILITY,
> DEPENDENCY_AUDIT, LONGEVITY, QUOTA_SAVER_PHYSICS, CROSS_DISTRO_RESULTS,
> CLAIMS_VERIFICATION, the NIGHT_TOTAL_LTS and NIGHT_DRAGON_LTS
> series, NIGHT_SKILL_1, NIGHT_HUNT_43), then the code each answer
> rests on was opened (kernel_floor.rs, host_caps.rs, capabilities/,
> session.rs, deny.toml, both Cargo.locks, the CI workflows, the
> gate scripts), and the three gates were run live on the audited
> tree. The honest boundary: this host has no root and no kernel
> 5.15, so the live-eBPF legs remain CI-owned — the standing boundary
> NIGHT_DRAGON_LTS_2C and NIGHT_TOTAL_LTS_14 record.

## Phase 1 — the LTS risk table

| Surface | Current posture | The proof/audit that signed it | The residual risk (named, not hidden) |
|---|---|---|---|
| Kernel floor and helper set (5.15.0) | LTS-ready, skipped | KERNEL_COMPATIBILITY.md verified matrix (5.15-7.1), every helper's introduction kernel cited in-tree; STABILITY.md honest limit 1 | Verifier drift on an unlisted future kernel: the object refuses loudly, never misbehaves (STABILITY.md:78-86); 6.1/6.6 LTS and 6.8 carry no RUNTIME record (build-only) — KERNEL_COMPATIBILITY.md:173-175 |
| Unsupported-kernel refusal | LTS-ready, skipped | src/ebpf/kernel_floor.rs:57-74 — the floor verdict refuses below 5.15 with the actionable fix, refuses an UNPARSABLE release honestly, unit-pinned (kernel_floor.rs:76-129); host_caps.rs:161-178 orders the Layer-0 refusals (floor, cgroup v2, root) | None on the refusal path — the failure mode is a loud branded error, never a silent no-op |
| Build reproducibility (the prebuilt lane) | LTS-ready, skipped | The three-arm parity contract (check-commit-gate.sh:10-17: commit time hook, push time wholesale workflow, ship time release.yml:377-378 + crates-io.yml); blake3 tree pin + phantom-pin guard (check-prebuilt-parity.sh); byte-identical forced-rebuild evidence 2026-09-27 and again at think-like-light-years-3 and dragon-lts-2c | Dated-nightly aging: the archived pin receives no fixes; from-source builds stall until a re-pin — build-time only, bites loudly, bootstrap detects and repairs (STABILITY.md:87-94) |
| Distro future | LTS-ready, skipped | CROSS_DISTRO_RESULTS.md 6/6 distros (5.13 → 7.1), BPF bytecode portable across that span (:240-251); the one-file tarball needs no toolchain (:253-267); musl static is the only libc shape, x86-64-v3/v4 baselines, v1 retired (release.yml:188-203) | Intel CPU, ARM64 (no cross-compile yet), Ethernet, and multi-interface runs carry no record (KERNEL_COMPATIBILITY.md:179-187); the CROSS_DISTRO rows predate the phase-3 embedded packaging (its header note) |
| cgroup v2 dependency | LTS-ready, skipped — a HARD dependency, not a soft assumption | host_caps.rs:161-178 refuses at attach when v2 is absent ("first miss" ordering); KERNEL_COMPATIBILITY.md:141-145 documents the check command; :206 records "will error on attach" for v1 | cgroup v1 hosts are refused outright — documented, intentional (the v1 lane does not exist to rot) |
| bpffs prerequisite | LTS-ready, skipped — documented with the recovery command | KERNEL_COMPATIBILITY.md:221-222 and the "Failed to pin map" troubleshooting block :263-270 (the exact mount command); bpffs.rs:34 detects a REAL mount via statfs BPF_FS_MAGIC, not a directory's existence | None — the failure is loud and the first command is printed |
| Dependency rot | LTS-ready, skipped | DEPENDENCY_AUDIT.md: six direct deps across the workspace, every one with live call sites (:70-108); deny.toml bans chrono + the full serde family (:61-89) with sources locked (:93-97); the JSON lane is hand-written (src/json/); root lockfile 44 crates, zero chrono/serde/time entries (re-grepped this audit) | The aya-build build-time chain (10 crates incl. serde) executes at every eBPF compile — upstream framework design, accepted as risk with three mitigations (committed lockfile, --locked CI, RustSec scan), DEPENDENCY_AUDIT.md:97-108 |
| Maintenance burden (long-uptime endurance) | LTS-ready, skipped | STABILITY.md silent-killer inventory (:171-359, verdict line 355) and the blade-6 table (:374-386): memo LRU 4096 generation-stamped, cookie/flow maps LRU 4096, session ledger bounded by MAX_TRACKED_CGROUPS 4096 (session.rs:156), policy/bucket/ring/stats reclaimed on unstrict/recover (reclaim.rs:42-45); hunt-43's two-signal zombie walk (zombie.rs) with the live supermassive stage | Hunt-43's three named residuals stand: a stale-pin-epoch zombie waits for manual `recover`; an alive-unresolvable-quiet root retires with the dead (requires an app-level unshare under a standing policy); a status sweep leaves the empty skeleton pinned for the next removal-family visit (NIGHT_HUNT_43 section 8) |
| Scheduled audits that fire without the owner | LTS-ready, skipped | audit.yml: every push + PR + weekly Monday cron (advisory DB watch, `cargo audit --deny warnings` + `cargo deny check`); codeql/fuzz/maintenance/miri weekly crons; the wholesale gate suite unfiltered on every push (MAINTENANCE.md:41-50 records the whole table) | The monthly/quarterly deep-audit cadence is an OWNER ritual by design (MAINTENANCE.md:271-274) — no machine can judge purpose drift; two doc surfaces still say "daily" of audit.yml (deny.toml:6-7, DEPENDENCY_AUDIT.md:283) where NIGHT-improve-38 deliberately set the weekly clock (audit.yml:24-28) — a wording nit with zero functional impact, named in Phase 3 |
| User trust (claims and grammar) | LTS-ready, skipped | CLAIMS_VERIFICATION.md: every public claim maps to a LIVE harness, a rootless PIN, or a CI lane (:33-103); the CLI grammar is frozen as a contract (PHILOSOPHY.md:75-83, docs/RULES.md); the peak declaration carries closure rules (QUOTA_SAVER_PHYSICS.md:306-309) | The quota-saver claim is one-host/one-link by its own conditions of validity; it transfers by the formula and re-measures by the harness — printed, not hidden (QUOTA_SAVER_PHYSICS.md:303-305) |

## Phase 2 — the five questions

### Q1: Will this run on a kernel that does not exist yet? — YES, and it refuses loudly where it cannot

- **The floor is enforced, not assumed.** `KERNEL_FLOOR = (5, 15)`
  (kernel_floor.rs:21) is consumed by the one probe every attach
  decision rides; below it the refusal names the floor AND the fix,
  and an unparsable release string is refused honestly rather than
  guessed (kernel_floor.rs:57-74, pinned by the tests at :76-129).
  The doctor rides the same ungated law, so even a half-life build
  answers the floor question identically (kernel_floor.rs:14-18).
- **The 6.8 helper wall is the worked example of the future-kernel
  failure mode — and it is CLOSED.** When 6.8 moved three helpers
  out of cgroup_skb's reach, the load failed with EINVAL; the fix
  dropped the dead event branch entirely so the observer's helper
  set is legal from 5.15 through 6.17+ (KERNEL_COMPATIBILITY.md
  :279-294). The lesson is institutional: the kernel-facing surface
  stays inside the helper set every matrix kernel allows, so the
  next wall has less to knock down (LONGEVITY.md section 2).
- **The build is reproducible from source.** The eBPF objects ride a
  dated nightly pin + bpf-linker 0.11.1 as a validated pair
  (STABILITY.md:36-47); host-CPU and host-linker rustflags are
  stripped from the nested build so any host produces identical
  objects (STABILITY.md:60-64); the prebuilt lane's blake3 tree pin
  is enforced at commit/push/ship (check-commit-gate.sh:10-17,
  release.yml:377-378) and ran GREEN live in this audit. The
  rebuild-and-byte-compare was proven twice on record (2026-09-27
  forced rebuild; the dragon-lts-2c re-pin, objects byte-identical).
- **A future maintainer can rebuild if the archived nightly ever
  disappears.** The documented path is one command
  (`scripts/dev/bootstrap-ebpf.sh`, which also detects and repairs a
  DAMAGED pin) plus the manual alternative naming the exact toolchain
  and the bpf-linker release URL (KERNEL_COMPATIBILITY.md:236-255);
  the version-sync gate holds pin == MSRV == CI version so a re-pin
  cannot drift silently (gate 10, check-rust-version-sync.sh). The
  honest limit is named in the record: release binaries need NO
  toolchain to exist — only from-source builders do (STABILITY.md
  :49-71, the LTS isolation contract).

### Q2: Will this run on a distro that does not exist yet? — YES; the kernel is the contract, the distro is noise

- The verified matrix spans 5.13 → 7.1 across six distros with real
  enforcement, and the BPF bytecode loaded unmodified across all of
  them (CROSS_DISTRO_RESULTS.md:79-88, :240-251) — the property a
  future distro inherits, since its kernel will sit inside (or above)
  the span and the UAPI is the stable ABI (LONGEVITY.md section 1).
- **cgroup v2 is a hard, enforced dependency**: Layer 0 of the attach
  probe refuses on its absence before any BPF work (host_caps.rs
  :161-178), the check command is documented (KERNEL_COMPATIBILITY.md
  :141-145), and v1 is a named non-support (:206). No silent break
  shape exists.
- **bpffs is a documented prerequisite with the recovery command in
  the troubleshooting record** (`sudo mount -t bpf bpf /sys/fs/bpf`,
  KERNEL_COMPATIBILITY.md:263-270), and the detection reads statfs
  magic so an empty directory never masquerades as a mount
  (bpffs.rs:23-34).
- **The binary shape is chosen for distro independence**: musl
  static is the ONLY libc shape (night-dragon-maintenance-6,
  build.sh:482-485), shipped as x86-64-v3 and v4 baselines with the
  v1 baseline retired (release.yml:188-203) — zero glibc coupling,
  the shape the 2030 stranger downloads.

### Q3: Will the dependencies rot? — The surface is six crates, watched by machines

- Every direct dependency's live call sites are recorded and were
  re-verified by grep in the standing audit (DEPENDENCY_AUDIT.md
  :70-108); the contract lives in Cargo.toml itself (:160-164: zero
  call sites means removed, feature lists pinned).
- The chrono ban is the Hinnant-clock precedent: wall-clock math is
  in-house (`civil_from_days` in build.rs, UTC-only, std-only), the
  crate is banned in deny.toml (:61-68), and neither `chrono` nor
  `time` exists in either lockfile (root: 44 crates, ebpf: 31 —
  re-grepped this audit).
- The JSON lane is hand-written in src/json/ (parse.rs Value tree +
  write.rs escape law); serde, serde_json, serde_core, and
  serde_derive are all banned (deny.toml:69-89), the ban is
  live-fire verified (DEPENDENCY_AUDIT.md:293-304), and the root
  lockfile re-verified serde-family-free this audit. The one serde
  consumer is the ebpf build-time aya-build chain — accepted,
  documented, outside the root scan (DEPENDENCY_AUDIT.md:97-108).
- **The advisory watch fires without the owner**: `cargo audit
  --deny warnings` + `cargo deny check` run on EVERY push and PR and
  on a weekly Monday cron that watches the advisory DB itself
  (audit.yml:19-29, :75-93); maintenance.yml keeps the lockfile a
  living surface weekly, behind the full test + deny matrix
  (maintenance.yml:13, DEPENDENCY_AUDIT.md:129-131); scanner
  binaries are version-pinned so red means a new advisory, never a
  new scanner (audit.yml:72-74).

### Q4: Will the maintenance burden outlive the owner? — The bounds are structural, the sweeps are wired, the clocks fire alone

- Every long-lived structure is bounded by construction and the
  blade-6 table names the bound AND the pin for each: memo LRU 4096
  generation-stamped, per-socket and per-cgroup maps LRU 4096,
  session ledger capped at MAX_TRACKED_CGROUPS 4096 (session.rs:156),
  rings and stats census-bounded by the 1024 policy map, u64 kernel
  counters wrap-coherent end to end (STABILITY.md:374-386, :129-145).
  NIGHT_SKILL_1 re-opened the table's anchors at 2026-11-07 and none
  had slipped.
- **Zombie/orphan cgroups are collected automatically**: the
  two-signal liveness walk (no identity entry AND a full 8s ring
  horizon of silence; traffic always vetoes) rides the status visit
  and all three apply-family tails (NIGHT_HUNT_43:42-62), pinned
  kernel-side and render-side (zombie_tests.rs, baseline_retire_tests.rs),
  proven live by the supermassive stage. The stale-epoch exception
  falls back to manual `recover` — named, bounded, honest.
- **The parity lane is enforced three ways** — commit time (the
  self-installed pre-commit hook), push time (the unfiltered
  wholesale workflow), ship time (crates-io.yml + release.yml
  :377-378) — check-commit-gate.sh:10-17, the exact three arms.
- **Scheduled audits fire without the owner**: the weekly Monday
  family (audit, CodeQL, fuzz deep session, dependency maintenance,
  miri) plus the unfiltered every-push battery (MAINTENANCE.md:41-50).
  The monthly/quarterly deep audits are owner rituals by design —
  the record says so plainly (MAINTENANCE.md:271-274) rather than
  pretending a cron can judge purpose drift.

### Q5: Will the user's trust survive a future capability change? — The peak is fenced by written rules, the grammar by a contract

- **The post-peak rule exists where the peak was declared.** The
  quota saver's closure rules govern the claim itself: no row added,
  no number revised, no rate claimed without a harness run — "new
  wire, new run — the harness is the only door" (QUOTA_SAVER_PHYSICS.md
  :306-309). The conditions of validity are printed with the claim
  (:303-305). The kernel-break case has its worked precedent: the
  6.8 wall was answered by REMOVING a dead branch, not by adding a
  feature (KERNEL_COMPATIBILITY.md:279-294); the security-fix case
  rides the standing gates (undocumented-unsafe deny gate,
  dragon-lts-2c); and the peak-skip protocol governs every verify
  task in the lineage (NIGHT_SKILL_1:9-11). A feature cannot re-enter
  a peaked surface without contradicting one of these written rules.
- **The CLI grammar is a documented contract**: verbs are named once
  and never renamed, expansion grows as one honest flag, scripts
  written against a release keep working across the line
  (PHILOSOPHY.md:75-83; docs/RULES.md; the surface/redirect/hidden-vocab
  test pins hold the door).
- **Every public claim maps to a verifier**: the ledger's five
  headline claims run LIVE on every CI push, the full inventory is
  PIN/CI-backed, and the re-proving commands are printed for the
  reader (CLAIMS_VERIFICATION.md:33-103). Nothing is claimed without
  a mechanism; "a claim with no mechanism is marketing" (:12-13).

## Phase 3 — residuals

**None requiring code.** No surface failed its question; no
failure mode lacks a documented bound, a first command, or a named
owner. Zero code changes, zero schema versions, zero new attack
surface. The observations this audit adds to the record — all
already bounded in the literature, listed so the next auditor does
not re-derive them:

1. Two doc surfaces say "daily" of the Dragon Guard audit run
   (deny.toml:6-7, DEPENDENCY_AUDIT.md:283); the clock NIGHT-improve-38
   deliberately set is weekly (audit.yml:24-28), and MAINTENANCE.md:45
   already records it correctly. Wording drift only; the machine
   behavior is the documented weekly one. Left untouched: the
   disclaimers cover doc staleness, the canonical cadence table is
   right, and a wording patch is not an LTS residual.
2. KERNEL_COMPATIBILITY.md's honest "no runtime record" rows (6.1,
   6.6, 6.8-runtime, Intel, ARM64, Ethernet) remain the matrix's open
   cells — named gaps in COVERAGE, not in the design; the floor and
   refusal behavior do not depend on them.
3. The dated-nightly aging limit (build-time only), the aya-build
   accepted risk, hunt-43's three named residuals, and the
   supermassive `settle()` sleep (dragon-lts-2g) stand as documented.

## Phase 4 — the LTS verdict

**zelynic is LTS-ready on the five axes.**

- **Kernel future**: YES — the 5.15 floor is enforced with a loud,
  actionable refusal; the helper set is legal across the whole
  verified span; the 6.8 wall is the closed worked example of the
  drift response; the build reproduces from source under a dated pin
  with a three-arm parity gate, and the shipped binary needs no
  toolchain to exist (STABILITY.md:49-71).
- **Distro future**: YES — musl static v3/v4, one file, no toolchain,
  bytecode proven portable 5.13 → 7.1; cgroup v2 and bpffs are hard,
  enforced, documented prerequisites with recovery commands.
- **Dependency rot**: NO PATH — six direct deps with recorded call
  sites, banned regressive crates, locked sources, weekly + per-push
  advisory watches that fire without the owner, and a policy that
  prefers std/libc/in-house before any new crate.
- **Maintenance burden**: BOUNDED — every long-lived structure is
  bounded by construction with a named pin; zombie collection is
  automatic and two-signal; the parity lane is enforced at commit,
  push, and ship; the scheduled guard family fires weekly alone, and
  the owner rituals that remain are documented as rituals.
- **User trust**: FENCED — the frozen CLI grammar is a written
  contract; the peak claim is closed under written closure rules
  with its validity conditions printed; every public claim maps to a
  LIVE/PIN/CI verifier; and the audits are dated immutable records,
  so the reasoning outlives the author (LONGEVITY.md section 4).

The evidence: the Phase 1 table (each surface, its signed audit, its
named residual), the file:line citations in every Phase 2 answer, and
the gates run live on the audited tree this session. The residuals:
none requiring code — three named observations, all already bounded
in the record (Phase 3). The recommended next action: **none — LTS
confirmed.** The next runtime rows belong to the matrix's open cells
whenever the owner's hardware offers them; that is coverage, not a
defect in this record.

## Gate results

- `./scripts/gate-keepers.sh`: 25 passed, 0 failed, 1 skipped
  (shfmt not installed in this seat — the CI wholesale seat installs
  every pinned tool and enforces it on every push). The prebuilt
  parity section ran GREEN in the battery: objects + manifest +
  ebpf/ tree pin all agree.
- `./scripts/build.sh check-all -q`: exit 0 (inside the 2-minute
  cap; clippy/fmt/test/policy/version lanes all green; cargo-audit
  and cargo-deny steps skipped locally — CI owns both weekly and
  per-push).
- `cargo test --features ebpf --locked`: 1089 passed, 0 failed,
  4 ignored (the benchmark harnesses, by design) across the lib and
  integration suites.
- Toolchain note: bpf-linker 0.11.1 was installed this session via
  the repo's own `scripts/dev/bootstrap-ebpf.sh`; the flagship musl
  build completed in 49s; no root and no kernel 5.15 exist on this
  host, so the live-eBPF legs (supermassive, endurance, VM matrix)
  remain CI-owned — the standing boundary of the whole audit series.

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
