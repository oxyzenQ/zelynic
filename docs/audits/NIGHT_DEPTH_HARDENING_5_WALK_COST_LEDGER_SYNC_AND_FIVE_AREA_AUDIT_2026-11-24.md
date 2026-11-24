<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# night-depth-hardening-5 — the walk-cost ledger sync, and the five-area LTS cross-check at the Z17 tree

> Audit date: 2026-11-24 (night-depth-hardening-5, the fifth rung of
> the depth-hardening series: hardening-1 landed the compositional
> determinism pins, hardening-2 the sweep, Z1 the reproducible-release
> chain, Z2 the object-integrity stamps). Scope: the owner's mandate —
> precision and deterministic output for every distro at the 5.15+
> floor, depth hardening for the existing innovations at LTS usage,
> ultra-scale server endurance, and the five-area cross-check
> (stability, hygiene, optimization, security, LTS) with the
> skip-if-peak protocol absolute. Audited at c3bbc58 (the Z17 landing,
> 13/13 CI lanes green) plus this session's fixes (f3a3286, 593b0d3,
> 5f74917). Method: every prior verdict read as the last known state
> (the 2026-11-10 five-area close, the 2026-11-18 infra and sharpest
> skill passes, the 2026-11-22/23 defense and speed-law records); the
> fresh work went where the tree had MOVED since those records — the
> Z17 gated belt, the proofs restructure, the ledger raise — and the
> five areas were re-censused live with greps and instruments at the
> exact tree. The honest boundary, stated once: this seat has no
> root, no BPF attach, no KVM — the live eBPF legs stay CI-owned (the
> tip's own Supermassive Verify run priced the estate green; the
> runtime-verification and verifier-budget jobs were read from the
> run's logs, not assumed). The toolchain was bootstrapped fresh in
> the seat (the 1.98.1 root pin, the nightly-2026-09-18 ebpf pin,
> bpf-linker 0.11.1, b3sum 1.8.7) and the prebuilt lane's parity gate
> ran green on the edited tree.

## 1. The finds — three, all the same class, all fixed

The class: the Z17 landing moved the walk cost, the ledger recorded
it (never silent, per its own growth law), and the tiers BELOW the
ledger did not follow. Three finds, one root cause:

1. **The source tier's stale present-tense pair** (ebpf/src/
   enforce_helpers.rs:18-23): the callee-shape block named the
   enforcer's walk at "141893 / 133020" with no date qualifier while
   presenting the numbers as the ceiling the mirror's reopen
   condition names — the shipped walk measured 141981 (the gated
   belt's verdict gate, +88) and the ul row moved to its ratcheted
   132960. Fixed in 593b0d3: the block now dates the Z14 measurement
   (run 45209186940) and carries the post-belt pair with both ledger
   events named — the comment names the events, the ledger owns the
   values.
2. **The ratchet law's encouraged follow-up unexecuted** (scripts/
   supermassive/verifier-budget-ledger.json): the tip's own green
   run (45374359811, job 138388443546, head envelope, kernel
   7.3.0-11-generic) measured enforce_ul at 132960 against its
   133020 pin, 60 states under — the ledger's ratchet law names
   lowering the pin to the measured number as "the encouraged
   follow-up", and the Z15a precedent executed the same shape.
   Fixed in f3a3286: one history row, kind "lower", the run named;
   the rootless self-test green (6 programs).
3. **The raise named only in the ledger**: the Z17 +88 dl raise
   (run 45370360921) had no sentence at the census record, D17's
   landing, or this file's Z17 entry. Fixed in 5f74917: one tight
   sentence at each tier naming the pair (141981 / 132960 on the
   head envelope), the raise, and the ratchet with their runs.

## 2. The prebuilt lane's byte-identity proof (the instrument that de-risked the comment edit)

The manifest's `ebpf_tree_blake3` pins the whole ebpf/ source tree
(comments included), so the comment edit forced a lane refresh
through the one writer. The rebuilt limiter object came back +8 file
bytes (925584 -> 925592) — a shape that HAD to be explained before
commit. The section-level compare (a direct ELF parser over the
EM_BPF objects — the host binutils refuses machine type 247):

- `.text` 9784 bytes: IDENTICAL. Every program section identical
  (cgroup_skb/egress 24752, cgroup_skb/ingress 25184, sockops 1096,
  maps 1064, license). `.BTF` 31120 identical (the type graph the
  verifier reads, func shapes included). `.maps`, `.rel.text`, and
  every program relocation identical. `.symtab`, `.strtab` identical.
- The only moving class: DWARF line-info (`.debug_line` +10,
  `.debug_info` +1, `.debug_abbrev` +2, `.BTF.ext`'s line rows) —
  the six added comment lines shifted the file's line numbers. The
  +8 file bytes are alignment over that drift, data and never code.
- The observer object: byte-identical whole.

The verifier prices `.text` and `.BTF`; both identical means the
ledger pins stay valid with no re-arming. The proof rides the task-2
commit message and this record; the parity gate ran green on the
result. Byte-reproducibility is NOT claimed as a contract — the
gate's own stance stands (pin the tree hash, the deterministic
surface); the section compare is the audit instrument that answers
"did codegen move", asked once, answered by evidence.

## 3. The five-area cross-check (skip-if-peak, every verdict carried)

| Area | Verdict | The evidence, live at this tree |
|---|---|---|
| Stability and crash | PEAK — no change warranted | The panic family census (unwrap, expect, panic!, unreachable!, todo!, unimplemented!) over ebpf/src: ZERO hits at c3bbc58, re-run live. The userspace half's census holds at the classified set (the two cfg(test) modules, the three documented-invariant expects: probe_role.rs:118, drift.rs:333, pool.rs:106 — the helper_ladder.rs:376/384/392 "checked" expects are inside the test module). The Z17 belt adds no division (compare + CAS only), so the 19-site guarded-division census carries forward. The E2E family, the C77 forensic rig, and the runtime verification all green on the tip; the belt's residual is named, quantum-bounded, and theorem-pinned |
| Code hygiene | PEAK — no change warranted | Zero TODO/FIXME/XXX/HACK markers tree-wide. Every allow(dead_code)/allow(unused) site explained at its line (the userspace-test-tree compilation class, the dormant-lane class). The 600-line cap gate-held; the audits-index and docs-index gates green in CI. The Z17 proofs restructure split at the cap cleanly (the sampler out of the laws file) |
| Optimization | PEAK — no change warranted | The walk cost is ledger-guarded at the exact collapsed shape (141981 / 132960, both pins at measured numbers after this session). The belt's per-packet cost is the gated verdict the live lanes priced (sustain medians restored to 79-83%). No profiling data in the seat; no hot-path change this session (the comment edit proven codegen-neutral by the section compare), so the 10s A/B benchmark is skipped by the documented docs-only rule |
| Security hardening | PEAK — no change warranted | SOLID_DEFENSE_1 (the AXP1-ZnQ sentinel) and 2 (the D5 GPG commit binding) landed 2026-11-22/23 — the security sweep is days old. CodeQL, Security Audit, and the advisory scans green on the tip. The fuzz tier carries the hostile seeds (RLO/bidi masquerade, OSC52 clipboard injection). The D4/D2 object-integrity stamps make any byte patch fail by name. Every uses: SHA-pinned except codeql's documented moving tag. The Z17 delta adds no input-parsing surface |
| LTS stability | PEAK after this session's sync | The growth-law events now named at every tier that speaks the numbers (the finds above). The determinism mandate is hardening-1's pinned law: byte-identical text and JSON across the supported distros (5.15+), the total sort orders (display_order.rs, the connections sort pair), the compositional pins proving input-order variance absorbed. The floor envelope honest by construction (verified_insns absent pre-v5.16 — the load-proof gate is the floor's verdict, confirmed green in the tip's own verifier-budget floor leg). The two documented boundaries stand: the memory-ordering tier unchecked, the two-word belt atomicity floor priced |

## 4. The residual ledger

Nothing carried forward. The three finds are fixed in this session's
commits; the five areas hold their peaks with the reasons named; the
walk-cost numbers now agree at every tier (the ledger canonical, the
comment and the docs naming the events). The next ratchet, if any,
belongs to a future measured run — the ratchet law's own shape.

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
