<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# night-audit-1 — the innovations ledger vs the frontier list: the implemented are documented, the deferred now have their ledger

Date: 2026-11-13. The owner's mandate, in shape: a master depth
audit — are the innovations implemented and documented on
`docs/INNOVATIONS.md`? Complete whatever is missing "for already
usage LTS and learning future", and depth-audit that all supermassive
tests have been updated to use the new innovations. The reference
list: the night-frontier-1 frontier of nine asks (four implemented,
five not).

## The frontier list, reconciled against the tree

| # | Frontier ask | State | Where it lives |
|---|--------------|-------|----------------|
| 3 | eBPF histogram / heatmap observability | implemented | INNOVATIONS #17 (the depth histogram, `ebpf/src/hist.rs`, schema v34, night-frontier-2B) |
| 7 | Adaptive BDP / measured RECWN | implemented | INNOVATIONS #14 (schema v25, night-spark-2) |
| 8 | sk_storage migration | implemented | documented inside #14/#15 (schema v32, night-T-4 — the RECWN twin's migration, kernel-managed row lifecycle) |
| 9 | netns:// and iface:// native targets | implemented | INNOVATIONS #16 (night-netns-1 + the iface twin) |
| 1 | BPF CO-RE | deferred | the core-1 audit's measured NO + the new Deferred-by-verdict ledger |
| 2 | XDP integration | deferred | the new Deferred-by-verdict ledger |
| 4 | Per-tenant hierarchical fair-share | deferred | the new Deferred-by-verdict ledger |
| 5 | LSM hook enforcement | deferred | the new Deferred-by-verdict ledger |
| 6 | BPF token (kernel 6.9+) | deferred | the new Deferred-by-verdict ledger |

The ledger had grown past the mandate's own reference point: "The
fourteen, in dependency order" is seventeen now — #14 RECWN, #15
egress socket pacing (schema v27, night-spark-5/6, an ask the frontier
list predates), #16 the namespace/interface resolvers, #17 the depth
histogram. The four implemented frontier asks each carry their entry
with the schema version, the map shapes, the rootless test pins, and
the live proof named.

## The supermassive coverage audit (the mandate's second half)

Each implemented innovation's fleet verification lane, checked at
HEAD:

- **supermassive-verify.yml** is the estate lane — its own header
  names it: "the estate sells — v31 adaptive BDP, v32 sk_storage, the
  netns:// and iface:// resolvers, the quota-saver A/B ground truth —
  deserve a lane". Phase 1 builds the netns+veth lab on the runner
  (`ip netns add rtt`, the veth pair, the dedicated cgroup), the
  netns members are exec'd through `systemd-run` so the netns://
  resolver's single-cgroup verdict lands, and the expected-failure
  probes (empty netns, empty VRF) print their exit codes as
  assertions.
- **The depth histogram** rides the supermassive server phase
  (night-verify-1): the 1tb clamp (a ceiling loopback physics cannot
  touch, held purely so the pin session survives the skeleton
  teardown), bulk loopback traffic on a worker thread, the
  `ee --depth --print-json` read taken MID-TRAFFIC past the depth
  command's liveness gate, asserting `sample_shift` pinned at 10,
  `samples == sum(buckets) > 0`, and non-null quantiles. The upload
  and srtt halves stay named-not-asserted (loopback does not
  guarantee them) — the honesty is part of the pin.
- **The probe family**: `scripts/bench/recwn-probe.sh` (the RECWN
  live proof) and `scripts/bench/edt-probe.sh` (the pacing lane's
  `ss` token, the two iproute2 dialects, the pinned-max exactness
  witness).
- **Rootless pins per innovation**: `test/ebpf/limiter/recwn_tests.rs`
  (the clamp table + the userspace-twin parity),
  `test/ebpf/identity/netns_tests.rs`, `test/ebpf/identity/iface_tests.rs`,
  `test/ebpf/limiter/hist_tests.rs` + `hist_raw_tests.rs` + the
  `depth_json_tests.rs` render pins.

Verdict on the mandate's second half: the supermassive tests USE the
new innovations — each implemented ask has a fleet lane, a probe
script, and rootless pins; nothing is implemented-but-unverified.

## The gap found and closed

The five deferred asks existed only in the session record: CO-RE
carried its own signed audit (NIGHT_CORE_1_CO_RE_PORTABILITY_AUDIT,
verdict NO with the one-field census), but XDP, per-tenant
fair-share, LSM, and BPF token had no tree home at all — a future
maintainer would re-derive them from scratch, exactly the rot the
ledger exists to prevent. The fix is docs-only: the new
"Deferred by verdict" section in `docs/INNOVATIONS.md` — five rows,
each with the ask, the measured state, the reason it is not built,
and the condition that would reopen it. The section sits beside
"Retired by verdict" (the tried-and-removed) so the two honest
rejection classes read as the pair they are: retired = was built and
cut; deferred = measured and deliberately never started.

## Verdict

The innovations ledger is COMPLETE against the frontier list: the
implemented four (+ pacing) documented and fleet-verified, the
deferred five now carried with their reopen conditions. Zero code
changes — docs only (one INNOVATIONS section, this record, the map
row). The LTS reading: a maintainer in 2030 inherits not just the
seventeen built innovations but the five deliberate non-builds with
their evidence — the ledger teaches the future instead of hiding it.

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
