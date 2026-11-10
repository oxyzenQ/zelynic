<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-zen-lts-1 final audit — the all-docs consistency pass and the 5-area verification close the book

> Audit date: 2026-11-10 (night-zen-lts-1). Scope: the final audit
> before the project closes its active work — (1) an all-docs
> consistency audit across every surface the four recent doc-changing
> tasks touched (night-quota-audit v29, night-recvn-audit v30,
> night-peace-1, night-price-1, plus night-ci-1's CI paragraph), and
> (2) a verification of the 5-area infra posture (stability, hygiene,
> optimization, security, LTS) against the six dated audits that
> signed it. This is NOT a re-audit from scratch: the peak-skip
> protocol is absolute, every prior verdict is read as the last known
> state, and a surface already at peak gets "peak — no change
> warranted" with proof. Method: the six prior audits were read in
> full first; the ten doc cross-checks (A-J) and the five areas were
> each verified by targeted reads and greps with file:line evidence;
> every claimed drift was then re-verified by eye at the cited line
> before any edit. The honest boundary, stated once: this sandbox has
> no root, no BPF attach, and no KVM (uid non-zero), so the live eBPF
> legs stay CI-owned as always; the Rust toolchain was bootstrapped
> fresh here (the 1.98.1 pin, bpf-linker 0.11.1, b3sum 1.8.7,
> markdownlint-cli2 pinned to the CI's own 0.18.1) and the full
> battery ran green on the audited tree.

## 1. The audit inventory (the six signed records, read before anything)

| Audit | Area | Verdict (signed) | Could v29/v30/peace/price invalidate it? |
|---|---|---|---|
| NIGHT_SKILL_1_MASTER_DEPTH_PEAK_AUDIT_2026-11-07.md | mechanism, scale, endurance, skill — peak verify | "peak — skipped, no change warranted" on all four axes | Code claims re-verified intact (window law, hooks, LRU/1024 ceilings, no-lock datapath). Its telemetry inventory line (RECWN v25/ECN v26/EDT v27/telemetry v28) and the RECWN-booking decomposition caveat are superseded by v29/v30 — historical record, correctly stale |
| NIGHT_SKILL_2_HARDWARE_AND_ACCELERATION_AUDIT_2026-11-08.md | hardware-agnostic YES (named boundaries), acceleration NO | "Q1 YES with named boundaries / Q2 NO" | Same split: hook/attribution/no-interface-names/Policy-bracket claims re-verify at their cited lines; the signed "EDT/ECN/RECWN split" telemetry sentence is superseded by v30's one-for-one booking — historical record, correctly stale |
| NIGHT_RELIABLE_LTS_1_DECADE_TRUST_AUDIT_2026-11-08.md | LTS five axes | "zelynic is LTS-ready on the five axes" | NO — re-proven held below (§7) |
| NIGHT_PERF_1_THREAD_AND_DEATH_AUDIT_2026-11-08.md | thread budget, CLI death/zombie | "every surface exits clean on every reachable path" / "PEAK" | NO — thread census re-verified (two spawns, spinner.rs + probe_role.rs) |
| NIGHT_PERF_2_LIVE_MEASUREMENT_CORRECTION_2026-11-08.md | live idle-CPU correction, truthful peak redeclared | "2.4% per core is the measured baseline; the truthful peak" | NO — measurement doc, untouched by the four changes |
| NIGHT_CYBER_1_CONTAINER_NATIVE_AUDIT_2026-11-08.md | container-native four questions | "peak, native, reliable, efficient, LTS — confirmed on all four" | NO — grammar and resolver re-verified below (§2 G) |

Reading: audits 1-2 carry superseded TELEMETRY sentences only — their
code claims were re-verified line-by-line at HEAD and hold; audits 3-6
are surface-untouched and re-proven. No audit's verdict is invalidated.

## 2. The all-docs consistency audit (the primary new work)

| Check | Surfaces cross-checked | Verdict |
|---|---|---|
| A. quota-saver numbers | README curve table (:824-837) vs QUOTA_SAVER_PHYSICS curve table (:198-204); the 87% top-line vs the 100kb anchor run | MATCH — the tables agree per row; the top-line traces to the 87.3/93.4 anchor run (README:807-812) while the curve's 100kb row reads 85.0/91.9, and the whitepaper documents the 2.3pp two-run variance explicitly (QSP:221-226). The buyer-simulation runs (86.57/93.54, 88.1/92.9) are recorded in no doc and contradicted by none — conversational validations, nothing to reconcile |
| B. counter semantics | README:385-387, USAGE:815-824 + 864-888, GLOSSARY:109-119 + 85-89, code footer display_lines.rs:248-252 | MATCH — all five define `dropped` as the real post-lane kernel drop-verdict discards and `allowed` as admitted-through bytes, with the same ingress-burns/egress-saves law |
| C. the booking | README:97, 763-775, 877-942; QSP:93-107, 138; GLOSSARY:129-137; INNOVATIONS:284-337; ARC:345-422 | DRIFT -> FIXED — four lines still spoke the retired ~85% window counterfactual as a LIVE ledger booking (README:780, :789, :812, :961; ARC:525 at 7aa8b29), contradicting the same docs' "both words read zero / the ECN one-for-one alone". Fixed in ab6a515 (§9) |
| D. the tiers | README:1063-1068, COMMERCIAL_LICENSE.md:80-87 (canonical, repo root), LICENSING_FAQ:25-33, LONGEVITY:97-101 | MATCH — the identical six-row ladder (Personal free / Professional $1,899 / Business $9,999 / Enterprise Node $2,499 min5-max19 / Enterprise Internal $49,999 / OEM $149,999-or-$249,999+20%) on every surface; every "Individual"/"$99" hit sits in a grandfather clause or a dated record (census: README:1074-1097, COMMERCIAL_LICENSE:89-160, CHANGELOG Unreleased, frozen research/archive) |
| E. license enforcement | README:1099-1106, COMMERCIAL_LICENSE.md:297-304, LICENSING_FAQ:118-129 | MATCH — all three carry the reframed "theft — not a gray area" wording; repo-wide "worst kind of human/rotten" census: 2 hits, both frozen (CHANGELOG.md:1142 historical, docs/archive/CHANGELOG-V20-ERA.md:2358); zero outside the frozen zones |
| F. the philosophy | README:548-561 | MATCH — the blockquote verbatim (:554-556), the wall/garden frame intact (:558-561), and a repo-wide grep proves README is the single source — no other doc quotes it |
| G. container grammar | README:334/:682/:1038, USAGE:542-544 + :581, NIGHT_CYBER_1:98-109, the parser | MATCH — `parse_container` (container/mod.rs:77-102) accepts every documented example exactly as written; the `://`-in-list refusal (target_grammar.rs:71-80) matches USAGE's refused-example contract verbatim |
| H. CLI help surface | README:280-284 + :299-300, USAGE:1891-1896 + :2604-2632, VERIFY_RELEASE.md:108, src/cli/root.rs:27-140, src/info/build.rs:98-158 + :227-232 | MATCH with one stale sample -> FIXED — every flag/version/build-label quote matches the source literals; the USAGE doctor-JSON sample (:2632 at 7aa8b29) still carried v50-era sample values ("50.0.0-beta.1", the bare pre-T1 variant shape) — refreshed to the current contract (80.1.0, `pro-linux-amd64-v3-musl`) in ab6a515 |
| I. CI documentation | MAINTENANCE.md:66-81 (night-ci-1), miri.yml:64-68, supermassive.yml:225-231, supermassive-e2e.yml:81-83, VERIFY_RELEASE.md:190, CLAIMS_VERIFICATION:94-101 | MATCH — the concurrency-supersede paragraph is corroborated by all three YAMLs' identical group shape and contradicted by no doc; report-only: supermassive-e2e.yml carries no explanatory comment above its block (its siblings do) — cosmetic, no change |
| J. stale references | repo-wide greps | CLEAN with one prose fix — "ABOUT_CI": 0 hits; "213 KB": 0; "NIGHT-zen/zen-lts/ZEN_LTS": 0 pre-existing; "0.033%": 18 hits, all inside the allowed file (NIGHT_PERF_2), the frozen corrected audit (NIGHT_PERF_1, header-flagged), or ledger index cells (docs/README.md:97-98); task-ID-in-prose: 1 hit fixed (README:764-765), while the record-bullet and RETIRED-annotation hits (README:889/:922/:948, INNOVATIONS:284/:314/:347, GLOSSARY:125-126, USAGE:856's annotation block) follow the docs' established `RETIRED (task, schema vX)` convention — classified legal, no change; the RECWN/EDT mention sweep: every booking mention states the retirement, none implies live savings |

## 3. Area 1 — Stability & Crash: PEAK — no change warranted

- Layout pins: `limiter_stats_raw_layout_is_pinned`
  (test/ebpf/limiter/types_tests.rs:275) asserts size 64 (:286),
  `offset_of!(LimiterStatsRaw, bytes_saved_by_edt) == 48` (:292-295),
  ecn at 56 (:296-299), byte round-trip (:304-312); the version walk
  `test_schema_version_constant` (:156, :243-263) carries the
  v28->v29->v30 history and pins `SCHEMA_VERSION_EXPECTED == 30`;
  the BPF/userspace anchor parity pins live at
  test/ebpf/limiter/schema_sync_pin_tests.rs:43-52.
- Zero-read pins: `the_saved_total_is_the_ecn_one_for_one_alone`
  (display_json_quota_tests.rs:127, asserts the EDT word == 0 at
  :148) and `the_recwn_saved_word_is_retired_and_books_zero`
  (display_quota_tests.rs:166, :183).
- The version-mismatch reload: src/ebpf/limiter/mod.rs:151-176 —
  any non-v30 value -> vlog + `unpin_all()?` -> full fresh load ->
  re-stamp; `unpin_all` unlinks and verifies empty
  (src/ebpf/pin.rs:227, 241+), all Result-returning: a pre-v30
  ledger on an upgraded host is wiped cleanly, no panic path.
- The retired functions: 10 hits for
  `recwn_saved_bytes|pacing_saved_bytes|book_edt_saved` across src/,
  ebpf/, test/ — ALL retirement records (comments, docs, tests); no
  live call site, no dead pub fn; `book_edt_saved` was deleted from
  math_atomics.rs by 6343c1a (diff: -21 lines) and the enforce.rs
  import went with it.
- The probes: edt-probe.py:654-681 row 6 FAILs on absent keys (:666)
  and gates on `delta_e == 0` (:675); recwn-probe.py:1130-1167 row 6
  gates on `delta_r == 0` (:1156, :1148, :1168) — the words must move
  ZERO over the driven legs; the userspace twins are pinned
  (display_quota_tests.rs:163-166).

Honest note, recorded not judged: the zero-reads are pinned on
current-state fixtures; no test replays a v28-era nonzero word across
the version walk — the honesty guarantee is structural (the kernel
writer is gone; the version-mismatch wipe erases any stale word), see
§6.

## 4. Area 2 — Code Hygiene: PEAK — no change warranted

- Duplicate: exactly one saved-booking function exists — `book_rescue`
  (ebpf/src/math_atomics.rs:158) booking `bytes_saved_by_ecn` at
  offset 56 (:168-175); callers socket_flow.rs:313 and
  enforce_helpers.rs:267. No retired/new double form.
- Redundant: the remaining `counterfactual` tests are retirement pins
  asserting zero (display_quota_tests.rs:166; display_json_quota_tests.rs:93, :127)
  and honesty-label pins (:26, :102). No test asserts retired
  nonzero behavior.
- Stale comments: the `errs LOW|erring HIGH|booked|counterfactual`
  sweep over src/ and ebpf/src/ returns zero STALE hits — field docs
  are past-tense (math.rs:228-251, :261-267), retirement blocks stand
  where the call sites were (pace.rs:93-113, pace_flow.rs:255-263,
  enforce.rs:286-301, display.rs:47-67), and the schema ledger tells
  the history (ebpf/src/schema.rs:490-570).
- Zombie: every `allow(dead_code|unused)` site is pre-existing and
  explained; the window's only code commits (6343c1a, eeec192) added
  none.
- Spaghetti: the six retirement-touched files import nothing retired;
  display.rs:171 copies the EDT word verbatim off the tail (the
  writer is gone — it reads zero) and :175 books
  `bytes_saved_by_recwn: 0` unconditionally;
  `quota_saved_line` (display_lines.rs:187-217) renders only when
  nonzero and names the retirement in the split (:203-207).
  Borderline, classified current-honest: :197-198's "(counterfactual
  estimate...)" label — the sole live booking is the estimate's
  conservative floor (math.rs:247) and the split names the
  retirement; no change.

## 5. Area 3 — Optimization: PEAK — no change warranted (the byte-delta proof)

The retirement removed one map read and one map write per packet from
the egress hot path, and the object shrank: `zelynic-limiter.o`
81920 -> 81608 bytes (-312, -0.38%) at 6343c1a (blake3
49d67a53... -> 8870fc4c...); `zelynic-observer.o` unchanged (3296
bytes, same blake3, staged at ec46268, untouched since). The RECWN
retirement (eeec192) refreshed the manifest's generated stamp and the
ebpf_tree_blake3 only (c8e50543 -> 79ebc282) — no .o byte change. The
hot-path diff (6343c1a^..HEAD): pace.rs +24/-65, pace_flow.rs
+8/-71 — net -104 lines, removal dominates; both files are empty
across 413e0ac..HEAD, so nothing re-entered the hot path after.

## 6. Area 4 — Security: PEAK — no change warranted

- The egress hot path: the retired `book_edt_saved` call site inside
  `try_enforce` is now a pure comment record (enforce.rs:286-301);
  the trust-boundary burst clamp is intact (:255-276,
  MAX_ENFORCABLE_BURST), the raw stats fetch unchanged (:284), the
  Option materialization unchanged (:306), and cookie == 0 still
  falls through to the DRR lane — never an unlimited pass (:315-319).
  The 6343c1a diff removed only the booking lines.
- The reserved zero: the honesty invariant holds by construction —
  the kernel writer for the EDT word is gone, and the only way a
  stale nonzero word can exist is a pre-v29 ledger, which the
  version-mismatch reload wipes before any read (mod.rs:162-176).
  There is no word-level clamp, and the JSON path deliberately pins
  verbatim rendering of what the map holds
  (display_json_quota_tests.rs:32-48) — a display-honesty pin, not a
  defect. A wrong savings number misleads, it does not execute; the
  wipe closes the only path to one.
- The CLI surface: zero commits touch src/main.rs in the window; the
  retirement's src/ diff adds no flag, no input surface.
- GPG / release: zero commits in scripts/release/, release.yml, and
  crates-io.yml across the window.

## 7. Area 5 — LTS Stability: PEAK — no change warranted (all five axes hold)

| Axis | State | Proof |
|---|---|---|
| Kernel future | HOLD | the window's two ebpf/ commits added ZERO bpf-helper calls (6343c1a, eeec192); current census 89 helper-call lines across 22 ebpf/src files; KERNEL_FLOOR (5, 15) enforced at kernel_floor.rs:21 with the refusal ladder :57-74 — unchanged |
| Distro future | HOLD | Cargo.lock and Cargo.toml: zero commits since 2026-11-08 |
| Dependency rot | HOLD | root lock 44 crates, ebpf lock 31 — exactly NIGHT_RELIABLE_LTS_1's re-grepped record; deny.toml untouched, the chrono and serde-family bans intact |
| Maintenance burden | IMPROVEMENT landed | the concurrency-supersede paragraph (MAINTENANCE.md:66-81, night-ci-1) — a red run's meaning is now documented where the workflow family lives |
| User trust | IMPROVEMENTS landed | the honest top-line (README:69), the philosophy (README:548), the reframed enforcement (README:1099-1106), the six-row ladder (README:1063-1068) |

## 8. The gaps found

Three drift classes, all doc-side, all proven against the v30
contract (the ledger books the ECN one-for-one alone; both retired
words read zero):

1. The retired ~85% window counterfactual spoken of as a live ledger
   booking in the present tense — README:780, :789, :812, :961 and
   ARC:525 at 7aa8b29 (the recvn-audit docs pass missed these four).
2. A stale doctor-JSON sample — USAGE:2632 carried v50-era sample
   values inside a field contract that had since moved (v80.1.0, the
   release variant label).
3. One past-24h task codename inside flowing user-facing prose —
   README:764-765, against the ledger-cells-only convention.

## 9. The fixes shipped

One commit: ab6a515 "fix: the doc drift is closed (night-zen-lts-1)"
— 4 files, +25/-13, docs-only:

- README.md: the Layer-4 paragraph now states the corrections by
  schema version, not codename (:764-765); the window counterfactual
  prices (not books) ~85% with the schema-v30 retirement named
  (:780-783) and the bounded-transfer sentence prices the overrun
  (:789); the measured-claim section states the booking is retired
  and the ledger books the ECN one-for-one alone (:811-813); the
  headline paragraph prices the counterfactual before its v30
  retirement (:961-964).
- docs/COSMIC_DRAGON_ARC.md: the mirrored headline sentence fixed the
  same way (:524-528).
- docs/USAGE.md: the doctor-JSON sample refreshed to the current
  build contract (:2632) — version 80.1.0, git_sha fc0b018, the
  release variant label, the v80.1.0-era build time and rustc.
- CHANGELOG.md: the Unreleased section records the closure.

Left untouched on purpose: `docs/audits/*` (frozen), `docs/archive/*`
(frozen), CHANGELOG history, the retired behavior in code (the
retirement is correct), and every product code path — zero code
changes shipped.

## 10. The gates

Run live on the audited tree in this seat, with the tool belt
bootstrapped to the repo's own pins (rust-toolchain.toml 1.98.1,
bpf-linker 0.11.1, b3sum 1.8.7, markdownlint-cli2 0.18.1 per the CI
workflow's pin):

- `cargo test --features ebpf --locked` -> 1032 passed, 0 failed
  (lib) + 72 passed, 0 failed (integration) = 1104 green.
- `./scripts/gate-keepers.sh` -> 26 passed, 0 failed, 0 skipped.
- `./scripts/build.sh check-all -q` -> exit 0.

The live eBPF legs (the root/KVM lanes) stay CI-owned as always —
no root, no KVM in this seat.

## 11. The final verdict

zelynic is docs-consistent and 5-area peak after the v29/v30
retirement, the peace reframe, and the price change. The book closes.

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
