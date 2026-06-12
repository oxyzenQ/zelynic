# I-33 — Brave Identity Scope Proof

**Phase**: I-33 (Intergalaxion Engine)
**Branch**: intergalaxion (experimental)
**Base**: main stable v3.1.0

## Purpose

Deterministic model for proving Brave identity scope before any future live
100KB/s upload/download limit. Model-only, dry-run only. This phase does not
execute commands, create cgroups, move processes, or scan /proc. It proves
identity scope only.

## Scope

Identity scope proof only. Not a rate limiter. Not a release. Not a public
feature. Not a packet filter. Not an enforcement engine. It answers: "How do
we know which Brave process to limit?"

## No Mutation

I-33 performs zero system mutation:
- No /proc scan
- No /sys/fs/cgroup read or write
- No systemd-run or systemd query
- No tc/ifb execution
- No process move or cgroup write
- No packet drop
- No enforcement
- No persistence
- No release
- No public CLI

Live apply is forbidden in I-33. No live commands are executed.

## Identity Methods Modeled

1. **Process name match**: "brave" or "brave-browser"
2. **Executable path match**: path containing "brave" or "brave-browser"
3. **Cgroup path match**: cgroup path containing "brave" or "brave-browser"
4. **Systemd user scope name**: optional, propagated when available
5. **Fixture PID list**: test-supplied PID for deterministic testing
6. **Confidence scoring**: None / Low / Medium / High / Ambiguous

## Confidence Levels

| Level | Criteria |
|---|---|
| None | No candidates or no matching candidates |
| Low | Name-only or executable-only match, no PID |
| Medium | PID + name match, no cgroup |
| High | PID + cgroup + name/executable match |
| Ambiguous | Multiple matching candidates detected |

## Honesty Model

I-33 does not overclaim per-app certainty:
- If PID/cgroup identity is unknown, target is Candidate, not Ready
- If only process name is known, confidence is Low
- If cgroup path is known and target matches Brave, confidence is High
- If multiple unrelated processes match, identity is Ambiguous
- If no Brave candidate exists, proof is Blocked

Download/upload limiting is **not proven** in I-33. This phase proves
identity scope only. No rate limit claims are made.

Fake identity success is rejected. Fake limit success is rejected.
There are no fields that sound like fake claims used as honest pending-proof
markers.

## Types

1. BraveIdentitySource (5 variants): ProcessName, ExecutablePath, CgroupPath, SystemdScope, FixturePidList
2. BraveIdentityConfidence (5 variants): None, Low, Medium, High, Ambiguous
3. BraveIdentityScopeStatus (6 variants): Draft, Candidate, Ready, Ambiguous, Blocked, LiveApplyForbidden
4. BraveIdentityDecision (9 variants): Stop, AcceptCandidate, AcceptReadyScope, RequirePidEvidence, RequireCgroupEvidence, RejectAmbiguousTarget, RejectNoTarget, RejectLiveApply, RejectPublicCli
5. BraveProcessCandidate (9 fields): pid, process_name, executable_path, cgroup_path, systemd_scope, matches_brave_name, matches_brave_executable, matches_brave_cgroup
6. BraveIdentityScopeProofInput (11 fields): target_name, candidates, dry-run/live flags, mutation allowances
7. BraveIdentityScopeProof (26 fields): status, decision, confidence, selected_pid, safety flags, findings

## Helper Functions

1. `default_brave_identity_scope_proof_input()` — safe defaults targeting brave
2. `build_brave_identity_scope_proof(input)` — builds proof from candidates, never scans /proc
3. `validate_brave_identity_scope_proof(proof)` — rejects any proof violating I-33 safety invariants
4. `brave_identity_source_label(source)` — maps source to string
5. `brave_identity_confidence_label(confidence)` — maps confidence to string
6. `brave_identity_scope_status_label(status)` — maps status to string
7. `brave_identity_decision_label(decision)` — maps decision to string

## Safety Invariants

- `release_allowed` = false (always)
- `must_remain_experimental` = true (always)
- `live_apply_allowed` = false (always)
- `public_cli_exposed` = false (always)
- `proc_scan_performed` = false (always)
- `cgroup_read_performed` = false (always)
- `systemd_query_performed` = false (always)
- `cgroup_mutation_performed` = false (always)
- `process_mutation_performed` = false (always)
- `persistence_performed` = false (always)
- `fake_identity_success_detected` = false (always)

## Ready Proof Requirements

A proof becomes Ready only when:
- Target name is "brave" or "brave-browser"
- Exactly one matching candidate exists
- Candidate has a PID
- Candidate has a cgroup_path
- Candidate matches Brave name or executable
- No mutation flags are true
- No fake identity success is detected

## I-32 Semantic Cleanup Note

I-32's `download_limit_claimed_without_ifb_proof` field had misleading naming.
I-33 uses clean, honest semantics:
- `identity_ready` = true only when identity is actually proven
- `fake_identity_success_detected` = always false, rejected by validation
- No field that sounds like a fake claim used as a pending-proof marker

## Constraints

- No tag, release, publish, version bump, or main merge
- No public stable CLI
- No enforcement in default build
- No packet drop in default build
- No tc/ifb/cgroup backend currently active
- No ledger persistence for identity proofs
- No mutation in default build
- All files under 1000 LOC

## Files

- `src/intergalaxion_engine/backends/ebpf/brave_identity_scope_proof.rs` — models and helpers
- `src/intergalaxion_engine/tests_i33.rs` — deterministic tests
- `docs/intergalaxion/I-33-brave-identity-scope-proof.md` — this document
