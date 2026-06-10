# Strict-Run-Lab Validation Freeze

## Purpose

This document records the validation freeze of the hidden experimental `strict-run-lab`
command after a successful live proof run confirmed that pre-launch cgroup placement
improves nft `socket cgroupv2` counter matching. The validation freeze locks the
command's invariants with deterministic tests, documents the live proof values, and
establishes the safety constraints that must be maintained going forward.

This freeze does NOT promote `strict-run-lab` to stable. It does NOT change existing
`strict` behavior. It does NOT add eBPF, quotas, daemon mode, watch mode, persistence,
ledger file I/O, enforcement mutations, or version bumps.

## Live Proof Summary

### Environment

- **Kernel**: Linux 6.18
- **Interface**: proton0 (ProtonVPN tunnel interface)
- **Child process**: aria2c (multi-connection downloader)
- **Command**: `zelynic strict-run-lab --diagnose --iface proton0 -d 100kb -- aria2c -x 1 -s 1 https://releases.ubuntu.com/24.04/ubuntu-24.04-desktop-amd64.iso`

### Observed nft Counter Values

| Counter | Packets | Bytes |
|---------|---------|-------|
| nft socket cgroupv2 match | 1,800 | 210,054 |
| nft ct mark | 1,971 | 286,838 |
| nft download policer | 3,236 | 4,456,466 |
| nft drop | 531 | 741,189 |

### Proof Classification

All four counter groups show nonzero packet and byte counts. This means:

1. **Socket cgroupv2 match (1,800 pkts / 210,054 bytes)**: The child process created
   sockets inside the target cgroup, and nft `socket cgroupv2` correctly matched egress
   packets from those sockets. This is the key improvement over the attach-after-socket
   approach, which showed 0/0.

2. **Download policer (3,236 pkts / 4,456,466 bytes)**: The conntrack mark set by the
   output chain was copied to the conntrack entry, and the input chain's download policer
   matched reply (download) traffic. This confirms the full shaping pipeline is active.

3. **Drop counter (531 pkts / 741,189 bytes)**: The policer dropped packets that exceeded
   the configured rate limit, confirming that bandwidth enforcement is occurring.

4. **Tunnel interface**: proton0 is a VPN/tunnel interface. The experiment succeeded on a
   tunnel, which is notable because the attach-after-socket approach consistently failed
   on this interface.

### Comparison: Attach-After-Socket vs Pre-Launch

| Metric | Attach-After-Socket (strict) | Pre-Launch (strict-run-lab) |
|--------|-------------------------------|-----------------------------|
| PID cgroup verification | Success | Success |
| nft socket cgroupv2 pkts | 0 | **1,800** |
| nft socket cgroupv2 bytes | 0 | **210,054** |
| nft download policer pkts | 0 | **3,236** |
| nft download policer bytes | 0 | **4,456,466** |
| nft drop pkts | 0 | **531** |
| nft drop bytes | 0 | **741,189** |
| Traffic proof active | No | **Yes** |

## Validation Freeze Invariants

The following invariants are enforced by deterministic unit tests in
`src/commands/strict_run_lab.rs` (Section K: Validation Freeze Tests, 13 tests):

### 1. Hidden from Help

The `StrictRunLab` variant uses `#[command(hide = true)]` in clap. Normal `zelynic
--help` output must NOT contain "strict-run-lab". Test: `freeze_hidden_from_help_cli_level`.

### 2. Requires `--` Before Child Command

The command requires at least one positional argument after `--`. Parsing without a
child command must fail. Test: `freeze_requires_double_dash_before_command`.

### 3. Experimental/Lab/Not Stable Wording

The handler source must contain "experimental", "lab", and "not stable". It must NOT
contain "stable command" as a positive claim. Test: `freeze_says_experimental_and_lab_and_not_stable`.

### 4. Pre-Launch Cgroup Placement Wording

The handler source must mention "pre-launch", "cgroup", and "before sockets". Test:
`freeze_says_pre_launch_cgroup_placement`.

### 5. Traffic Proof Reuse

The handler must use `from_traffic_proof()`, `build_traffic_proof()`, and
`render_strict_traffic_proof()` from the shared `traffic_proof` module. No parallel
parsing or alternative proof logic is allowed. Test: `freeze_traffic_proof_reuses_shared_model`.

### 6. No False Success Claims

Even when `placed_before_exec=true`, zero counters must NOT yield
`is_traffic_proof_active()`. Partial proof (cgroup match only, no policer) must also
NOT be active. Test: `freeze_no_false_success_on_zero_counters`.

### 7. Cleanup Wording

The handler must contain the cleanup phrases "removed target cgroup directory",
"removed tc class and filters", and "failed to remove cgroup dir". Test:
`freeze_cleanup_wording_present`.

### 8. Cleanup on Error Path

On policy application failure, the handler must: kill the child, wait for child exit,
then call cleanup. Test: `freeze_cleanup_on_error_path`.

### 9. Strict Behavior Unchanged

The lab handler must NOT call `handle_strict()` or `force_reconnect_existing_sockets()`.
It delegates to `apply_limit_with_diagnostics()` but does not modify stable strict
semantics. Test: `freeze_strict_behavior_unchanged`.

### 10. Usage JSON Schema Unchanged

The lab handler must NOT reference `schema_version` or `UsageSnapshot`. The v3.0 usage
JSON schema remains frozen. Test: `freeze_no_usage_json_schema_change`.

### 11. No Forbidden Features

The lab handler must NOT contain: daemon, watch, quota, eBPF, LedgerPersistencePlan,
schema_version, systemd-run, enforcement_active, arg_required_else_help. Test:
`freeze_no_forbidden_features`.

### 12. Live Proof Values Reproducible

A deterministic test using the exact live proof values (socket cgroupv2: 1800 pkts /
210054 bytes, policer: 3236 pkts / 4456466 bytes, tunnel: proton0) must produce
`is_traffic_proof_active() == true`. This ensures the proof model correctly classifies
the observed experiment results. Test: `freeze_live_proof_values_reproducible`.

### 13. Outcome Model Exhaustive

All five `StrictRunLabOutcome` variants (Launched, PolicyApplied, Completed,
ErrorBeforeLaunch, ErrorAfterLaunch) must be constructible and match expectations.
Test: `freeze_outcome_all_variants_exhaustive`.

## Pure Model Types

The validation freeze introduces (or retains from prior implementation) three pure
model types in `src/commands/strict_run_lab.rs`:

### `StrictRunLabOutcome` (enum)

```
Launched { child_pid, verified_in_cgroup }
PolicyApplied { child_pid, verified_in_cgroup, proof_state }
Completed { child_pid, verified_in_cgroup, proof_state, exit_success, cleanup_attempted }
ErrorBeforeLaunch         (default)
ErrorAfterLaunch { child_pid, cleanup_attempted }
```

### `StrictRunLabProofState` (struct)

```
checked: bool
cgroup_match_observed: bool
policer_match_observed: bool
drop_observed: bool
is_tunnel: bool
placed_before_exec: bool
```

With methods:
- `from_traffic_proof(proof, placed_before_exec) -> Self`
- `is_traffic_proof_active() -> bool` (requires checked + cgroup + policer all true)

### `render_lab_proof_summary(proof, interface)`

Renders a detailed proof summary to stdout distinguishing policy installed, traffic
proof observed, and drop counter states.

## Output Honesty Polish

The lab output distinguishes three states:

1. **Policy installed**: nft/tc rules were successfully applied. This says nothing about
   whether traffic actually matched the rules.
2. **Traffic proof observed**: nft counters showed nonzero packet/byte counts, confirming
   the shaping pipeline is active for this run.
3. **Drop counter active**: policer dropped packets exceeding the rate limit, confirming
   enforcement is occurring.

The output explicitly states:
- "PID moved/placed is not the same as traffic proven."
- "Attach-after-socket limitation remains for stable 'strict'."
- "Do not use this as evidence that Zelynic shaping works in production."
- "This experiment is not stable. Do not promote based on a single run."

## Test Count Summary

| Module | Before Freeze | After Freeze | Delta |
|--------|--------------|--------------|-------|
| strict_run_lab.rs | 63 tests | 76 tests | +13 |
| cli/tests.rs | 5 SRL tests | 5 SRL tests | 0 |
| Total unit tests | 1577 | 1590 | +13 |

## Files Changed

### Modified
- `src/commands/strict_run_lab.rs`: Added 13 validation freeze tests (Section K),
  changed `StrictRunLabProofState` to derive `Default`, changed `StrictRunLabOutcome`
  to derive `Default` with `#[default]` attribute on `ErrorBeforeLaunch`, added
  `use clap::{CommandFactory, Parser}` to test imports.

### Created
- `docs/strict-run-lab-validation-freeze.md`: This document.

### Updated
- `docs/strict-prelaunch-cgroup-wrapper-experiment.md`: Added live proof section.
- `docs/strict-traffic-proof-honesty-audit.md`: Added pre-launch success note.
- `CHANGELOG.md`: Added validation freeze entry.

## Scope Constraints

The validation freeze is strictly tests + docs + minor output/honesty polish:

- Does NOT promote `strict-run-lab` to stable
- Does NOT change existing `strict` behavior
- Does NOT add eBPF, quotas, daemon mode, or watch mode
- Does NOT modify the v3.0 usage JSON schema
- Does NOT add persistence, ledger file I/O, or identity resolution
- Does NOT change version numbers or create releases
- Does NOT add tags, GitHub releases, or package publications

## Future Stable Wrapper Design Contract

A design contract for a future stable wrapper command has been documented in
[strict-run-wrapper-stable-contract.md](strict-run-wrapper-stable-contract.md).
That document defines the chosen command shape (`zelynic strict --run`), the
safety contract, the traffic proof contract, the cleanup contract, the
compatibility contract, and the promotion checklist. It is design only and does
not implement any stable command.

## Non-Goals

- This is NOT a production feature promotion
- This does NOT claim the experiment is conclusive (single run, single environment)
- This does NOT fix the VPN/tunnel limitation for attach-after-socket
- This does NOT replace the stable `strict` command
- This does NOT prove Zelynic shaping works in all environments