# Validation Report: v2.7.0 Experimental Attach Lab

## Host Information

| Field | Value |
|-------|-------|
| Distro name | CachyOS (Arch-based) |
| Distro version | rolling |
| Kernel version | 6.18.33-1-cachyos-lts |
| Architecture | x86_64 |
| Install type | bare metal |
| cgroup mode | pure cgroup v2 |
| nftables version | v1.1.6 |
| tc / iproute2 version | 7.0.0 |
| systemd available | yes |
| systemd-run available | yes |
| Zelynic version | post-v2.6.0 / v2.7-prep |
| Zelynic commit | a811c24 |
| Test date | 2026-06-04 |

## Release Candidate

| Field | Value |
|-------|-------|
| Release candidate | v2.7.0 Experimental Attach Lab |
| Binary version string | May still print v2.6.0 until version bump |
| Live PID movement | Not implemented |
| Live limiter attach | Not implemented |

## Scope

This report validates the v2.7.0 Experimental Attach Lab release, which spans
five merged phases (phase 1 through phase 5) plus a CLI refactor phase (1.1).
All phases are CI-green and merged to main. This is a documentation and
release-prep validation; it does not change Rust runtime behavior.

For the v2.5 Scope Runner validation on this host, see
[scope-runner-v2.5.md](scope-runner-v2.5.md).

## Feature Scope

### Phase 1: Experimental Attach Gate Checklist

- Added `--experimental-single-pid-attach`, `--i-understand-this-moves-pids`,
  and `--rollback-required` as explicit future-consent flags.
- Pure gate checklist evaluating all existing Scope Runner gates plus the three
  new consent flags, single-PID constraint, valid original cgroup capture, PID
  liveness, self-protection, model-only transaction plan, move-only mutation
  mode, and nftables/tc/Zelynic state disabled.
- Gate is pure/model-only and remains blocked.

### Phase 1.1: CLI Refactor

- Split `src/cli.rs` from approximately 998 LOC to approximately 522 LOC.
- Moved CLI tests to `src/cli/tests.rs`.
- Deduped the experimental gate safety footer across attach gate output paths.

### Phase 2: Move-Only Executor Skeleton

- Pure, non-mutating model of the future single-PID cgroup move and immediate
  rollback sequence.
- Documents target cgroup preparation, `cgroup.procs` writes, verification,
  rollback, and safe cleanup while keeping execution blocked.
- Future write sequence modelled, not executed.
- No PID movement, no nftables/tc change, no Zelynic state change.

### Phase 3: Target Cgroup Preflight

- Pure model for future target cgroup path validation and `cgroup.procs`
  write-target previews.
- Keeps parent/target creation as future work.
- Performs no live cgroup reads or writes.
- Target cgroup preflight modelled, not executed.

### Phase 4: Cgroup Environment Diagnostics

- Pure parser/model for sample `/proc/self/mountinfo` cgroup v2 mount facts,
  including mount path, read-write/read-only mode, missing mount detection, and
  unexpected mount path reporting.
- No live mountinfo read in the Scope Runner output path.
- `cgroup.procs` writes remain blocked.

### Phase 5: Operation Journal Preview

- Pure operation journal model for the future move-only executor.
- Deterministic preview operation IDs derived from target, PID list, and mode.
- Operation owner: `zelynic-scope-runner`.
- Ordered journal events from `planned` through `blocked_not_executed`.
- Rollback boundary: operation-owned state only.
- State writes: blocked.
- Journal is model-only and not persisted. No Zelynic state file is written.

## Safety Status

| Safety Property | Status |
|-----------------|--------|
| `--attach-live` remains hard-blocked | Confirmed |
| PID movement is not implemented | Confirmed |
| cgroup directory creation is not implemented | Confirmed |
| `cgroup.procs` write is not implemented | Confirmed |
| nftables/tc/state changes from Scope Runner are not implemented | Confirmed |
| limiter attach is not implemented from Scope Runner | Confirmed |

## Tested Local Smoke Matrix

### 1. Non-Root Full Experimental Consent (Blocked at Root Gate)

**Command:**

```bash
zelynic run --execute --scope-mode system --probe-live --attach-live \
  --experimental-single-pid-attach --i-understand-this-moves-pids \
  --rollback-required -d 500kbit -u 500kbit -- sleep 30
```

**Result:** Blocked. Returns "Scope Runner live probe requires root (euid == 0)."
No systemd scope launched, no mutation. All three experimental consent flags are
parsed and recognized, but the probe gate blocks before any probe execution.

### 2. Root Full Experimental Consent (Passed — Probe, Preflight, Gate, Block)

**Command:**

```bash
sudo zelynic run --execute --scope-mode system --probe-live --attach-live \
  --experimental-single-pid-attach --i-understand-this-moves-pids \
  --rollback-required -d 500kbit -u 500kbit -- sleep 30
```

**Result:** Passed. The Scope Runner:

- Launched a transient systemd scope.
- Discovered ControlGroup path.
- Discovered PID from `cgroup.procs`.
- Captured original cgroup from `/proc/<pid>/cgroup`.
- Rendered PID safety checks (liveness: alive, self-protection: allowed).
- Rendered all preflight and gate sections.
- Rendered move-only executor skeleton.
- Rendered target cgroup preflight.
- Rendered cgroup environment diagnostics.
- Rendered operation journal preview.
- Printed canonical safety footer.
- Returned "Experimental PID move is not implemented yet."
- Unit cleaned up inactive/dead.

**No mutation observed:**

- No PID was moved into any Zelynic target cgroup.
- No limiter attach was performed.
- No nftables rules were added or modified.
- No tc/qdisc/filter state was changed.
- No Zelynic cgroup directories were created.
- No `cgroup.procs` was written.
- No Zelynic state files were written.
- No Zelynic state file was written for the operation journal.
- Bandwidth limiting was not active.
- Cleanup leaves transient scope inactive/dead.

## Expected Root Output Sections

When run with the full experimental consent bundle as root, the output includes
the following sections in order:

1. **Future attach preview** — Discovered PID(s), future target cgroup,
   requested rates, attach source, strict backend, preview-only status.
2. **Attach safety preflight** — PID liveness, original cgroup capture,
   self-protection, rollback plan, mutation ownership.
3. **PID safety checks** — Liveness, self-protection, eligibility per PID.
4. **Future attach transaction plan** — Pure mutation transaction plan and
   rollback transaction model (v2.6 groundwork).
5. **Experimental attach gate** — Checklist of all required gates including
   the three consent flags, single-PID constraint, cgroup capture, liveness,
   self-protection, transaction plan, move-only mode, state disabled.
6. **Move-only executor skeleton** — Modelled future write sequence for
   single-PID move, verify, rollback, cleanup.
7. **Target cgroup preflight** — Future target namespace, target cgroup path,
   target and rollback `cgroup.procs` paths, parent/target creation status.
8. **Cgroup environment diagnostics** — Mount path model, read-write/read-only
   status, target namespace check, target cgroup check, `cgroup.procs` write
   status.
9. **Operation journal preview** — Operation ID, owner, mode, ordered events,
   rollback boundary, state-write status, execution status.
10. **Canonical safety footer** — No PID moved, no limiter attach, no
    nftables/tc/Zelynic cgroup/state changes, bandwidth not active,
    cleanup command.

## Final Confirmations

| Confirmation | Status |
|--------------|--------|
| No PID was moved | Confirmed |
| No limiter attach was performed | Confirmed |
| No nftables, tc, Zelynic cgroup, or state changes were made | Confirmed |
| Bandwidth limiting is not active from Scope Runner | Confirmed |
| Operation journal is model-only and not persisted | Confirmed |
| Cleanup leaves transient scope inactive/dead | Confirmed |
| No privileged commands were run in validation | Confirmed |
| No sudo was used in validation (automated checks) | Confirmed |
| `zelynic strict` was not executed | Confirmed |

## Automated Validation

All automated checks passed:

- `cargo fmt --all -- --check` — formatting clean
- `cargo test --locked` — all tests passed
- `cargo clippy --all-targets --all-features -- -D warnings` — no warnings
- `python3 scripts/check-policy.py` — all files under 1000 LOC, all headers
  present
- `git diff --check` — no whitespace errors

## Non-Root Smoke Summary

The non-root smoke test command with all experimental consent flags returns
"Scope Runner live probe requires root (euid == 0)." and does not launch
anything. No systemd scope was created, no process was launched, no mutation
was attempted.

## Final Status

| Field | Value |
|-------|-------|
| Status | Validated |
| Scope | v2.7.0 Experimental Attach Lab (documentation and release-prep only) |
| Runtime behavior changed | No |
| PID movement implemented | No |
| Cgroup directory creation implemented | No |
| `cgroup.procs` write implemented | No |
| Limiter attach implemented | No |
| nftables/tc/Zelynic cgroup/state changes performed | No |

## Metadata

| Field | Value |
|-------|-------|
| Date | 2026-06-04 |
| Tester | rezky_nightky |
