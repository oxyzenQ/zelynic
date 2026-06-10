# Strict-Run-Lab Manual Validation Matrix

## Purpose

This document defines a repeatable manual validation matrix for the hidden experimental
`strict-run-lab` command. The matrix specifies the exact scenarios that must be manually
tested and their expected behaviors, including nft counter expectations, cleanup
requirements, and pass/fail criteria. This matrix is a prerequisite for any future
stable wrapper implementation.

**This phase does NOT implement stable wrapper behavior.** It does NOT promote
`strict-run-lab` to stable. It does NOT change existing `strict` behavior. It defines
the manual evidence required before stable promotion can be considered.

A single successful live test is NOT enough for stable promotion. All scenarios (or
documented exceptions with rationale) must be completed and recorded with actual
counter values, speed measurements, and cleanup verification.

Traffic proof requires nft counters, not only PID/cgroup verification. Speed alone is
not sufficient evidence; nft counters must be recorded for every scenario. Cleanup
proof (no orphaned cgroup/tc/nft state) is required before stable promotion.

VPN/tun behavior may vary by kernel version, VPN application, routing table
configuration, and interface type. Results on one VPN do not guarantee results on
another. Each VPN/tun scenario must be documented with its full environment details.

## Scope Constraints

- This is a manual validation matrix, not automated test infrastructure
- Does NOT implement `strict --run` or any stable wrapper command
- Does NOT promote `strict-run-lab` to stable
- Does NOT change existing `strict` behavior or enforcement semantics
- Does NOT add eBPF, quota, daemon/watch, or ledger persistence
- Does NOT change the v3.0 usage JSON schema
- Does NOT bump version, create tags, releases, or publications

## Environment Template

Every scenario execution must record the following environment context:

| Field | Value |
|-------|-------|
| Kernel version | (e.g., Linux 6.18.0) |
| Distribution | (e.g., Ubuntu 26.04) |
| Architecture | (e.g., x86_64) |
| Zelynic version | (e.g., v3.0.1) |
| Zelynic commit | (e.g., 6883c39) |
| VPN software | (e.g., ProtonVPN CLI 4.x, WireGuard 1.x, OpenVPN 2.x) |
| VPN interface name | (e.g., proton0, tun0, wg0) |
| Physical interface | (e.g., wlan0, eth0) |
| Download tool | (e.g., aria2c 1.37, curl 8.x, wget 1.x) |
| Browser | (e.g., Firefox 128, Chromium 127) |
| Date/Time | (ISO 8601) |

## Scenario Matrix

### Scenario 1: Non-VPN, Single-Connection aria2c

| Field | Value |
|-------|-------|
| **scenario_id** | `SRL-MVM-001` |
| **command** | `zelynic strict-run-lab --diagnose -d 100kb -- aria2c -x 1 -s 1 <download_url>` |
| **interface** | Physical (e.g., wlan0, eth0) — auto-detected or `--iface` |
| **expected route interface** | Same as `interface` field above |
| **expected cgroup placement** | Child PID verified in `/sys/fs/cgroup/zelynic/target_aria2c/cgroup.procs` |
| **expected nft socket cgroupv2 counter behavior** | packets > 0, bytes > 0 (egress from cgroup-classified sockets) |
| **expected ct mark counter behavior** | packets > 0, bytes > 0 (conntrack mark propagation on reply path) |
| **expected download policer counter behavior** | packets > 0, bytes > 0 (policer matching download traffic) |
| **expected drop counter behavior** | packets > 0, bytes > 0 (rate limit enforcement drops) |
| **expected speed behavior** | Measured speed approximately at or below 100kb/s (+/- 10%) |
| **expected cleanup behavior** | Target cgroup directory removed, tc class/filters removed, state entry removed, nft table removed if no other limits |
| **pass/fail criteria** | PASS: All four counter groups nonzero, speed at or below limit, no orphaned state. FAIL: Any counter zero, speed exceeds limit significantly, or orphaned cgroup/tc/nft state detected |
| **notes** | This is the baseline scenario. Single connection removes connection-counting complexity. Use a large file (ISO, 100MB+) for sustained traffic. Record counter values at 10s, 30s, and end of run |

### Scenario 2: Non-VPN, Multi-Connection aria2c

| Field | Value |
|-------|-------|
| **scenario_id** | `SRL-MVM-002` |
| **command** | `zelynic strict-run-lab --diagnose -d 100kb -- aria2c -x 4 -s 4 <download_url>` |
| **interface** | Physical (e.g., wlan0, eth0) — auto-detected or `--iface` |
| **expected route interface** | Same as `interface` field above |
| **expected cgroup placement** | Child PID verified in target cgroup. Note: aria2c spawns helper processes; only the main child PID is placed in the cgroup. Helper processes may inherit the cgroup via fork but this is not guaranteed |
| **expected nft socket cgroupv2 counter behavior** | packets > 0, bytes > 0. May be higher than single-connection due to multiple TCP streams from the same cgroup |
| **expected ct mark counter behavior** | packets > 0, bytes > 0. Higher than single-connection due to multiple connections |
| **expected download policer counter behavior** | packets > 0, bytes > 0. Aggregate policer should enforce 100kb/s across all connections |
| **expected drop counter behavior** | packets > 0, bytes > 0. Drops expected when aggregate exceeds rate |
| **expected speed behavior** | Measured aggregate speed approximately at or below 100kb/s |
| **expected cleanup behavior** | Same as Scenario 1 |
| **pass/fail criteria** | PASS: All counters nonzero, aggregate speed at or below limit, no orphaned state. Note: if helper processes escape the cgroup, their traffic will NOT be counted — document this separately as a known limitation |
| **notes** | Multi-connection tests whether the policer correctly aggregates bandwidth across connections from the same cgroup. aria2c's `-x 4` opens 4 server connections. Helper processes (aria2c RPC server, etc.) may fork outside the cgroup |

### Scenario 3: VPN/Tun Interface, Single-Connection aria2c

| Field | Value |
|-------|-------|
| **scenario_id** | `SRL-MVM-003` |
| **command** | `zelynic strict-run-lab --diagnose --iface proton0 -d 100kb -- aria2c -x 1 -s 1 <download_url>` |
| **interface** | VPN/tunnel (e.g., proton0, tun0, wg0) — explicit via `--iface` |
| **expected route interface** | Same as `interface` field (traffic routes through VPN) |
| **expected cgroup placement** | Child PID verified in target cgroup |
| **expected nft socket cgroupv2 counter behavior** | packets > 0, bytes > 0. This is the key scenario where the attach-after-socket approach previously showed 0/0. Pre-launch placement should produce nonzero counters |
| **expected ct mark counter behavior** | packets > 0, bytes > 0. Conntrack mark propagation must work on tunnel interfaces for the full pipeline |
| **expected download policer counter behavior** | packets > 0, bytes > 0. Policer must match download traffic on the tunnel interface |
| **expected drop counter behavior** | packets > 0, bytes > 0. Enforcement drops confirm the policer is active on the tunnel |
| **expected speed behavior** | Measured speed approximately at or below 100kb/s. VPN overhead may add latency |
| **expected cleanup behavior** | Same as Scenario 1. Verify tunnel interface state is clean after cleanup |
| **pass/fail criteria** | PASS: All counters nonzero (especially cgroup match, which was 0/0 with attach-after-socket), speed at or below limit, no orphaned state on tunnel interface. FAIL: Any counter zero (would match attach-after-socket failure pattern) |
| **notes** | This is the highest-value scenario. The original strict-run-lab experiment confirmed this works on Linux 6.18 + proton0. Must be re-tested on different VPN types (WireGuard, OpenVPN, Tailscale). Tunnel encapsulation may affect which interface the nft rules see. Document whether `ip route get` shows the tunnel interface for the download IP |

### Scenario 4: VPN/Tun Interface, Multi-Connection aria2c

| Field | Value |
|-------|-------|
| **scenario_id** | `SRL-MVM-004` |
| **command** | `zelynic strict-run-lab --diagnose --iface proton0 -d 100kb -- aria2c -x 4 -s 4 <download_url>` |
| **interface** | VPN/tunnel (e.g., proton0, tun0, wg0) — explicit via `--iface` |
| **expected route interface** | Same as `interface` field (traffic routes through VPN) |
| **expected cgroup placement** | Child PID verified in target cgroup |
| **expected nft socket cgroupv2 counter behavior** | packets > 0, bytes > 0. Should be higher than Scenario 3 due to multiple connections |
| **expected ct mark counter behavior** | packets > 0, bytes > 0 |
| **expected download policer counter behavior** | packets > 0, bytes > 0. Aggregate policer enforcement across multiple VPN-tunneled connections |
| **expected drop counter behavior** | packets > 0, bytes > 0 |
| **expected speed behavior** | Measured aggregate speed approximately at or below 100kb/s |
| **expected cleanup behavior** | Same as Scenario 1. Verify tunnel interface state is clean |
| **pass/fail criteria** | PASS: All counters nonzero, aggregate speed at or below limit, no orphaned state. Document any VPN-specific anomalies (reconnections, route changes during download) |
| **notes** | Combines VPN/tunnel complexity with multi-connection complexity. VPN reconnects during the download may cause counter resets. Record whether the cgroup placement survives a VPN reconnect. This scenario may be impractical on unstable VPN connections |

### Scenario 5: Browser Process Wrapper Smoke Test

| Field | Value |
|-------|-------|
| **scenario_id** | `SRL-MVM-005` |
| **command** | `zelynic strict-run-lab --diagnose -d 500kb -- firefox --no-remote` (or chromium, brave) |
| **interface** | Auto-detected or `--iface` (may differ for VPN vs non-VPN) |
| **expected route interface** | Whichever interface the browser uses for its first connection |
| **expected cgroup placement** | Main browser PID verified in target cgroup. Note: browsers spawn many child processes (GPU, renderer, sandbox). Only the main process PID is explicitly placed. Child processes may or may not inherit the cgroup depending on the browser's process model |
| **expected nft socket cgroupv2 counter behavior** | packets > 0, bytes > 0 for the main process sockets. Child process sockets may or may not be counted depending on cgroup inheritance |
| **expected ct mark counter behavior** | packets > 0, bytes > 0 for matched traffic |
| **expected download policer counter behavior** | packets > 0, bytes > 0 for download traffic from the main process |
| **expected drop counter behavior** | May be 0 if rate is generous (500kb/s). Should be > 0 with lower rate (100kb/s) |
| **expected speed behavior** | Speedtest should show approximate limiting. Not as precise as aria2c due to browser connection pooling, prefetch, and multiple processes |
| **expected cleanup behavior** | Same as other scenarios. Browser process tree cleanup: when the wrapper kills the main process, the browser may orphan child processes. This is expected and should be documented, not considered a zelynic cleanup failure |
| **pass/fail criteria** | PASS (smoke): Cgroup match counter > 0 for main process. Partial pass: some traffic counted but not all. Document which browser process model was tested and which traffic was/was not counted |
| **notes** | This is a smoke test, not a precision test. Browsers are complex process trees. The key question is whether the main browser process's sockets are classified under the cgroup. Chromium's zygote/sandbox model may prevent cgroup inheritance for renderer processes. Firefox's e10s model may behave differently. Test with `--no-remote` to avoid interfering with existing browser instances. Practical only if the operator can close all other browser instances first |

### Scenario 6: Failed Exec Cleanup

| Field | Value |
|-------|-------|
| **scenario_id** | `SRL-MVM-006` |
| **command** | `zelynic strict-run-lab -d 100kb -- /nonexistent/binary/path` |
| **interface** | Auto-detected |
| **expected route interface** | N/A (no network traffic) |
| **expected cgroup placement** | Fork may succeed and write PID to cgroup.procs, but exec fails |
| **expected nft socket cgroupv2 counter behavior** | 0/0 (no network traffic) |
| **expected ct mark counter behavior** | 0/0 |
| **expected download policer counter behavior** | 0/0 |
| **expected drop counter behavior** | 0/0 |
| **expected speed behavior** | N/A |
| **expected cleanup behavior** | Cgroup directory must be removed (or removal attempted with error reported). TC class/filters may not exist if policy was not applied. State entry must be cleaned. Command must exit with nonzero status |
| **pass/fail criteria** | PASS: Command exits with error, cgroup directory removed or removal error reported, no orphaned cgroup directory in `/sys/fs/cgroup/zelynic/`, no orphaned tc state. FAIL: Cgroup directory left behind, tc state left behind, or no cleanup attempted |
| **notes** | Tests the error path cleanup. The fork+pre_exec may write the child PID to cgroup.procs before exec fails. The cleanup must handle this case. Verify with `ls /sys/fs/cgroup/zelynic/` after the command exits |

### Scenario 7: Ctrl+C Cleanup

| Field | Value |
|-------|-------|
| **scenario_id** | `SRL-MVM-007` |
| **command** | `zelynic strict-run-lab -d 100kb -- sleep 300` (then press Ctrl+C after 5 seconds) |
| **interface** | Auto-detected |
| **expected route interface** | N/A (sleep produces no network traffic) |
| **expected cgroup placement** | Child PID verified in target cgroup |
| **expected nft socket cgroupv2 counter behavior** | 0/0 (sleep produces no network traffic) |
| **expected ct mark counter behavior** | 0/0 |
| **expected download policer counter behavior** | 0/0 |
| **expected drop counter behavior** | 0/0 |
| **expected speed behavior** | N/A |
| **expected cleanup behavior** | After Ctrl+C: signal forwarded to child (or process group), child exits, cleanup runs (cgroup dir removed, tc class/filters removed, state entry removed, nft table removed if no other limits). Output must show cleanup messages |
| **pass/fail criteria** | PASS: Command terminates within a few seconds of Ctrl+C, cleanup messages shown, no orphaned cgroup directory, no orphaned tc state. FAIL: Command hangs, orphaned state detected, or cleanup messages missing |
| **notes** | Use `sleep` for deterministic behavior (no network, no fast exit). The wrapper should handle SIGINT by forwarding to the child, waiting, then cleaning up. Test with `set -x; zelynic strict-run-lab -d 100kb -- sleep 300; echo "exit: $?"; ls /sys/fs/cgroup/zelynic/` |

### Scenario 8: Child Exits Normally Cleanup

| Field | Value |
|-------|-------|
| **scenario_id** | `SRL-MVM-008` |
| **command** | `zelynic strict-run-lab -d 100kb -- sleep 2` |
| **interface** | Auto-detected |
| **expected route interface** | N/A (sleep produces no network traffic) |
| **expected cgroup placement** | Child PID verified in target cgroup |
| **expected nft socket cgroupv2 counter behavior** | 0/0 (sleep produces no network traffic) |
| **expected ct mark counter behavior** | 0/0 |
| **expected download policer counter behavior** | 0/0 |
| **expected drop counter behavior** | 0/0 |
| **expected speed behavior** | N/A |
| **expected cleanup behavior** | After child exits (2 seconds): cgroup dir removed, tc class/filters removed, state entry removed. Output must show cleanup messages. Command exits with code 0 (or child's exit code) |
| **pass/fail criteria** | PASS: Command exits after ~2s, cleanup messages shown, no orphaned cgroup/tc/nft state. FAIL: Orphaned state detected or cleanup messages missing |
| **notes** | Simplest cleanup test. No network traffic means counters are 0/0, which is expected and correct. The key assertion is cleanup completeness, not counter values. Verify with `ls /sys/fs/cgroup/zelynic/ && tc class show dev <iface> && tc filter show dev <iface> && nft list tables` after the command |

### Scenario 9: Interface Mismatch Warning Behavior

| Field | Value |
|-------|-------|
| **scenario_id** | `SRL-MVM-009` |
| **command** | `zelynic strict-run-lab --diagnose --iface lo -d 100kb -- sleep 2` (or `--iface nonexistent0`) |
| **interface** | `lo` (loopback) or a non-existent interface name |
| **expected route interface** | May differ from specified interface |
| **expected cgroup placement** | Depends on whether the command proceeds past interface validation |
| **expected nft socket cgroupv2 counter behavior** | N/A or 0/0 |
| **expected ct mark counter behavior** | N/A or 0/0 |
| **expected download policer counter behavior** | N/A or 0/0 |
| **expected drop counter behavior** | N/A or 0/0 |
| **expected speed behavior** | N/A |
| **expected cleanup behavior** | If command proceeds: cleanup runs normally. If command rejects: no state created, no cleanup needed |
| **pass/fail criteria** | PASS: Command either rejects with clear interface error or proceeds with a warning about the interface mismatch. No silent mismatch. FAIL: Command proceeds on wrong interface without any warning |
| **notes** | Tests interface validation. The existing strict code path has tunnel interface detection via `is_tunnel_interface()`. The lab handler delegates to `apply_limit_with_diagnostics()` which includes interface checks. Document the exact warning message. Test with `lo`, a non-existent interface, and a VPN interface when not connected to VPN |

### Scenario 10: No-Root / Permission Error Behavior

| Field | Value |
|-------|-------|
| **scenario_id** | `SRL-MVM-010` |
| **command** | `sudo -u nobody zelynic strict-run-lab -d 100kb -- sleep 2` (or run as non-root user) |
| **interface** | N/A (should fail before interface resolution) |
| **expected route interface** | N/A |
| **expected cgroup placement** | N/A (should fail before cgroup creation) |
| **expected nft socket cgroupv2 counter behavior** | N/A |
| **expected ct mark counter behavior** | N/A |
| **expected download policer counter behavior** | N/A |
| **expected drop counter behavior** | N/A |
| **expected speed behavior** | N/A |
| **expected cleanup behavior** | No cleanup needed (no state created). Command must exit with nonzero status |
| **pass/fail criteria** | PASS: Command exits immediately with clear root-required error message. No state change. No cgroup directory created. No nft/tc rules installed. FAIL: Command proceeds as non-root, or error message is unclear, or partial state is created before the root check |
| **notes** | The handler must check UID 0 before any state mutation. Test that the error message mentions root/sudo. Verify with `ls /sys/fs/cgroup/zelynic/` after the command to confirm no state was created |

### Scenario 11: Existing Attach-Based Strict Still Works

| Field | Value |
|-------|-------|
| **scenario_id** | `SRL-MVM-011` |
| **command** | Step 1: `zelynic strict -d 100kb firefox` (attach mode, existing behavior). Then Step 2: verify strict-run-lab did not alter strict behavior |
| **interface** | Auto-detected or `--iface` |
| **expected route interface** | Default route interface |
| **expected cgroup placement** | Strict moves existing PID into cgroup (attach-after-socket) |
| **expected nft socket cgroupv2 counter behavior** | May be 0/0 (known attach-after-socket limitation on tunnel interfaces). On physical interfaces, may be > 0 for new connections after reconnect |
| **expected ct mark counter behavior** | Depends on whether cgroup match succeeded |
| **expected download policer counter behavior** | Depends on whether ct mark was set |
| **expected drop counter behavior** | Depends on whether policer matched |
| **expected speed behavior** | Policy installed; actual shaping depends on counter behavior |
| **expected cleanup behavior** | Strict's existing cleanup behavior (via `zelynic remove` or Ctrl+C on `zelynic strict`) |
| **pass/fail criteria** | PASS: `zelynic strict` behaves identically to pre-strict-run-lab behavior. Same output wording. Same counter patterns. No new warnings or error messages introduced by the strict-run-lab code |
| **notes** | This is a regression test for the compatibility contract. The strict-run-lab implementation must not have modified the existing strict handler, `apply_limit_with_diagnostics()`, traffic proof module, or any shared infrastructure in a way that changes strict behavior. Compare output with pre-strict-run-lab commits if possible. Test both with and without `--diagnose` |

### Scenario 12: Existing Attach-Based Strict Still Reports Traffic Proof Honestly

| Field | Value |
|-------|-------|
| **scenario_id** | `SRL-MVM-012` |
| **command** | `zelynic strict -d 100kb --diagnose <target>` with a running process, then inspect the traffic proof section of the output |
| **interface** | Auto-detected or `--iface` |
| **expected route interface** | Default route interface |
| **expected cgroup placement** | Strict moves existing PID into cgroup (attach-after-socket) |
| **expected nft socket cgroupv2 counter behavior** | Same as before strict-run-lab: may be 0/0 on tunnel, > 0 on physical |
| **expected ct mark counter behavior** | Same as before strict-run-lab |
| **expected download policer counter behavior** | Same as before strict-run-lab |
| **expected drop counter behavior** | Same as before strict-run-lab |
| **expected speed behavior** | Same as before strict-run-lab |
| **expected cleanup behavior** | Same as before strict-run-lab |
| **pass/fail criteria** | PASS: Traffic proof output is identical in format and classification to pre-strict-run-lab behavior. Counter values follow the same pattern. "Policy installed" wording (not "limited"). Honest proof classification (NotChecked, NoMatchObserved, CgroupMatchObserved, PolicerMatchObserved, Inconclusive). FAIL: Wording changed, classification changed, or new fields appeared in the proof output |
| **notes** | Validates the traffic proof honesty audit remains intact. The strict-run-lab code shares the `render_strict_traffic_proof()` function but must not have modified it. Compare the exact output text with the traffic proof honesty audit documentation. Pay attention to whether the proof status classification matches the expected state based on counter values |

## Recording Template

For each scenario execution, record:

```
Date: <ISO 8601>
Scenario: <scenario_id>
Kernel: <uname -r>
Distribution: <cat /etc/os-release | grep PRETTY_NAME>
Zelynic: <zelynic --version>
Commit: <git rev-parse --short HEAD>
VPN: <software and version, or "none">
Interface: <ip link show | grep <iface>>
Command: <exact command used>
Duration: <seconds>

Counter Values (at end of run):
  nft socket cgroupv2: <pkts> pkts / <bytes> bytes
  nft ct mark:          <pkts> pkts / <bytes> bytes
  nft download policer: <pkts> pkts / <bytes> bytes
  nft drop:             <pkts> pkts / <bytes> bytes

Speed: <measured speed>
Proof classification: <NotChecked|NoMatchObserved|CgroupMatchObserved|PolicerMatchObserved|Inconclusive>

Cleanup verification:
  ls /sys/fs/cgroup/zelynic/: <output or "empty">
  tc class show dev <iface>: <output or "no zelynic class">
  tc filter show dev <iface>: <output or "no zelynic filter">
  nft list table inet zelynic: <output or "table does not exist">

Result: PASS / FAIL
Notes: <any observations, anomalies, VPN reconnects, etc.>
```

## Relationship to Other Documents

- [strict-run-lab-ctrlc-cleanup-audit.md](strict-run-lab-ctrlc-cleanup-audit.md): Records
  the audit and fix of the Ctrl+C cleanup behavior. SRL-MVM-007 (Ctrl+C cleanup)
  was partially failing before this audit phase. The fix adds a libc-based SIGINT
  handler that triggers cleanup on Ctrl+C.
- [strict-run-wrapper-stable-contract.md](strict-run-wrapper-stable-contract.md): Defines the
  future stable wrapper design contract. This matrix is the evidence-gathering phase
  that feeds into that contract's promotion checklist (Section 6).
- [strict-run-lab-validation-freeze.md](strict-run-lab-validation-freeze.md): Defines the
  deterministic invariant tests that freeze the lab command's code-level invariants.
  This matrix complements those tests with manual, environment-dependent validation.
- [strict-prelaunch-cgroup-wrapper-experiment.md](strict-prelaunch-cgroup-wrapper-experiment.md):
  Describes the experiment hypothesis and architecture. This matrix defines the
  structured validation of that experiment's claims across multiple scenarios.

## Current Status

| Scenario | Status | Date | Result |
|----------|--------|------|--------|
| SRL-MVM-001 | PASS (single run) | 2026-06-10 | All 4 counter groups nonzero; speed 60-106 KiB/s at 100kb policy; manual unstrict cleanup succeeded; Ctrl+C cleanup NOT tested before ctrlc-cleanup-audit phase |
| SRL-MVM-002 | Not run | - | - |
| SRL-MVM-003 | Partially run (Linux 6.18 + proton0, single run, nonzero counters) | 2026-06-10 | PASS (single run) |
| SRL-MVM-004 | Not run | - | - |
| SRL-MVM-005 | Not run | - | - |
| SRL-MVM-006 | Not run | - | - |
| SRL-MVM-007 | Fix implemented; pending re-test | 2026-06-10 | Ctrl+C cleanup now uses libc sigaction handler. See ctrlc-cleanup-audit.md |
| SRL-MVM-008 | Pending re-test | - | - |
| SRL-MVM-009 | Not run | - | - |
| SRL-MVM-010 | Not run | - | - |
| SRL-MVM-011 | Not run | - | - |
| SRL-MVM-012 | Not run | - | - |

## Non-Goals

- This is NOT automated test infrastructure
- This does NOT replace the deterministic unit tests in `strict_run_lab.rs`
- This does NOT implement stable wrapper behavior
- This does NOT promote `strict-run-lab` to stable
- This does NOT claim any scenario is conclusive from a single run
- This does NOT guarantee behavior across all kernel versions, VPN types, or network configurations