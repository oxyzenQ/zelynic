# Strict Traffic Proof Honesty Audit

## Purpose

This phase makes strict output honest about the distinction between "PID moved and
verified into the correct cgroup" and "traffic is actually being shaped by nftables
policer rules." These are not the same thing. A PID may be successfully moved into a
cgroup, nft rules may be successfully installed referencing that cgroup, and the
summary may report the process as "limited" — yet the actual traffic may bypass the
policer entirely.

The live finding on Linux 6.18 + ProtonVPN/proton0 + aria2c confirms this gap:

**Verified PID moved ≠ verified traffic shaped.**

This phase introduces diagnostics, output wording, and documentation changes to
surface the honest state: that policy was installed, but whether traffic actually
matched the nft rules is a separate and observable question.

## Live Finding

**Environment**: Linux 6.18, ProtonVPN (proton0 tunnel interface), aria2c download

**Command**: `strict --diagnose --iface proton0 -d 100kb aria2c`

**Result**:

1. PID is moved and verified into the correct cgroup — success
2. nft rules are installed successfully — success
3. aria2c download still exceeds 100 KB/s — **shaping not effective**
4. `nft list table` shows cgroup match rule and download policer rule are present
5. nft cgroup match counters: **0 packets / 0 bytes**
6. nft download policer counters: **0 packets / 0 bytes**

**Conclusion**: Existing sockets created before the cgroup move and/or VPN/tunnel
routing (proton0) bypass the current socket-cgroup nft match. The nft `meta cgroup`
expression matches sockets that belong to the cgroup at match time, but sockets
already established through the VPN tunnel before the PID was moved retain their
original routing context. The cgroup match may also not apply to traffic routed
through tunnel interfaces that use separate network namespaces or bypass the
standard cgroup classification path.

This is not a bug in the limiter logic — the PID move and rule installation are
correct. The issue is that the output claimed the process was "limited" when in
fact the traffic was not being shaped.

## Changes Made

### New Module: `src/limiter/traffic_proof.rs` (905 LOC)

Pure model, parser, and renderer for strict traffic proof diagnostics. Contains no
enforcement code, no filesystem I/O, no process scanning, no nft/tc mutation. This
module provides:

- Model types for representing nft counter state and traffic proof status
- Parser for extracting counter values from `nft list table` output
- Renderer for producing human-readable traffic proof diagnostics
- Classifier for determining the honest status from observed counter values
- Tunnel interface detection for VPN/tunnel awareness

### Modified: `src/limiter/output.rs` (102 LOC)

Summary wording changes only:

- Wording changed from "limited" to "policy installed" to honestly reflect that
  policy was installed but traffic shaping effectiveness is not guaranteed
- Added traffic proof section to summary output when `--diagnose` is used, showing
  nft counter values and honest status classification

### Modified: `src/limiter/mod.rs` (848 LOC)

- Added `build_traffic_proof()` helper that reads nft counters (diagnostic-only,
  only when `--diagnose` is passed) and detects tunnel interfaces
- Integrated into apply flow: after nft rules are applied but before summary print
- No enforcement semantics change

### Modified: `src/limiter/cleanup.rs` (926 LOC)

- Improved interface change warning in status to be tunnel-aware
- When the stored interface is a VPN/tunnel interface (matching tun*/wg*/proton*/
  tap*/vpn*), the warning notes this is expected behavior when using `--iface`
  instead of suggesting re-apply

### Modified: `src/limiter/refresh.rs` (459 LOC)

- Same tunnel-aware improvement for refresh interface mismatch warning
- When interface mismatch involves a VPN/tunnel interface, the warning provides
  appropriate context instead of suggesting standard re-apply

## Model Types

### `StrictTrafficProofCounters`

Represents the raw nft counter values observed for the cgroup match rule and the
download policer rule:

```
StrictTrafficProofCounters {
    cgroup_match_packets: u64,
    cgroup_match_bytes: u64,
    policer_packets: u64,
    policer_bytes: u64,
}
```

### `StrictTrafficProofStatus` (enum)

Classification of what the counters reveal:

| Variant | Meaning |
|---------|---------|
| `NotChecked` | No diagnostic read was performed (no `--diagnose`) |
| `NoMatchObserved` | Counters read and both cgroup match and policer show 0 packets/0 bytes — traffic is bypassing the rules |
| `CgroupMatchObserved` | Cgroup match counter is nonzero but policer counter is 0 — traffic reaches the match rule but policer did not trigger |
| `PolicerMatchObserved` | Policer counter is nonzero — traffic is being actively shaped |
| `Inconclusive` | Counter state is ambiguous (e.g., policer nonzero but cgroup match zero, or partial data) |

### `TunnelInterfaceCheck`

Detects whether the active interface matches known VPN/tunnel interface name
patterns:

```
TunnelInterfaceCheck {
    interface_name: String,
    is_tunnel: bool,
}
```

### `StrictTrafficProof`

Top-level aggregate:

```
StrictTrafficProof {
    status: StrictTrafficProofStatus,
    counters: StrictTrafficProofCounters,
    tunnel_check: TunnelInterfaceCheck,
}
```

## Parser

### `parse_nft_counter_lines_for_mark()`

Reads "packets N bytes M" lines from `nft list table` output for specific rule
marks (cgroup match and policer rules). The parser:

- Accepts a slice of output lines from `nft list table`
- Searches for lines containing "packets" and "bytes" keywords
- Extracts the numeric counter values
- Returns `StrictTrafficProofCounters` with parsed values (0 if not found)
- Is deterministic and testable with injected input — no live nft calls

## Output Wording Changes

### Summary Wording

**Before**: `Download: 1 MB/s (limited, nftables policer)`

**After**: `Download: 1 MB/s (policy installed, nftables policer)`

The change from "limited" to "policy installed" honestly reflects that the policy
was installed but does not claim the traffic is actually being shaped.

### Tunnel Interface Warning

When the interface matches known VPN/tunnel patterns (tun*, wg*, proton*, tap*,
vpn*), a warning is included in the output noting that tunnel interfaces may bypass
socket-cgroup matching.

### Traffic Proof Not Observed Warning

When nft counters are zero (both cgroup match and policer), a warning is included
in the `--diagnose` output:

```
Traffic proof warning: nft counters show 0 packets / 0 bytes for both
cgroup match and policer rules. Traffic may be bypassing the installed
policy. This is expected with VPN/tunnel interfaces.
```

### Improved Interface Mismatch Warning

For VPN/tunnel interfaces in status and refresh, the interface mismatch warning
provides tunnel-specific context:

**Before** (generic): `Interface mismatch detected — consider re-applying`

**After** (tunnel-aware): `Interface mismatch: proton0 is a VPN/tunnel interface.
This is expected when using --iface. If shaping is not effective, traffic may be
bypassing the cgroup match due to tunnel routing.`

## What This Phase Does NOT Change

This phase is strictly diagnostics, output wording, and documentation:

- **No enforcement semantics**: nft/tc/cgroup mutation logic unchanged
- **No eBPF**: No eBPF code added or modified
- **No daemon/watch**: No background monitoring or continuous observation
- **No quota**: No quota tracking or limits
- **No persistence**: No file read/write for state
- **No ledger file read/write**: Ledger persistence untouched
- **No v3.0 usage JSON schema change**: Output JSON format unchanged
- **No version bump**: Version remains unchanged
- **No new dependencies**: Only existing crates used
- **No new public commands**: No CLI surface changes
- **No new /proc reads beyond existing strict diagnostics**: Counter reading only
  occurs through existing nft diagnostic infrastructure when `--diagnose` is used

## Tests

35 deterministic tests in `traffic_proof.rs` covering:

### Counter Parsing (13 tests)
- Zero counters (both rules show 0/0)
- Nonzero counters (one or both rules have values)
- Both rules nonzero
- Large counter values (u64 edge cases)
- Empty input (no lines)
- Missing counter fields
- Malformed counter lines
- Counter line with extra whitespace
- Multiple counter lines (selects correct ones by mark)

### Classification (6 tests)
- `NotChecked` status when diagnostic not performed
- `NoMatchObserved` when both counters are zero
- `CgroupMatchObserved` when cgroup counter nonzero but policer zero
- `PolicerMatchObserved` when policer counter nonzero
- `Inconclusive` for ambiguous counter states

### Tunnel Detection (6 tests)
- proton0 detected as tunnel
- tun0 detected as tunnel
- wg0 detected as tunnel
- tap0 detected as tunnel
- vpn0 detected as tunnel
- wlp1s0 NOT detected as tunnel (normal interface)
- Case sensitivity handling

### Output Wording (6 tests)
- "policy installed" appears in summary (not "limited")
- Bypass warning content present when counters are zero
- Counter values appear in `--diagnose` output
- Honest "not checked" status when `--diagnose` not used
- Tunnel interface warning content

### Structural Safety Invariants (4 tests)
- No enforcement code in module source (source-level audit)
- No ruleset generation code in module source
- No filesystem persistence code in module source
- No ledger persistence code in module source

## Design Rationale

The core insight is that "PID moved successfully" and "nft rules installed
successfully" are necessary but not sufficient conditions for "traffic is being
shaped." The gap exists because:

1. **Pre-existing sockets**: Sockets created before the PID was moved into the
   cgroup may retain their original cgroup classification or routing context
2. **Tunnel routing**: VPN/tunnel interfaces (like proton0) route traffic through
   a tunnel device that may not pass through the standard cgroup match path
3. **Socket ownership timing**: The nft `meta cgroup` match applies to sockets
   at the time of packet processing, but socket creation and cgroup membership
   are not atomic

By surfacing the nft counter state honestly, users can see whether their traffic
policy is actually being applied, and take appropriate action (e.g., restarting
the target process after policy installation, or using a different shaping
approach for tunnel traffic).
