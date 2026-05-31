# `zelynic strict` backend design

This document describes the current `zelynic strict` enforcement backend. It is intentionally descriptive, not a claim that bandwidth limiting is fully reliable on every Linux host.

## Current backend

`zelynic strict` currently combines three Linux mechanisms:

1. **cgroup v2 process grouping**: discovered target PIDs are moved under `/sys/fs/cgroup/oxy/target_<name>/` and verified through `/proc/<pid>/cgroup`.
2. **nftables socket matching and conntrack marking**: the generated `table inet oxy` marks egress packets with `socket cgroupv2 level ...`, copies the packet mark to `ct mark` in postrouting, and uses the connection mark for download policing in the input hook.
3. **tc HTB upload shaping**: target packet marks are routed by `tc` fw filters into a per-target HTB class.

The implementation deliberately does not use `meta skuid` as the isolation primitive. UID matching would affect unrelated processes owned by the same user and would hide cgroup/socket coverage bugs that need to be fixed directly.

Compatibility note: Zelynic currently preserves legacy oxy runtime paths and nft/cgroup identifiers for backward compatibility. These may migrate in a future major release with a safe migration path.

## Apply workflow

A strict apply should preserve these invariants:

1. Validate root privileges, rates, and network interface.
2. Clean orphaned state before adding new state.
3. Resolve the requested target to one or more PIDs.
4. Create `/sys/fs/cgroup/oxy/target_<sanitized_name>/`.
5. Move every discovered live PID into that cgroup and verify membership through `/proc/<pid>/cgroup`.
6. Re-resolve name-based targets before saving state so newly spawned live PIDs are not silently missed.
7. Persist one state record per verified PID while sharing the per-target nftables mark and tc class identity.
8. Install or refresh tc HTB classes and fw filters.
9. Generate `/run/oxy/oxy.nft`, preflight it with `nft -c -f`, then apply it with `nft -f`.
10. Save `/run/oxy/state.json` only after enforcement artifacts have been created.
11. Force a short reconnect window because sockets created before cgroup movement keep their old socket cgroup association.

## Why this is fragile

The backend is sensitive to details that vary by kernel, nftables version, systemd policy, and process model:

- `socket cgroupv2 level ...` matching depends on the cgroup path and ancestor level semantics accepted by the installed nftables/kernel pair.
- A PID can be written to `cgroup.procs` successfully and then be moved back by systemd or another manager.
- Multi-process applications can spawn new network-capable processes while `zelynic strict` is applying.
- Sockets created before cgroup movement retain their original socket cgroup association.
- Download limiting relies on egress packet marking being copied to conntrack and later observed on reply packets.
- nftables input-hook rate limiting is policing, not queueing/shaping, so behavior can differ from upload HTB shaping.

## Requirements to validate on a real machine

A useful bug report should include:

- kernel version (`uname -r`)
- nftables version (`nft --version`)
- iproute2/tc version (`tc -V`)
- cgroup mode and cgroup2 mount line from `/proc/self/mountinfo`
- target PID list and `/proc/<pid>/cgroup` before and after movement
- generated `/run/oxy/oxy.nft`
- stdout/stderr from `nft -c -f /run/oxy/oxy.nft` and `nft -f /run/oxy/oxy.nft`
- relevant `tc qdisc`, `tc class`, and `tc filter` output
- `/run/oxy/state.json`

`zelynic strict --diagnose ...` now prints most of this during an apply attempt so the next fix can be based on observed host behavior rather than guesses.

## Backend alternatives

### 1. Current cgroup v2 + nftables backend

This remains the best short-term path because it is already implemented and preserves per-target isolation without UID leakage. The safest next step is to make failures observable, confirm the exact nftables cgroupv2 syntax and level semantics on target hosts, then make a narrow correction if diagnostics prove one is needed.

### 2. `systemd-run` transient scope/slice backend

Instead of moving arbitrary existing PIDs, `zelynic` could create or request a transient systemd scope/slice and place the target there. This may cooperate better with systemd but is harder for already-running GUI applications and requires systemd-specific code paths.

### 3. cgroup v1 `net_cls` fallback

Where available, cgroup v1 `net_cls.classid` can integrate with tc cgroup filters. This is not a good primary path on modern pure cgroup v2 systems and should remain a compatibility fallback only.

### 4. process-tree + fwmark fallback

A fallback could repeatedly discover target process trees and apply marks by process-related metadata. This is likely less precise and risks cross-process leakage if it falls back to UID-level matching.

### 5. application wrapper mode

The most reliable cgroup placement model is for `zelynic` to start the target process inside the desired cgroup before any sockets exist. That avoids the existing-socket problem and reduces races, but it is a new user workflow and does not solve already-running applications.

## Recommended next implementation path

1. Keep the current backend behavior intact.
2. Use `zelynic strict --diagnose` on an affected Arch/Linux machine.
3. Fix only the proven failure point, most likely in cgroup path/level generation, PID movement verification, or nftables rule application.
4. Consider adding a small backend boundary later around rule installation and cleanup, but do not rewrite PID discovery, cgroup movement, state, and tc/nft orchestration until the current failure is proven.
