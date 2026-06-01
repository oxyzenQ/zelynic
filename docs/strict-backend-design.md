# `zelynic strict` backend design

This document describes the current `zelynic strict` enforcement backend. It is intentionally descriptive, not a claim that bandwidth limiting is fully reliable on every Linux host.

## Current backend

`zelynic strict` currently combines three Linux mechanisms:

1. **cgroup v2 process grouping**: discovered target PIDs are moved under `/sys/fs/cgroup/zelynic/target_<name>/` and verified through `/proc/<pid>/cgroup`.
2. **nftables socket matching and conntrack marking**: the generated `table inet zelynic` marks egress packets with `socket cgroupv2 level ...`, copies the packet mark to `ct mark` in postrouting, and uses the connection mark for download policing in the input hook.
3. **tc HTB upload shaping**: target packet marks are routed by `tc` fw filters into a per-target HTB class.

The implementation deliberately does not use `meta skuid` as the isolation primitive. UID matching would affect unrelated processes owned by the same user and would hide cgroup/socket coverage bugs that need to be fixed directly.

Runtime namespace note: Zelynic uses `/run/zelynic`, `/sys/fs/cgroup/zelynic`, and `table inet zelynic`. v2.0.0-era `oxy` runtime artifacts are legacy cleanup targets and should not be used for new strict state.

## Apply workflow

A strict apply should preserve these invariants:

1. Validate root privileges, rates, and network interface.
2. Clean orphaned state before adding new state.
3. Resolve the requested target to one or more PIDs using conservative process-name matching. Numeric PID targets are exact; text targets match `/proc/<pid>/comm`, the `/proc/<pid>/exe` basename, or argv[0] basename with safe aliases such as `brave` -> `brave-browser`.
4. Create `/sys/fs/cgroup/zelynic/target_<sanitized_name>/`.
5. Move every discovered live PID into that cgroup and verify membership through `/proc/<pid>/cgroup`.
6. Re-resolve name-based targets before saving state so newly spawned live PIDs are not silently missed.
7. Persist one state record per verified PID while sharing the per-target nftables mark and tc class identity. When available, state also records the PID's original cgroup v2 path before movement.
8. Install or refresh tc HTB classes and fw filters.
9. Generate `/run/zelynic/zelynic.nft`, preflight it with `nft -c -f`, then apply it with `nft -f`.
10. Save `/run/zelynic/state.json` only after enforcement artifacts have been created.
11. Force a short reconnect window because sockets created before cgroup movement keep their old socket cgroup association.

Interface note: when `--iface` is not provided, strict mode detects the interface
at apply time from `ip route show default`. The tc HTB upload side remains
attached to that interface. If the host later switches default routes, re-run
`unstrict` and apply strict again; automatic tc migration is intentionally not
implemented yet.

Unstrict note: Zelynic tries to restore each live PID to its recorded original
cgroup when the path is still under `/sys/fs/cgroup`, exists, and exposes
`cgroup.procs`. If that cannot be proven safely, Zelynic avoids guessing
systemd/user paths and falls back to the `/sys/fs/cgroup/zelynic` parent cgroup
or leaves the target cgroup in place when it is not empty.

Refresh note: Zelynic does not run a daemon or automatically capture a fully
reopened application. `zelynic refresh <target>` is the explicit manual path for
that lifecycle: it reuses the existing state and target cgroup, discovers current
matching PIDs, moves only missing live PIDs into the cgroup, records their
original cgroup where available, and leaves nftables/tc rules untouched.

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
- generated `/run/zelynic/zelynic.nft`
- stdout/stderr from `nft -c -f /run/zelynic/zelynic.nft` and `nft -f /run/zelynic/zelynic.nft`
- current nftables table handles from `sudo nft -a list table inet zelynic`
- relevant `tc qdisc`, `tc class`, and `tc filter` output
- `/run/zelynic/state.json`

`zelynic strict --diagnose ...` now prints most of this during an apply attempt, including why each selected PID matched, so the next fix can be based on observed host behavior rather than guesses.

`zelynic backend doctor` is the read-only preflight for host capability detection. It reports kernel, cgroup, nftables, tc, conntrack, systemd, and eBPF signals, then scores backend candidates without modifying nftables, tc, or cgroups. Backend Doctor can recommend the safest available backend, but strict mode is only truly validated after a real `zelynic strict --diagnose ...` test.

## Support matrix

| Host type | Status |
|-----------|--------|
| Arch/CachyOS pure cgroup v2 | Tested |
| Modern systemd + cgroup v2 distros | Expected |
| Older Ubuntu/Debian, hybrid cgroup, containers, WSL, non-systemd distros | Partial/unknown |
| systemd-scope backend, cgroup v1 fallback, eBPF backend | Future |

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
