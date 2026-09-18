<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Safety Analysis

> Is zelynic safe? Is it malware? What happens when it crashes?

## Short Answer

**zelynic is safe. It is not malware.** It is a pure eBPF bandwidth limiter
that:
- Does NOT collect, transmit, or store user data
- Does NOT make network connections (except `--check-update` which is opt-in
  and refuses to run as root)
- Does NOT modify system files (except `/sys/fs/bpf/zelynic/` pin files)
- Does NOT install services, cron jobs, or daemons
- Does NOT require internet access to function
- Fails SAFE: on any error, BPF allows all traffic (no blocking on failure)

## What zelynic Does

### BPF Programs (kernel)
- Hooks `cgroup_skb/ingress` and `cgroup_skb/egress` on cgroup v2 root
- Counts packets per cgroup (observer)
- Enforces token-bucket rate limits per cgroup (limiter)
- **Returns 1 (allow)** on every error path — never blocks on failure

### Userspace (Rust binary)
- Loads BPF programs via aya
- Reads/writes BPF maps (policies, stats, watchdog)
- Walks `/proc` to resolve process names → cgroup IDs
- Pins programs + links + maps to `/sys/fs/bpf/zelynic/` for
  fire-and-forget enforcement (no process needs to stay alive)

### What zelynic Does NOT Do
- No telemetry, analytics, or phone-home
- No automatic network connections (except opt-in `--check-update`)
- No data collection or logging of user activity
- No modification of system files (except BPF pin files)
- No installation of systemd services or cron jobs
- No background process of any kind — enforcement lives in the kernel
- No reading of user files (only `/proc/*/comm` and `/proc/*/cgroup`)
- No network packet inspection (BPF only counts bytes, doesn't read content)

## File System Access

| Path | Read/Write | Purpose |
|------|------------|---------|
| `/proc/*/comm` | Read | Process name for target resolution |
| `/proc/*/cgroup` | Read | Cgroup path for target resolution |
| `/proc/*/status` | Read | UID for identity display |
| `/sys/fs/cgroup/*` | Read | `cgroup.id` file for ID resolution |
| `/sys/fs/cgroup` | Read | Attach BPF programs |
| `/sys/fs/bpf/zelynic/*` | Read/Write | Pinned BPF programs, links, maps |
| `/tmp/zelynic.pid` | Remove-only | Legacy cleanup (never written since v10; removed if left by old versions) |
| `/run/zelynic/zelynic.lock` | Read/Write | flock-based operation guard inside the root-owned 0700 `/run/zelynic/` dir (NIGHT-hunt-14); the legacy `/tmp/zelynic.lock` is remove-only hygiene |

**No other file system access.** No reading of user documents, browser data,
network config, or system passwords.

## Network Access

zelynic makes **zero outbound network connections** during normal operation.

The only network-related activity:
1. **BPF programs**: hook network packets in kernel (count/enforce) — do NOT
   read packet content, do NOT connect to anything
2. **`--check-update` flag**: opt-in GitHub API call to check latest release.
   Disabled by default. Only runs when user explicitly requests it — and
   **refuses to run as root** (exit with an error before any network I/O;
   re-run without sudo).

## Privilege Model

Full root-usage audit (NIGHT-hunt-11). Every command has exactly one
privilege contract:

| Surface | Root? | Contract |
|---------|-------|----------|
| `strict-single`/`strict-multi`/`limit-all`, `block-single`/`block-multi`/`block-all`, `unstrict`/`unstrict-all`/`recover` | required | load, attach, and pin BPF programs; write policy maps. Fail fast with a "re-run with sudo" tip before touching BPF state when run non-root |
| `status`, `observe`, `top` | required | read pinned BPF maps (same fail-fast guard) |
| `list-apps`, `doctor` | either | pure `/proc` + `/sys` reads; `doctor` additionally reports pin state when root |
| `--help`, `-h`, `-V`/`--version`, bare invocation | either | pure stdout, no side effects, no file or network access |
| `--check-update` | **refused** | network fetch via curl — exits with a branded error when euid is 0, before any network I/O |

The `--check-update` refusal is deliberate: a root network round-trip buys
nothing (the check only reads a release tag), curl would inherit root's
environment wholesale, and any future download step would plant root-owned
files into the invoking user's home. This is the mirror image of the eBPF
guard: there root is the requirement, here root is the hazard.

## Crash Safety

### If zelynic crashes mid-operation:
1. Enforcement is unaffected — it lives in pinned BPF programs + links,
   not in any zelynic process
2. A crash between "pin" and "write policy" can leave orphaned pin files;
   `zelynic recover` detects and removes them
3. The flock guard (`/run/zelynic/zelynic.lock`) releases automatically when the
   crashed process dies — no stuck lock

### If user runs `unstrict-all`:
1. All pin files removed (`/sys/fs/bpf/zelynic/*`)
2. Pin directory removed
3. BPF programs + links unloaded (kernel cleans up when the last
   reference closes)
4. **Zero residue** — system returns to pre-zelynic state

### If user reboots:
1. bpffs is not persistent — all pins vanish with the mount
2. BPF programs unloaded, limits gone
3. **Zero residue** after reboot

## BPF Safety

### Verifier guarantees:
- **No infinite loops**: BPF verifier guarantees program termination
- **No out-of-bounds access**: all memory accesses bounds-checked
- **No unbounded resource consumption**: maps have fixed max_entries
- **No kernel crash**: BPF runs in sandbox, cannot crash kernel (Linux 5.x+)

### Fail-safe design:
- No policy for cgroup → allow (return 1)
- Bucket creation fails → allow (return 1)
- Map lookup fails → allow (return 1)
- Watchdog expired → allow (return 1) — dormant mechanism, see below

### Pin mode (fire-and-forget):
- The watchdog is never armed since v10 (deadline 0 = absent) — BPF always enforces
- Rate = 0 is an explicit user request: `block-single`/`block-*` write a
  zero rate and BPF blocks all traffic for that cgroup (schema v3)
- If anything unexpected happens to the pins, `zelynic recover` repairs
  state and `unstrict-all` removes everything

## Memory Safety (Rust)

zelynic is written in Rust, which provides:
- **Memory safety**: no buffer overflows, no use-after-free, no null dereferences
- **Thread safety**: no data races (Rust ownership model)
- **No unsafe code** in userspace outside six audited `unsafe` blocks:
  `libc::flock` (operation guard), three raw `bpf()` syscall wrappers
  (bpf_syscall.rs — link create/pin/close), `libc::clock_gettime`, and
  `libc::ioctl(TIOCGWINSZ)` for terminal width — all standard POSIX
  calls with well-defined semantics

### BPF C code:
- BPF verifier ensures memory safety at load time
- All map accesses bounds-checked by verifier
- No dynamic allocation (BPF programs can't allocate memory)

## Race Conditions

### BPF map access:
- BPF maps are kernel-managed, atomic operations
- Multiple CPUs can access maps concurrently — kernel handles synchronization
- `stats->packets += 1` is NOT atomic, but this is acceptable:
  - Under-counting is possible (lost updates)
  - Over-counting is not possible
  - Stats are for display only, not for enforcement decisions

### Concurrent CLI invocations:
- The flock guard (`lock.rs`) serializes mutating operations — two
  zelynic processes never write policy maps at the same time
- Kernel BPF map operations are atomic per-entry
- No torn reads/writes possible

## Security Audit (NIGHT-hunt-14 / security-1, 2026-09)

Master audit across every attack surface a local unprivileged user,
a hostile environment, or a malicious input can reach. Two real
findings fixed; the rest of the surface verified clean and pinned.

### Finding 1 (fixed): world-writable lock file

The flock guard lived at `/tmp/zelynic.lock`, giving any local
unprivileged user two primitives against the root-running tool:

- **Lock squatting (local DoS):** create the file and hold `flock`
  forever — every enforcement command then fails with "another zelynic
  operation is in progress" until an admin deletes the file, and the
  attacker can re-plant it at will.
- **Symlink following:** root's `open(O_WRONLY)` on a `/tmp` path
  follows attacker-planted symlinks (no write/truncate happens in the
  current code, but the open itself must never follow untrusted links).

Fix: the lock now lives at `/run/zelynic/zelynic.lock` inside a
root-owned `0700` directory zelynic creates on first use (`/run` is a
root-owned tmpfs — same trust class as `/sys/fs/bpf`; only root can
create entries inside). A unit test pins the path so it cannot silently
move back into a world-writable location. The legacy `/tmp` file is
removed opportunistically (unlink is symlink-safe by syscall
semantics). Error wording and the non-blocking retry contract are
unchanged.

### Finding 2 (fixed, defense-in-depth): CI script-injection class

`ci.yml` interpolated `${{ github.event.*.sha }}` directly inside a
`run:` script. The values are git-controlled SHAs (not attacker free
text), so there was no exploitable path — but the canonical
defense-in-depth pattern is env-var isolation, which now applies: all
event context reaches scripts through `env:` only. No other workflow
interpolates event context inside `run:` blocks (release.yml's
`${GITHUB_REF_NAME#v}` is shell-level expansion at runtime, on tags
already format-validated by the release `validate` job; `pull_request`
— never `pull_request_target` — is the PR trigger, so fork builds see
no secrets).

### Verified clean (no change needed)

- **update.rs (`--check-update`):** fixed HTTPS URL, argv-array curl
  invocation (no shell, no injection), `--max-time 15` hang bound,
  mapped failure codes (DNS/refused/timeout/TLS/HTTP), UTF-8 checked,
  manual tag scan with `?` propagation (no panics), root refused before
  any network I/O (NIGHT-hunt-11).
- **Panic hunt:** every `unwrap`/`expect`/`panic!` outside
  `#[cfg(test)]` was audited — none reachable from user input; rate,
  interval, and JSON parsing all propagate errors. The 70-case
  non-root matrix (scripts/nonroot-depth-test.sh) asserts exit 101 and
  backtraces never occur.
- **Path handling:** `/proc/<pid>/{comm,cgroup,status}` are read with
  error-tolerant matches; cgroup paths come from kernel-generated
  `/proc` files (cgroup names cannot contain `/` or `..`), so the
  `/sys/fs/cgroup{path}` join has no traversal vector. BPF object
  discovery only probes fixed, root-writable locations.
- **Arithmetic:** `default_burst` clamps (no overflow); rate parsing
  maps parse errors to friendly errors with typo tips.
- **cgroup ID width:** BPF map keys are `u32` while kernel cgroup IDs
  are `u64`. Truncation collision would require ~4 billion kernfs node
  creations on one boot — accepted as unreachable for the tool's
  lifetime; revisit only if the kernel ever recycles IDs aggressively.
- **Dangerous-target blocklist:** string matching on `comm` is a UX
  guard, not a security boundary — the operator invoking zelynic is
  already root and owns the system. Renaming a binary to dodge the
  blocklist is out of scope by design.

## Verifying Safety Yourself

### Check network connections:
```bash
# While zelynic is running, check for any network connections
sudo ss -tunp | grep zelynic
# Should show nothing (except --check-update if running)
```

### Check file access:
```bash
# Trace file access by zelynic
sudo strace -f -e trace=openat zelynic strict-single brave 100kb 2>&1 | head -50
```

### Check BPF programs:
```bash
# See what BPF programs are loaded
sudo bpftool prog show | grep -A2 enforce
```

### Check BPF maps:
```bash
# See what BPF maps are pinned
ls -la /sys/fs/bpf/zelynic/
```

### Check for residue after unstrict-all:
```bash
sudo zelynic unstrict-all
ls /sys/fs/bpf/zelynic/ 2>&1  # should not exist
ls /tmp/zelynic.pid 2>&1      # should not exist
sudo bpftool prog show | grep enforce  # should be empty
```

## License

GPL-3.0-only — source code is fully open. Anyone can audit, modify, and
verify every line of code.

## Conclusion

zelynic is safe, non-malicious, and fails in the safe direction (allow all
traffic on any error). It does not collect data, make network connections,
or modify system files beyond BPF pin files. The source code is open for
full audit under GPL-3.0-only.
<!-- ZELYNIC-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every doc — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`, `bpf/*.bpf.c`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
