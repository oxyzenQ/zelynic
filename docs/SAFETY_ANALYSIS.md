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

## Security Audit (NIGHT-cybersecurity-1, 2026-09)

Second master audit, hunting beyond the hunt-14 surface list. Two
real findings fixed; the rest of the sweep verified clean.

### Finding 1 (fixed): comm-label terminal injection

`prctl(PR_SET_NAME)` lets ANY unprivileged process set its own
`/proc/<pid>/comm` to 15 bytes of near-arbitrary content — including
ANSI/OSC escape sequences and newlines. zelynic printed those labels
raw on every display surface that runs as root in the admin's
terminal: the list-apps table, the observe/top monitor tables, the
eagle-eyes per-process detail lines, and the verbose resolution
trace. That is a terminal-injection primitive handed to an
unprivileged attacker:

- **OSC 52** (`ESC ] 5 2 ; ... BEL`) can rewrite the admin's
  clipboard in terminals that honor it (exfiltration and poisoning).
- **Newlines** forge lines that look like zelynic's own output — a
  fake table row with a wrong cgroup ID nudges an admin toward
  unstricting/blocking the wrong target.
- **Escape sequences** corrupt the alt-screen monitor mid-render.

Fix: `sanitize_comm()` (src/ebpf/identity/sanitize.rs) replaces every
control character — Rust `char::is_control`, covering C0, DEL, and
the C1 range — with `?` at all THREE /proc read boundaries (identity
walk, connection walk, and the resolve_target match walk), so every
downstream consumer (display, JSON, matching, majority-vote tally)
is safe by construction and matching operates on the same canonical
label list-apps displays. procps-ng applies the same substitution to
comm for the same reason. NIGHT-optimized-1 then consolidated the
three boundaries into two canonical helpers — `pid_cgroup_id()` and
`pid_comm()` (src/ebpf/identity/mod.rs) — that all three walks call,
so sanitize and every future boundary fix apply once and can never
drift between surfaces. The kernel quirk that a copied binary's
basename becomes its comm gives the non-root depth suite a
pure-shell spoofer: it plants hostile comms and asserts list-apps
output (text and JSON) never carries a raw ESC byte; the sanitize
behavior itself is pinned by unit tests covering the OSC-52,
forged-row, DEL, and C1 families plus the clean-pass fast path.

### Finding 2 (fixed): u64 overflow in the BPF token refill

The limiter's refill product `elapsed_ns * rate_bps` overflowed
u64 whenever rate exceeded `u64::MAX / 1s` (~18.4 GB/s) and the
bucket sat idle past ~0.18 s — squarely inside the documented 100
GB/s ceiling (one 800 GbE NIC). The in-code comment claimed safety
with stale math ("1e9 ns * 1e9 bps = 1e18") that assumed a 1 GB/s
rate cap the CLI never had. Demonstrated damage (see the
verification harness): at rate 100gb after 184467441 ns of idle the
wrapped product collapsed the refill to 26 bytes where the true
refill caps at the 100 MB burst — the post-idle burst credit lost
by a factor of ~4,000,000. No enforcement bypass was possible (the
result is still capped at `burst_bytes`), but the rate-precision
contract broke exactly at the high end, and most wrap offsets cap
by luck, which is why the bug hid.

Fix: two-path arithmetic in `enforce()` (bpf/limiter.bpf.c). A
fill-detect threshold (`elapsed >= 2 * burst * NS_PER_SEC / rate`)
credits the burst directly — below it, the product is provably
`< 2 * burst * NS_PER_SEC <= 2e17` for any burst the userspace
clamp admits (100 MB), safely inside u64. The `rate > 0` guard is
explicit (callers already short-circuit rate 0 to the block drop,
so the division is protected twice). Verified against an exact
`__int128` reference across 2,880 parameter combinations (rates
1kb..100gb spanning the 18.4 GB/s overflow edge, elapsed
sub-microsecond..2 s, three burst sizes, token/fraction states,
and fill-threshold boundary-adjacent values): bit-identical
everywhere, with the old arithmetic's wrap demonstrated first.
Harness kept outside the repo (workspace
scripts/verify-bpf-refill.c — compiles with plain cc, no BPF
attachment needed).

### Verified clean (no change needed, this pass)

- **Rate parsing:** `checked_mul` on the suffix multiply with a
  documented rejection path; raw-byte input bounded by MAX_RATE
  with a typo tip; timestamps use `saturating_mul` (hunt-14 held).
- **Observer datapath:** pure counter accumulation — no multiplies,
  no division, no attacker-controlled arithmetic.
- **Spoofed-comm resolution:** an unprivileged process renaming
  itself to a target's name joins the resolution result
  symmetrically (same strict/unstrict action as the real target —
  self-DoS, the SECURITY.md out-of-scope class); the verbose trace
  shows every matched (pid, cgroup) pair, so the noise is visible.
- **cmdline/environ:** never read — comm (15 bytes) is the only
  /proc-derived attacker-controlled string, and it is now
  sanitized at the boundary.

## Render Path Audit (NIGHT-improve-2, 2026-09)

The monitor loop's emission was audited while porting the cosmic
dragon engine's diff-based rendering (the owner's full-redraw
complaint). One real terminal-safety hazard found and removed:

- **ESC[2J inside the alternate screen (fixed).** The former
  `run_alt` wiped the whole alt screen (ESC[2J + ESC[H) on EVERY
  refresh. On VTE-based terminals a 2J inside the alt screen can set
  an internal flag that wipes the MAIN screen's scrollback when the
  alt screen is later left — the same hazard cosmostrix's dragon
  engine documented and designed around. zelynic now never emits 2J
  at all: frame resets use ESC[H + ESC[J (cursor-anchored erase —
  same visual result, no scrollback side effect), and per-frame
  wipes are gone entirely because only changed rows are written.
- **Broken-pipe contract preserved:** the diff engine discards
  write errors exactly like `println_safe!` did — a short reader
  (pipe closed mid-frame) ends the monitor quietly, never a panic.
- **Syscall surface reduced:** one `write(2)` per frame (via a raw
  fd writer) where the former path issued one write+flush per line
  plus the wipe; idle frames (nothing changed) write nothing. The
  emission path performs no `ioctl` beyond one TIOCGWINSZ size probe
  per frame (the resize check — the render layer already probed
  twice per frame for layout).
- **Unicode safety by construction:** rows are written whole and the
  cursor is only positioned at row starts, so double-width glyphs
  never desync column math (a cell-grid renderer has to handle this
  per cell; the line-granularity diff cannot express it).

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
