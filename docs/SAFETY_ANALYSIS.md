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
| `/sys/fs/cgroup/*` | Read | `stat(2)` inode for cgroup ID resolution |
| `/sys/fs/cgroup` | Read | Attach BPF programs |
| `/sys/fs/bpf/zelynic/*` | Read/Write | Pinned BPF programs, links, maps |
| `/tmp/zelynic.pid` | Remove-only | Hygiene: never written by the current line; removed if left by an old install |
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
| `strict-single`/`strict-multi`/`strict-all`, `block-single`/`block-multi`/`block-all`, `unstrict`/`unstrict-all`/`recover` | required | load, attach, and pin BPF programs; write policy maps. Fail fast with a "re-run with sudo" tip before touching BPF state when run non-root |
| `status`, `eagle-eyes` | required | read pinned BPF maps (same fail-fast guard) |
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
- Map full (bucket/stats insert fails) → allow (return 1) — the
  reclamation below keeps this unreachable in practice
- Watchdog expired → allow (return 1) — dormant mechanism, see below

### Pin mode (fire-and-forget):
- The watchdog is never armed (deadline 0 = absent) — BPF always enforces
- Rate = 0 is an explicit user request: `block-single`/`block-*` write a
  zero rate and BPF blocks all traffic for that cgroup (schema v3); the
  drop is booked through the same atomic fetch_add the rate path uses
  (schema v9, NIGHT-master-3 — the v5 plain `+=` lost drop increments
  when a blocked cgroup had traffic on several CPUs)
- The operational check is link-aware (NIGHT-hunt-19): on bpf_link
  kernels (5.7+) a pinned state counts as active only when BOTH program
  pins AND BOTH link pins exist — the links are the cgroup attachment
  itself, so a half-attached state (crash between program pinning and
  link creation) reloads instead of being "reused" with nothing
  enforcing. Every policy-writing command runs this ladder
  unconditionally (NIGHT-hunt-21) — no handler pre-checks its way
  past the schema-version migration
- If anything unexpected happens to the pins, `zelynic recover` repairs
  state and `unstrict-all` removes everything

## Overflow & Long-Endurance Audit (NIGHT-improve-10 / security-3, 2026-09)

### Enforcement-boundary sanitization

The token-bucket refill math is overflow-proof by construction —
but only for inputs inside a contract. The fill-detect guard
(NIGHT-cybersecurity-1) bounds every product the multiply branch
can form below `2 * burst * NS_PER_SEC`, which is representable
for any burst up to `u64::MAX / (2 * NS_PER_SEC)`. Before this
audit, only userspace enforced that ceiling (`default_burst`
clamps to 100 MB) — while the maps holding burst and tokens are
persistent kernel state that outlives every writer. The BPF
program now treats the maps as untrusted input: `burst_bytes` and
the stored `tokens` are clamped to `MAX_ENFORCABLE_BURST`
(9,223,372,036 bytes) at the trust boundary, before any consumer
derives math from them. A corrupt, drifted, or hand-written map
entry can no longer make the kernel arithmetic wrap; it is clamped
to the same value a healthy full bucket would carry. Userspace
applies the mirror bound on write, and both sides pin the constant
by value in tests. Schema v4 forces pinned v3 programs to reload
into the hardened object.

The v4 clamp family had a third member missing until schema v6
(NIGHT-depthbore-1): `frac_rem` is bounded below NS_PER_SEC by the
carry in HEALTHY flow, but a drifted or hostile bucket could carry
any u64 there, and `frac_rem + refill_frac` could wrap — silent
garbage in the release BPF build (bounded by the burst cap, so the
damage was refill noise of at most one byte per packet). v6
sanitizes the stored remainder on read — a value >= NS_PER_SEC is
treated as the empty remainder, the same clamp-to-healthy-value
contract burst and tokens already follow — so no stored map value
can make the kernel arithmetic wrap at all now: the triple
(burst, tokens, frac) is complete. The refill math lives in
ebpf/src/math.rs since depthbore-1: pure `core`, #[path]-shared
between the BPF object and the userspace test tree, so the exact
arithmetic the kernel runs is pinned by rootless unit tests —
fill-detect threshold equivalence, fractional-carry long-run
exactness (no 0.5-1% truncation drift), conservation under churn,
the hostile-state clamps, and the largest-legal-product corner at
the MAX_ENFORCABLE_BURST bound.

### Counter wrap horizons

All enforcement counters are u64 and monotonically incremented by
per-packet values (packet counts by 1, byte counts by ≤ 64 KiB),
so a wrap is a pure function of sustained traffic, not of uptime:

| Counter | Capacity | Sustained rate | Wrap after |
|---------|----------|----------------|------------|
| bytes_allowed / bytes_dropped | 18.4 EB | 1 TB/s (MAX_RATE) | ~213 days |
| bytes_allowed / bytes_dropped | 18.4 EB | 1 GB/s | ~585 years |
| bytes_allowed / bytes_dropped | 18.4 EB | 100 MB/s | ~5,849 years |
| packets_allowed / packets_dropped | 1.8e19 | 1 M pps | ~584,942 years |

No maintenance window exists below 1 TB/s sustained; userspace
consumers already use saturating deltas, so even the theoretical
wrap degrades one sample instead of corrupting history. The token
bucket itself never accumulates: tokens are capped at burst every
refill, `last_refill_ns` is ktime (wraps after ~584 years of
uptime), and `frac_rem` is bounded below NS_PER_SEC by the carry.

### Display-format ceiling (NIGHT-boost-22, LTS audit)

The monitor's byte formatter answers for the whole u64 domain: the
SI ladder runs B -> KB -> MB -> GB -> TB -> PB -> EB. The old code
stopped at TB on a wrong premise — its terminal-tier note claimed
"u64::MAX is ~18.4 TB", but 2^64 is ~18.4 EXABYTES, and past
999.95 TB the formatter rendered five-digit figures ("18446.7 TB"),
breaking the promotion contract (never a thousands digit) at its own
terminal tier. The extended ladder bounds every display at 8 columns
("999.9 PB"), and the EB tier is the honest terminal: zettabytes
(1e21) need 71 bits, so no eighth tier exists to lie about. The
min/max answer for zelynic data: minimum the byte, maximum the
exabyte.

Two overflow surfaces were audited and hardened with it:

- **Exact integer tenths.** The one-decimal rendering used to be
  `bytes as f64 / div` — and f64 loses exactness above 2^53 (~9 PB),
  the u64 domain's upper half. The nearest-double error (up to 64 at
  the EB edge) could flip the displayed tenth ACROSS the promotion
  boundary the integer tier-walk had just enforced:
  999_949_999_999_999_999 walked to the PB tier, then rendered
  "1000.0 PB". The rendering is now u128 integer tenths
  (`(bytes*10 + div/2) / div`), the same round-half-away discipline
  as the fractional rate parser — the tier walk and the display sit
  on one exact contract, no float anywhere in the formatter.
- **Walk-guard arithmetic.** The tier walk's largest evaluated
  threshold is the PB edge (1e18 - 5e13); the guard stops at the EB
  tier before the 1000x multiple of its divisor (1e21) could
  overflow u64 — pinned by construction and by the u64::MAX pin.

Display-only decisions that stay deliberately simple (no
over-engineering): the rate conversion feeding the formatter is a
saturating f64 division (Rust float-to-int `as` casts saturate — a
saturated counter renders "18.4 EB/s", never a wrapped figure), and
the focus view's per-direction packet counts render as raw integers
(free-form rows, not column cells; a saturated 20-digit count is the
honest ceiling of a counter whose wrap horizon at 1 M pps is
~585,000 years — the footer census line that carries the aggregate
count again since NIGHT-engrave-4 reads the SESSION accumulator,
which saturates the same way and renders its full raw figure). The
footer's session speed pair (NIGHT-engrave-6) adds no new overflow
surface: the MAX line's peaks are running `max` operations (max
cannot overflow — it selects one of two existing values), and the
AVG line is the saturating f64 division above over the session legs
(a saturated leg over a 70s uptime renders "263.5 PB/s", the honest
ceiling-over-horizon figure, pinned). The peaks ride the same
admission bound as the byte fold (one `admits` rule, two callers),
so the max line can never claim traffic the grand total cannot
account for.

### Map slot reclamation (the LTS budget)

The individual bucket and stats maps hold hard 1024 entries. BPF
is deliberately fail-open on a full map (an insert failure allows
the packet — a bookkeeping map must never brick the network), so
map exhaustion would turn into silently unenforced limits. Every
policy removal now reclaims what it can: unstrict deletes the
cgroup's bucket entries per confirmed-gone direction and the stats
entry once both directions are gone (including ENOENT-only walks,
which are the residue of crashed removals); recover does the same
for dead-cgroup orphans. The maps stay proportional to live
policies, not to host history. Shared group buckets are exempt —
their lifecycle belongs to the strict-multi group, not to any one
member's removal.

## Memory Safety (Rust)

zelynic is written in Rust, which provides:
- **Memory safety**: no buffer overflows, no use-after-free, no null dereferences
- **Thread safety**: no data races (Rust ownership model)
- **No unsafe code** in userspace outside the audited `unsafe`
  inventory (NIGHT-hunt-15: recounted from the drifted "six" to the
  real set, then consolidated in the same audit — the two separate
  TIOCGWINSZ probes became one canonical terminal-layer probe,
  leaving 9 blocks + 4 marker impls): `libc::flock` (lock.rs,
  operation guard); two raw `bpf()` syscall wrappers plus
  `libc::close` (bpf_syscall.rs — link create/pin/close);
  `libc::clock_gettime` (format.rs); `libc::ioctl(TIOCGWINSZ)` ONCE
  (terminal/raw.rs — the canonical probe since the NIGHT-ultimate-2
  cap split of diff.rs: the limiter's
  terminal_width and the render engine's per-frame geometry both
  route through it); `libc::write` (terminal/raw.rs — the diff
  engine's one write syscall per frame, the RawStdout writer); and `libc::statfs` twice
  (capabilities/mod.rs — the doctor's real-bpffs mount check,
  NIGHT-hunt-28). The four `unsafe impl aya::Pod` markers
  (limiter/types.rs, loader.rs) are zero-code layout attestations for
  map value types. All are standard POSIX calls with well-defined
  semantics

### BPF program code:
- BPF verifier ensures memory safety at load time (the pure-Rust
  aya-ebpf source compiles through the same verifier as the former
  C twin — NIGHT-improve-1 phase 3)
- All map accesses bounds-checked by verifier
- No dynamic allocation (BPF programs can't allocate memory)
- Arithmetic on map-resident values is sanitized at the trust
  boundary before use (see the overflow audit above)

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

## Policy Error-Path Audit (NIGHT-hunt-20, 2026-09)

Owner-named surface: apply/remove mid-flight error paths in
`policy.rs` and the unstrict/recover handlers. Three real defects
closed; the rest of the surface evaluated and kept by design.

### Finding 1 (fixed): partial apply was invisible

`apply_single`/`apply_group` write per-cgroup policies in a loop; a
mid-flight write failure (map full at 1024 entries — reachable via
`strict-all`/`block-all` on cgroup-dense systemd desktops, ENOMEM, or a
map-open failure) propagated the error while the already-written prefix
stayed ENFORCED with no mention — the inverse of the hunt-19 trap: a
command that "failed" while silently limiting. Fix: strict
all-or-nothing. Every write is ledgered; the first failure rolls the
whole invocation back, and if a rollback delete itself fails, the error
names the exact surviving policies. Both outcome wordings are
unit-pinned.

### Finding 2 (fixed): delete errors conflated with "absent"

`delete_policy` mapped EVERY remove error to `Ok(false)` ("not found"),
so ENOENT was indistinguishable from ENOMEM/EACCES/EINVAL; `unstrict`
then reported "No active limits found" while limits stayed enforced,
and `recover` counted failed deletes as removed. Fix: only ENOENT
classifies as absent (`MapError::SyscallError` with
`io::ErrorKind::NotFound` — a pure classifier, unit-pinned against the
real errno set); every other error surfaces with its cgroup and
direction. `recover`'s orphan sweep now counts actual per-direction
deletions instead of printing the orphan-cgroup count as if it were
removed policies, and names any deletes that failed.

### Finding 3 (fixed): destructive unpin on read failure

`count_remaining_policies` used `unwrap_or_default`: a transient
map-read failure counted as ZERO remaining policies, and zero is the
auto-unpin trigger — a failed read could tear down ALL enforcement while
the user had asked to remove one target's limits. Fix: the zero must be
verified. Read errors propagate; on failure the pins stay and a warning
names the repair tool. The unstrict honesty note likewise only claims
"N other policies remain" from a verified count.

### Kept by design (evaluated, no change)

- Removal stays best-effort across cgroups (a partial remove maximizes
  cleanup progress) but every survivor is reported — strict
  all-or-nothing applies to apply, not to cleanup.
- `group_id` generation (pid*1000 + subsec_nanos%1000): a collision
  needs a pid delta whose *1000 mod 2^32 lands under 1000 — unreachable
  with Linux pid_max <= 4194304 and one apply per CLI process.
- The per-(cgroup, direction) pinned-map open during apply is 2N map
  opens — measurable only at hundreds of cgroups; correctness-first,
  left as is (a `with_policy_map` accessor now deduplicates the
  acquisition path for write and delete).

## Status Display Audit (NIGHT-hunt-22, 2026-09)

Owner-named surface: stats.rs and the monitor display reads. One real
defect closed; three adjacent surfaces verified clean.

### Finding 1 (fixed): status fabricated "no limits" from failed reads

`print_status`/`print_status_json` flattened every map-read failure
into empty data (`unwrap_or_default`, `.ok().flatten()`), and
`read_watchdog` converted a failed read into "not set". Both print
paths are invoked only after `handle_status` verified the enforcement
pins are operational, so a read failure there is an anomaly by
definition — yet the human path rendered "Active limits: none" and the
JSON path emitted `{"active_limits": 0, "limits": []}` while limits
were enforced. For a tool whose status command is the primary way to
check enforcement (and whose JSON feeds scripts), that is the most
user-facing form of the hunt-20 honesty trap. Fix: read failures
propagate — non-zero exit with the map path in the error. The
`--print-json` contract is now pinned by six unit tests via a pure
`status_json` builder (field names, cgroup-count semantics of
`active_limits`, null-vs-zero direction rendering, stats joining,
watchdog wordings, the one honest zero state).

### Verified clean (no change needed)

- **Pin-name alignment:** every `PIN_MAP_*`/`PIN_PROG_*`/`PIN_LINK_*`
  constant matches its BPF object name one-to-one — a wrong name would
  have ENOENT-ed into exactly the swallowed-empty display that was
  just fixed; the alignment removes that failure class.
- **Live eagle-eyes loops (NIGHT-boost-1 merge of observe/top):** a transient poll failure renders a zero
  frame and retries on the next tick — the documented task-7
  soft-read decision for a live transient observer; the first poll
  before the loop is hard-fail (`?`), so a dead observer never enters
  the loop.
- **Clean-state JSON:** `{"watchdog": "clean", ...}` from the
  no-pin-files branch is a third wording by design — it reports "no
  zelynic state at all", distinct from "enforcing" (pins up, nothing
  limited) and the stale-pins error report.

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
  non-root matrix (scripts/depth/nonroot-depth-test.sh) asserts exit 101 and
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
terminal: the list-apps table, the eagle-eyes monitor tables, the
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

Fix: two-path arithmetic in the enforcer (ebpf/src/bin/limiter.rs,
ported from the former bpf/limiter.bpf.c). A
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

Ceiling note (NIGHT-research-1, owner-approved option B): the
documented maximum rate is now 1 TB/s (8-TbE-class headroom, a
decade of margin over shipping NICs). The Finding 2 fix needs no
change there — its safety argument is rate-agnostic: the
fill-detect threshold takes over before the multiply, and the
exact-multiply product stays bounded by `2 * burst * NS_PER_SEC`
(<= 2e17 at the unchanged 100 MB burst clamp) regardless of
rate. At 1 TB/s the fill-detect path engages after just 200us of
idle (`2 * 1e8 * 1e9 / 1e12`), so every longer gap skips the
multiply entirely, and the 2e17 product bound retains ~92x
headroom under u64::MAX.

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
  plus the wipe; idle frames (nothing changed) write nothing. Two
  TIOCGWINSZ probes per frame remain — the resize check plus the
  render layer's layout probe, both through the one canonical helper
  (NIGHT-hunt-15 collapsed the old three per frame into these two).
- **Unicode safety by construction:** rows are written whole and the
  cursor is only positioned at row starts, so double-width glyphs
  never desync column math (a cell-grid renderer has to handle this
  per cell; the line-granularity diff cannot express it).
- **Tall-regime scroll removed (NIGHT-improve-6):** the improve-2
  fallback for frames meeting or exceeding the terminal height
  (every terminal at or under the render cap — the classic 80x24
  included, plus piped monitors on the 80x24 probe fallback)
  preserved the pre-diff scrolling semantics: a trailing linefeed at
  the viewport bottom scrolled the alternate screen one line per
  refresh, the title bar drifted off, tall-to-short transitions
  misaligned against the scrolled screen, and the idle fast path was
  disabled there, so even an unchanged frame repainted in full. The
  emission is now top-aligned and clipped to min(rows, height) with
  no trailing linefeed, and the idle path covers the tall regime, so
  no refresh scrolls the screen at ANY height — the layout and
  scrollback guarantees hold uniformly. A `painted` row count marks
  clipped rows dirty, so a terminal that grows repaints exactly the
  rows it just revealed.

## Eagle-Eyes Accumulate-Explosion Audit (NIGHT-boost-16 / safety-security-1, 2026-09)

The owner's long-horizon question: what happens to the eagle-eyes
monitor when session totals EXPLODE — months of uptime, saturated
u64 counters, cgroup churn? Every arithmetic surface in the
monitor's session path was audited; four real hazards were found
and fixed, one purely as defense-in-depth:

- **The ranking key panicked debug builds (fixed).**
  `SessionAcc::total()` was a plain `dl + ul`. A monitor that
  accumulated toward u64::MAX on both legs (an 18.4 EB session —
  reachable in principle on a 40 GbE trunk over ~40 days of
  sustained saturation, or instantly through a corrupted map read)
  would PANIC a debug build the moment the sum crossed the boundary,
  and a release build would WRAP to a small number — the
  leaderboard crowning a wrap-around winner while the footer
  reported a tiny grand total. The total is now `saturating_add`:
  both legs at the ceiling read as the ceiling, and the pinned test
  `saturated_totals_read_as_maximum` holds the contract.
- **The footer's four sums had the same class of bug (fixed).**
  The dl/ul rate sums, the grand session total, and the packet
  census were `Iterator::sum()` over plain `+` — the same
  debug-panic/release-wrap shape, one frame later. All four are now
  `fold(0, u64::saturating_add)` over saturating legs; the render
  pin `saturated_session_renders_without_panic` drives a fully
  saturated frame (deltas AND accumulator at u64::MAX) through the
  real render path and asserts the TOTAL row carries the honest
  18446744.1 TB ceiling figure.
- **The rank-row TOTAL cell (fixed, found by the pin itself).**
  The first saturated-frame render exposed a fifth site the static
  audit missed: `format_bytes(acc.dl + acc.ul)` in the row renderer.
  Every `+` over u64 counters in the render tree is now saturating.
- **The focus view's rate and lifetime rows (fixed).** The
  per-frame rate (`ingress_bytes + bytes`) and the lifetime row
  (`ingress_total_bytes + total_bytes`) summed kernel u64 counters
  with plain `+` — the focus twin of the same hazard, now
  saturating.
- **Unbounded leaderboard growth (bounded, defense-in-depth).**
  `SessionState` folds one HashMap entry per cgroup the counters
  ever named. The observer's two BPF counter maps hold 1024 slots
  each (`COUNTER_MAP_MAX_ENTRIES`), and the kernel silently stops
  counting cgroups beyond a full map — so deltas can only ever name
  at most 1024 distinct cgroups and the accumulator's growth was
  ALREADY bounded by the data source. The userspace bound is now
  explicit (`MAX_TRACKED_CGROUPS = 1024`, mirroring the kernel
  constant): if a future kernel, map type, or bug ever produced
  more, a months-long monitor's memory stays capped (~64 KiB of
  accumulator) instead of leaking one entry per cgroup churn. The
  honest shape of the board — the kernel's own ceiling — is
  preserved: a cgroup the kernel never counted cannot rank.

What remains intentionally NOT defended: the kernel-side counters
themselves are u64 by schema (schema v6, pinned by
`SCHEMA_VERSION_EXPECTED`'s parity test — NIGHT-ultimate-1 truth
fix: this paragraph previously said v7, a version that never
shipped) — 18.4 EB per direction
per cgroup is the ceiling of the whole architecture, and the
monitor's saturating presentation is the honest rendering of that
ceiling, not a repair of it. Long-endurance guidance: on a trunk
that could genuinely move exabytes per cgroup per session, restart
the monitor on a cadence (the session horizon resets), or read the
lifetime figures from `status` — the limiter's pinned maps carry
their own accumulator contracts documented in the overflow audit
above.

## Comprehensive Security/LTS Audit (NIGHT-ultimate-1, 2026-09-24)

The owner-task: a full depth pass over security, mitigation, LTS,
and every other comprehensive aspect — "should be complete peak,
high potential gains for LTS investment". Method: line-by-line read
of every privilege-bearing and kernel-boundary surface (the two BPF
programs and their maps, the raw-syscall wrappers, the pin lifecycle,
the operation lock, both /proc walks, the pidfd_getfd join, the
untrusted-string boundaries, the update check, the privilege
ladders in every mutating command, the terminal layer), the CI
toolchain wiring (build.rs staging, bootstrap, the workflows'
gatekeeper mirrors), and the docs' claims audited against the code
they describe. Verdict per surface:

- **Privilege ladders — peak.** Every mutating handler climbs the
  same order: input parse (with typo tips) → dangerous-target
  blocklist → `ensure_root()` → flock → attach → apply → final-state
  validation, and the parse-first ladder is pinned by tests that
  prove the error precedes the root guard
  (`rate_typo_surfaces_before_root_guard` and siblings). The one
  command where root is the hazard, not the requirement
  (`--check-update`), refuses euid 0 before any network I/O
  (hunt-11). No new gap found.
- **Operation lock — peak.** `/run/zelynic` (root-only 0700,
  defensively re-tightened), non-blocking flock, legacy /tmp lock
  unlinked opportunistically, symlink-squatting both structurally
  impossible (hunt-14, re-verified: `/run` is root-owned tmpfs).
- **Untrusted strings — peak.** The one canonical sanitizer covers
  both live injection classes (`/proc` comm via prctl, the network
  release tag), every consumer routes through it
  (cybersecurity-1/2), and the pins drive real OSC-52/newline
  payloads through the boundary. The endpoint strings
  (IP:port) are kernel-formatted hex parses — not attacker text.
- **Map integrity — peak.** The kernel side clamps every stored
  value it consumes (security-3 burst clamp, depthbore-1 frac_rem
  triple), rate-0 drops are booked (v5), fail-safe is allow-on-any-
  bookkeeping-failure, and the schema-version ladder reloads stale
  pins instead of writing new layouts into old maps (hunt-21).
- **pidfd_getfd join (boost-26) — sound.** The fd walk opens one
  pidfd per PID lazily, marks failures sticky (no retry storm),
  closes explicitly per PID; the Copy-enum redesign makes the
  drop-recursion class structurally impossible, and the
  known one-leaked-fd panic window is documented as best-effort
  class. Cookie 0 is skipped honestly in-kernel.
- **Toolchain quarantine — peak.** Dated nightly scoped to the ebpf
  sidecar, host flags stripped from the nested build (hunt-28),
  damaged-artifact self-heal (hunt-29), alignment preflight with a
  one-line diagnosis, no C fallback anywhere.
- **Panic surface — clean.** A repo-wide sweep for
  `unwrap`/`expect`/`panic!`/`unreachable!` in production paths
  found every instance in `#[cfg(test)]` blocks with guarded
  preconditions; runtime failures are `Result`-propagated (with the
  one documented one-frame-tolerance fold in the monitor loop,
  optimized-2's audited exception).

**The find (fixed in this task): comment/doc claims overstated
kernel-side saturation.** `bump_socket_counter`'s doc claimed
"Saturating add like every counter in the observer" — the cgroup
counters it sits next to have NEVER been saturating (they keep the
C twin's plain adds), RESEARCH_TOOLCHAIN_AND_MONITORING.md §2.2
called the kernel counters "saturating u64", and STABILITY.md's
long-endurance item read as if the kernel map counter itself
saturates. The truth: kernel-side adds are plain (a wrap needs
years of saturated line-rate through one cgroup inside one
session-scoped map — physically unreachable, and the display
renders the session ledger's saturating figures, never the raw map
word), and making them saturating would charge the per-packet hot
path instructions to guard an unreachable state — over-engineering
against the owner's rule. All three claim sites now tell the truth;
the socket-cookie counters (which DO saturate) keep their
discipline, and the userspace session ledger remains the saturation
contract users see.

**Deliberately not changed (over-engineering guard):** converting
the kernel cgroup-counter adds to saturating (unreachable state, hot
path); a UID source swap from `/proc/<pid>/status` to directory
stat (would silently change semantics for setuid processes);
hardening beyond the documented threat model (attacker-already-root
is out of scope by SECURITY.md). The security posture is peak for
the declared class; the residual risks are the five documented
honest limits in STABILITY.md, each failing closed and saying so.

## Security/LTS Audit (NIGHT-lts-1 / safety-1, 2026-09-25)

The owner's comprehensive depth-audit task: security, safety,
mitigation, complete peak. The pass re-walked every prior audit's
surface plus the newest code (the hunt-31/improve-30 rescue lineage),
hunting the residual classes. Two findings, both fixed; everything
else verified at peak.

### Finding 1 (fixed, defense-in-depth): root-run rescue externals
resolved through the inherited PATH

`--reset-terminal` spawns `stty` / `reset` / `tput` through PATH
lookup (`Command::new("stty")`). The rescue is designed to need no
privileges — but the broken-terminal moment is exactly when an admin
runs it as root (`sudo zelynic --reset-terminal` over a wedged TUI
session), and sudo's `secure_path` is the ONLY thing standing between
that spawn and a user-controlled PATH entry (`sudo -E`,
`env_keep+=PATH`, legacy sudoers configs): a planted `stty` higher in
the PATH than /usr/bin executes as root. Not exploitable under any
default configuration — the same register as the CI
script-injection class (Finding 2, 2026-09): defense-in-depth is the
doctrine.

Fix: when the rescue runs as root, the three spawns pin
`PATH=/usr/sbin:/usr/bin:/sbin:/bin` (`RESCUE_SYSTEM_PATH`,
src/term_reset.rs) — the four canonical system directories every
mainstream distro packages the trio into (usrmerge and pre-merge
layouts both covered, Alpine's busybox symlinks included). A non-root
rescue keeps the inherited PATH (same user, same privilege, no
boundary to cross — and NixOS's /run/current-system/sw/bin lookup
keeps working). The documented trade: a root rescue on NixOS skips
the two best-effort belt layers, layers 1-3 having already restored
the critical terminal state.

### Finding 2 (fixed): CJK/fullwidth glyphs counted one column wide
across the render budget system

The residual untrusted-input class of the cybersecurity-1 family:
the sanitizer closed escape-byte injection, but ideographs and
fullwidth forms render TWO terminal columns per char, and every
width decision in the crate counted CHARS — `truncate_label`'s
budget, the eagle row's `{:<w0$}` padding, `title_bar`'s fill math,
the border's `fit()` glyph counter, and the list-apps comm column. A
prctl-set five-ideograph comm (15 bytes — the kernel cap) sits inside
every char budget while painting twice it: the row runs past the
content width, the right rail jags, the numeric columns shift. And
this is not just an attacker class — CJK app names are real on real
desktops (the sanitizer's own pass-through pin uses one).

Fix: a canonical display-width module
(src/output/width.rs — the pragmatic wcwidth subset: wide East Asian
ranges 2, combining marks 0, else 1, no new dependency) and the five
budget surfaces routed through it (`fit_to_width` /
`pad_to_width` / `char_width`), following the one-acquisition-path
doctrine. Pins: the width classes, the CJK truncation ladder, the
char-padding drift regression, and the end-to-end frame pin
(`cjk_label_keeps_the_rails_straight`: with a ten-column label on
the board, every composed row still renders exactly the frame
width).

### Verified clean (no change needed)

- **Panic surface**: every `unwrap`/`expect`/`panic!` in the crate
  lives inside `#[cfg(test)]` modules — zero production panics.
- **Unsafe blocks**: every production `unsafe` carries its SAFETY
  comment; the guard child's fork path is async-signal-safe by
  construction (syscalls only after fork, the hunt-31 discipline).
- **The lock** (/run/zelynic, root-owned 0700), the /proc comm
  boundary, the burst/frac/tokens clamp family, the SMP atomics
  (boost-38/improve-29), the saturating display math (boost-16), the
  update check's argv-array curl, and the CI env-var isolation all
  re-verified at their documented state — peak.

## Terminal Rescue Under Sudo Interposition (NIGHT-improve-31,
## re-shaped in NIGHT-improve-34, 2026-09-25)

The owner's live report: after a root TUI session died violently,
`sudo zelynic --reset-terminal` left the screen staircased (the
`%` marker at the wrong column, the prompt drawn mid-line), while
the same command WITHOUT sudo recovered it perfectly and
cosmostrix's identical five layers also passed. The gap was never
the layers — it was WHICH terminal they reached.

### The finding

sudo 1.9.14+ enables `use_pty` by default: sudo forks a monitor
that keeps the user's real terminal and allocates a NEW
pseudo-terminal pair for the command. Under that interposition:

1. The rescue's fd 0 is the throwaway pty. Layer 1's `tcsetattr`,
   `stty sane`'s stdin, and `reset`'s termios fiddling all repair
   the pty nobody is looking at.
2. The escape bytes alone survive — the monitor relays them — so
   the emulator-side modes reset and the screen LOOKS half-fixed,
   while the real terminal's kernel termios stays raw.
3. The monitor holds the real terminal RAW on purpose while the
   command runs (`sudo_term_raw`: full cfmakeraw, OPOST off — the
   relay's transparency), saving the pre-run state first and
   restoring it at exit — with one guard NIGHT-improve-34 read in
   the sudo source (lib/util/term.c): `sudo_term_restore` DECLINES
   to restore when the terminal was "changed out from under us"
   (its INPUT/OUTPUT flag masks no longer match the monitor's
   raw), so any in-flight fix that touches OPOST — exactly what
   move 2 does — makes the monitor leave the rescue's cooked
   state in place. A post-exit fix is still owed for the shapes
   where nothing tripped the guard (the in-flight apply failed) or
   there was no restore at all (a monitor killed with its raw
   still holding the terminal) — but it must be DISCRIMINATED,
   never blanket.

### The mitigation (src/term_reset/outer.rs)

Three moves, all best-effort, none requiring any new privilege:

1. **Discover**: the real terminal is the tty held by the sudo
   monitor — resolved through `/proc/$SUDO_PID/fd/0`, accepted only
   when it opens, answers `isatty`, and names a DIFFERENT terminal
   than the rescue's own (the non-`use_pty` sudo and every
   non-sudo context fail that check and keep the classic behavior
   exactly). An euid-gated parent fallback covers a
   stripped-`SUDO_PID` policy.
2. **Apply direct**: the termios restore + both ANSI sequences on
   the real terminal by path, and the external utilities
   (`stty sane`, `reset`, `tput reset`) with their stdin
   redirected onto it.
3. **Re-apply after sudo, DISCRIMINATED** (NIGHT-improve-34): a
   bounded orphan child (the guard's boost-33 discipline: renamed
   away from "zelynic" so `pkill zelynic` cannot kill it,
   syscalls only after fork, 5 ms poll slices, a hard 10 s budget)
   waits for the monitor to exit, then READS the real terminal
   before touching it. The output lane decides: OPOST|ONLCR not
   both on (the staircase class — the monitor's raw residue, or a
   restored broken snapshot) fires the OUTPUT-LANE CURE ONLY
   (OPOST|ONLCR back on, every input/local/control flag and the
   whole c_cc table preserved, TCSANOW — never a flush) plus the
   NON-destructive restore bytes; the lane already whole (the
   in-flight fix survived the guard, or the monitor restored a
   healthy snapshot) touches NOTHING — zero ioctls, zero bytes —
   because by then the user's shell may be mid-prompt in its own
   raw mode. THE WHY: the improve-31 blanket re-apply (full cooked
   + TCSAFLUSH) landed under that live line editor — the kernel's
   echo doubled every typed character and the flush ate queued
   keystrokes (the owner's fresh report: `sudo zelynic
   --reset-terminal` on a HEALTHY terminal left typing garbled,
   the typed line rendered twice, the prompt redrawn over it, the
   right-side prompt arriving without its left half — and the
   live harness below shows the old code eating the user's FIRST
   TYPED CHARACTER in every scenario). The one residue,
   documented: a NON-line-editor reader on a terminal whose input
   flags a dead monitor left raw gets the output cure but keeps
   blind typing — the plain `zelynic --reset-terminal` (no sudo:
   no monitor, no orphan, the classic five layers own the whole
   terminal) finishes that job.

### The safety ledger

- **No new attack surface**: the discovery opens
  `/proc/<sudo-pid>/fd/0` and one tty by path — both operations
  the rescue's privilege already covered. The root-run external
  PATH pin (`/usr/sbin:/usr/bin:/sbin:/bin`, NIGHT-lts-1) is
  unchanged and covers the redirected-stdin spawns.
- **No terminal takeover**: the orphan opens the real terminal
  `O_NOCTTY` (a setsid child must never adopt the user's
  terminal) and only ever restores modes toward their defaults —
  the mouse-contract direction rule, unchanged.
- **No lingering process**: the orphan exits unconditionally at
  the 10 s budget; two settle-gap passes catch the nested-sudo
  chain, then it is gone.
- **No live-reader stomp** (NIGHT-improve-34): the post-exit pass
  is discriminated by the output lane and the cure is
  lane-pure — a healthy terminal receives zero ioctls and zero
  bytes; a broken output lane receives exactly OPOST|ONLCR. A
  live zle/readline reader's input contract (its own raw mode,
  its own echo) is structurally unreachable by the orphan.
- **Verified**: unit pins (the discovery discrimination, the
  by-path apply on a real cfmakeraw-broken pty, the bounded
  budget, the re-apply discrimination matrix, and the cure's lane
  purity — `test/terminal/outer_reset_tests.rs`, 16 pins green in
  the terminal family) plus a live end-to-end harness simulating
  the full interposition — a faithful sudo monitor (the save,
  cfmakeraw raw, the pty relay, and sudo's REAL exit-restore
  guard read from the source) around the REAL rescue, with a
  zsh-style player that sets a line editor's raw, draws a prompt,
  types, and echoes: three scenarios (healthy-at-start + guard,
  broken-at-start + guard, broken-at-start + forced restore) all
  green — single-echo typing, the guard leaving the in-flight fix
  in place, the orphan silent when healthy, the belt curing only
  the output lane when the broken snapshot lands. The SAME
  harness against the improve-31 orphan PANICS in every scenario:
  its TCSAFLUSH under the live reader eats the first typed
  character before any doubling is even countable — the exact
  "not yet 100% clean" residue the owner kept reporting.

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

## End-to-End Depth Audit (NIGHT-depthbore-1 / blade-13, 2026-09-26)

The server-and-desktop-LTS end-to-end pass: every CLI handler walked
(update, safety, strict family, block family, cleanup/recover,
monitor, eagle-eyes depth, rates, limiter attach/policy/reclaim,
lock, pin), the full unit suite re-run, and the non-root CLI battery
driven against the built binary. One high-severity find, one minor
find, both fixed; the rest of the sweep verified clean.

### Finding 1 (fixed, high severity): the blocklist missed its own daemons

`is_dangerous_target` matched EXACTLY, but the blocklist's entries
carry the kernel's 15-byte truncated comms (`systemd-resolve`,
`systemd-journal`, `systemd-timesyn`, ...) while the display-name
enrichment (NIGHT-engrave-7) restores the FULL names
(`systemd-resolved`, `systemd-journald`, ...) — and the same enriched
comms feed `strict-all`'s and `block-all`'s sweeps. Two live
consequences on every current distro:

- A copy-pasted `zelynic ss systemd-resolved 100kb` (the name
  list-apps itself displays) sailed past the guard with no
  `--force-this`.
- `strict-all 500kb` — whose ONLY system-app filter is this
  blocklist, no uid check — swept the enriched system-daemon comms
  INTO the user-app set: DNS (resolved), logging (journald), NTP
  (timesyncd) limited with no override asked at all.
- The split-daemon era added a fresh shape: OpenSSH 9.8+ runs each
  connection's process as `sshd-session` — an exact match for
  nothing, so a strict-all sweep rate-limited every ACTIVE SSH
  session: the exact "limit myself out of SSH" hazard the blocklist
  exists to prevent.

The fix is the family rule (fail-safe direction): a target is
dangerous when it EXTENDS a blocklist entry (case-insensitive
prefix). Both shapes above are entry+suffix; the truncated spelling
a user might type from an old listing (`gnome-session-b`) is covered
by the same rule. An innocent app that merely shares a prefix (a
hypothetical `rootlesskit` under `root`) now costs one `--force-this`
— the accepted trade, because the miss direction breaks systems. The
contract is pinned by test/commands/safety_tests.rs (exact names,
enriched twins, split siblings, clean apps, the verdict ladder, and
the fail-safe direction itself).

### Finding 2 (fixed, minor): apply_group double-wrote duplicate cgroups

Two targets can name the SAME cgroup by different spellings
(`sm brave:brave`, `sm cg:123/12345`): the group apply loop wrote
every duplicate — same map key, so enforcement was correct, but the
applied-policy count the success epilogue reports was inflated, the
superseded-group ledger double-pushed, and the verbose trace
double-printed. The fix dedups across targets (first-seen order):
one cgroup, one write, one count.

### Verified clean

The update check (root refusal, sanitized network tag, 15s timeout),
the lock (/run 0700, flock lifecycle), the verified unpin, the
recover orphan ladder (propagated reads, verified counts, incomplete
= exit 1), the policy rollback ledger (hunt-20), the unset-leg
removal (improve-29), the group reclaim (lts-7), the rate grammar
(exact u128 fractional math, overflow errors, typo rescue), the
observer teardown, and the monitor loop (blade-6's endurance bounds)
all held under the end-to-end pass. The non-root battery runs 78/78;
the root+eBPF smoke battery rides CI (the sandbox micro-VM needs
kvm/qemu unavailable in the auditing session).

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

  Source code (`src/**/*.rs`, `ebpf/src/**/*.rs`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
