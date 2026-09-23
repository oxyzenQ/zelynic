<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# zelynic — Complete Usage Guide

This is the flagship reference for using zelynic day to day: every
command explained, real workflows, the exact mental model of how
enforcement works, and — importantly — an honest list of what zelynic
does **not** do. If you read one document before relying on zelynic,
read this one. Build instructions live in the
[README](../README.md); this guide starts after the binary works.

---

## Table of contents

1. [The 30-second version](#the-30-second-version)
2. [How zelynic actually works](#how-zelynic-actually-works)
3. [Command reference](#command-reference)
4. [Global flags](#global-flags)
5. [Workflows and recipes](#workflows-and-recipes)
6. [Honest limitations — read this](#honest-limitations--read-this)
7. [Troubleshooting](#troubleshooting)
8. [JSON reference for scripting](#json-reference-for-scripting)
9. [Exit codes](#exit-codes)
10. [FAQ](#faq)
11. [Maintainer's map](#maintainers-map)

---

## The 30-second version

```bash
sudo zelynic list-apps                 # find the app + its cgroup id
sudo zelynic strict-single brave 100kb # limit it (download AND upload)
sudo zelynic status                    # verify the limit is live
sudo zelynic eagle-eyes                # watch traffic live, ranked (q to quit)
sudo zelynic unstrict-single brave   # remove the limit
```

Limiting is **fire-and-forget**: the command writes rules into pinned
BPF maps and exits. The kernel enforces from that moment on — no
daemon, no service, no config file. Nothing runs in the background
burning CPU or battery.

---

## How zelynic actually works

Understanding three facts prevents 90% of surprises:

**1. zelynic limits cgroups, not processes.**
The Linux kernel puts every app into a *control group* (cgroup). zelynic
attaches two tiny eBPF programs at the cgroup-v2 root — one for ingress
(download), one for egress (upload). Every packet that crosses any
cgroup boundary is classified by its cgroup ID and checked against a
rate policy in a BPF map. Enforcement is pure kernel work: no proxy, no
`tc`, no `LD_PRELOAD`, no userspace hop.

**2. A "target" is resolved once, at command time.**
When you type `zelynic strict-single brave 100kb`, zelynic walks
`/proc`, finds every process whose name is `brave`, resolves the cgroup
each one lives in, and writes one policy per cgroup (per direction).
That resolution is a **snapshot** — see
[Honest limitations](#honest-limitations--read-this) for what that
means when you launch new apps later. A numeric cgroup ID (from
`list-apps`) targets one cgroup exactly, skipping name matching.

**3. State lives in the kernel, pinned under `/sys/fs/bpf/zelynic/`.**
Programs, links, and policy maps are pinned there, which is why
enforcement survives zelynic exiting. `status` simply reads the pinned
maps back. `recover` removes orphaned pins left by a kill mid-operation.
That directory lives on bpffs — a pseudo-filesystem — so **reboot wipes
it** (and re-assigns cgroup IDs anyway): limits are not reboot-persistent.

---

## Command reference

Names follow one grammar: **strict** applies limits, **block** cuts
access entirely, **unstrict** removes limits. `-single` takes one
target, `-multi` takes a colon-separated list, `-all` sweeps every user
app. `strict` is the shorthand for `strict-single`; `unstrict` is the
shorthand for `unstrict-single` (NIGHT-hunt-16 — the canonical always
carries the `-single` suffix, so the two verb families read
symmetrically). Every enforcement verb plus the monitor also has a
two-letter short alias (NIGHT-improve-25): `ss` strict-single, `sm`
strict-multi, `la` limit-all, `bs` block-single, `bm` block-multi,
`ba` block-all, `us` unstrict-single, `um` unstrict-multi, `ua`
unstrict-all, `ee` eagle-eyes — e.g. `zelynic ss brave 100kb` or
`zelynic ee brave --interval 1s`.

### strict-single / strict — limit one app

```bash
sudo zelynic strict-single <target> [rate] [-d <rate>] [-u <rate>]
sudo zelynic strict brave 100kb        # shorthand form
```

- `<target>`: a process name (`brave`) or a cgroup ID (`18571`, from
  `list-apps`).
- A positional `rate` sets **both** download and upload. `-d`/`-u` set
  them independently — and they take precedence: if either flag is
  present, the positional rate is ignored (no silent mixing), so
  `strict-single brave 100kb -d 1mb` limits download only.
- `--allow-dangerous`: permits rates below 1kb (can effectively brick
  an app — hence the name).
- `--force`: permits limiting the protected system blocklist (root,
  systemd, kthreadd, ... — 57 names; see `--help`).

The command prints what it did, e.g. `Limiting 'brave' to 100.0 KB/s +
100.0 KB/s (2 policies, active in background)` — one policy per
direction per cgroup, so a name resolving to two cgroups counts four.

Name matching details worth knowing: it is case-insensitive and matches
the kernel's `comm` name (max 15 chars). It matches **all** cgroups that
contain at least one process with that name — a browser plus its
crash-handler helper both match `brave`. Use `list-apps` /
`eagle-eyes <id>` to inspect what actually carries the traffic,
and target the cgroup ID directly when you want surgical precision.

### strict-multi — one shared rate for several apps

```bash
sudo zelynic strict-multi brave:curl:pacman 1mb
```

All listed targets share **one** rate collectively: if one app saturates
it, the others starve. Use it for download tools you want to cap as a
pool (`curl:pacman:aria2c 1mb`), not for apps that each need their own
guaranteed slice — apply separate `strict-single` calls for that.

### limit-all — cap every user app

```bash
sudo zelynic limit-all 500kb
sudo zelynic limit-all -d 1mb -u 500kb
```

Snapshots the current app list (same resolution as above) and applies
the rate to every non-system app. System/dangerous targets are excluded
unless `--force`. This is the command where the snapshot semantics
matter most — newly launched apps afterwards are **not** covered; re-run
it after starting new apps.

### block-single / block-multi / block-all

```bash
sudo zelynic block-single brave
sudo zelynic block-multi brave:curl:pacman
sudo zelynic block-all [--force]
```

Cut internet access entirely — packets are dropped at the cgroup
boundary in both directions. Same target grammar and `--force` contract
as strict. `unstrict-single` removes a block exactly like it removes
a rate limit (blocks and limits live in the same policy maps; a
blocked cgroup shows a 0-rate policy in `status`).

### unstrict-single / unstrict-multi / unstrict-all

```bash
sudo zelynic unstrict-single brave     # canonical ('unstrict' is the shorthand)
sudo zelynic unstrict brave            # shorthand form
sudo zelynic unstrict-multi brave:curl:pacman
sudo zelynic unstrict-all              # emergency reset: removes everything
```

Removes policies for the resolved cgroups and reports how many policies
(dl + ul) it removed — the same counting strict uses, so "4 policies"
in and "4 policies" out line up. Every removal also reclaims the
cgroup's token-bucket and stats entries behind it (NIGHT-improve-10):
the 1024-slot maps stay proportional to live limits, so a long-lived
host with churny cgroups never reaches the point where new limits
would silently stop applying (verbose mode traces each reclaim).
`unstrict-all` also removes the pin
directory itself: after it, `status` reports a clean state.

### recover — crash cleanup

```bash
sudo zelynic recover
```

If zelynic was killed mid-operation (SIGKILL, OOM, power loss), pin
files can be orphaned. `recover` detects and removes them, and
reclaims the bucket/stats state of dead-cgroup orphans alongside
their policies (the same LTS budget unstrict maintains). Safe to run
anytime — it does nothing when state is clean. `status` tells you when
you need it ("Stale BPF pin files detected").

### status — what is limited right now

```bash
sudo zelynic status [--print-json]
```

Reads the pinned maps and prints the active limits: how many dl/ul
policies, and a table of CGROUP / DOWNLOAD / UPLOAD / ALLOWED /
DROPPED per cgroup, with labels resolved by majority vote over the
live processes inside each cgroup. ALLOWED/DROPPED carry cumulative
BYTE counters since the maps were created — one metric per cell,
evidence of enforcement rather than a live rate meter; the packet
counts ride `--print-json` where automation reads them.

The output opens with the purple flagship title bar (the same anchor
the eagle-eyes monitor carries) and signs off with the signature
footer — `zelynic v<version> by oxyzenQ (rezky_nightky)` — bottom-left
(NIGHT-boost-5). The watchdog line appears only when the BPF
auto-expiry deadline is actually ARMED; a dormant watchdog prints
nothing ("Watchdog: not set (enforcing)" was retired as noise — it
read like a state, but it was the absence of one). `--print-json`
keeps the `"watchdog"` field unchanged for scripts.

### list-apps — discovery

```bash
zelynic list-apps [--print-json]
```

Lists every cgroup with live processes: PROCESS, PROCS, SOCKETS,
CGROUP ID, UID. The PROCS/SOCKETS columns expose multi-tenancy — a row
labeled `alacritty` hosting 4 processes and 7 sockets is probably
carrying your `curl`. Works without root; enforcement commands do not.

### eagle-eyes — the unified live monitor

```bash
sudo zelynic eagle-eyes [targets] [--interval <1s-60s>]
```

One surface for the former `observe` + `top` pair (NIGHT-boost-1;
`ee` is the short alias, NIGHT-improve-25 — the singular `eagle-eye`
alias is removed, and typing it lands on a redirect tip pointing
here). Apps are RANKED by session accumulation (NIGHT-boost-5):
rank 1 is whoever has moved the most bytes since the monitor
started — a heavy downloader that stops keeps its crown until
another app's accumulated total passes it. Rows persist across
quiet frames (an app that goes idle stays on the board with em-dash
rates and its accumulated TOTAL — no more collapsing to "waiting
for traffic..." once traffic has been seen), with per-cgroup detail
lines naming the processes and remote endpoints inside.

The frame is a PINNED composition (NIGHT-boost-14, the owner's
masterclass engraving): the table floats under the header and the
grip footer stays near the bottom of the terminal whatever the
table does — the TOTAL row framed by two purple grid lines, the
packets/cgroups census under its own-width grip, the "Top consumer"
autodetect (the busiest process inside the rank-1 cgroup, its name
green) under its own grip, the exact `strict-single` command to cap
it, and the signature copyright last. All footer text renders calm
grey except the purple copyright — subordinate information reads
dimmer than the data it annotates. The tiers are a STATIC traffic
light (the takeover blink is gone — eye strain): rank 1 champion
red, rank 2 warning yellow, rank 3 and below status green; the
subprocess usage lines render grey. A breathing blank line sits
under the title bar, and the grid under the column header is brand
purple, same source as the header text above it. The census wording
is `N packets + M cgroups` (a `+` join, never a dot).

Dynamic screen size (NIGHT-boost-14): the loop probes the terminal
geometry every 50ms wake and renders a change within one wake — not
at the next refresh tick, so even `--interval 60` resizes instantly.
Adaptive compact mode on narrow frames: the subprocess detail hides
(below width 51, where the TOTAL column itself drops) and every
detail line is cut to the frame width, so a long process or endpoint
string can never wrap the frame or shift the pinned footer. Short
terminals compress the footer through a tier ladder — breathing
blanks drop first, then the grips, then the discovery hints —
before the table loses its rows; the census and the copyright
survive at every height. The row count follows the terminal height
— there is no `--limit`: the window IS the budget. DOWNLOAD and
UPLOAD carry live per-direction RATES; TOTAL carries the
session-accumulated bytes (the "total accumulated" function v10
had). The frame's left border is one straight edge (NIGHT-boost-5):
the title bar carries the same two-column gutter the rows use, and
the label column absorbs the remaining width so every line closes
flush at the frame's right edge. The column header's rank cell is
blank — the digits speak for themselves. Frames render through the
diff-based engine (NIGHT-improve-2): only the rows that changed
since the previous frame are written — one write syscall per frame,
an unchanged frame costs zero I/O at every terminal height
(NIGHT-improve-6), and the screen is never wiped or scrolled
mid-session (no flicker, no drift, no alt-screen scrollback side
effects). Every frame closes with the column-aligned TOTAL row
(aggregate down/up/rate sums over every candidate, not just the
rows shown) and the census. Byte figures keep one decimal on every
tier and promote at the rounding edge (999_950 B is "1.0 MB",
never "1000.0 KB").

The positional `targets` filter is autodetected per token: all digits
means a cgroup ID (find one with `list-apps`), anything else a
process name — and names watch ALL matching cgroups, the same
whole-app semantics as strict/block. One target that resolves to a
single cgroup switches to the deep focus view: per-direction deltas,
rate, lifetime totals (both lifetime counters summed — download and
upload since attach, never a per-refresh delta), and every
socket-holding process with its endpoints, uncapped. Multiple
targets (`12345/brave/firefox`) keep the ranked table, filtered.
Resolution re-runs every frame against the live identity map, so an
app started mid-session appears on the next refresh. Default refresh
1s — realtime precision; `--interval` calms it down to at most 60s.
**Quit with `q` — the only quit key** (NIGHT-hunt-16; ESC and Ctrl+C
are drained, never treated as quit).

### doctor — support check

```bash
zelynic doctor [--print-json]
```

Reports kernel version, cgroup v2 layout, BPF filesystem, pin state,
and whether your machine can run zelynic. Run this first on a new
distro. The BPF-filesystem check verifies that `/sys/fs/bpf` is a
real mounted bpf filesystem (statfs), not merely a directory that
happens to exist (NIGHT-hunt-28) — the kernel creates that directory
on every system, so existence alone says nothing.

---

## Global flags

| Flag | Effect |
|------|--------|
| `-h, --help` | The single end-to-end reference (commands, flags, formats, examples). No separate man page exists — this is it. |
| `-V, --version` | Version + build report (architecture, build label, hash, timestamp). Parses at every level — after a subcommand's arguments too (NIGHT-boost-12). |
| `--check-update` | Checks the latest GitHub release. **Refuses to run as root** — it is a plain network fetch and must not ride sudo. |
| `-v, --verbose` | stderr diagnostic trace: target resolution (pids per cgroup), every policy write (rate + burst), BPF lifecycle (pin reuse, schema, link mode), plus loader-level eBPF debug — object size, kernel release, load/attach timings, and the loaded map inventory (id, type, key/value size, max_entries, the `bpftool` facts). JSON output stays clean. |
| `--print-json` | Machine-readable output where applicable (`status`, `list-apps`, `doctor`). |

Privilege matrix in short: enforcement and monitoring commands
(`strict*`, `block*`, `unstrict*`, `recover`, `status`, `eagle-eyes`)
require root and fail fast with a sudo tip otherwise;
`list-apps`, `doctor`, `--help`, `-V` run on any uid;
`--check-update` is the one surface that refuses root.
Full matrix: [docs/SAFETY_ANALYSIS.md](SAFETY_ANALYSIS.md).

---

## Workflows and recipes

**Discover, limit, verify, remove** (the core loop):

```bash
sudo zelynic eagle-eyes               # who is eating bandwidth? (q to quit)
sudo zelynic list-apps                # confirm name + cgroup id
sudo zelynic strict-single brave 100kb
sudo zelynic status                   # see the policy + counters
# ... browse with the limit active; check a speed test site:
# 100kb means 100 KB/s = 0.8 Mbps on speed-test readouts (decimal SI)
sudo zelynic unstrict-single brave
```

**Cap a pool of download tools:**

```bash
sudo zelynic strict-multi curl:pacman:aria2c 1mb
```

**Asymmetric limits (e.g., slow uploads for a game):**

```bash
sudo zelynic strict-single firefox -d 5mb -u 500kb
```

**Focus a noisy background updater:**

```bash
sudo zelynic eagle-eyes               # ranked; raise the window for more
sudo zelynic eagle-eyes 8066         # zoom in, see endpoints (q to quit)
sudo zelynic strict-single 8066 50kb  # target the cgroup id directly
```

**Scripted monitoring** (JSON is stable, jq-friendly):

```bash
sudo zelynic status --print-json | jq '.limits[] | select(.bytes_dropped > 0)'
```

**After a crash or a weird state:**

```bash
sudo zelynic status                   # "Stale BPF pin files detected"?
sudo zelynic recover
```

---

## Honest limitations — read this

zelynic is deliberately small and stateless. These are real behaviors,
not bugs — knowing them makes the tool predictable.

**1. Rules are a snapshot, not a subscription.**
When you run `zelynic strict-single A 100kb` or `limit-all 100kb`,
zelynic resolves the apps that exist **at that moment** and writes
their cgroup rules. If you launch a new app (or a new instance of an
already-limited app that gets a fresh cgroup) **after** the command,
that newcomer is **not** limited. There is no daemon watching for new
processes — by design (no background cost, no config drift). Re-run
zelynic after launching new apps:

```bash
sudo zelynic limit-all 500kb          # run again to sweep in newcomers
```

The precise rule: enforcement follows **cgroups**, not processes. A new
process that *joins an already-limited cgroup* (e.g., you run `curl`
inside the same terminal session that is already limited) **is**
limited. A new process that gets a **new** cgroup is not. On systemd
distros, GUI apps usually get their own cgroup per launch — so a
restarted browser needs a re-run.

**2. Limits do not survive reboot.**
Pins live on bpffs (`/sys/fs/bpf/zelynic/`), which is wiped at boot —
and cgroup IDs are re-assigned by the kernel anyway. After a reboot,
re-apply your limits. There is no boot-time persistence layer by
design; if you need one, a systemd unit or shell profile calling
zelynic is a user-side decision.

**3. Name resolution needs the app to be running.**
`strict-single` matches live processes in `/proc`. An app that is not
running has no cgroup to resolve — start the app first, or target a
cgroup ID from an earlier `list-apps` if you know it. A name that
matches nothing prints `No cgroup found for '<name>'` plus a
`list-apps` tip.

**4. A name can match more than one cgroup.**
`strict-single brave` limits every cgroup containing a process named
`brave` — including browser helpers (e.g., a crash-pad handler). That
is usually what you want (the app's whole footprint), but for surgical
control, target the cgroup ID directly and verify with
`eagle-eyes <id>`. Status labels show the majority-vote process name
plus what lives inside, so mis-attribution is visible rather than
silent.

**5. Rates are decimal SI and per direction — fractions included.**
`100kb` = 100,000 bytes/s = 0.8 Mbps on a speed-test site, and
`5.5mb` = 5,500,000 bytes/s (NIGHT-boost-15: the value grammar is
`[0-9]+(\.[0-9]+)?` before the lowercase unit — exact u128 integer
math, rounded half-away-from-zero at the final byte; a fractional
input that rounds to zero is rejected because `0` is the block
verdict, and `5.5h` stays a duration error, fractions are rates
only). A positional rate sets **both** directions — `strict-single
brave 100kb` limits upload too, not just download. Minimum 1kb,
maximum 1tb; both bounds overridable with `--allow-dangerous` —
below 1kb an app can stop working entirely (hence the flag's name).

**6. Monitoring surfaces also need root.**
`status`, `eagle-eyes` read BPF maps; only `list-apps`, `doctor`,
`--help`, `-V` are unprivileged. This is kernel map access, not a
policy choice.

**7. Kernel 5.13+ with cgroup v2.**
Old distributions booting cgroup v1 cannot host zelynic. Run `zelynic
doctor` on a new machine; the full feature-dependency and distro
matrix lives once in
[docs/KERNEL_COMPATIBILITY.md](KERNEL_COMPATIBILITY.md).

**8. One enforcement-changing operation at a time.**
A non-blocking file lock (`flock` on `/run/zelynic/zelynic.lock`, inside a
root-only directory) guards
strict/block/unstrict/recover: a second concurrent operation exits
immediately with "another zelynic operation is in progress — wait for
it to finish, then retry" rather than waiting silently or interleaving
map writes. A teardown racing an apply is detected after the fact and
reported with a `recover` tip.

**9. Counters are cumulative evidence.**
The ALLOWED/DROPPED columns in `status` accumulate since the maps were
created — they prove enforcement is biting, but they are not a live
throughput meter. Use `eagle-eyes` for live rates.

**10. The CLI surface is frozen (v11).**
Commands, flags, and output formats are stable API from v11.0.0.
Removed surfaces (`man`, `completions`, `unblock`, `-i/--info`,
`--live`, `--duration`, `--help-all`, and the NIGHT-boost-1 merge
`observe`/`top` -> `eagle-eyes`) exit with a usage error on
purpose — `--help` is the single reference.

**11. eagle-eyes tracks at most 1024 distinct cgroups.**
The monitor's counter maps hold 1024 entries per direction (raised
from the port-time 256 in NIGHT-improve-8: Kubernetes nodes,
systemd-heavy servers, and container hosts can exceed 256 live
cgroups, and a full map silently stopped counting new cgroups).
A host with more live cgroups than 1024 shows only the first 1024
in the monitor rows.

---

## Troubleshooting

| Symptom | Meaning / fix |
|---------|---------------|
| `root required — eBPF operations need CAP_BPF` | Re-run with `sudo`. Only `list-apps`/`doctor`/`--help`/`-V` skip this. |
| `--check-update` refuses to run as root | Re-run **without** sudo. It is a plain network fetch. |
| `zelynic help` exits 2 with a tip | By design: help is the `--help` flag, not a subcommand (the single-tier reference). The tip names the spelling (NIGHT-boost-13). |
| Unknown flag after a full command shows NO "use `--`" tip (e.g. `ss brave 550kb -i`) | Honest silence: the escape-hatch tip prints only where following it actually parses (the NIGHT-boost-13 probe re-parses with the splice). No tip means the positional slots are full — the usage line under the error is the failing command's own grammar, and nothing more fits. |
| `--json` (a habit from other tools) | The vocabulary rescue tips the zelynic spelling: `--print-json` (NIGHT-boost-13). |
| `No cgroup found for '<name>'` | The app is not running (or the name is wrong). Start it, check `zelynic list-apps`, or target a cgroup ID. |
| `Invalid rate '1MB'` (with a tip) | Units are lowercase. The tip suggests the fix (`1mb`; fractional twins like `5.5MB` -> `5.5mb` work the same way). |
| `Invalid interval '90s'` | Refresh interval must be 1s..60s. |
| `Stale BPF pin files detected` | A previous run was killed mid-operation. Run `sudo zelynic recover`, then re-apply limits. |
| `Failed to load BPF object` with `caused by:` lines under it | Every runtime error now prints its full cause chain (NIGHT-hunt-28) — read the `caused by:` lines: they name the exact map, syscall, and errno (e.g. `failed to create map 'X' with code -22`). If the chain ends in a pin/EINVAL shape instead, it is the mount below. |
| `error parsing BPF object: error parsing ELF data` at startup (strict/limit) | Two distinct causes share this one error text, both fixed at the source. (1) Address misalignment (NIGHT-hunt-30, the 2026-09-20..21 occurrences): aya's ELF parser reads the embedded object straight out of the binary's `.rodata` and requires the buffer's address to be 8-byte aligned — the plain `include_bytes!` static had that only by linker luck, per host per build. Both objects are now embedded inside an `AlignedElf` wrapper, aligned by construction, with a load-path preflight that names any violation precisely ("address is N bytes past an 8-byte boundary"). (2) A bpfel object damaged on disk (NIGHT-hunt-29): cargo never re-verifies build outputs, so a truncated artifact stayed "fresh" and every rebuild re-embedded it; builds now structurally validate both objects and self-heal a damaged one, visible as a `cargo:warning` naming the exact violation (e.g. `truncated: section header table (10 x 64 at 4984) exceeds the 1000-byte file`) followed by one forced relink. A binary already showing this error only needs a rebuild from current source: `cargo pro-native-gnu`. |
| `/sys/fs/bpf is not a mounted bpf filesystem` | The limiter pins its maps under `/sys/fs/bpf/zelynic`, and pinning needs a real bpffs mount — a directory merely existing there is not enough (the kernel always creates it; some distros never mount bpffs on it). Fix: `sudo mount -t bpf bpf /sys/fs/bpf`, made permanent via fstab or a systemd mount unit. Note `eagle-eyes` needs no bpffs (its maps are unpinned) — if the monitor works but strict/limit fail, this is exactly it. |
| `invalid CPU znver3` (or any CPU name) from bpf-linker during `cargo pro-native-gnu` | Fixed (NIGHT-hunt-28): the alias's `-C target-cpu=native` used to leak into the nested eBPF build and reach bpf-linker as `--cpu <host-cpu>`, which it rejects. build.rs now strips host-CPU and host-linker rustflags from the nested build's environment; the aliases work on any host CPU. |
| `the pinned nightly toolchain ... is not installed` / `bpf-linker is not on PATH` (build time) | One command fixes both — and since NIGHT-improve-16 it finishes the whole host setup: `./scripts/bootstrap-ebpf.sh` installs the pair, fixes its own PATH for the build, persists the `~/.local/bin` export to `~/.profile`, and builds the flagship binary (NIGHT-host-1). If bpf-linker already sits in `~/.local/bin`, put that directory on PATH. `the pure-Rust eBPF build failed with prerequisites present` is a real compile error — read the nested cargo output above it. The old "BPF object file not found" error class is gone (objects are embedded). |
| `BINARY GATE: refusing to test a zelynic that is not this checkout's build` (supermassive-test / supermassive-test-v2 / limiter-depth-test startup) | Working as designed (NIGHT-improve-16): the harness resolves the checkout's own build first — repo target outputs, newest mtime wins — and hard-aborts when the resolved binary's `-V` version differs from the checkout's Cargo.toml. Before the gate, the 2026-09-21 debian13 run silently tested a stale `/usr/bin/zelynic` v4.0.0-alpha (repo build had never succeeded there) and filed 12 decoy failures: `unrecognized subcommand 'block-single'`, v4 rate guards rejecting v11 rungs, `no limit row ... in status JSON` (v4 schema). Fix: `./scripts/bootstrap-ebpf.sh` (prerequisites + flagship build, one command), or `--binary ./target/pro-native-gnu/zelynic` for an existing matching build. |
| `bootstrap-ebpf.sh` looks stuck on the bpf-linker download | It is the one big fetch (~100 MB) and can take minutes on slow links. On a terminal the script shows a live progress bar for exactly this step (NIGHT-hunt-24); piped/logged runs stay quiet. Killing it mid-download is safe — re-running skips whatever already finished. |
| `error: missing manifest in toolchain 'nightly-...'` from rustup, or a build dying inside rustup commands | The dated nightly install is damaged — an interrupted `rustup toolchain install` (Ctrl-C, power loss, full disk) leaves the toolchain listed while its manifests are gone, so every component operation fails even though `rustc` itself still runs (which is why it slips past naive checks). Fix: run `./scripts/bootstrap-ebpf.sh` again — it detects the damaged state, removes the toolchain, and reinstalls it from scratch, no manual rustup commands (NIGHT-hunt-27); the build.rs preflight names this exact state with the same one-command repair. |
| Monitor won't exit | Press `q` — the only quit key (NIGHT-hunt-16). ESC and Ctrl+C are deliberately drained, never treated as quit. If a wedged terminal swallows the `q` byte: `pkill zelynic` from another shell, then `stty sane`. |
| Limit seems not enforced | Check `sudo zelynic status` — is the cgroup listed? Verify the app's traffic is actually flowing through the limited cgroup (`eagle-eyes <id>`). If the app was restarted after the limit was set, re-apply (see limitation #1). |
| Two zelynic commands interfered | The lock is deliberately non-blocking: the second command exited with "another zelynic operation is in progress". Wait for the first to finish, re-run it. If pins ended up inconsistent: `recover`. |

When diagnosing, add `-v`: the verbose trace shows the exact pid-to-
cgroup resolution and every policy write, which answers most "what did
it actually do?" questions in one run.

---

## JSON reference for scripting

`--print-json` output is stable API (v11 contract). Every command
emits ONE compact single-line JSON document per invocation
(NIGHT-boost-3, the machine-first contract — `jq`-ready and
NDJSON-friendly; pretty-print on the consumer side with `| jq '.'`).
Field shapes:

`status --print-json`:

```json
{"watchdog":"enforcing","active_limits":2,"limits":[{"cgroup_id":18571,"label":"brave","download_bps":100000,"upload_bps":100000,"packets_allowed":232,"packets_dropped":4718,"bytes_allowed":29520,"bytes_dropped":8031234}]}
```

`list-apps --print-json`:

```json
{"total":142,"apps":[{"process":"brave","cgroup_id":18571,"uid":1000,"processes":4,"sockets":9}]}
```

`doctor --print-json` reports the capability check fields (kernel,
cgroup v2, BPF fs, pins). Run it once to see the shape on your distro.

A missing limit list with `"active_limits": 0` and `watchdog: "clean"`
means exactly that: nothing is limited right now.

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (including informational output like `--help`, `status`). |
| 1 | Runtime failure — root missing, BPF object absent, stale state. The error carries a branded `error:` label and often a white `tip:` line. |
| 2 | Usage error — unknown command/flag, missing arguments, invalid values. clap renders it with did-you-mean suggestions for typos, the usage line is the FAILING command's own grammar (NIGHT-boost-13), and every escape-hatch tip is verified before printing: a "use `--`" tip that fails when followed is dropped. |

---

## FAQ

**Does limiting slow my whole system?**
No. Two eBPF programs run per packet crossing a cgroup boundary —
nanosecond-scale work, no userspace involved. Benchmarks live in
[docs/PERFORMANCE.md](PERFORMANCE.md).

**Why does `strict-single brave 100kb` also slow my uploads?**
A positional rate means both directions. Use `-d`/`-u` to split them.

**I limited an app but a speed test shows full speed.**
Three usual causes: (1) the app was restarted after you set the limit —
re-apply; (2) the traffic flows through a different cgroup than the one
you limited — check `eagle-eyes`/`status` labels and target the cgroup ID;
(3) unit conversion — 100kb is 0.8 Mbps, verify against
[limitations #5](#honest-limitations--read-this).

**Can I limit myself out of SSH?**
The dangerous-target blocklist guards `sshd` and friends by default;
`--force` is the explicit override. If you do brick connectivity,
recovery is a reboot away (limits do not survive it) or
`sudo zelynic unstrict-all` from any working session.

**Where is the config file?**
There is none — CLI flags only, ever. State lives in pinned BPF maps,
not in your home directory.

**Does it work on macOS/BSD?**
No. zelynic is Linux-only (cgroup v2 + eBPF). It is a Linux-native tool
by design.

**How do I quit eagle-eyes?**
Press `q` — the only quit key (NIGHT-hunt-16). ESC was removed as a
quit key in NIGHT-hunt-12 (escape sequences from arrows/mouse made
accidental quits too easy); Ctrl+C quit was removed in NIGHT-hunt-16
for the same single-key contract as htop/vim — the title bar says
"q quit" and nothing else quits.

**Can I select and copy/paste text while the monitor runs?**
No — box mode takes the pointer AND kills terminal-side selections on
a fixed beat (NIGHT-improve-7 + NIGHT-improve-8, superseding the
NIGHT-strict-1 mouse clause). The monitor enables mouse tracking
(1000 press/release, 1002 button-drag, 1006 SGR encoding) for its
whole lifetime, so click-drag selects nothing and middle-click never
lands in the monitor's stdin. The one hole mouse tracking cannot
close is the terminal's own Shift+click bypass — no escape sequence
can switch that off — so the monitor additionally re-emits the
whole frame every 100 ms while it runs: terminals clear a selection
the moment its cells are rewritten (the same physics that makes
`watch` output unselectable), which means a Shift+click selection
cannot outlive one beat, and every copy path that needs a live
selection (Ctrl+Shift+C, right-click Copy) finds nothing to copy.
Every mode is restored on exit: press `q` and selection/paste work
again immediately, nothing stays captured. Honest physics boundaries,
documented not hidden: an X11-style terminal that mirrors a COMPLETED
selection into the PRIMARY clipboard at button release can still
catch whatever re-accumulates after the last beat (a terminal-side
behavior no Linux application can retract), and a Select All + Copy
fired inside a single 100 ms beat lands before the next rewrite —
both are terminal emulator features outside any application's reach.
Pasted bytes that do reach stdin are drained like any other non-`q`
input — a paste whose first byte is `q` still quits (the
NIGHT-hunt-16 q-only contract). The contract is enforced by unit
tests (`test/terminal/mouse_contract_tests.rs` pins the byte
sequences, the guard beat, and the loop scheduler, and scans the
whole source tree for any unsanctioned terminal-mode literal;
`test/terminal/diff_tests.rs` pins the guard's whole-frame
repaint), so a future commit cannot silently loosen or widen the
takeover.

---

## Maintainer's map

Where things live when a command changes (update these together):

| Change | Files to touch |
|--------|----------------|
| New/changed command or flag | `src/cli/mod.rs` (definition), `src/commands/mod.rs` (dispatch), handler in `src/commands/`, `src/commands/help.rs` (reference), `test/integration/help_pins.rs` (drift pins: `test_help_lists_every_command` + removal pins) + `test/integration/surface_pins.rs` (alias/removal wiring), README Commands block |
| Monitor rendering | `src/ebpf/render/` (`eagle.rs`, `focus.rs`, `detail.rs` — line builders), `src/terminal/mod.rs` (monitor loop), `src/terminal/diff.rs` (diff engine + quit keys live in mod.rs), `docs/BRANDING.md` |
| Rate/interval parsing | `src/ebpf/limiter/format.rs`, `src/cli/ux.rs` (typo tips) |
| CLI error tips and usage lines | `src/cli/ux.rs` (the bridge: typo/vocabulary/authority rescues, redirects, usage regeneration), `src/cli/argv.rs` (escape-hatch honesty probe, failing-command walk), `test/cli/` (ux + argv pins), `test/integration/cli_ux.rs` (binary-level pins) |
| Status/JSON shapes | `src/ebpf/display.rs` — JSON is stable API, treat changes as breaking |
| Docs after any behavioral change | This file + README + CHANGELOG; `docs/SAFETY_ANALYSIS.md` for privilege changes |
| Security-relevant change | `SECURITY.md` posture table + `docs/SAFETY_ANALYSIS.md` audit section — move them together |

Quality gates before every commit: the two commands and what each one
runs are documented once in
[CONTRIBUTING.md](../CONTRIBUTING.md) (`build.sh check-all` +
`gate-keepers.sh`).

Frame-level render changes additionally get the 10s A/B benchmark:
`scripts/frame-bench.py` before/after, reporting density gini, frame
entropy, fps, dirty cells, and (NIGHT-improve-2) the diff engine's
emitted bytes per frame against the logical frame (protocol in the
script header).

Source of truth is always `src/**` — if any doc (including this one)
disagrees with the code, the doc is wrong; open a PR.
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
