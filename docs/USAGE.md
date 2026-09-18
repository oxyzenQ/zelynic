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
sudo zelynic observe                   # watch traffic live (q to quit)
sudo zelynic unstrict brave            # remove the limit
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
app. `strict` is the shorthand for `strict-single`; `unstrict-single`
is an alias of `unstrict`.

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
`observe --cgroup <id>` to inspect what actually carries the traffic,
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
as strict. `unstrict` removes a block exactly like it removes a rate
limit (blocks and limits live in the same policy maps; a blocked cgroup
shows a 0-rate policy in `status`).

### unstrict / unstrict-multi / unstrict-all

```bash
sudo zelynic unstrict brave            # (alias: unstrict-single)
sudo zelynic unstrict-multi brave:curl:pacman
sudo zelynic unstrict-all              # emergency reset: removes everything
```

Removes policies for the resolved cgroups and reports how many policies
(dl + ul) it removed — the same counting strict uses, so "4 policies"
in and "4 policies" out line up. `unstrict-all` also removes the pin
directory itself: after it, `status` reports a clean state.

### recover — crash cleanup

```bash
sudo zelynic recover
```

If zelynic was killed mid-operation (SIGKILL, OOM, power loss), pin
files can be orphaned. `recover` detects and removes them. Safe to run
anytime — it does nothing when state is clean. `status` tells you when
you need it ("Stale BPF pin files detected").

### status — what is limited right now

```bash
sudo zelynic status [--print-json]
```

Reads the pinned maps and prints: watchdog state (normally "not set
(enforcing)"), how many dl/ul policies are active, and a table of
CGROUP / DOWNLOAD / UPLOAD / ALLOWED / DROPPED per cgroup, with labels
resolved by majority vote over the live processes inside each cgroup.
ALLOWED/DROPPED are cumulative packet/byte counters since the maps were
created — they are evidence of enforcement, not a live rate meter.

### list-apps — discovery

```bash
zelynic list-apps [--print-json]
```

Lists every cgroup with live processes: PROCESS, PROCS, SOCKETS,
CGROUP ID, UID. The PROCS/SOCKETS columns expose multi-tenancy — a row
labeled `alacritty` hosting 4 processes and 7 sockets is probably
carrying your `curl`. Works without root; enforcement commands do not.

### observe — live traffic monitor

```bash
sudo zelynic observe [--cgroup <id>] [--interval <1s-60s>]
```

Always-live box mode (NIGHT-hunt-12): full-screen in-place refresh, no
scrollback spam, adaptive layout (columns degrade on narrow terminals;
a RATE column appears from width 50). `--cgroup` zooms into one cgroup
with per-process and per-socket endpoint detail. Default refresh 1s;
`--interval` calms it down to at most 60s. **Quit with `q`** (Ctrl+C
also exits; ESC no longer quits — stray escape sequences made it a
coin flip).

### top — live bandwidth ranking

```bash
sudo zelynic top [--limit N] [--interval <1s-60s>]
```

Always-live top-talkers table (NIGHT-hunt-12): rank, PROCESS, DOWNLOAD,
UPLOAD, TOTAL, with per-cgroup detail lines naming the processes and
remote endpoints inside. Default shows top 10, refreshed every 5s. The
"Top consumer" footer names the busiest process inside the #1 cgroup
and suggests the exact `strict-single` command to limit it. Quit with
`q`.

### doctor — support check

```bash
zelynic doctor [--print-json]
```

Reports kernel version, cgroup v2 layout, BPF filesystem, pin state,
and whether your machine can run zelynic. Run this first on a new
distro.

---

## Global flags

| Flag | Effect |
|------|--------|
| `-h, --help` | The single end-to-end reference (commands, flags, formats, examples). No separate man page exists — this is it. |
| `-V, --version` | Version + build report (architecture, build label, hash, timestamp). |
| `--check-update` | Checks the latest GitHub release. **Refuses to run as root** — it is a plain network fetch and must not ride sudo. |
| `-v, --verbose` | stderr diagnostic trace: target resolution (pids per cgroup), every policy write (rate + burst), BPF lifecycle (pin reuse, schema, link mode). JSON output stays clean. |
| `--print-json` | Machine-readable output where applicable (`status`, `list-apps`, `doctor`). |

Privilege matrix in short: enforcement and monitoring commands
(`strict*`, `block*`, `unstrict*`, `recover`, `status`, `observe`,
`top`) require root and fail fast with a sudo tip otherwise;
`list-apps`, `doctor`, `--help`, `-V` run on any uid;
`--check-update` is the one surface that refuses root.
Full matrix: [docs/SAFETY_ANALYSIS.md](SAFETY_ANALYSIS.md).

---

## Workflows and recipes

**Discover, limit, verify, remove** (the core loop):

```bash
sudo zelynic top                      # who is eating bandwidth? (q to quit)
sudo zelynic list-apps                # confirm name + cgroup id
sudo zelynic strict-single brave 100kb
sudo zelynic status                   # see the policy + counters
# ... browse with the limit active; check a speed test site:
# 100kb means 100 KB/s = 0.8 Mbps on speed-test readouts (decimal SI)
sudo zelynic unstrict brave
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
sudo zelynic top --limit 20           # wider ranking
sudo zelynic observe --cgroup 8066    # zoom in, see endpoints (q to quit)
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
`observe --cgroup`. Status labels show the majority-vote process name
plus what lives inside, so mis-attribution is visible rather than
silent.

**5. Rates are decimal SI and per direction.**
`100kb` = 100,000 bytes/s = 0.8 Mbps on a speed-test site. A positional
rate sets **both** directions — `strict-single brave 100kb` limits
upload too, not just download. Minimum 1kb, maximum 100gb; both bounds
overridable with `--allow-dangerous` (min) — below 1kb an app can stop
working entirely.

**6. Monitoring surfaces also need root.**
`status`, `observe`, `top` read BPF maps; only `list-apps`, `doctor`,
`--help`, `-V` are unprivileged. This is kernel map access, not a
policy choice.

**7. Kernel 5.13+ with cgroup v2.**
zelynic uses `cgroup.id` files and bpf_link. Run `zelynic doctor` on a
new machine. Old distributions booting cgroup v1 cannot host zelynic.

**8. One enforcement-changing operation at a time.**
A non-blocking file lock (`flock` on `/tmp/zelynic.lock`) guards
strict/block/unstrict/recover: a second concurrent operation exits
immediately with "another zelynic operation is in progress — wait for
it to finish, then retry" rather than waiting silently or interleaving
map writes. A teardown racing an apply is detected after the fact and
reported with a `recover` tip.

**9. Counters are cumulative evidence.**
The ALLOWED/DROPPED columns in `status` accumulate since the maps were
created — they prove enforcement is biting, but they are not a live
throughput meter. Use `observe` for live rates.

**10. The CLI surface is frozen (v11).**
Commands, flags, and output formats are stable API from v11.0.0.
Removed legacy surfaces (`man`, `completions`, `unblock`, `-i/--info`,
`--live`, `--duration`, `--help-all`) exit with a usage error on
purpose — `--help` is the single reference.

---

## Troubleshooting

| Symptom | Meaning / fix |
|---------|---------------|
| `root required — eBPF operations need CAP_BPF` | Re-run with `sudo`. Only `list-apps`/`doctor`/`--help`/`-V` skip this. |
| `--check-update` refuses to run as root | Re-run **without** sudo. It is a plain network fetch. |
| `No cgroup found for '<name>'` | The app is not running (or the name is wrong). Start it, check `zelynic list-apps`, or target a cgroup ID. |
| `Invalid rate '1MB'` (with a tip) | Units are lowercase. The tip suggests the fix (`1mb`). |
| `Invalid interval '90s'` | Refresh interval must be 1s..60s. |
| `Stale BPF pin files detected` | A previous run was killed mid-operation. Run `sudo zelynic recover`, then re-apply limits. |
| `BPF object file not found` | Compile the BPF objects (see README Build section) or install a release tarball, then `zelynic doctor`. |
| Monitor won't exit | Press `q`. Ctrl+C also exits. ESC deliberately no longer quits (NIGHT-hunt-12). |
| Limit seems not enforced | Check `sudo zelynic status` — is the cgroup listed? Verify the app's traffic is actually flowing through the limited cgroup (`observe --cgroup`). If the app was restarted after the limit was set, re-apply (see limitation #1). |
| Two zelynic commands interfered | The lock is deliberately non-blocking: the second command exited with "another zelynic operation is in progress". Wait for the first to finish, re-run it. If pins ended up inconsistent: `recover`. |

When diagnosing, add `-v`: the verbose trace shows the exact pid-to-
cgroup resolution and every policy write, which answers most "what did
it actually do?" questions in one run.

---

## JSON reference for scripting

`--print-json` output is stable API (v11 contract). Shapes:

`status --print-json`:

```json
{
  "watchdog": "enforcing",
  "active_limits": 2,
  "limits": [
    {
      "cgroup_id": 18571,
      "label": "brave",
      "download_bps": 100000,
      "upload_bps": 100000,
      "packets_allowed": 232,
      "packets_dropped": 4718,
      "bytes_allowed": 29520,
      "bytes_dropped": 8031234
    }
  ]
}
```

`list-apps --print-json`:

```json
{
  "total": 142,
  "apps": [
    {
      "process": "brave",
      "cgroup_id": 18571,
      "uid": 1000,
      "processes": 4,
      "sockets": 9
    }
  ]
}
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
| 2 | Usage error — unknown command/flag, missing arguments, invalid values. clap renders it with did-you-mean suggestions for typos. |

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
you limited — check `observe`/`status` labels and target the cgroup ID;
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

**How do I quit observe/top?**
Press `q` (Ctrl+C also exits). ESC was removed as a quit key in
NIGHT-hunt-12 — escape sequences from arrows/mouse made accidental
quits too easy.

---

## Maintainer's map

Where things live when a command changes (update these together):

| Change | Files to touch |
|--------|----------------|
| New/changed command or flag | `src/cli/mod.rs` (definition), `src/commands/mod.rs` (dispatch), handler in `src/commands/`, `src/commands/help.rs` (reference), `tests/integration_test.rs` (drift pins: `test_help_lists_every_command` + removal pins), README Commands block |
| Monitor rendering | `src/ebpf/render/` (`observe.rs`, `top.rs`, `detail.rs`), `src/terminal/mod.rs` (alt screen + quit keys), `docs/BRANDING.md` |
| Rate/interval parsing | `src/ebpf/limiter/format.rs`, `src/cli/ux.rs` (typo tips) |
| Status/JSON shapes | `src/ebpf/display.rs` — JSON is stable API, treat changes as breaking |
| Docs after any behavioral change | This file + README + CHANGELOG; `docs/SAFETY_ANALYSIS.md` for privilege changes |

Quality gates before every commit (both must pass):

```bash
./scripts/build.sh check-all     # fmt + clippy + tests + policy (2-min local cap)
./scripts/gate-keepers.sh        # 13 checks: lint, policy, versions, disclaimers
```

Frame-level render changes additionally get the 10s A/B benchmark:
`scripts/frame-bench.py` before/after, reporting density gini, frame
entropy, fps, dirty cells (protocol in the script header).

Source of truth is always `src/**` — if any doc (including this one)
disagrees with the code, the doc is wrong; open a PR.
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
