<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# zelynic — The End-to-End Guide: Basic to Advanced

The simplified walkthrough. This page teaches the whole product in one
reading: what a limit actually is, the four-command flow, and — the
part most users get wrong — when plain `strict` is enough and when the
advanced brackets (`--floor`, `--ceil`, `--per-socket`, `--during`)
earn their keep. Every claim here was verified against the source tree
(`src/cli/surface.rs`, `src/commands/guarantee.rs`,
`src/commands/strict.rs`, `src/ebpf/limiter/`); where the docs and the
binary ever disagree, the source is the truth. The flagship reference
with every flag and error remains [USAGE.md](USAGE.md).

---

## Table of contents

1. [The mental model (read this once)](#the-mental-model-read-this-once)
2. [The end-to-end flow](#the-end-to-end-flow)
3. [Basic usage — the 80 percent](#basic-usage--the-80-percent)
4. [What basic actually polices (the key fact)](#what-basic-actually-polices-the-key-fact)
5. [Advanced usage — the 20 percent](#advanced-usage--the-20-percent)
6. [The decision table](#the-decision-table)
7. [Worked scenarios with honest arithmetic](#worked-scenarios-with-honest-arithmetic)
8. [The honest limits (short list)](#the-honest-limits-short-list)
9. [Where to read next](#where-to-read-next)

---

## The mental model (read this once)

Three facts explain almost everything you will ever see:

**1. Enforcement lives in the kernel, not in a program.**
zelynic attaches two small eBPF programs at the cgroup-v2 root — one
for ingress (download), one for egress (upload). Every packet crossing
a cgroup boundary is classified by its cgroup ID and checked against a
rate policy stored in a BPF map. There is no proxy, no `tc`, no
`LD_PRELOAD`, no userspace hop. The rules are pinned under
`/sys/fs/bpf/zelynic/`, so enforcement continues after the command
exits. That is why limiting is **fire-and-forget**: no daemon, no
service, no config file, nothing running in the background. The flip
side: the pin directory lives on bpffs, so a **reboot wipes all
limits** (and the kernel re-assigns cgroup IDs anyway).

**2. A target is resolved once, and the limit follows its subtree.**
`zelynic s brave 100kb` walks `/proc`, finds every process named
`brave`, resolves each one's cgroup, and writes one policy per cgroup.
The policy is subtree-aware (AMMSP): any process that later spawns
BENEATH a limited cgroup is covered the moment its first packet moves —
child cgroups, containers, grandchildren, at any depth up to 32 levels.
No re-run needed. One honest bound: resolution is a snapshot of
`/proc` at command time.

**3. "Applied" is a claim, "VERIFIED" is a measurement.**
After every strict apply, zelynic measures itself: a short (~3s)
loopback flow runs through the just-written policy and the epilogue
prints a verdict. UNVERIFIED prints honestly but never fails the
command; `--no-test` skips the measurement for scripted use.

---

## The end-to-end flow

Four commands, start to finish:

```bash
zelynic doctor              # 1. can this host + build enforce? (support, build flavor)
sudo zelynic list-apps      # 2. find the app and its cgroup id
sudo zelynic s brave 100kb  # 3. apply the limit (verified with a ~3s probe)
sudo zelynic status         # 4. read the pinned maps back: what is limited right now
sudo zelynic ee brave       # watch it live (q quits)   — optional
sudo zelynic u brave        # remove the limit          — when done
```

`status`, `eagle-eyes`, and `--print-json` all read the same pinned
kernel state; nothing you see is a guess. `recover` exists for the
crash case (orphaned pins after a kill mid-operation) — safe to run
anytime.

---

## Basic usage — the 80 percent

Basic means: **one rate, applied to a cgroup.** If you only learn the
commands in this section, zelynic already does its job.

```bash
sudo zelynic s brave 100kb                  # cap download AND upload at 100 KB/s each
sudo zelynic s brave -d 1mb -u 500kb        # download 1 MB/s, upload 500 KB/s
sudo zelynic s brave::steam::discord 1mb    # GROUP: one shared 1 MB/s bucket for all three
sudo zelynic s --all 500kb                  # SWEEP: every user app at 500 KB/s
sudo zelynic b brave                        # BLOCK: no internet at all
sudo zelynic u brave                        # remove the limit again
```

Reading the grammar: `s` = strict (limit), `b` = block (cut off),
`u` = unstrict (undo), `ee` = eagle-eyes (watch). The target is a
process name (`brave`), a cgroup ID (`73386` or `cg:73386` — the
display prefix round-trips), or a container reference
(`docker://nginx`). A `::`-separated list is the group lane — the
separator is doubled because a single `:` already lives inside targets
(`cg:`, `docker://`).

### The numbers, honestly

Rates are **decimal SI**: `1kb` = 1000 bytes/s. A speed-test site
reports bits, so `100kb` reads as **0.8 Mbps**, `1mb` as **8 Mbps**.
The smallest rate is `1kb` (anything below asks for `--force-this`),
the largest `1tb`. Both directions get the same rate unless you split
with `-d`/`-u` — and a direction you do NOT set is removed, not left
stale: `zelynic s brave -d 1mb` caps download and leaves upload
unlimited.

---

## What basic actually polices (the key fact)

This is the single fact behind the whole basic-vs-advanced question.

**Basic polices the cgroup, not the connections or the subprocesses.**
One app = one cgroup = one shared bucket per direction. Every tab,
renderer, GPU process, and download inside Brave drinks from the same
100 KB/s. When three subprocesses want traffic at once, the bucket is
shared — and how the kernel divides it inside the cgroup is the
fair-share default, not something you chose.

Two consequences, both verified in the source:

- **The default is usually fine.** If you just want "Brave gets at
  most 100 KB/s total", you are done. Nothing else needed.
- **The default is not always what you meant.** If one download
  subprocess can eat the whole bucket while your video call starves,
  or if you run a server where every connection deserves its own full
  rate, you have crossed into the advanced lanes. That is the entire
  reason they exist.

---

## Advanced usage — the 20 percent

### The two lanes (the whole secret)

There are exactly two advanced lanes, and they answer different
questions:

| Lane | Flags | Question it answers | Bucket granularity |
|---|---|---|---|
| Fair-share | `--floor`, `--ceil` (+ per-direction spellings) | How do the app's **subprocesses** divide the shared bucket? | one bucket per **subprocess leaf** |
| Per-socket | `--per-socket` | Should every **connection** get its own full rate? | one bucket per **socket** |

They are different geometries, which is why the CLI refuses to combine
them. The source error says it exactly
(`src/commands/guarantee.rs`):

```
error: --floor/--ceil police the target's subprocess leaves (the
fair-share lane) and are not offered beside --per-socket (every
connection its own budget at the full rate).
Drop one: --per-socket for the server shape, --floor/--ceil for the
subprocess shape.
```

`--per-socket` is also single-lane only: a `::` group shares one
bucket by definition, so the flag is refused on lists.

### `--floor` and `--ceil`, honestly

`--floor RATE` — a **guaranteed minimum per subprocess leaf**. Every
subprocess under the target is guaranteed at least RATE of the shared
budget, however greedy its siblings. Two honest properties from the
datapath: it is a **priority, not a reservation** — an idle subprocess
lends its unspent share back to the pool; and **over-subscribed floors
degrade gracefully** — if the guarantees sum above the rate, the pool
never creates budget and you simply get the fair split.

`--ceil RATE` — a **maximum per subprocess leaf**. No subprocess may
exceed RATE even when its siblings are idle and the pool is rich. It
binds even a lone subprocess (a cap that only folds in when siblings
appear would not be a cap).

**The ladder** — validated fail-fast, per direction, before the
command does anything:

```
floor <= ceil <= rate
```

Each rung has its own refusal, with the numbers you typed:

```
floor 100000 exceeds the download rate 50000 - the pool never refills
that fast, so the guarantee could never bind.

ceil 2000000 exceeds the upload rate 1000000 - the pool refills at
the rate, so a ceiling above it never binds.

floor 500000 exceeds ceil 300000 on the download row - a guarantee
above the cap is a contradiction.
```

A floor above the rate is refused because a minimum guaranteed from a
pool that refills at `rate` could never bind; a ceiling above the rate
is refused for the mirror reason (it would never bind anyway).

**The one-flag law:** `--floor` sets BOTH directions' rows. The
per-direction spellings `--floor-download` / `--floor-upload` (and the
`--ceil-` twins) set one row each, and refuse to combine with the
both-directions flag — `--floor 100kb --floor-download 200kb` is a
mis-typed rate, not a wider guarantee. A per-direction bracket also
refuses if its direction has no rate in this invocation (a guarantee
for a row that will not exist is a mistake, named before anything
applies).

### `--per-socket`, honestly

`--per-socket` gives **every connection its own bucket at the full
rate** — the server shape (one process, many sockets). The honest
arithmetic: the cgroup total is `rate x concurrent sockets`, NOT rate.
`zelynic s nginx 500kb --per-socket` means each client connection gets
500 KB/s; ten concurrent clients move 5 MB/s in aggregate. That is the
point — it is also the number to check against your uplink before you
type it.

### `--during`, honestly

`--during 2h` auto-expires the row after a duration — and the KERNEL
decides when the window is over (no daemon, no cron; every zelynic
visit re-stamps the clock bridge). Units: `s m h d mn y`, bounds 1s to
10y. It rides any strict or block lane, so a time-boxed block is
`zelynic b discord --during 2h` and nothing else.

---

## The decision table

| You want | Type |
|---|---|
| Cap one app, total | `zelynic s brave 100kb` |
| Different download vs upload | `zelynic s brave -d 1mb -u 500kb` |
| One shared cap across several apps | `zelynic s brave::steam::discord 1mb` |
| Cap every user app at once | `zelynic s --all 500kb` |
| Guarantee each subprocess a minimum | `zelynic s brave 2mb --floor 500kb` |
| Stop one subprocess hogging the bucket | `zelynic s brave 2mb --ceil 1mb` |
| Both of the above, per direction | `--floor-download` / `--ceil-upload` (etc.) |
| Server: cap per connection | `zelynic s nginx 500kb --per-socket` |
| Auto-expire anything | append `--during 2h` |
| Cut an app off entirely | `zelynic b brave` |
| Undo | `zelynic u brave` (or `u --all` for the emergency reset) |

If your row is the first one, stop at basic. Brackets you do not need
are not sophistication — they are surface area.

---

## Worked scenarios with honest arithmetic

**Scenario: one activity at a time.** `sudo zelynic s brave 1mb`.
Every tab and download shares 1 MB/s. If you browse while a 100 MB
download runs, they split the bucket; the download alone takes about
100 seconds at the full rate. Basic is enough — this is the 80
percent.

**Scenario: video call must survive a big download.**
`sudo zelynic s brave 2mb --floor 500kb`. Total bucket 2 MB/s; each
subprocess leaf is guaranteed 500 KB/s when it asks. The call's
processes hold their floor; the download uses the remainder. Honest
note: the floor is per subprocess leaf inside the cgroup, so it
protects the call only insofar as the call's traffic rides its own
leaf — watch `eagle-eyes brave` once to see the real leaf layout
before trusting any bracket.

**Scenario: nobody gets to monopole.** `sudo zelynic s brave 2mb
--ceil 1mb`. Any single subprocess is capped at 1 MB/s even with the
whole pool idle, so one download can never starve everything else by
being first in line.

**Scenario: asymmetric link.**
`sudo zelynic s brave -d 2mb -u 500kb --ceil-upload 250kb`. The
upload row exists (`-u` set it), so the upload ceiling is legal:
ladder checked per direction — download has no bracket, upload is
capped at 250 KB/s per subprocess. Flip the sides with
`--floor-download 300kb` when the download side needs the guarantee
instead.

**Scenario: the server shape.**
`sudo zelynic s nginx 500kb --per-socket`. One listening process,
many clients; each connection gets its own 500 KB/s bucket. With ten
concurrent clients the cgroup total is 5 MB/s — check that against
your uplink. `--floor`/`--ceil` refuse beside this flag: with
per-connection buckets there is no subprocess leaf left to bracket.

**Scenario: the time-boxed block.**
`sudo zelynic b discord --during 2h`. The kernel lifts the block
itself after two hours. No daemon, no cron job, no "remember to
unblock".

---

## The honest limits (short list)

- Targets are resolved **once**, at command time — a snapshot of
  `/proc` (the subtree-aware policy still covers processes born later
  BENEATH a limited cgroup).
- **Reboot wipes everything** (bpffs pins + cgroup IDs re-assigned).
- A cgroup hierarchy deeper than 32 levels resolves unlimited.
- The ~3s verification probe needs an unsaturated link to prove its
  verdict; UNVERIFIED is honest, not a failure. `--no-test` skips it
  for scripts.
- `--all` sweeps **user apps** from `list-apps`; system targets stay
  behind `--force-this`.
- Rates below `1kb` and the dangerous-target blocklist both answer to
  the single override `--force-this`.
- Enforcement is Linux-only, cgroup-v2, and needs a supported eBPF
  host — `zelynic doctor` answers for your machine in one command.

---

## Where to read next

- [USAGE.md](USAGE.md) — the flagship reference: every flag, every
  error, JSON for scripting, exit codes, troubleshooting.
- [FAQ.md](FAQ.md) — the questions that keep coming back.
- [GLOSSARY.md](GLOSSARY.md) — the coined-term decoder.
- [SAFETY_ANALYSIS.md](SAFETY_ANALYSIS.md) — what zelynic does and
  does not touch.
- [PERFORMANCE.md](PERFORMANCE.md) — the measured overhead numbers.
- [SANDBOX.md](SANDBOX.md) — test limits in a micro-VM instead of on
  your host.
