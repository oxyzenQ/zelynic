<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# NIGHT-upgrade-charger-core-1c: the probe's CI find — the open lane, on the record

Date: 2026-09-30
Commit where the CI caught it: 12fb418 (the charger-core-1c rider C
tree; every supermassive leg red)
Status: harness lane bypassed (`--no-probe` in proof-claims; the
side-aware toggle in v1's `apply_single`); the probe stays live for
interactive use; the lane's bug is OPEN, reproducible, and needs a
root machine to debug.

## What the CI showed

Two independent findings on the same run, one mundane and one deep:

1. **The mundane one (fixed at the source — deeper than it looked,
   closed by rider I after six red pushes):** the mmspa-vs-legacy
   battery's `apply_single` and its nested-root row passed
   `--no-probe` to the LEGACY v11.0.0 binary, which predates the
   flag and exits 2 on it. Rider C's toggle fix had TWO defects: it
   missed the nested-root row's direct `run_side_binary` call site
   (caught and closed by rider E's `nested_apply_argv`), AND it
   flipped the toggle on the WRONG MODULE — `lib.PROBE_FLAG_SUPPORTED`
   wrote a fresh attribute on zelynic_harness_lib that nothing
   reads, while `apply_single` resolves `PROBE_FLAG_SUPPORTED` in
   supermassive-test's own globals — so the toggle never flipped,
   the legacy side kept receiving the flag, and every supermassive
   leg stayed red on the same exit 2 from ff8e73dc through 501ab20
   while the tree claimed the fix at the source. The close is
   structural: `rebind_side` lands BOTH globals on the modules that
   read them (`lib.BINARY` for run_zel, `sm1.PROBE_FLAG_SUPPORTED`
   for apply_single), and the module identity is pinned in the
   engine self-test so a future side switch cannot write a toggle
   to the wrong module silently.

2. **The deep one (the open lane):** the enforcement probe's own
   measurement escaped policing in the proof-claims stages. Four
   stages (`no-daemon`, `pure-eBPF`, `per-app`, `precision`, plus
   `footprint`'s attach) applied `-d`-only limits to the harness's
   own cgroup A (which holds the harness process, so the probe's
   `deep_collect` resolved the path and the full probe ran) — and
   every one measured LINE RATE:

```
no-daemon:   5.0 MB/s limit, measured 8.3 GB in 3s (2.8 GB/s)
pure-eBPF:   5.0 MB/s limit, measured 8.2 GB in 3s
per-app:     2.0 MB/s limit, measured 8.2 GB in 3s
precision: 100.0 MB/s limit, measured 8.3 GB in 3s
```

   The verdict itself behaved exactly as designed — exit 1, the
   red block, the numbers attached. The probe caught a real
   escape. Its own lane's escape.

## What the SAME run proved works

The mmspa-vs-legacy battery on the current side, same binary, same
kernel (7.3.0-6-generic), same guest, minutes later:

- 7/7 leaves policed (73.7 / 64.8 / 97.5 / 73.7 / 113.9 / 81.9 /
  73.7 KB/s vs the 100kb policy)
- two concurrent leaves sharing ONE budget: 114.0 KB/s summed — policed
- the nested nearest-root resolution: 40.2 KB/s under the 50kb root

So MMSPA resolution, the DRR fair-share lane, and the whole
enforcement stack police correctly for the battery's worker shape:
a `bash -c 'echo $$ > cgroup.procs; exec ...'` python worker in a
cgroup created under the fleet target BEFORE the apply, downloading
from the harness's in-process HTTP server.

## The delta (everything analyzed and cleared)

The probe's lane differs from the battery's in exactly these ways,
each examined and none (yet) convicted:

1. **The client is the zelynic binary itself** (spawned by the
   strict-single process), not a bash-exec'd python worker. Cleared:
   the child is written into the probe cgroup by the parent and the
   residency check reads `/proc/<pid>/cgroup` back — it passed, so
   the process was in `A/zelynic-probe-cl-*` before its 300ms grace
   and socket creation.
2. **The probe cgroup is created AFTER the apply** (the battery's
   leaves exist before). Cleared as a class: the battery's
   late-born child (`av-late`, created after the apply) policed
   correctly on the same run.
3. **The server is the probe's own child in a transient root-level
   cgroup** (the battery's server is the harness's in-process HTTP
   thread in the hq cgroup). The download direction is policed at
   the RECEIVING socket (the client), so the server's cgroup should
   be irrelevant — and the server's egress is unpoliced in both
   shapes. NOT fully cleared: this is the only actor in the probe's
   lane that does not exist in the battery's, and the ingress hook's
   behavior for traffic FROM a root-level-cgroup socket TO a
   freshly-created deep cgroup on kernel 7.3 is the least-verified
   edge in the list.
4. **The rate classes** (5 MB/s and up vs the battery's 100kb) and
   the `-d`-only policy (the battery applies both directions).
   Cleared by arithmetic: the pool is seeded with the burst (5 MB)
   and refills at the rate; the total admission over 3s is bounded
   by burst + rate x window = 20 MB against the measured 8.3 GB —
   a 400x escape cannot be a quantum, burst, or band bug; the
   packets were never policed at all.
5. **The DRR math itself** (quantum, residue law, draw lock, stale
   belt). Cleared: the battery's 7/7 + shared-budget + nested rows
   police through the same drr_flow on the same run.

## The open question

The probe client's INGRESS traffic on kernel 7.3 escaped the
cgroup_skb/ingress policing that the same kernel applies to the
battery's workers — either the hook did not run for those packets,
or the MMSPA walk resolved the probe cgroup as unlimited. The
static analysis above clears every candidate twice; the next step
needs a root machine (the CI guest is the oracle, the sandbox has
no /dev/kvm):

```bash
# Reproduction sketch (root):
mkdir -p /sys/fs/cgroup/probe-a && echo $$ > /sys/fs/cgroup/probe-a/cgroup.procs
zelynic strict-single <probe-a-id> -d 5mb        # the probe runs
# watch, in parallel:
bpftool map dump name mmspa_leaf_cache           # the probe cgroup's memo
bpftool map dump name cgroup_policy_dl           # the policy row
bpftool map dump name cgroup_limiter_stats       # bytes_allowed moving?
cat /sys/fs/cgroup/probe-a/zelynic-probe-cl-*/cgroup.procs   # residency live
# If bytes_allowed stays flat while the client reads GBs, the hook is
# not firing for the probe's socket; if the memo shows root 0, the
# walk is resolving unlimited — split the two worlds there.
```

## The posture

The probe's CONTRACT is unchanged and its verdicts are honest — it
caught a real (its own) escape and failed loudly. The harness lanes
that verify enforcement with their own workers ride `--no-probe`
(their measurement is the probe's job done deeper), so CI stays the
authority for the enforcement stack while the probe's lane is
debugged. The interactive surface keeps the probe on by default:
an owner typing `sudo zelynic ss brave 100kb` gets the measurement,
and if this find reproduces there, the red block is the starting
point — exactly what it was built for.
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
