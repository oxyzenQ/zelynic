<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-improve-50 decision audit — is an extreme-mode supermassive test needed at 1000 / 1 million / 1 trillion cgroups?

> Audit date: 2026-10-07 (NIGHT-improve-50). Scope: the owner's
> verbatim intent — "depth audit to create a new supermassive test
> extreme mode e.g the default normal usage supermassive test using
> 64 cgroup to test, but on extreme mode can have cgroup 1000, 1
> milion, even 1 trilion/near limit kernel. this needed? if not
> skip. need approval from owner." Method: the product's own cap
> map read from source (which surface even SEES a cgroup count),
> the fleet's construction cost measured from the harness's own
> shapes (one mkdir + one `sleep 600` fork per member), the VM
> envelope from the workflow's own sizing rules, and the physics
> arithmetic for each candidate scale. Audited at 325585b (v20
> tree, task-1 pushed). Status: DECISION DOCUMENT ONLY — the
> recommendation below is presented for owner approval; nothing
> is implemented by this task ("need approval from owner" is the
> task's own gate).

## 1. The question, decomposed

"Extreme mode" is three different proposals wearing one number,
and they fail differently:

1. **1000 cgroups** — 15.6x the current fleet, still under every
   cap the product carries.
2. **1 million / 1 trillion** — past every cap AND past the
   kernel's own nameable space.
3. **"near limit kernel"** — the honest reading: whatever scale
   actually stresses the system's real boundaries.

The audit's job: find where zelynic's behavior CHANGES with
cgroup count, and test there — or conclude the change-point is
already covered and skip.

## 2. The cap map — what each surface actually sees

Read from source, the surfaces that scale with cgroup count:

| surface | cap | behavior at/past the cap | live-pinned in CI today? |
|---|---|---|---|
| `list-apps` census | none (the /proc + cgroupfs walk) | counts every LIVE cgroup on the host | yes, at 64 (the dense fleet stage) |
| observer counter maps (dl/ul) | LRU 4096 | live-with-traffic always counted; idle entries age out; eviction-restart reads as fresh bytes (the half-space discriminator) | NO — 64 < 4096, never crossed |
| socket cookie maps | LRU 4096 | same LRU lane | no |
| userspace leaderboard | 4096 (live since NIGHT-mitigate-1) | dead rows retire, fresh cgroups board | no (six unit pins carry the contract) |
| policy / bucket / stats / window / rate-ring maps | HashMap 1024 | the apply's `map.insert` errors propagate — the 1025th policy leg is refused, the atomic rollback owns the partial state | no (construction-verified, never crossed live) |
| strict-multi argv | MAX_ARG_STRLEN 128 KB per arg | ~4100 ids ≈ 29 KB — fine; ~16k ids ≈ 114 KB — the edge | no (64 ids ≈ 450 B today) |
| the datapath itself | none | allow-and-skip: a full map loses the COUNT, never the packet — enforcement is count-insensitive by design | n/a |

The decisive row: **the product's behavior-changing points are
1024 (policy) and 4096 (observer/leaderboard) — NOT a million,
NOT a trillion.** Past 4096 live-with-traffic cgroups, every
further cgroup exercises the SAME three mechanisms (LRU aging,
allow-and-skip, retirement) with zero new semantics: the curve
is flat by construction. An extreme mode above ~5000 live
cgroups tests the HOST's cgroupfs scalability, not zelynic.

## 3. The physics, scale by scale

**1000 cgroups (1000 sleepers):** ~1-2 MB of cgroup structs +
kernfs nodes; ~60-100 MB of task memory (task_struct + 16 KB
kernel stack + minimal userspace per `sleep`); setup ~5-10 s of
mkdir + fork. Fits BOTH VM profiles (low = 1/8 of runner RAM
floored at 1024 MB, best = 3/4). Verdict: cheap, and proves
exactly what the 64-fleet proves — the density walk, the census,
one strict-multi write — 15.6 times more. No new semantics. A
soak, not a test.

**1 million:** the sleepers are the wall — ~60+ GB of task
memory at ~60 KB each (the best-specs VM carries 3/4 of the
runner's RAM: ~12 GB; the largest GitHub runner family is
~16 GB). Without sleepers, 1M EMPTY cgroups prove only that
cgroupfs can hold a million directories — a kernel fact
zelynic never observes: an empty cgroup has no processes (the
census never sees it), no traffic (the observer maps never see
it), no policy (the limiter never sees it). The harness's own
mkdir loop alone runs ~30-60 s; a million `sleep` forks at
~1-2 ms each run 17-33 minutes before the OOM. Verdict: not
creatable, and not product-visible even if created.

**1 trillion / "near limit kernel":** the kernel cannot NAME a
trillion cgroups — the kernfs id is a u32 (4.29e9 ids total;
`ebpf/src/stats.rs` documents the same arithmetic for the
cgroup-id map key: "a real host cannot live through the ~4
billion cgroup lifetimes a 2^32 wrap-around would take"). 1e12
is 233x past the entire id space; the structs alone (~500 B
each) would want ~500 GB of kernel memory. "Near the kernel's
limit" for cgroups is MEMORY-bound and id-space-bound, both
orders below a trillion on any deployed machine. Verdict:
physically impossible, meaningless as a test target. The
honest "near limit" is where the PRODUCT's own limits live —
1024 and 4096.

## 4. What the current 64-fleet already covers, and the one hole

The v1 server phase's dense-fleet stage (stage 2) pins: the
census of every member via `list-apps --print-json`, ONE
strict-multi write policing all 64 at once (status JSON
verifying every row), a measured download under the shared
bucket with the kernel-side drop proof, and the zero-residue
teardown. At 64 this proves the walk, the write, the read, and
the cleanup — none of the caps.

The one CI-unproven region is the band BETWEEN 1024 and 4096+
live cgroups, where three documented mechanisms engage for the
first time:

1. the policy family's 1024 ceiling — the apply's refusal
   shape past the 1025th leg (insert error propagation, the
   atomic rollback's partial-state ownership);
2. the observer LRU's eviction-restart cycle — a cgroup
   evicted cold and returning with traffic reads its fresh
   bytes (the half-space discriminator — unit-pinned in the
   wrap pins, never crossed live);
3. the leaderboard's cap + retirement (tonight's
   NIGHT-mitigate-1 — six unit pins, never crossed live).

The honest boundary: a LIVE eviction proof requires the
eagle-eyes TUI asserting footer figures under churn inside a
CI job — v2 kills TUIs mid-render, it does not read them; the
fragility of scraping a live TUI's footer from a serial console
is exactly the class of flake the busy-hour residual already
documents. The discriminator and the retirement carry unit
pins instead — that trade is already made and standing.

## 5. The recommendation

**SKIP the extreme mode as proposed.** The 1M and 1T shapes are
physically impossible and product-invisible; the 1000 shape is
a 15.6x soak of already-proven semantics. The default
64-cgroup fleet plus the unit pins is the honest coverage for
everything the owner named.

**The one candidate worth owner approval** (named, costed, NOT
implemented): a single cap-crossing density stage on the
existing v1 server phase — ~4100 live cgroups with resident
sleepers (one mkdir + one `sleep 600` each), asserting the
census integrity at 4100 JSON rows, the ~29 KB strict-multi
argv shape, the status JSON's integrity across 4100 cgroup
ids, and the policy family's 1024 ceiling refusal (the apply
past 1024 targets must fail CLEAN — the refusal itself is the
pin, not a workaround). Cost: ~15-25 s of fleet construction,
~250-350 MB of task memory (fits both VM profiles — the low
leg floors at 1024 MB with ~800 MB of documented slack),
~60-80 s stage runtime total inside the existing 1500-2100 s
vm_timeout. The eviction/restart/retirement semantics stay
unit-pinned (section 4's honest boundary).

If the owner wants the live-eviction proof too, that is a
separate, explicitly-flake-prone lane (a TUI assertion under
churn) — recommended against, but nameable.

## 6. The answer to "this needed?"

No — not as proposed. The default fleet plus tonight's unit
pins already carry every semantics the named scales can
exercise; the only real extreme is the product's own 1024/4096
caps, and IF the owner wants that band crossed live, the
cap-crossing stage above is the minimal honest shape, awaiting
approval here.
