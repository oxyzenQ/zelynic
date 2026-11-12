<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# The per-tenant design — SHELVED

> **Status: shelved, not rejected.** This design is technically
> complete and measured (night-frontier-3C Phase 1, 2026-11-12).
> It is NOT scheduled for implementation.
>
> **Why shelved:**
>
> - zelynic entered maintenance mode at v80.0.0. New policy
>   primitives (a host-wide envelope, a tenant registry, a new
>   grammar verb) are out of scope for maintenance mode's
>   "stability, compatibility, performance, bug fixes" contract.
> - The origin use case (per-app rate limiting on a desktop) does
>   not need it. The buyer personas exercised in the 2026-11
>   simulation (SRE limiting a runaway service, sysadmin forensic
>   work) do not need it.
> - The market that DOES need hierarchical fair-share (managed
>   hosting, SaaS platforms) has better tools at their layer
>   (systemd slices + tc HTB at the qdisc, cloud provider egress
>   controls, Kubernetes bandwidth managers). A per-app eBPF
>   limiter is not the right tool for fleet bandwidth arbitration.
> - The implementation cost (new map family, Policy row growth,
>   schema v35, 8 failure modes, 3-5 day sprint) is disproportionate
>   to a use case the owner does not personally have.
>
> **When this design gets unshelved:**
>
> 1. A user with a real workload asks for it (not a hypothetical).
> 2. The kernel ships a BPF-native hierarchical scheduling
>    primitive (§8 reversal trigger 1).
> 3. The project exits maintenance mode for any reason.
>
> Until then: the design exists, the math is proven, the harness
> is spec'd, and the implementation is one "design approved" away.
> The dragon knows how. The dragon chooses not to.
>
> The Phase 1 evidence (premise audit, math, failure modes,
> reversal triggers) is preserved below for the future maintainer.

---

## The per-tenant design — hierarchical fair-share across cgroup roots

> night-frontier-3C. The design document the owner reads before any
> code exists — Phase 1 of a sprint whose only Phase 1 deliverable
> is this file. One paragraph first: today, MMSPA resolves a packet
> to its policy root and DRR fair-shares that root's pool across its
> leaves; but two DIFFERENT roots' pools never interact, so
> "tenant A gets 50%, tenant B gets 50%" has no layer to live in.
> This design adds that layer as a second bracket law one level
> above the DRR ledger: an optional host-wide envelope (per
> direction) that declared tenants fair-share, each tenant's
> aggregate bound riding the resolved policy row the datapath
> already holds. Zero new walks, zero new helpers, zero change to
> the unlimited fast path, zero change to the pool conservation
> law; schema v34 becomes v35 additively, under the standing
> one-time-reload contract. This is v81.0.0 material by owner
> directive — no version, tag, or release surface is touched by
> this design.

## 0. The premise audit (Phase 0 — what exists, what is missing)

Everything below was read from this tree at HEAD (`9b0567e`,
schema v34, v80.2.0) — no assumption rode in from any sibling
project, the NIGHT-CORE-1 posture.

What exists, one law each:

- **MMSPA** (`ebpf/src/mmspa.rs`, `mmspa_resolve.rs`): the ascending
  ancestor walk (absolute levels `0..32`, break at 0) resolves a
  socket's leaf cgroup to the NEAREST policy root; the per-leaf memo
  (LRU 4096 per direction, packed `(generation << 32) | root`) keeps
  the steady state at one lookup per packet, and the generation belt
  (the `mmspa_generation` Array word every mutation bumps after its
  writes land) makes every stale memo self-invalidating. Root `0` is
  the unlimited sentinel; kernfs ids start at 1.
- **DRR** (`ebpf/src/drr.rs` family, `drr_flow.rs`): the pool (the
  resolved root's own bucket, refilled at the policy rate through
  the exact `refill_window`) feeds per-leaf buckets (LRU 4096 per
  direction) that spend only quanta they DREW — the take is the
  residue law (at most half the pool) further capped by the
  learned-share split (`pool / (drawees + 2)`, the drawee count kept
  per pool in a packed u64 word) and bounded by the epoch ledger's
  carry (allowance = per-epoch refill / drawee PEAK, stockpile = one
  quantum). The guarantee bracket (schema v24, `drr_guarantee.rs`)
  clamps the allowance between floor and ceiling per leaf: the floor
  is a PRIORITY, not a reservation; the ceiling binds even a lone
  drawer; on a contradiction the ceiling wins; over-subscribed
  floors degrade to the pool law. The stale-quantum belt zeroes a
  leaf whose generation stamp no longer matches.
- **The enforcement math** (`ebpf/src/math.rs`): `Policy` is 40
  bytes (`rate_bps`, `burst_bytes`, `floor_bps`, `ceil_bps`,
  `group_id`, `flags`), the bucket is 24 bytes, the stats row 72;
  enforcement is the SMP-safe CAS family (window-ownership refill,
  sufficiency-verified consume with the bounded retry);
  `MAX_ENFORCABLE_BURST` keeps every product provably inside u64.
- **The verdict path** (`ebpf/src/enforce.rs`): per packet — leaf
  cgroup id, direct policy hit, else the memoized walk; then the
  window gate, the watchdog, the block verdict, the RECWN/pacing
  primes, and the three lanes: per-socket (`POLICY_FLAG_PER_SOCKET`),
  group (`group_id != 0`, one shared bucket, FCFS by documented
  scope), and the DRR lane (`group_id == 0`, pool -> leaf -> CAKE
  flow). The ECN rescue and the rate ring book every verdict at the
  resolved root.
- **The userspace write path** (`src/ebpf/limiter/policy_write.rs`):
  `write_policies_for_cgroup` builds the `PolicyRaw` row, writes it
  direction-scoped, and records the transactional rollback snapshot
  (`PolicyMutation`) plus the superseded-group capture. Persistence
  IS the pin: every map is PIN_BY_NAME under `/sys/fs/bpf/zelynic`
  and survives process exit — there is no second state store.
- **The grammar** (`src/commands/target_grammar.rs`): the target
  prefixes are `cg:`, `docker://`, `k8s://`, `netns://`, `iface://`
  (single-colon or URI); `::` anywhere in a target is the LIST
  separator (the group lane) — the one byte sequence that can never
  collide with the prefixes, and therefore the one a new grammar
  must also never collide with.
- **The root-cgroup guard** (`src/commands/safety.rs`,
  `check_dangerous_cgroup_id`): the cgroupfs root POSITION is
  checked before any member walk (NIGHT-hunt-Z3) — the id whose
  row would match every socket on the machine refuses, exactly the
  guard a tenant layer must inherit.
- **The CO-RE posture** (`docs/audits/NIGHT_CORE_1_...md`): the two
  shipped objects carry zero relocations because the datapath is
  helper-mediated everywhere; a design that adds a kernel-internal
  struct deref would be the first to need CO-RE, and this one adds
  none (map reads and the already-fetched `bpf_ktime_get_ns` only).

What is missing — the gap this design fills: **no layer bounds the
AGGREGATE of several roots against one shared budget.** Each root's
pool refills at its own rate, forever independent; the group lane
shares one bucket across enumerated members but is FCFS with no
fairness law and no brackets. The premise's four questions, answered
here so the next auditor starts from the verdicts:

1. **Does a "tenant" map to a cgroup root, a path prefix, or a UID?**
   To a named set of POLICY ROOTS. The kernel's own attribution is
   the chain the datapath already walks: `bpf_skb_cgroup_id` names
   the socket's leaf, the ancestor walk names the chain, the resolved
   root is the budget owner. A tenant that rode a UID would need an
   attribution the cgroup_skb hooks do not carry per packet; a
   tenant that rode a path prefix would be a cgroup root one level
   up — the root IS the prefix's anchor, so the named set of roots
   is the strictly more general form. Riding the resolved root costs
   the hot path nothing: the policy row is already in hand when the
   tenant identity is needed.
2. **What is the guarantee?** A weighted share of an optional
   host-wide ENVELOPE (one parent budget per direction), realized as
   a per-tenant floor (a priority, never a reservation — the v24 law
   verbatim one level up), a per-tenant ceiling (binds even when the
   tenant is the only active one), and the envelope's fair split as
   the default. v1 splits the envelope EQUALLY across active tenants
   (the weighted-split law is named in section 9 with the packing
   arithmetic that blocks it today); a tenant's floor approximates
   weight priority in the meantime.
3. **How does the tenant layer enter the MMSPA walk?** It does not.
   The tenant id rides the RESOLVED policy row (a new field, schema
   v35) — the walk, the memo, the generation belt, and the unlimited
   fast path are byte-identical to today. The tenant bound is
   consulted only on the policed DRR lane, only when an envelope
   exists, only when the row carries a tenant.
4. **How does the tenant layer interact with DRR — a second pool
   above the first, or a hierarchical parent?** It is a BRACKET
   ABOVE THE LEDGER: the tenant allowance joins the take's existing
   min-chain (residue law, learned split, leaf room, and now tenant
   room), and the take spends a tenant-granularity carry ledger with
   the same packing, the same CAS discipline, and the same
   fail-open posture. The full comparison — and why "pool above the
   pool" loses — is section 5.

## 1. Definition — what a tenant is, and the grammar

A **tenant** is a named, administratively declared set of policy
roots whose aggregate traffic shares one envelope-derived budget.
The tenant is NOT a cgroup, NOT a target, and owns no sockets —
it is metadata on policy rows plus one class row per tenant.

The grammar pick: **the `--tenant <name>` flag on the strict verb**,
per the owner's first candidate form:

```text
zelynic strict --tenant web cg:1234 50mb
zelynic strict --tenant web docker://nginx 50mb        # container targets compose
zelynic strict --tenant web brave::curl::steam 50mb    # the :: list lane composes
zelynic tenant web --floor 20mb --ceil 400mb           # the class brackets (optional)
zelynic tenant envelope 1gbit                          # the parent budget (--download/--upload spellings; bare = both)
zelynic tenant remove web                              # strip membership transactionally, delete the class
zelynic tenant list                                    # the census
```

Why the flag and not the `tenant://<name>::<target>` URI form:

- **The `::` collision is fatal, not cosmetic.** `target_is_list`
  routes on one substring test: `::` anywhere means the group lane.
  `tenant://web::cg:1234` is today a two-member LIST whose first
  member is the garbage string `tenant://web` — the exact class of
  mistake blade-18 closed (empty/garbage members silently dropped)
  and improve-53 re-closed (the separator law). Every grammar rung
  would need a carve-out for one new prefix.
- **A tenant is not a traffic target.** Every existing URI names
  something the kernel resolves to sockets (a cgroup id, a
  container, a namespace, an interface). A tenant names no socket —
  the datapath never resolves it — so it belongs in the metadata
  position (a flag), not the target position (a URI).
- **The flag composes with every existing target grammar and both
  lanes** — a multi-member strict can join one tenant wholesale,
  and no existing parse, validation, or pin changes.

The name grammar, validated at parse and pinned rootlessly: 1..32
bytes, ASCII alphanumeric plus `-` and `_`; `:` and `/` are refused
(the prefix grammar's own bytes), `::` is refused by the same law
(the list separator), a name that parses as a bare number is
refused (the `cg:` numeric door's confusion class). The name is
case-sensitive (no case-folding machinery exists in the CLI).

Tenant identity in the kernel is a u32 id derived from the name by
a stable userspace hash (FNV-1a 32 over the name bytes); id `0` is
the "no tenant" sentinel (kernfs-style, one family with root `0`
and `group_id` 0), a hash that lands on 0 is salted once and named.
A collision between two distinct names is a NAMED write-time error
("tenant id collision — pick another name") checked against the
class map's name bytes — never a silent merge. The kernel never
sees names; the class row carries them for the status join.

## 2. The math — the hierarchical scheduling law

The layer is a second epoch ledger one level above the leaf ledger.
The envelope is a DECLARATION, not a bucket: the tenant allowances
are virtual, self-earning budgets exactly the way the leaf ledger's
allowance is — nothing strands, nothing needs a refill cascade.

The laws, in order (every one is an existing pinned law, one level
up, or a one-line composition of two):

```text
envelope_epoch_refill = envelope_bps / 10
    // epoch_refill's own shape (DRR_WINDOW_MS = 100); envelope_bps = 0
    // means the lane is OFF — no envelope, no tenant law, today.

fair_split(T) = envelope_epoch_refill / max(active_peak, 1)
    // active_peak = the tenant-granularity drawee PEAK — the same
    // packed share word drr.rs keeps for pools (last/running/peak/
    // epoch, u12 fields, PEAK_DECAY_EPOCHS decay), counting ACTIVE
    // tenants instead of leaves. A peak < 2 (a lone tenant, a cold
    // envelope) keeps the whole envelope — epoch_allowance's
    // lone-drawer row, verbatim.

floor_refill(T)  = epoch_refill(min(T.floor_bps, envelope_bps))   // 0 = unset, skips
ceil_refill(T)   = epoch_refill(min(T.ceil_bps,  envelope_bps))   // 0 = unset, skips

tenant_allowance(T) = guaranteed_allowance(fair_split_rate(T), T.floor, T.ceil, active_peak)
    // the v24 bracket law verbatim one level up: the floor RAISES
    // the earn rate, the ceiling LOWERS it, an unset side skips,
    // and on a floor-above-ceil contradiction the CEILING WINS.
    // Both bracket sides clamp against the envelope (a bracket above
    // the parent budget is arithmetic noise, the law-side clamp's
    // own reasoning).

tenant_quantum(T) = quantum of the tenant's own split, floored at the
                    GSO admit floor (65_536)
    // guaranteed_stockpile's law one level up: a set ceiling
    // tightens the banking cap to the ceiling's quantum; no ceiling
    // keeps the fair split's quantum. The GSO floor is load-bearing
    // HERE TOO: a leaf waiting to admit a 64 KiB super-packet needs
    // a draw that big, so a tenant whose room fell below one admit
    // would bar its own leaves forever — the carry form's banking
    // (below) is the close, exactly as it is one level down.

tenant_room(T) = ledger_room(tenant_word(T), now_epoch,
                             tenant_allowance(T), tenant_quantum(T))
    // the epoch ledger's carry form verbatim: the banked carry plus
    // the elapsed epochs earned at the allowance, capped at the
    // quantum, the elapsed multiply bounded by ELAPSED_CEILING so
    // no saturating_mul ever enters the BPF ISA.

take = min( take_size(quantum(pol), pool, learned_leaf, leaf_allowance, leaf_room),
            tenant_room(T) )
    // THE ONE-LINE LAW the whole design exists for: the existing
    // v17/v24 take chain, further bounded by the tenant's banked
    // room. The bound only enters the chain when an envelope is
    // active AND the resolved row carries a tenant; otherwise the
    // chain is bit-identical to today.

spend: the take debits the tenant carry through one CAS pair (the
       ledger_note form), the same two-attempt posture the leaf
       ledger spends with; a lost race leaves the spend unrecorded —
       bounded by the take, tenant-local, the safe direction, the
       same documented honesty the leaf ledger's own lost race
       carries.
```

The conservation and fairness properties, stated so the harness can
hold them:

- **The pool law is untouched.** A pool still refills at its own
  policy rate and never hands out what it does not have; the tenant
  bound can only REFUSE a draw the pool law would have allowed, can
  never create budget. Aggregate conservation at every level.
- **The envelope split is conserved up to the learned estimate's
  slack.** The active tenants' allowances sum to
  `envelope_epoch_refill x K / peak` — with the peak divisor the
  same repair-4 logic that stops a starved leaf's silence from
  inflating the survivors: a tenant whose leaves all back off stops
  asking, its PEAK slot decays on the standing cadence, and its
  share releases within ~8 x PEAK_DECAY_EPOCHS epochs.
- **The over-subscription law.** When the declared floors sum above
  the envelope's refill, the floors degrade to the pool law exactly
  as drr_guarantee documents one level down: the envelope never
  hands out what it does not have, late-epoch tenant draws find an
  empty carry and fail (the safe verdict — and the ECN rescue still
  sees the drop, whichever bound caused it), and the distribution
  settles between the fair split and the floors. Degradation is a
  decision, not drift; the harness reports it.
- **The degenerate envelopes.** `envelope_bps <` the members'
  policy rates: the envelope binds first (the parent cap is the
  point). `envelope_bps >` their sum: the policies bind first and
  the envelope is inert — no invented headroom, the honest posture.
- **The trickle inheritance.** Below ~640 KB/s the admit floor
  dominates the window's share one level down; the tenant level
  inherits the same coarseness (tenants alternate on quantum
  boundaries instead of never at all) — the same documented
  tradeoff, now at both levels, pinned so it stays a decision.

The fairness consequence in one sentence: **within a tenant, DRR
shares the tenant's member pools' budget across leaves as it does
today; across tenants, the envelope's split bounds each tenant's
aggregate so ten eager tenants on one envelope deliver ~10% each
(within the learned-share bounds — the battery's 1.75x-fair +
one-quantum worst-leaf law, and the harness's own tighter bar:
any tenant under 50% of its share while another hogs is a design
failure, per the owner's Phase 4 rule).**

## 3. The state — new BPF maps, layouts, schema v35

Schema v34 -> v35, additive and version-gated, under the standing
one-time-reload contract (a pinned v34 object lacks every row this
design needs; the forced reload wipes the pins once, re-apply after
upgrade — the same contract as every bump before it). Three new map
families and one grown row:

| map | type / cap | key | value | readers |
|-----|-----------|-----|-------|---------|
| `tenant_class` | HashMap, 256, pinned | tenant_id u32 | `TenantClass`, 48 B | both hooks (read), userspace (read/write) |
| `envelope_rate_dl` / `envelope_rate_ul` | Array, 1, pinned | — | u64 BPs, 0 = off | one hook each (read), userspace (write) |
| `tenant_state_dl` / `tenant_state_ul` | LruHashMap, 4096, pinned | `(generation << 32) \| tenant_id` | `TenantState`, 16 B | one hook each (read/write), datapath-internal |

`TenantClass` (48 bytes, the userspace mirror in the layout
contract):

```text
name        [u8; 32]   // NUL-padded; the status join's label; the
                       // kernel never parses it
floor_bps   u64        // 0 = unset (the bracket's own sentinel)
ceil_bps    u64        // 0 = unset
```

`TenantState` (16 bytes, two words the drr family already owns the
laws for):

```text
ledger  u64   // carry:32 | epoch:32 — the ledger_pack form verbatim
share   u64   // last:12 | running:12 | peak:12 | epoch:28 — the
              // pool_share packing verbatim, counting TENANTS
```

The policy row grows 40 -> 48 bytes: `tenant_id: u32` inserts at
offset 32, `group_id` moves to 36, `flags` to 40 — the v24 growth
is the exact precedent (bracket bytes inserted between the burst and
the tail pair, offset pins moved, size pin updated on both trees,
the one-time reload wiping no readable state). The 1024-entry policy
maps keep their cap; the row census does not grow.

Capacity honesty: `tenant_class` at 256 is the group map's own
census posture — tenants are administrative objects a human declares
(sections 6 and 9 hold the saturation behavior); `tenant_state` at
4096 x direction is the leaf-state posture (occupancy bounded by
active tenants per generation, stale entries age out through the
LRU on every generation bump). The registry persistence IS the pin:
names, brackets, and envelope rates survive process exit in the
pinned maps — no second state store, the policy maps' own law.

Rootless pins (the same discipline every layout in this repo
carries): the size/offset asserts for `TenantClass`, `TenantState`,
and the grown `Policy` on both trees; round-trip pack/unpack pins
for the tenant ledger and share words; the law pins for the new
compositions (the envelope split, the bracket one level up, the
take-chain min, the banking cap, the over-subscription degradation)
in the drr test family's own files.

## 4. The interaction with MMSPA

**Zero new walks.** The tenant identity is read from the resolved
policy row — the row `try_enforce` already holds after the direct
hit or the memoized walk. The walk's loop body, the memo's packing,
the generation belt, the direction-scoping, and the unlimited fast
path (leaf lookup + memo lookup, NIGHT-lts-2) are byte-identical to
today: a packet with no policy never learns tenants exist.

The tenant state rides the generation belt it inherits: the state
key is `(generation << 32) | tenant_id`, and every policy mutation
AND every tenant mutation (`tenant remove`, bracket edits, envelope
edits) bumps the same `mmspa_generation` word after its writes land
— the ordering proof in mmspa.rs's header covers the tenant rows
unchanged, because they are stamped and matched under the same
counter. A stale tenant carry (a budget the mutation retired) can
never be spent: its key no longer matches, and the LRU retires the
orphaned row lazily — the drr_pool_state posture, one lane over.

The `--during` window gate composes honestly: a policy whose window
is INACTIVE answers ALLOW before any lane runs, so its takes never
spend the tenant ledger — an inactive member simply stops drawing,
the same miss shape the gate documents today; the envelope's other
tenants are untouched.

## 5. The interaction with DRR — the two options and the pick

**Option A — the bracket above the ledger (the pick).** The tenant
allowance joins the take's existing min-chain; the take spends a
tenant-granularity carry ledger. The hot path pays one Array read
(envelope rate) and one LRU lookup + CAS pair (tenant state) per
DRR-lane packet, only while an envelope is active. The pool refill,
the leaf ledger, the flow lane, the ECN budget keys, and the ring
are untouched — the tenant bound composes as one more `min` arm.

**Option B — a pool above the pools (rejected).** A tenant-level
token bucket that each member pool's refill draws from before
crediting. Drawn honestly, it fails on four counts:

1. **Two-level refill ownership.** The window-ownership CAS is the
   refill's correctness core; cascading it (own the pool window
   only after drawing the tenant window) doubles the CAS chains in
   the hottest loop the datapath runs and creates a partial-credit
   state (pool window won, tenant draw lost) the current arithmetic
   has no verdict for.
2. **Stranding.** Tokens that leave the tenant bucket into a pool
   the tenant's leaves never draw sit there — there is no return
   path, and a churned root strands its share until the generation
   belt retires it. The carry form never moves budget anywhere: it
   earns where it is spent.
3. **Burst semantics drift.** A pool pre-loaded with tenant tokens
   banks them at the pool level, multiplying the stockpile bound
   the leaf law carefully caps at one quantum.
4. **The fairness consequence is worse, not better.** Refill-side
   sharing distributes CAPACITY; take-side sharing distributes
   DELIVERY. The guarantee the owner names (measured per-tenant
   delivery near the fair split) is a delivery property — bounding
   refills bounds only what pools MAY hold, and leaves that draw
   lazily still deliver unevenly.

Option A's own fairness consequence, stated plainly: the tenant
bound is statistical at the same confidence the leaf bound is (the
learned-share battery's bounds — worst drawer within 1.75x fair
plus one quantum, quietest within fair/4 — transferred one level
up); the live harness (Phase 4) is the proof, and its 50% starvation
bar is the acceptance rule.

## 6. The failure modes

Each mode, with the behavior and the law that produces it:

- **A tenant with no live policies (empty tenant).** The class row
  exists; no policy row carries its id; no ledger row is ever
  created; the envelope's split ignores it (the active PEAK counts
  tenants that DRAW, not tenants that are declared — the
  priority-not-reservation law's own reasoning: an absent tenant
  costs nothing, earns nothing). `tenant list` shows it honestly
  with zero counters.
- **A tenant deleted while its policies are active.** `tenant
  remove` walks the member census (the userspace knows the members
  from the policy rows it can scan for the id), strips `tenant_id`
  from every member row transactionally (the rollback ledger's
  own machinery), deletes the class row, and bumps the generation
  AFTER the writes land — the belt retires every stale ledger row
  and every stale memo in one word, the standing proof. A packet
  in flight rides the fail-open posture: its row's post-mutation
  read says no tenant, the take chain runs today's shape.
- **A new leaf spawns under a tenant mid-session.** Nothing to do.
  The leaf's first packet misses the memo, the walk resolves the
  same root, the root's row carries the tenant id, and the leaf
  draws bounded by the tenant ledger that already exists. The memo
  rewrite stamps the current generation — zero new state, zero new
  code paths.
- **A tenant's member root is the cgroupfs root (`cg:1`).**
  Refused before the tenant registry is ever consulted — the
  existing position guard (`check_dangerous_cgroup_id`,
  NIGHT-hunt-Z3) already refuses the root-catch-all on every apply
  path a `--tenant` strict rides. The envelope declaration never
  targets a cgroup, so it cannot trip the guard; a tenant can
  therefore never contain the one row that would match every
  socket on the machine.
- **The envelope unset while tenants are declared.** The tenant
  lane is OFF (envelope rate 0 = the lane's own sentinel): class
  rows are inert labels, no ledger rows, no bounds — today's
  behavior exactly. `status` says so in words, not silence.
- **A tenant id collision (two names, one hash).** A named write
  error at `--tenant` time (section 1), checked against the class
  map's name bytes — the registry is the pin, the check is the
  pin's own read.
- **`--tenant` combined with `--per-socket`.** Rejected at write
  time as an incoherent pair: the per-socket lane multiplies the
  rate across concurrent sockets by documented contract, which is
  exactly the aggregate the tenant law exists to bound. The refusal
  names both laws. (A future design that bounds socket takes by the
  tenant room is a named extension, not this one.)
- **`--tenant` combined with a group id.** Rejected the same way:
  the group lane is one shared bucket across enumerated members
  (FCFS by documented scope); a tenant bracket on top of a group
  bucket would bound a budget the group's own apply already
  enumerated. One lane per row, the apply validates.

## 7. The bounds

- **The 32-level MMSPA depth bound is untouched** — the tenant
  layer adds no walk, so no new depth constant exists. A socket
  deeper than 32 levels resolves unlimited exactly as documented
  (USAGE.md's honest limitation), tenant or not.
- **Map caps.** The design adds: 256 x 1 (`tenant_class`), 1 x 2
  (the envelope words), 4096 x 2 (`tenant_state`) — every one under
  an existing cap philosophy (the group map's 256, the leaf-state
  family's 4096). The 1024 policy cap, the 4096 leaf/memo caps, the
  2048 histogram caps: unchanged. Total new pinned memory at the
  caps: `256 x 48 + 2 x 8 + 2 x 4096 x 16` = 144 KiB — two orders
  under the existing families' footprint.
- **The policy row grows 40 -> 48 bytes** with the offset moves the
  size pins carry on both trees; the v24 precedent is the contract
  for the one-time reload and the pin updates.
- **The kernel floor stays 5.13+.** The design adds zero helper
  calls: the envelope reads are Array map reads, the tenant state
  is LRU map reads plus the CAS family the ISA already carries
  (BPF_ATOMIC fetch/CMPXCHG, 5.12+), and the clock is the
  `bpf_ktime_get_ns` fetch the policed path already made. The
  NIGHT-CORE-1 verdict is unaffected: zero new kernel-internal
  derefs, zero new relocations.
- **The hot-path cost ledger** (the NIGHT-lts-2 law's own books):
  the unlimited fast path pays nothing new (the envelope lives
  behind the policy hit); a policed packet on a tenant-free host
  pays one u32 field read (`tenant_id == 0` from the row already in
  hand); a policed DRR-lane packet under an active envelope pays
  one Array read + one LRU lookup + one CAS pair — the cost class
  the leaf ledger already added (repair-3) and the CI lanes
  measured.
- **The u12 share fields cap at 4095** — the tenant count ceiling
  is the same saturating law the leaf side carries; 4095
  concurrently active tenants is three orders past any
  administrative reality, and the saturation is graceful (the
  divisor stops growing, the split stops shrinking — the same
  posture as the leaf side).

## 8. The trigger that would reverse this design

The facts that would make this design wrong, named so the next
auditor has the check:

1. **A BPF-native hierarchical scheduling primitive.** A future
   kernel map type or helper that implements hierarchical token
   buckets or fair queuing in-kernel (a cgroup-granularity shaping
   primitive attachable from `cgroup_skb` without tc) makes the
   tenant ledger redundant — the envelope law should migrate to it.
   The architecture's no-tc law stays; the ledger was only ever the
   strongest shape the verifier's straight-line budget admits, the
   same honesty drr.rs documents.
2. **A helper that names tenant-relevant identity per packet
   cheaper than the resolved row** (for example a cgroup-relative
   level helper or a cheaper ancestor read): the tenant id riding
   the policy row is optimal at zero extra lookups; any change that
   makes row reads non-free reopens the identity decision.
3. **A research result proving a better online fair share without
   iteration** — the learned-share bounds are statistical
   (1.75x-fair + one quantum worst case, transferable one level
   up); a scheduling result that tightens the bound at equal
   verifier cost replaces the peak-divisor law at BOTH levels.
4. **A measured failure of the transfer assumption.** The design
   assumes the leaf-level laws (residue, learned split, epoch
   banking) compose unchanged one level up because the tenant's
   askers are its leaves' draws. If the Phase 4 harness measures a
   tenant-granularity starvation or hog shape the leaf battery
   never reproduced (for example, a tenant whose many leaves
   micro-draw past the tenant carry), the tenant word needs its own
   repair iteration — the honest response is to re-run the same
   simulate-first cycle drr.rs ran, not to tune live.
5. **Per-NIC envelope semantics becoming a requirement.** The v1
   envelope is host-wide per direction; a multi-homed host that
   needs per-interface envelopes needs direction x interface keys —
   a growth, not a reversal, but it changes the envelope maps'
   shape and must not be smuggled in.

## 9. The scope — what this design does NOT build

Named so absence reads as a decision:

- **Cross-host or cross-node tenant fair-share.** One envelope per
  direction, host-wide. No coordination, no gossip, no cluster
  identity.
- **Weighted fair queue.** v1 splits the envelope equally; a
  tenant's floor approximates weight priority. Real weights need a
  per-epoch WEIGHT-SUM field that does not fit the proven u12
  packing (count 12 bits + sum 20 bits leaves the epoch nothing),
  and inventing a second packing for v1 doubles the pinned surface
  for a property floors already approximate. The packing math is
  recorded here so the extension starts from arithmetic, not
  opinion.
- **Tenant nesting.** One level: envelope -> tenants -> member
  pools. A tenant of tenants is the group lane's problem wearing a
  costume.
- **The tenant law on the group lane and the per-socket lane.**
  Group rows are enumerated-member applies (their fairness problem
  does not exist, the documented scope); per-socket + tenant is
  refused at write time (section 6).
- **Tenant-level observability beyond the status join.** No tenant
  histogram, no tenant rate rings, no new stats row: a tenant's
  delivered bytes derive from its member roots' existing stats and
  ring rows (the status joins them by the id the rows already
  carry). A dedicated tenant counter family is a named future
  scale, not a rider on this one.
- **Quota-saver interactions.** The RECWN and pacing hints
  advertise the policy row's own rate, not the envelope's share —
  the advertised window can exceed what the envelope will deliver.
  The quota-saver physics is UNCHANGED (this layer is scheduling,
  not quota saving — the owner's own prediction, confirmed): no
  QUOTA_SAVER_PHYSICS.md row changes, no Layer number moves.
- **Per-tenant `--during` composition beyond the gate's own
  semantics.** Windows stay per-policy-root; a tenant is not a
  window scope.
- **Any change to the version, tag, or release process.** The
  design lands as v81.0.0 material by owner directive; no version
  surface is touched.

## 10. The implementation order (the Phase 3 contract)

The owner's build order, bound to the sections above — each step's
"done" is its rootless pins green plus the standing gates:

1. **BPF map + kernel struct** (section 3): the three map families,
   the grown Policy, the size/offset pins on both trees, schema v35
   with the one-time-reload contract, the rootless pin for the
   layout (size, offset, round-trip).
2. **Kernel program logic** (sections 2, 4, 5): the envelope read,
   the tenant state fetch, the take-chain min, the tenant CAS
   spend — every math path pinned rootlessly BEFORE any live run,
   the simulate-first cycle drr.rs set as the discipline.
3. **Userspace surface** (section 1): the `--tenant` flag and the
   `tenant` verb family, the policy write path's id plumbing, the
   status JSON's `tenants[]` array (additive, honestly absent while
   no tenant exists — the histogram-null precedent) and the human
   footer line.
4. **The CLI grammar + pins** (section 1): the parse, the name
   validation, the per-socket/group combination refusals, the
   collision check — pinned rootlessly.
5. **The docs**: USAGE.md (grammar + example), GLOSSARY.md (the
   term), INNOVATIONS.md (ledger entry **18** — the current count
   ends at 17, the depth histogram), COSMIC_DRAGON_ARC.md (a new
   scale row), QUOTA_SAVER_PHYSICS.md untouched (section 9).
6. **The tests**: the rootless pins of steps 1-2, the grammar pins
   of step 4, and the live harness `scripts/bench/per-tenant-test.sh`
   (10 tenants x 10 subprocesses, measured per-tenant delivery, the
   50% starvation bar), wired as the supermassive-verify leg's
   per-tenant phase.

Phase 5 gates, unchanged from the owner's spec: `cargo test
--features ebpf --locked` green, `gate-keepers.sh` 26/0/0,
`check-all -q` exit 0, no regression on the MMSPA/DRR/quota-saver
A/B families. Commit structure per owner directive:
`research: the per-tenant design (night-frontier-3C)` (this file),
then `feat:`, `docs:`, `test:` on the implementation session —
each `Signed-off-by: oxyzenQ
<130107241+oxyzenQ@users.noreply.github.com>`, English only.

## 11. The open questions for the owner

Three things the design cannot decide alone:

1. **The envelope default when only brackets are declared.** A
   tenant with a floor but no envelope has nothing to earn from —
   should `tenant web --floor 20mb` WITHOUT an envelope be (a) an
   error naming the missing envelope (the strict reading), or (b)
   accepted as an inert declaration (the permissive one)? The
   design picks (a) — a guarantee nothing can fund is the
   contradiction class the ceiling law already refuses — but the
   verb ergonomics are the owner's call.
2. **The envelope's blast radius spelling.** `tenant envelope
   1gbit` sets both directions (the bare-flag reading); the
   per-direction spellings (`--download` / `--upload`) follow the
   bracket family's pattern. Should an asymmetric envelope be
   REQUIRED to spell both sides explicitly (refusing the bare
   form)? The design picks: bare = both, spellings override — the
   rate family's own law.
3. **The harness's host.** Phase 4 needs a root + cgroup v2 runner
   with a known-shape link (the supermassive lane's own); if the
   CI lane's netem shaping interferes with the envelope's
   arbitration, the harness should pin the RAW link (no netem) and
   read relative shares only — the design picks relative shares
   either way, absolute numbers only as color.

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
