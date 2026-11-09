<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# The Quota Saver — Physics, the Measured Curve, and the Peak Declaration

> The quota saver in one paragraph: on a metered link, a dropped
> download is a purchase, not a saving — the packet already crossed
> the radio. What saves quota is making the sender send fewer bytes,
> and the size of that saving is the share of the wire you refuse.
> This document is the quota saver's canonical record: the problem,
> the mechanism (RECWN v25, ECN v26, EDT v27, telemetry v28), the
> formula, the five-point measured curve, the eight physics losses no
> receiver can close, the lanes' honest contribution boundary, the
> practical guidance, and the formal peak declaration of the
> 2026-11-07 measurement campaign.

Every number in this document is wire-read, not modeled. The
measurement discipline is the A/B harness
(`scripts/bench/quota-saver-ab.sh`): the same real download and the
same real upload run twice — scenario A under a live zelynic limit,
scenario B with no enforcement — and the saving is read off the
interface deltas, not off any ledger. Where a booking was an
estimate, this document says so — and where an estimate broke the
errs-LOW contract (the RECWN booking, retired 2026-11-09,
night-recvn-audit), the retirement record below names it. Nothing here is
extrapolated: five rates were measured, and exactly five rows exist.
The README's quota-saver section is the buyer-facing summary; this
document is what it summarizes.

## 1. The problem: a dropped download does not save quota

A metered link bills the bytes that cross it. The two enforcement
hooks sit on opposite sides of the radio: `enforce_dl` runs on
`cgroup_skb/ingress` (download), `enforce_ul` on `cgroup_skb/egress`
(upload) — and the two sides are not symmetric (docs/USAGE.md,
limitation #15).

Egress drops save quota directly. The hook runs inside the kernel
before the packet reaches the NIC — a dropped upload never crosses
the WiFi air or the metered link behind it. For upload-heavy traffic
the refusal is the saving.

Ingress drops cost quota anyway. The hook runs after the packet has
already crossed the ISP's link, the router's, and the WiFi air; every
drop point a host can own (XDP, tc, netfilter, cgroup_skb) sits
behind the radio. A dropped download has already been paid for — and
the sender retries it (TCP and QUIC both retransmit what was never
acknowledged), so the same bytes can be paid for twice. Only shaping
upstream of the radio — a router or an ISP cap — can drop a download
before it crosses the WiFi hop.

That asymmetry defines the design space. A receiver cannot un-bill a
byte the wire carried; the only lever it owns is to tell the sender
to slow down before the bytes cross. That lever is the saver: the
receive-window clamp, the congestion mark, and the egress pacer are
three ways of saying "send less" to a sender still on its own side of
the link.

One more condition comes from the workload, not the wire: the saving
exists only where the sender overruns. A bounded transfer (a 20 MB
curl that ends because the file ended) never attempts the overrun,
so there is nothing to refuse — the bounded-pair A/B run of
2026-11-06 measured ~0% (the enforced leg moved +1.21 MB download and
+0.64 MB upload MORE than the unenforced leg, against bookings of
82.58% / 75.85%). The saver's claim lives on the overrunning
workload: the clock-bounded eager session, the harness's own leg.

## 2. The mechanism: four lanes, three physics, one ledger

The saver is four layers, each landed as its own schema version, each
owning one physics.

**Layer 1 — RECWN, receive-window control (schema v25).** A policed
cgroup's own sockets advertise a rate-shaped receive window — the
rate times a 200 ms delivery-cadence estimate, clamped to
[2 x MSS, 1 MiB] — so remote TCP senders hold their in-flight bytes
down before the link bills them. The sender throttles itself; the
download side of the quota saver stands on TCP's own flow control
(the owner's coined name, deliberately not "RWND").

**Layer 2 — ECN, mark instead of drop (schema v26).** An over-budget
packet that an ECT-capable sender can read is delivered CE-marked
instead of dropped, so RFC 9002 QUIC stacks back off without a single
lost datagram. `ce_marked_packets` / `ce_marked_bytes` in
`status --print-json` make the lane measurable.

**Layer 3 — EDT, egress socket pacing (schema v27).** The egress hook
primes a cookie-keyed hint and the sock_ops program pins
`SO_MAX_PACING_RATE` onto the row's upload sockets: the kernel's own
TCP pacer spaces the outgoing stream at the policy rate, with no tc
qdisc anywhere.

**Layer 4 — telemetry (schema v28; the EDT booking retired in v29,
the RECWN estimate retired in v30).**
The lanes' work is booked, not just enforced: `bytes_saved_by_ecn`
in the kernel ledger — the sole live booking — and
`bytes_saved_total` named by `status --print-json` and rendered by
the human table's `Quota Saved` line. The v28 `bytes_saved_by_edt`
word keeps its place in the layout and reads zero since v29, and
the `bytes_saved_by_recwn` key keeps its place reading zero since
v30 (the retirements are documented with the bookings below).

The bookings, one law each (the derivations live in
docs/COSMIC_DRAGON_ARC.md's Layer 4 section):

- `bytes_saved_by_recwn` — RETIRED (night-recvn-audit, schema v30).
  The v28-era law read `(bytes_allowed / clamped) x (default -
  clamped)` userspace-side, with `default` pinned at the kernel's
  128 KiB initial receive buffer and named "the conservative pole,
  so the estimate errs low, never high". The formula booked a
  counterfactual that assumes the clamp binds for every delivery
  cycle, and on a real link it rarely does. The owner's live
  ss -tip reading (2026-11-09, brave at 200kb on the home WiFi)
  proved the law's three hidden assumptions false: the autotuned
  rcv_wnd ran 48-78 KB across 11 connections — the 128 KiB
  "default" the formula books against was never on the wire; only
  1 of the 11 connections carried a BDP at or above the 40 KB clamp
  (the other ten sat at 1.8-14.7 KB — physically impossible to fill
  a 40 KB clamp at the policed rate, let alone the 128 KiB
  default); and almost every socket carried `app_limited` — the
  sender was not pushing at max, so the window never filled. The
  formula booked 165 MB against 72.4 MB of allowed traffic; the
  honest per-connection upper bound recomputes to at most a few MB
  (only the one long-RTT connection can contribute at all; the
  strict fill-bounded bound is ~6.5 MB, ~25x lower). A value that
  errs 20x HIGH cannot sit under the "errs LOW, never high"
  contract, and zero errs neither high nor low. The key stays in
  `status --print-json` at zero (the additive contract), the
  estimate function came out of the display layer, and the lane's
  real work — the SO_RCVBUF clamp, the bufferbloat reduction — is
  untouched: the RECWN lane still primes hints and clamps when it
  can, and its wire effect is the A/B harness's measurement, never
  a booked number.
- `bytes_saved_by_ecn` — one-for-one with `ce_marked_bytes`: every
  delivered CE-marked byte is a byte that never becomes a
  loss-and-retransmission pair, and a dropped byte costs metered
  quota twice, so 1:1 is the conservative pole.
- `bytes_saved_by_edt` — RETIRED (night-quota-audit, schema v29).
  The v28 law read `(rate x time_elapsed) - bytes_uploaded`, the
  preserved-headroom counterfactual with the idle gap capped at one
  second and the rate sanitized at 4 GiB/s. The owner's 2026-11-09
  live reading broke the contract this document's other bookings
  keep: a brave at 500kb booked 744.6 MB against a 20 MB
  doc-formula prediction (36.8x over), a python3 at 300kb booked
  1.8x over. The formula's only NONZERO content is the budget the
  sender did not use — a saturated paced lane books nothing, and an
  idle-ish lane books `rate x capped-gap` per packet, headroom for
  an upload that was never pending. A pacer reschedules bytes; it
  does not remove them, so the honest booking is zero: the word
  stays at its offset reading zero from v29 on, the pacing lane's
  enforcement is untouched, and the lane's real wire effect — the
  suppressed burst-retransmission storm — is the A/B harness's
  measurement (section 5), never a booked number.

Direction split, stated plainly: RECWN and ECN shape the download
side (they keep bytes from crossing), EDT owns the upload side (it
spaces the bytes that leave). None of them un-send a datagram the
wire already carried.

**Reading the counters: `dropped` is not `bytes_saved_total`.**
The status counter `dropped` is the kernel discards AFTER the lanes
did their work — the bytes the token bucket's drop verdict actually
discarded since apply. The status counter `bytes_saved_total` is
the counterfactual estimate of what the lanes prevented (the
telemetry sum: the ECN one-for-one alone — the retired EDT word
reads zero since v29 and the retired RECWN estimate reads zero
since v30, rendered with the honest "(est., counterfactual)" label). The two are not the same number
and answer different questions: `dropped` says how many bytes the
policer was forced to drop; `bytes_saved_total` says how many bytes
the saver lanes withheld the policer from ever seeing. On a working
saver-lane deployment, `dropped` is SMALL and `bytes_saved_total`
is LARGE; on a lane-not-binding rate — the sender not cooperating
with the clamp, the mark, or the pace — `dropped` grows and
`bytes_saved_total` flattens, and the honest wire savings is the
A/B harness's number (section 8), not the booked counterfactual.
The lane-by-lane physics live in the layers above and in
docs/COSMIC_DRAGON_ARC.md's Layer 4 section (the lane docs); the
schemas are v25 RECWN, v26 ECN, v27 EDT, v28 telemetry, v29/v30 the
retirements. USAGE.md's
status section carries the same distinction for the surface reader.

## 3. The formula and the measured curve

The savings is the rate limit itself. When `rate_limit <
network_speed`, the limit binds, and the eager app cannot push more
bytes than the limit allows. At 5mb on a 1 MB/s link, the limit is
above network speed, nothing is being throttled, and the same test
shows ~0% savings. The formula:

```
(network_speed - rate_limit) / network_speed × 100%
```

Five rate limits, same 30-second overrun session, same host, same
wire-measurement discipline. Measured on 2026-11-07 on a ~1.08 MB/s
WiFi link (interface wlp1s0; the formula's base is that 1080 kb/s):

| Rate limit | Formula predicts | Download measured | Delta | Upload measured |
|-----------:|-----------------:|------------------:|------:|----------------:|
| 50kb       | 95.4%            | 94.9%             | -0.5pp | 95.9%          |
| 100kb      | 90.7%            | 85.0%             | -5.7pp | 91.9%          |
| 300kb      | 72.2%            | 79.7%             | +7.5pp | 86.7%          |
| 500kb      | 53.7%            | 59.7%             | +6.0pp | 83.5%          |
| 1mb        | 7.4%             | 40.3%             | +32.9pp | 72.3%         |

The download curve tracks the formula to within noise (±7pp) at most
rates. Two things bend it:

- At 100kb the measured download sits ~6pp UNDER the formula: the TCP
  retransmit and timer overhead the saver lanes cannot remove (loss
  3 below).
- At 1mb the measured download runs ~33pp ABOVE the naive
  prediction, because with the rate limit barely binding, the
  ECN-first lane's retransmit rescue is what saves the burst (the
  lanes' contribution, section 5).

The upload curve sits consistently above download because EDT pacing
suppresses the burst-retransmit storm that an unthrottled upload
produces — scenario B retransmitted 4-7 MB in every 30-second run.

The two 100kb runs, named so no reader sees a contradiction: the
measured-claim anchor run (same day, same harness) read 87.3%
download / 93.4% upload; the curve series' 100kb row read 85.0% /
91.9%. That is 2.3pp of run-to-run variance on one link, and both
runs land in the same band — high-80s to low-90s download, low-90s
upload at 100kb.

The practical reading: pick your rate below your network speed. At
half your network speed you save ~60%. At a twentieth, ~95%. Above
your network speed, the savings falls toward zero because nothing is
being throttled.

## 4. Where it fails: eight physics losses no receiver can close

Even at the measured 85-95%, the residual is physics, not engineering
debt. Eight losses bound the saver; no receiver-side code can close
them.

1. **The radio bills before the host sees the packet.** Every drop
   point a host can own — XDP, tc, netfilter, cgroup_skb — sits
   behind the WiFi hop. A dropped download was already paid for; no
   receiver code can un-bill a crossed byte.
2. **Retransmission bills the same bytes twice.** TCP and QUIC
   retransmit what was never acknowledged. Measured on this campaign:
   the unthrottled upload leg retransmitted 4-7 MB in every
   30-second run, and in the 1mb run scenario B's upload carried
   4.34 MB of retransmission — about 12% of that leg's wire. The
   lanes shrink the storm (that is the 1mb finding); they cannot zero
   it.
3. **The TCP timer and ramp-up tax at low rates.** At 100kb the
   download curve sits ~6pp under the formula (85.0 vs 90.7):
   retransmit overhead and slow-start ramp spend wire time the
   formula does not model. The sender's own timers are not the
   receiver's to remove.
4. **The upstream ACK lane.** A download is a conversation: every
   segment received obliges an upstream acknowledgement, and on a
   symmetric metered plan the upstream counts too. A receiver cannot
   refuse to acknowledge without stopping the flow entirely.
5. **Framing and encryption ride the limit.** TCP/IP headers, TLS
   record framing, and QUIC packet headers bill like payload. The
   rate limit spends them at the same cadence as data, and the
   formula's percentage is protocol-blind.
6. **Connection setup handshakes.** TCP plus TLS or QUIC handshakes
   cost round trips of overhead per connection; short transfers pay
   proportionally more. The eager session opens and reopens
   connections; the formula counts none of it.
7. **Uncontracted WiFi queue behavior.** The AP's queue forgives
   bursts: at 300kb and 500kb the measured download ran ~6-7pp ABOVE
   the formula. The bonus is real but unowned — no receiver controls
   it, and the same queue dynamics invert into bufferbloat loss on
   other links.
8. **The cooperative-sender ceiling.** The lanes shape what a sender
   ALLOWS: the RECWN clamp works through the receive window a
   cooperative TCP stack respects, ECN works through ECT-capable
   senders, and a QUIC first packet still crosses the wire. An
   uncooperative sender above the lanes' reach bills at its own
   pace; a receiver can refuse delivery, but not the bill.

For hard per-byte download guarantees, the conclusion is the one
limitation #15 already states: shape at the router or close the app.
The saver's contract is the overrunning workload's marginal savings —
measured, bounded, and honest about its ceiling.

## 5. Where the lanes contribute: neutral at 100kb, carrying at 1mb

Two truths, both measured, neither retracting the other.

**Truth one — neutral at 100kb on this workload.** The vs-legacy
harness (`scripts/bench/quota-saver-ab-vs-legacy.sh`) ran the A/B
pair twice at the same rate — once with the latest zelynic (v80.1.0,
the saver lanes present), once with the legacy release binary
(v80.0.0, the pre-saver drop-based limiter). The 2026-11-07 host run
at 100kb: overrun download 87.58% (v80.1.0) vs 87.33% (v80.0.0),
delta +0.25pp; bounded upload 16.44% vs 16.86%, delta -0.42pp. Both
within noise. At 100kb the saving is the rate limit itself, and the
lanes add nothing measurable on this workload.

**Truth two — load-bearing at 1mb.** At the wire's edge the naive
prediction collapses to 7.4%, and the measured rows do not: 40.3%
download (+32.9pp) and 72.3% upload (+64.9pp). That margin is the
lanes' work. The 1mb run's wire reads: scenario B's upload leg moved
37.54 MB, 4.34 MB of it retransmission — about 12% of that leg's
wire; scenario A's upload leg, paced by EDT, moved 6.19 MB with no
storm. Download-side, the ECN-first lane rescued what the
barely-binding throttle could not.

The frame that holds both: the lanes are neutral where the limit
binds and load-bearing where it does not — the difference between
"nothing is throttled, so nothing is saved" and "the marginal savings
at the throttle margin." The primary mechanism and the lanes are
additive, each carrying the rung the other cannot.

The workload condition rides on top of both truths: a bounded
transfer overruns nothing and saves ~0% at any rate (section 1). The
curve is an overrunning-workload curve, end to end.

## 6. Practical guidance: target savings to rate

Pick the row whose measured savings matches the target. The rows are
the measured ones and only those — no rate below or between them is
claimed here; on a different link, re-run the harness and the
fractions of the wire transfer by the formula.

| You want | Pick (on this ~1.08 MB/s link) | The curve measured |
|---|---|---|
| ~95% saved | 50kb — a twentieth of the wire | 94.9% dl / 95.9% ul |
| ~85-90% saved | 100kb — a tenth of the wire | 85.0% dl / 91.9% ul |
| ~80% saved | 300kb | 79.7% dl / 86.7% ul |
| ~60% saved | 500kb — about half the wire | 59.7% dl / 83.5% ul |
| ~40-70% saved | 1mb — at the wire's edge | 40.3% dl / 72.3% ul |

Three rules the curve earns:

- Pick the rate below your network speed. The saving is the share of
  the wire you refuse; a rate at or above network speed refuses
  nothing and saves ~0%.
- Think in fractions of your own wire, not in the table's absolute
  rates. The rows above are one link's measurements; the formula is
  the transferable part.
- The workload must overrun. A bounded transfer saves ~0% at every
  rate in the table — the saver prices an overrun that actually
  happens.

On metered upload-heavy traffic (sync clients, backups), the upload
column is the one to read — it is the direction egress enforcement
saves directly, and the direction EDT protects hardest.

## 7. The peak declaration

The measurement campaign that produced this document is formally
closed.

- **Opened:** 2026-11-07, the five-rate A/B series and the
  vs-legacy pricing on one host (WiFi wlp1s0, ~1.08 MB/s).
- **Closed:** with this document, the quota saver's claim is stated
  in full and needs no further run to stand.
- **The claim, in full:** on a metered link, with the rate limit
  below network speed and the workload overrunning, the wire saving
  is the share of the wire refused — `(network_speed - rate_limit) /
  network_speed` — measured within ±7pp of the formula at four of
  five rungs, bent ~6pp low by TCP overhead at 100kb, lifted ~33pp
  high by the ECN-first rescue at 1mb download and ~65pp high by EDT
  pacing at 1mb upload; the saver lanes are neutral at 100kb on this
  workload and load-bearing at 1mb; a bounded workload saves ~0%.
- **The conditions of validity:** one host, one link, one workload,
  one date. The claim does not transfer to other links by assertion;
  it transfers by the formula and re-measures by the harness.
- **The closure rules:** no row may be added without a harness run;
  no number in this document may be revised without a harness run
  that contradicts it; no rate not in the table is claimed. New
  wire, new run — the harness is the only door.

The quota saver is peaked: measured at five rungs, priced against
both counterfactuals (no zelynic, and the legacy limiter), bounded by
eight physics losses, and declared in print. What remains open is
explicitly nothing that a claim needs — only what a new wire would
measure, which is a new campaign, not this one.

## 8. Sources

- **The A/B harness** — `scripts/bench/quota-saver-ab.sh` (the wire
  contract: same real download, same real upload, A under a live
  limit, B unenforced, verdict read off wire deltas) and
  `scripts/bench/quota-saver-ab.py` (the engine). Root, cgroup v2,
  and curl required; a missing prerequisite refuses, never fabricates.
- **The five runs** — 2026-11-07, host WiFi wlp1s0 at ~1.08 MB/s,
  one full harness invocation per rate (symmetric download/upload
  rate), each row quoted from that run's wire verdict:
  `--download-rate 50kb --upload-rate 50kb` (94.9 / 95.9),
  `100kb` (85.0 / 91.9), `300kb` (79.7 / 86.7), `500kb` (59.7 /
  83.5), `1mb` (40.3 / 72.3). The measured-claim anchor (87.3 /
  93.4 at 100kb) is a separate same-day invocation. The 1mb run's
  wire reads (B upload 37.54 MB incl. 4.34 MB retransmission; A
  upload 6.19 MB) come from the same series.
- **The vs-legacy pricing** — `scripts/bench/quota-saver-ab-vs-legacy.sh`;
  the 2026-11-07 host run recorded in its header: v80.1.0 vs v80.0.0
  at 100kb — overrun download 87.58% vs 87.33%, bounded upload
  16.44% vs 16.86%.
- **The lane docs** — docs/COSMIC_DRAGON_ARC.md (Layers 1-4 and the
  booking math), the live proofs `scripts/bench/recwn-probe.sh`,
  `scripts/bench/ecn-probe.sh`, `scripts/bench/edt-probe.sh`, and
  the README's "The formulas" block (the booking laws, their
  conservative poles, and the EDT and RECWN retirements).
- **The schemas** — `ebpf/src/schema.rs` (`SCHEMA_VERSION` 30 and
  the contract history): v25 RECWN, v26 ECN, v27 EDT, v28 quota
  telemetry, v29 the EDT booking retired (night-quota-audit), v30
  the RECWN estimate retired (night-recvn-audit); the
  `bytes_saved_total` /
  `bytes_saved_by_edt` / `bytes_saved_by_ecn` /
  `bytes_saved_by_recwn` keys in `status --print-json`.
- **The asymmetry record** — docs/USAGE.md limitation #15 (ingress
  drops do not save download quota), and the 2026-11-06 bounded-pair
  A/B finding (README: ~0% on a bounded transfer, enforced leg moved
  +1.21 MB download / +0.64 MB upload more, against bookings of
  82.58% / 75.85%).

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
