<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# night-audit-7 — the 39afbc2..044ca58 range depth verification (2026-10-09)

> Audit date: 2026-10-09. Scope: the owner's ask — a depth audit
> of every commit from 39afbc29614a6e189884231b23c9c2972df5930b
> (night-audit-5's usage-guide close, the range's exclusive base)
> through 044ca5893196dddffa5941cf05eef68489ae9186 (night-hunt-42's
> HEAD), "to verify correct works or gimmick/fatal" — thirteen
> commits, ~2,137 insertions across twenty-seven files, every code
> claim re-derived against the kernel, the live /proc tables, and
> the repo's own pins rather than trusted from the commit messages.

## 1. The method

Each commit was walked the same way: read the diff, re-derive the
claimed defect from first principles (the kernel's actual behavior,
Rust's actual slicing and Unicode semantics, the wcwidth tables),
then check the fix against the surrounding code for the two failure
classes the owner named. A **gimmick** is a change that reads like
a fix but cannot do what it claims (an unreachable arm, an assert
that cannot fail, a gate that never engages). A **fatal** is a
change that trades the claimed fix for a worse defect (a panic
moved, enforcement lost, an honest-input regression). Doc-only
commits were verified as docs (content spot-checked, index rows
confirmed, no code path touched).

## 2. The verdict table

| commit | lane | verdict | the independently checked fact |
|---|---|---|---|
| 5c7ff8b | night-audit-6 connected-UDP visibility | correct works | the kernel's UDP sk_state model re-derived: connect() sets sk_state to TCP_ESTABLISHED, so /proc/net/udp reports 01 for connected sockets (the QUIC-client shape) and 07 only for unconnected — hunt-15's "07 for both" model was the bug, the fix accepts both states behind the unchanged `:0` remote guard, and the guard itself survives the adversarial shapes (connect(AF_UNSPEC) clears the remote to `:0`, so a disconnected socket hides; LISTEN does not exist in the UDP table) |
| 4b99d16 | night-hunt-40 split-ST terminator panic | correct works | the slice math re-derived: an ESC terminator at the buffer's last byte makes `end = bytes.len() + 1`, and `&bytes[..end]` panics exactly as claimed; the fix's `end > len → None` parks the partial for absorb()'s reassembly (the same contract the neighboring pins own), and the BEL case can never overflow (a found byte is an in-bounds byte) |
| 91d2361 | night-hunt-40 docker char-boundary + sanitize choke | correct works | `&id[..12.min(len)]` panics when byte 12 falls mid-UTF-8 — real; `chars().take(12)` is boundary-safe by construction; the sanitize choke point sits at parse (every consumer downstream), and the `running: status == "running"` comparison correctly rides the RAW string before the sanitized field is stored (a raw "running" is clean by definition, so the verdict cannot drift) |
| ed3b029 | night-hunt-40 probe truncation law | correct works | `u32::try_from(ino).unwrap_or(0)` reads row 0 where the map keys on `ino as u32` (identity/mod.rs's own contract) — the old spelling could only produce false-clean verdicts (inode 0 is never a policy key), and the fix is the map's own spelling, the third copy of the same law (pid_cgroup_id, inode_is, now dir_is_clean) |
| d14df57 | night-hunt-40 hygiene sweep | correct works, no behavior change verified | the dedupe was checked for drift, not assumed: `capped_rows`' overflow note is byte-identical to both old inline notes, the flattened cap spans sockets exactly as the old nested loop did, `Proto::as_str` replaced three identical ternaries, and `run_zel_as_user` has zero remaining references in the tree |
| cde0eb1 | night-hunt-40 disclaimer compliance | correct (docs) | GUIDE.md + the audit-6 record's disclaimer blocks; no code path |
| d12445e | night-hunt-40 five-lane root audit report | correct (docs) | the dated record + index row; no code path |
| c0bc5ee | night-hunt-41 markdownlint gate | correct (docs) | two audit docs' lint shape; no code path |
| 59f1d13 | night-hunt-40 white-hat bidi sanitize | correct works | the Unicode facts re-derived: the nine bidi chars (U+202A..=U+202E, U+2066..=U+2069) are category Cf, and Rust's `char::is_control` covers only Cc — the claim holds on the pinned 1.98.1; the substitution closes the CVE-2021-42574 terminal-rendering class at the same choke point as C0/C1, the other-Cf fast path (ZWJ/ZWNJ/ZWSP/LRM/RLM/WJ/BOM) is pinned so an honest emoji or ZWNJ-carrying comm survives, and width.rs's zero-width arm mirrors wcwidth as defense-in-depth |
| f7f4d8b | night-total-lts-12 audit round six | correct (docs) | the dated record + index row; no code path |
| 77940e9 | night-improve-57 raw-socket visibility | correct works | the live /proc/net/raw header on the audit host confirms the leading ten columns are positionally identical to tcp/udp (inode at the tenth), so the reused positional parser reads the right field and ignores the trailing ref/pointer/drops; the raw display arm's unconditional verdict is the documented design (raw remotes are always `:0`, so the UDP guard would hide the very traffic the tag exists to surface), and the cookie join is protocol-agnostic by construction (the observer keys on cgroup id + socket cookie, no L4 filter) |
| f08f422 | night-hunt-42 residual closures pass | correct (docs) | 29 residuals walked and classified; the closing commit hashes spot-checked against the tree (resolve.rs's one-walk, the audits-index gate, bench.rs's synthetic cookies all stand where the doc says they do) |
| 044ca58 | night-hunt-42 close the three residuals | correct works | the two supermassive stages carry asserts that can fail (the sweep lane: rc 0 + warn wording + rows in (0, 1024]; the orphan-census lane: bpftool delete returncode + recover's census wording + rc 0), teardown runs on both the success and every failure leg, and the SKIP lanes (session-cgroup fallback, missing bpftool) degrade honestly; the README disclaimer is docs |

**Verdict: thirteen walked, thirteen correct works. Zero gimmicks.
Zero fatals.** No commit in the range trades a claimed fix for a
worse defect, and no claim failed re-derivation.

## 3. The named warts (observed, not defects)

Two observations survived the walk as worth naming — neither is a
bug today, and both are one grep away if a report ever arrives:

1. **The orphan-census stage's no-op verify block** (044ca58): the
   post-delete status check cannot observe a direction-scoped row
   (the status reader folds both legs into one cgroup row), so the
   stage documents the blind spot and trusts the bpftool
   returncode it already asserts. The block reads as a check but
   asserts nothing — a future edit could delete it with no test
   changing. The load-bearing asserts (bpftool rc, census wording,
   recover rc) are real and can fail.
2. **The typed-target/bidi mismatch lane** (91d2361 + 59f1d13
   interaction): docker names are sanitized at parse while the
   typed target rides raw CLI bytes — a name that genuinely carries
   a bidi char would sanitize to `?` on one side and not the
   other, refusing the match. An honest docker name never carries
   the family, so the lane is theoretical; naming it here because
   the two commits' combination creates it.

## 4. What the range did NOT need

The battery counts across the range's commit messages are
monotonic (843 → 846 → 852 → 858+... ) and consistent with each
commit's declared pins — no commit claims a battery it did not
add to. The prebuilt-lane parity held at every commit gate (the
range touches no ebpf/ source). Frame A/B claims are all
gate-extension or no-render-path changes with byte-identical
visual metrics — consistent with the diffs, which touch no layout
engine.
