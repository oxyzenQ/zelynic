# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The changelog is split into per-era records so this one stays
navigable (NIGHT-docs-1): this file carries ONLY the entries newer
than the v20.0.0 stable release — the fresh record since the owner
cut v20 at commit b743d9c (2026-10-04). NIGHT-improve-43
(2026-10-06) trimmed the legacy bulk out: the 9,217 pre-split
lines moved to the frozen era file, leaving this one at the
post-v20 record alone — the same task's re-issue later moved the
era file out of the root entirely, so the root tree carries
nothing legacy at all. The v20-era history (the v11-line entries
through the v20.0.0 release, the changelog blob as it stood at
b743d9c) is archived in
[docs/archive/CHANGELOG-V20-ERA.md](docs/archive/CHANGELOG-V20-ERA.md);
the pre-v11 release
history (entries [1.0.0] through [7.0.0]) is archived in
[docs/archive/CHANGELOG_PRE_V11.md](docs/archive/CHANGELOG_PRE_V11.md)
— restored there by NIGHT-dinner-15 (2026-09-28), superseding
NIGHT-hunt-18's git-history-only call.

## [Unreleased]

### Added

- **test(supermassive): NIGHT-improve-49 — the real-user drop
  lane: the rootless-lane rows now RUN on the root VM legs instead
  of skipping, the supermassive test's user experience made real
  (no fake root, no fake rootless).** The owner's mandate, verbatim
  intent: "make the supermassive test is real usage as a user don't
  fake root/rootles. why? aim to effective real usage and be
  honest." The find beneath it (the round-2 audit's inventory): the
  VM leg runs every battery as root (the init context v1/v2 need
  for BPF), so the 20 rows whose contract is the refusal a REAL
  user sees — v4's 19 rootless-lane rows (the snapshot/restore
  privilege verbs, the during grammar's 8 valid rows, the guarantee
  ladder's 4, the tier pair, the shadowed-positional triple) plus
  v3's privilege-gate stage — skipped without executing: the
  battery labeled "rootless" was executing as root and honestly
  declining to fake the user, delegating the whole user experience
  to the rootless CI leg. The fix, one lane: the shared lib gains
  privdrop_prefix/run_zel_as_user (setpriv --reuid=65534
  --regid=65534 --clear-groups, the classic unprivileged uid,
  numeric — no userdb dependency; probed once, cached; absent
  setpriv degrades to the old honest SKIP), and when the harness
  itself is root the rootless-lane rows re-execute through the
  drop: the gate refuses the dropped user exactly as it refuses a
  real one, the refusal needle asserts for real, and the verdict
  is a genuine PASS/FAIL stamped "real-user drop (uid 65534)".
  Safety is inherited, not weakened — a dropped uid cannot pass
  the root gate, so no case ever executes a policy (the same
  construction that makes the rows safe on the rootless CI leg);
  the enforcement batteries (v1/v2, the rigs, the claims proof)
  stay root-only, untouched. The wiring: v4's runner takes the
  as_user parameter (the needle-case engine and stage 9's shadow
  loop share it), v3's stage 2 runs its refusal ladder through the
  same lane, both batteries' banners say which lane they run, the
  VM init's MASS-RESULT labels now name the real shape ("full,
  user rows via the real-user drop" — the old "(full, rootless)"
  label was the lie this task retires), and the self-test pins the
  drop engine (the prefix's exact five-token shape when setpriv
  resolves, the honest None when it does not). Verified locally:
  the engine self-tests green on v1/v3/v4 (v4's new privdrop pin
  reading /usr/bin/setpriv --reuid=65534 --regid=65534
  --clear-groups), the drop composition proven live against the
  real prefix (the subprocess ran setpriv+BINARY+argv and got
  setpriv's own refusal on this non-root host — correct: only root
  drops; the VM leg runs as real root where the drop succeeds),
  ruff check and format clean, shellcheck/shfmt/bash -n clean on
  every touched .sh. The live proof landed on run 232 (the
  fixpass commit's own supermassive run, all four legs green
  after the busy-hour first attempt took its documented
  shared-runner residual on the two best-specs legs and the
  re-run on fresh runners passed everything): the v4 batteries
  read 155 passed, 0 skipped on every leg — the 19 rootless-lane
  rows each stamped "real-user drop (uid 65534)" — the v3 legs
  read 30/0/2 (the gate stage's five refusal rows through the
  drop; only the two runtime-absent E2E rows stay, their own
  workflow carrying them).

- **ci(bench): NIGHT-improve-48 closure — the claims battery's
  three tool-absent VM skips closed at the rootfs: nftables rides
  the plain apt line, one flavor's bpftool is staged at
  /usr/bin.** The round-2 audit's closure landing: every VM leg
  since the claims battery landed (NIGHT-lts-6) skipped exactly
  three rows on a rootfs that shipped no nft and no bpftool — the
  pure-eBPF ruleset snapshot, the bpftool prog/link visibility
  row, and the footprint's kernel run-time numbers — while the
  same battery on a real desktop answered them (both tools one
  apt away). The rootfs assembly now installs nftables with the
  python3/iproute2/curl set, and stages bpftool the honest way:
  Ubuntu ships no standalone package (the binary lives inside the
  per-ABI linux-tools debs, and the VM's kernel — the 5.13
  floor or the dynamically resolved latest — never matches the
  rootfs's tools ABI, so the dispatcher cannot resolve it in the
  guest), so the assembly WALKS the linux-tools dependency chain:
  each level's deb is downloaded and probed for the binary, and
  the first one that carries it wins (run 231's lesson, fixed in
  the fixpass: noble's per-kernel -generic package carries the
  binary directly while jammy's is a 1.8 KB shell whose Depends
  names the per-ABI package that carries it — both shapes resolve
  in two levels or fewer, the walk mock-tested against both
  suites' real index shapes). Only the ~0.7 MB binary is staged
  at /usr/bin/bpftool; the rest of the deb is thrown away — the
  RAM-res initramfs gains the binary, not perf and its lib
  closure. The binary talks to the kernel through the stable
  bpf(2) ABI (prog/link/cgroup show predate the 5.13 floor), the
  same PATH-probe shape the battery uses and the same
  standalone-package shape a Debian user gets. A resolve failure
  FAILS the leg on the runner (the legacy-fetch doctrine: an
  in-VM row must never silently skip). The live proof landed on
  run 232 (the fixpass commit's own run, all four legs): the
  quick-mode verdict reads 29 passed, 0 failed, 0 skipped on
  every leg — the nft ruleset snapshot comparing structure
  before and during enforcement, bpftool's prog/link visibility
  showing the 2 cgroup_skb programs and 4 cgroup links, and the
  footprint's kernel run-time row printing real per-program
  numbers (1293-2425 ns per attached-prog run across the legs,
  bound 20,000); a host without the tools still answers honestly
  (the row names the missing tool, never guesses — the SKIP path
  stays for real tool-absent hosts).

- **docs(audit): NIGHT-improve-48 round 2 — the completeness
  question re-audited from run 229's own logs, the full skip
  inventory classified, 23 of 47 skips per leg found closable
  (docs/audits/NIGHT_IMPROVE_48_SUPERMASSIVE_COMPLETENESS_ROUND_2_AUDIT_2026-10-07.md).**
  The owner's suspicion, re-read after the round-1 fix: the named
  claim — the precision 0.00% proof — is NOT missing; run 229
  (the fix commit's own supermassive run, 6e80916) ran it live
  and green on all four legs (4.553%/6.772%/9.691%/8.431% under
  the 12.0% bound, the best-gnu leg's first 13.068% window taking
  its same-rate re-attempt). What the suspicion actually caught,
  pulled fresh from the four legs' downloaded logs: 47 skipped
  rows per leg, 24 environmental or physical and honest about it
  (the loopback-only realnet lanes, the hardware-ceiling ladders,
  the GSO accounting floors, the AMMSP diagnostics, the
  container-runtime E2E the container workflow carries), and 23
  closable — one root cause family: the VM leg runs everything
  as root, so the 20 rootless-lane rows that assert what a real
  user sees (v4's 19: the snapshot/restore verbs, the during
  grammar's 8, the guarantee ladder's 4, the tier pair, the
  shadow triple; plus v3's privilege-gate stage) skip instead of
  running, and the claims battery's 3 tool rows (the nft ruleset
  snapshot, both bpftool surfaces) skip on a rootfs that ships
  no nft and no bpftool. The closures are mapped in the audit:
  the real-user drop lane (NIGHT-improve-49) and the rootfs
  tools closure (this task's follow-on commit). The completeness
  ledger after both: nothing skips that could run, everything
  that skips names why and where it runs instead.

- **fix(bench): NIGHT-improve-48 — the precision proof-claim's red
  supermassive lane root-caused and closed: the starved-window
  discriminator, the honest adaptation, the honest SKIP
  (docs/audits/NIGHT_IMPROVE_48_SUPERMASSIVE_PRECISION_ROW_AUDIT_2026-10-06.md).**
  The owner's suspicion verified from the CI evidence: runs 219/221/
  224/228's best-specs legs failed exactly one lane — the claims
  proof's precision row, reading 21.297%/29.775% under the 12%
  bound while the 5.13 floor legs read 3.606% green on the same
  runs and the same 7.3 kernel read 1.921% green in quieter hours
  (the clocksource-watchdog line in run 222's log names the
  starvation). The physics: a drop-only bucket admits min(offer,
  refill), so an under-band window with ZERO refusals measured its
  own offer — the four-flow aggregate starved on the contended
  host (admitted==client at ratio 1.004, the TCP-level row at
  69.9-78.4%), while the policer held its contract perfectly; the
  same under-band WITH refusals is the real regression signature
  the row exists to catch. The fix, three shapes: the stage reads
  both counters (bytes_allowed AND bytes_dropped) in one status
  read per window edge (the midpoint estimator's spawn pricing
  unchanged); the under-band branch discriminates before it acts —
  the real signature keeps the old same-rate patience and fails
  red with the refused-surplus evidence, the starved shape adapts
  once (80% of its own measured offer, capped at the configured
  rate, floored at the 5mb loopback GSO rung) and a second starve
  or an unfundable offer records the honest SKIP (a starved window
  measures the offer, not the policer — the evidence rows ride
  every verdict unchanged). Three new self-test rows pin the pure
  functions on the exact CI shapes (78.4mb adapts to 62mb, 69.9mb
  to 55mb, the 5mb floor, both sides of the discriminator) — the
  engine self-test reads 36/0, ruff check and format clean, the
  gates 16/16. The "others" sweep: the other four headline claims'
  rows green on the same failing runs, the whole lane inventory
  (v1 matrix, AMMSP, v2, v3, v4 155 rows, the three rig suites)
  green on them too, and the five-claims coverage map verified
  present and running — the estate's coverage was never the gap,
  the instrument's robustness on shared runners was, and it is
  closed (the charger-core-1c probe-lane bug stays OPEN where it
  lives, unchanged). Proven live: the fix commit's own
  supermassive run (229) went green on all four legs — the
  formerly-red best-specs gnu leg's precision row passing at
  9.691% after a 13.068% mixed first window took its same-rate
  re-attempt, the musl leg in-band at 8.431% on its first
  window.

- **docs: NIGHT-improve-43 re-issue — the v20-era file moved from
  the repo root into the archive, the root left carrying the fresh
  record alone.** The owner's mandate, the intent verbatim: the
  old era moves to the archive, not the root — CHANGELOG.md stays
  fresh post-v20 data, no legacy bulk at the tree's front door.
  The first pass had parked CHANGELOG-V20-ERA.md at the root; this
  pass moves it to docs/archive/CHANGELOG-V20-ERA.md, the
  frozen-history home the PRE_V11 file established
  (NIGHT-dinner-15), and gives it the archive wrapper that home
  demands: the license header the header gate asks of every
  non-root .md, a short archive note naming the provenance (the
  b743d9c blob, the root history, the relative-path reading), and
  the bottom disclaimer the injector demands outside the root
  changelog family. The frozen entries are untouched — the wrapper
  sits around the blob, the H1 retitled to self-identify
  ("Changelog — V20-Era Archive"), the one recorded blob deviation
  (the NIGHT-audit-2 name-case line) unchanged, zero entry lines
  edited. Every live reference moved with it: this file's header
  and History map, docs/RULES.md's frozen-record law, the
  gatekeeper's markdownlint excludes (the dead root glob retired
  — the docs/archive/** exclusion is the file's lint shield now),
  and the four gate scripts' era-file arms re-pinned to the new
  home (check-headers.sh, inject-disclaimer.sh, check-language.sh,
  gate-keepers.sh — the name-based skip sets keep matching the
  file wherever it lives, the path-anchored regex arms kept as the
  old-checkout shield the V11 arm already documents).

- **docs(audit): NIGHT-improve-46 — the help surface and the
  documents verified against the source, both directions, honest
  and transparent
  (docs/audits/NIGHT_IMPROVE_46_HELP_DOCS_CONSISTENCY_AUDIT_2026-10-06.md).**
  The two-way flag extraction: all 22 source long flags documented
  on the rendered --help (globals in their section, -d/-u in every
  strict usage line, the thirteen advanced flags in Pro mode held
  by the 13-flag drift pin), and the help's only flag mentions
  without source definitions (--info, --limit) verified as NEGATIVE
  documentation — retirement and absence named on purpose. The
  empirical bounds walk: every numeric claim on the help probed
  from both sides of its boundary on the built binary — interval
  1s-60s, focus 1s-30s, rate 1kb-1tb with the SI wording, the
  --during 1s..10y ceiling with the removed-window-shape refusal
  by name, and the full bracket ladder (the contradiction, the
  over-subscription, the legal mixed spelling, the one-spelling
  law) — every one enforced exactly as printed. The blocklist's
  "57 system processes" is computed from DANGEROUS_TARGETS.len()
  (counted 57 at source, drift-proof by construction). The docs
  drift scan: 434 --flag mentions across the live docs classified
  — zero real drift (live flags, documented retired spellings,
  other tools' flags, script surfaces, payload examples). The
  command census: all 16 verbs, the 10 short aliases, and the 2
  shorthands documented, the alias routing probed live. The
  contract for tomorrow: help_pins.rs's 14 tests, all green in
  the fresh battery. One presentational convention verified as
  deliberate (--download/--upload parse but the docs present the
  interface as -d/-u, the source's own recommendation); the
  display-mangling lesson hit twice more and dissolved at the
  byte level both times. Verdict: consistent, nothing to fix.

- **docs(audit): NIGHT-improve-47 — the supermassive depth tests
  for the private-research-4 features, verified feature by feature
  (docs/audits/NIGHT_IMPROVE_47_SUPERMASSIVE_DEPTH_AUDIT_2026-10-06.md).**
  The owner's seven-feature list (ECN-first policing, per-socket
  tier, time-windowed policies, CAKE-style flow isolation in
  cgroup, snapshot/restore, QUIC-aware mode, guaranteed minimum)
  audited for DEPTH — not the CLI surface improve-42 pinned, but
  the behavioral law underneath: every feature mapped to its Rust
  pin files with the test names read for behavior (the ECN budget
  law and the goodput verdict against the drop policer, the
  QUIC conversation lifecycle with every refusal riding the raw
  cookie, the CAKE flow-shape simulation harness, the DRR
  guarantee brackets, the snapshot round-trips including the
  drifted-schema and v23 zero-sentinel documents, the 21+13 time
  window pins, the per-socket convergence closure), the root-gated
  live probes verified present (ect-probe, guarantee-probe), and
  the fresh empirical runs green on this tree: the full battery
  812+48, the v4 surface 155/155 rootless, the engine self-test.
  Verdict: all seven features carry real depth — the division of
  labor coherent (surface in the battery, law in the Rust pins,
  live kernel in the probes and the VM matrix), no feature resting
  on its CLI surface alone, no gaps, nothing to add.

- **docs(audit): NIGHT-depthbore-1 — the cosmic dragon engine
  depth audit, the peak verdict re-verified honestly
  (docs/audits/NIGHT_DEPTHBORE_1_COSMIC_DRAGON_ENGINE_AUDIT_2026-10-06.md).**
  The mandate: read the render-engine lineage the architecture doc
  names — the diff engine (terminal/diff.rs), its raw-fd twin
  (raw.rs), the chroma dragon engine (output/chroma.rs, the
  improve-41 OKLab polar port), and the render layer it drives
  (ebpf/render.rs, the improve-44 fourteen-module split) — and
  report whether the dragon already sits at peak stable ultra-LTS.
  The walk: full line reads with every documented contract checked
  against its implementation (shadow diff, idle fast path, one
  write per frame, the byte-exact crossover, the tall regime, sink
  death, blade-16 allocation stability, the gamut-mapping
  hardening over the cosmostrix source), a risk-pattern sweep
  over the whole engine family (zero unwrap/expect/panic, zero
  TODO/FIXME/HACK, the nine unsafe blocks all narrow documented
  syscall FFI), and fresh empirical gates on the clean tree: the
  full battery 812+48 / 0 failed, clippy clean under CI's own
  RUSTFLAGS="-D warnings" contract (the exact lane that caught the
  improve-44 fixpass round), fmt clean, the flagship binary
  booting v20.0.0. The walk's only alarm — an apparent `#ust_use]`
  syntax error at diff.rs:418 — dissolved under byte-level
  verification: the file carries `#[must_use]` verbatim and the
  mangling lived in the audit tooling's display path, the same
  rendering-quirk class the long-horizon-1 audit documented as
  its `#ap]` ghost; the re-occurrence is evidence the
  verify-at-byte-level discipline stays load-bearing. Verdict:
  peak — every contract implemented where its doc says it is,
  nothing mitigated because nothing needed mitigation, and the
  honest residuals are the documented toolchain/physics limits,
  none of them engine-internal.

- **The supermassive v4 depth audit — the private-research-4
  features pinned at the CLI surface they own
  (NIGHT-improve-42, the owner's seven-feature list, 34 new rows,
  the battery 121 -> 155): three new stages, the command surface's
  persistence pair, and one REAL REGRESSION the depth run caught on
  its first pass.** The audit's division of labor is the contract
  (the same doctrine that split v1 through v4): the TIME-WINDOWED
  policies get the `--during` grammar ladder (stage 10 — every valid
  unit and both bounds parse to the gate across every enforcement
  verb including the block family's bedtime shape, and the wrong
  shapes refuse by category: the unknown unit names the grammar, the
  bounds name their own floors and ceilings, and the removed
  window/date shapes are refused BY NAME, the duration-only
  revision's own wording); the GUARANTEED MINIMUM gets the
  `--floor`/`--ceil` law ladder (stage 11 — the one-spelling law
  both sides, the floor<=ceil<=rate contradictions, the
  removed-direction law, the rate ask, and the legal mixed spelling
  that composes a both-directions floor with per-direction
  ceilings); the PER-SOCKET TIER gets its flag surface (stage 12 —
  `--per-socket` and `--no-probe` parse to the gate on the one verb
  that owns them, and the group verb's parse-boundary refusal is
  pinned so the tier flag can never silently widen); and
  SNAPSHOT/RESTORE join the command surface (recognized verbs whose
  own privilege refusal names the sudo ladder — the COMMANDS rows'
  recognized proof in the pair's own shape, plus the
  no-extra-positionals parse refusal). The three automatic lanes —
  ECN-first policing, CAKE-style flow isolation, QUIC-aware
  attribution — have NO CLI surface by design (kernel-side, no
  flag, no opt-out), and the audit says so where the battery's
  documentation lives: their depth stays where it already is (the
  Rust pin suites, the root-gated live probes ect-probe.sh and
  guarantee-probe.sh, v1's VM matrix). Every valid-shape row is a
  rootless-lane row (the Z9 doctrine: a valid policy shape past a
  passing gate is an enforcement attempt the battery refuses to
  make; the rootless CI leg carries them on every push, the VM's
  root init skips them), and the refusal rows hold under every uid.
  The typo ladder grows the new grammar's own near-misses
  (`--durign`/`--flor`/`--cel` carry their tips). THE CATCH: the
  first full run failed the pre-existing `--check-updat` row — the
  improve-40-b bracket family had put `--ceil-upload` in
  strict-single's suggestion pool, and clap's local pool (which
  never carries the root-level flags) fired a 0.78-confidence
  `--ceil-upload` for the 0.97-confidence `--check-updat` typo,
  shadowing the right tip the silent-fallback path would have
  given. The fix is the shadowed-suggestion rescue
  (cli/ux.rs::rescue_shadowed_suggestion): when clap fires its own
  UnknownArgument tip, the rescue re-scores BOTH candidates with the
  one case-insensitive Jaro metric and keeps the better tip —
  strictly greater wins, a tie keeps clap's (its pool knows the
  subcommand's flags), and an authority winner redirects to the
  top-level spelling (`zelynic --check-update`, honest about the
  position where the flag actually parses). Two Rust pins hold the
  rescue (the authority redirect lands, the subcommand-flag typos
  keep their own tips), and the battery's row is the end-to-end
  proof. Verified rootless: 155/155 on this tree, self-test green.

- **The chroma dragon engine — src/output/chroma.rs, the OKLab polar
  color core ported from the mature cosmostrix
  (NIGHT-improve-41, the owner's "better high quality monitoring
  output colors" ask): TrueColor frames now render the eagle-eyes
  rail gradient in the perceptual space, with the legacy color
  ladder as the documented fallback for every system that cannot
  represent truecolor.** The port is cosmostrix's sole production
  gradient path (its `chroma_dragon_engine/gradient/`, the v30
  decision): every sRGB -> OKLab -> sRGB conversion with Ottosson's
  reference constants verbatim, the polar (chroma + hue)
  interpolation that rotates hue through the shortest arc instead
  of cutting through the desaturated cube center, and the blend API
  the rails call per row. The port's own hardening over the source:
  a HUE-PRESERVING gamut mapping (`oklab_to_srgb_mapped`) — an
  out-of-gamut blend reduces its chroma to the sRGB boundary with
  lightness and hue held exactly (the CSS Color 4 oklch mapping
  discipline) where cosmostrix's per-channel clamp lets the hue
  drift (the port's own pins caught it live: the brand purple at
  42% lightness clamps the green channel negative and the hue
  shifts 0.1 rad; the mapped anchor lands on the pinned bytes
  (52, 0, 89), the same hue with as much chroma as the gamut can
  carry at that lightness). The ramp's floor changes domain with
  the engine: the chroma path's dark anchor is 42% of the brand's
  OKLab LIGHTNESS (perceived brightness — the same hue, honestly
  darker), while every legacy rung keeps the encoded-channel 0.42
  multiply it always had. The chroma-first/fallback contract, the
  owner's wording: PRIMARY chroma wherever the terminal can render
  what the engine computes (TrueColor), fallback to legacy colors
  byte-for-byte where it cannot — the 256-color quantization, the
  16-color flat SGR, and the Mono glyphs are the pre-port bytes,
  and the A/B record proves it (the Mono pair is byte-identical at
  1,919.0 bytes/frame; the TrueColor pair carries the engine's
  honest price, fps -2.0% on the synthetic 10s blast — about
  3.3 microseconds per frame against a 1-second cadence). The
  engine's anchor derivation is hoisted per frame (one
  scale_lightness per wrap, not per row — the first A/B measured
  -8.4% before the hoist, the residue is the per-row blend alone).
  Nine rootless pins (test/output/chroma_tests.rs): the round-trip
  ±1 law, the pinned brand OKLab triple (the constants tripwire),
  endpoint preservation with clamp, the polar saturation law on
  opposing-hue pairs, the gray-endpoint Cartesian fallback, the
  anchor's hue/L/chroma laws with the pinned bytes, the gamut
  mapping's own direct-path and boundary laws, the same-hue
  sweep's no-drift law, and the lightness ramp's monotonicity. The
  border pins carry both engines side by side (the legacy sweep
  unchanged, the chroma sweep over the perceptual anchor, the two
  anchors' difference documented as the change itself). QA.md Q8's
  inheritance list updates with the port (the cosmic dragon's diff
  discipline and now the chroma dragon's gradient discipline; the
  crystal dragon's ambient-mood concern still does not apply — a
  monitor's palette follows the user's theme, not the system's
  mood), and USAGE.md documents the user-facing contract.

- **The guarantee live probe — scripts/bench/guarantee-probe.sh: the
  per-leaf floor/ceiling bracket measured in REAL cgroups on the
  running kernel (improve-40-b, the owner's root-gated-battery
  ask).** The rootless battery pins the arithmetic on the sim
  engine; this harness pins the KERNEL side on the real cgroup tree
  the lane was built for: four REAL leaf cgroups under one
  bracketed target (the DRR lane's own unit — a leaf cgroup, never
  a bare process), every leaf blasted past the budget through its
  own counted drain, and six verdict rows — the instrument
  (rootless --self-test: the leaf machinery itself round-trips
  without root or policy), the floor's promise per leaf (every
  leaf's delivered volume at or above the floor's share of its OWN
  measured window, the BAND_LO slack the refill cadence earns),
  the ceiling's cap per leaf (the floor==ceil geometry pins every
  leaf between the bracket's two sides), the pool law (the sum
  inside the refill x window + the shared burst — the bracket
  redistributes, it never creates), the per-direction split's
  ledger row (improve-40-b live: download_floor_bps present with
  the merged floor_bps honestly ABSENT, read off the row the kernel
  is actually enforcing), and the split's floor holding per leaf
  on the download-only leg. The honesty contracts ride the
  ect-probe discipline: sender sockets created before any move
  (sk_cgroup_data pins the unpoliced root), leaf receivers created
  AFTER their move (each pinning its own leaf cgroup), the go byte
  AFTER the policy stands (the blast never races the attach), and
  teardown best-effort. The live lane needs root (a root host or
  the sandbox micro-VM); the rootless instrument lane is the CI
  shape, green on this tree.

- **The per-direction guarantee spellings — `--floor-download` /
  `--floor-upload` and the `--ceil-` twins (improve-40-b, the
  owner-approved lane to the bracket's peak: the asymmetric link's
  own bracket; no schema change — v24 already stores floor_bps /
  ceil_bps on every direction's row, the split rides the fields the
  way the rate rows always have).** One spelling per side: the
  both-directions flag and its per-direction twin refuse together
  (a combined `--floor 100kb --floor-download 200kb` is a mis-typed
  rate, not a wider guarantee — the resolver's one-spelling rung,
  pinned), and a per-direction side whose direction the invocation
  REMOVES (no `-d` rate, so no download row) refuses outright
  before the root ask, the improve-29 removal law named in the
  wording — a guarantee for a row that will not exist is a mistake,
  not an intent. The validation ladder judges the contradiction and
  the never-binding sides PER SET DIRECTION (floor <= ceil <= rate
  on each row that will exist; cross-direction freedom — a download
  floor never consults the upload rate). The read surfaces carry
  the split honestly: `status` renders the one-flag line unchanged
  while the pairs are equal and direction-prefixed halves when they
  differ (`guarantee: dl floor 100.0 KB/s ceil 300.0 KB/s / ul
  floor 50.0 KB/s ...`), only the set halves named; the JSON keeps
  the merged `floor_bps`/`ceil_bps` for the equal shape and rides
  the split on additive `download_floor_bps` /
  `download_ceil_bps` / `upload_floor_bps` / `upload_ceil_bps`
  fields, the merged pair honestly absent when the directions
  differ — never a fabricated merge; the persistence pair collapses
  PER DIRECTION (each leg's entry feeding its own direction's
  pair), so an asymmetric snapshot restores as the asymmetric
  policy it captured. The flags ride the whole strict family
  (single, multi, all — one spelling per side everywhere), the
  kernel side needs nothing (the row's own fields, read per row),
  and the guarantee battery's law pins stand unchanged beside the
  resolver's new wording pins (the one-spelling and
  removed-direction rungs pinned fresh, the mixed spellings'
  per-side composition included — a both-directions floor beside a
  per-direction ceiling never collides).

- **The guarantee brackets — `--floor` / `--ceil` (improve-40,
  schema v24): the DRR pool's fair split gains per-subprocess
  min/max brackets, floor/ceiling + hierarchical borrowing (the
  HTB rate/ceil idiom carried into a policer that cannot queue —
  HFSC-lite, the close of the DRR arc).** The Policy row itself
  grows `floor_bps`/`ceil_bps` (24 -> 40 bytes, the FIRST
  value-size change a schema bump ever carried — the reload the
  bump forces is required, not polite; re-apply active limits
  after upgrading, the same one-time contract as every bump).
  `--floor 100kb` guarantees every subprocess under the target at
  least 100kb however greedy its siblings; `--ceil 300kb` caps
  every subprocess at 300kb even when its siblings are idle — and
  binds a lone subprocess too. The floor is a PRIORITY, not a
  reservation (an idle leaf costs nothing; the pool's own
  accumulation is the lender — the hierarchical borrowing with no
  carve-out and no daemon); the ceiling tightens the banking
  stockpile to its own quantum. The zero sentinel is unset on both
  sides: a 0/0 row is the exact v23 arithmetic (the fail-open
  posture — the bracket composes onto the v16/v17 laws, proven by
  the ledger/highload batteries standing unchanged). One flag sets
  both directions; validation (floor <= ceil <= rate per set
  direction, the per-socket scope rejection) rides the
  parse-before-execute ladder; `status`, the verbose trace, the
  JSON (`floor_bps`/`ceil_bps`), and the persistence pair all
  carry the bracket (a v23 state file restores as the unset
  sentinel). The law's own first draft was caught by its battery
  before any kernel saw it: the unset ceiling's zero sentinel read
  as a clamp to zero and every split collapsed to 0 — the
  zero-bracket pin failed in exactly the shape it exists to fail
  in. Over-subscribed floors (the sum above the refill) degrade to
  the pool law with the quietest keeping the unfloored no-starve
  bound — pinned rootlessly by the new guarantee battery
  (drr_guarantee_tests.rs) and the shared sim engine it shares
  with the ledger family (drr_sim.rs).

- **The unified `--during` time windows (night-during, schema
  v23, NIGHT-private-research-4's Tier A candidate — the owner's
  unified-grammar decision: one flag, three shapes, UTC
  everywhere).** A policy row may now carry its own lifetime:
  `--during 09:00-17:00` (a recurring daily UTC window, wrapping
  midnight — the bedtime shape), `--during 2026-10-15` (the whole
  named UTC day, dormant until it arrives), or `--during 2h` /
  `--during 20d` (a duration from apply: units s, m, h, d, mn, y;
  bounds 1s..10y; months 30 days, years 365). The KERNEL decides
  when the window is over — no daemon, no cron: SPAN rows store
  wall instants pre-translated into the monotonic clock
  (drift-free under NTP slew and manual clock steps; the stated
  residue is suspend), DAILY rows read the wall through a
  pinned one-entry offset Array every zelynic visit re-stamps,
  with a 2s both-edges margin that can only fail toward LESS
  enforcement. The gate is one side-map read on the policed path
  only (the unlimited fast path pays nothing — the NIGHT-lts-2
  law verbatim); an inactive window answers ALLOW until the lazy
  sweep (every later apply collects ended spans through the
  unstrict/reclaim machinery) reclaims the row. The flag rides
  every enforcement verb (strict-single/multi/all,
  block-single/multi/all — a bedtime block that lifts itself),
  parses on the fail-fast rung before the privilege ask, and an
  apply without it clears any stale window. `status` renders each
  windowed row's lifetime line (until X, Nm left / sleeps until /
  expired awaiting sweep / daily hours with the verdict) and
  `--print-json` gains the additive `window` field (kind, state,
  the span's WALL instants or the daily pair). snapshot/restore
  carry the window in its WALL-clock form — auto-expire survives
  the reboot it was born for, never converting into forever. The
  verdict core (ebpf/src/during.rs) is pure and rootless-pinned
  (during_tests.rs: the wrap arithmetic, the margin law, the
  monotone-erosion safety property; during_user_tests.rs: the
  grammar's refusal family, the twin grid, the persistence
  round-trip).
- **The ECT live probe — scripts/bench/ect-probe.sh: the per-socket
  lane's ECN marking proven on the running kernel
  (NIGHT-private-research-4 follow-up, the owner's next-candidate
  pick).** The rootless fleet sims (ecn_tests.rs,
  ecn_socket_tests.rs) pin the debt arithmetic; this harness pins
  the KERNEL side: real ECT(0) UDP traffic (IP_TOS, QUIC-shaped
  1200-byte datagrams) blasted through a real --per-socket 8kb
  policy, the CE codepoint read back at the receiver through the
  IP_RECVTOS cmsg, and seven verdict rows: the instrument (rootless
  --self-test — ECT(0) survives loopback and the cmsg reads it,
  pinning the setsockopt/cmsg constant pair), the mark landing
  (CE-marked datagrams delivered past the burst — the
  bpf_skb_ecn_set_ce call, live), the debt cap's bite (CE bytes
  bounded by 64 KiB + the window's refill + one packet), the
  Not-ECT control leg (drops beyond the same burst — the helper's
  refusal IS the legacy verdict), the goodput gain (the ECT leg
  beats the control — the local shape of the campaign's ~30%+
  claim), the budget law's closed form (delivered <= burst +
  rate*t + 64 KiB + one packet, measured), and the ledger
  cross-check (the kernel books refusals and rescues). The honesty
  contracts: sender sockets pin the unpoliced root cgroup at
  creation (the datapath attributes by SOCKET, never by task),
  receiver sockets pin the policed cgroup and the pair is
  connected (the early-demux shape the ingress attribution
  resolves; the documented DRR fallback carries the same marking
  law), the go byte releases the blast only AFTER the policy
  stands, and the window is the measured drain-until-quiet clock.
  PERFORMANCE.md's ECN-first law gains the live reproduce line;
  USAGE.md the user-facing one.

- **Schema v22 — QUIC-aware attribution: per-CONNECTION keys for
  QUIC (HTTP/3) traffic on the per-socket and CAKE flow lanes
  (NIGHT-private-research-4 candidate, approved for
  implementation).** QUIC multiplexes many connections over ONE
  UDP socket — the browser shape (Chromium and Firefox share a
  single socket across every QUIC session, demuxed by connection
  ID) — so the socket cookie both lanes keyed by collapsed all of
  them into one bucket: the flow lane's isolation degraded to its
  own measured monopoly shape (2.9:1), and the --per-socket
  promise ("each connection its own budget") silently meant "the
  whole socket shares one" for exactly the protocol that
  multiplexes. The new pure core (ebpf/src/quic.rs, the
  math.rs/ecn.rs discipline — core-only, #[path]-wired into both
  trees) parses RFC 9000 v1/v2 long headers exactly (explicit CID
  lengths, stateless keys) and learns the short header's
  connection-state CID length from the handshake's own length
  bytes into two new pinned LRU maps (quic_cid_hint_dl/ul, shared
  across both hooks by object construction), gated by a
  CONFIRMATION rule — the same nonzero length must survive a
  second long-header sighting before any short header keys on it,
  so the throwaway Initial DCID a peer replaces after its Server
  Initial can never poison the lane alone. Every refusal (non-UDP,
  non-QUIC, unparsable, unconfirmed, zero-length CID, IPv6
  extension headers) rides the RAW COOKIE, the exact pre-v22
  verdict: the feature refines attribution, never degrades it. Ten
  rootless pins (test/ebpf/limiter/quic_tests.rs): the strict-shape
  refusals, the hint state machine, the direction symmetry (the
  mirrored egress/ingress views of one conversation share one hint
  key), the IHL/IPv6 parse laws, the full handshake lifecycle with
  three distinct CID lengths (transients never activate), and the
  N-connections-one-cookie isolation property. PERFORMANCE.md
  gains the QUIC-aware attribution law section (the honest
  residues stated: the 8-byte CID prefix share, mid-flight CID
  rotation, the server-role transient); USAGE.md documents the
  user-facing behavior (automatic, no flag, restores CAKE
  isolation for HTTP/3). No existing struct layout changes; the
  bump forces pinned v21 programs to reload into the QUIC-aware
  object — active limits are dropped once, re-apply after upgrade,
  the same one-time contract as every bump before it.

- **The ECN-first budget law section — docs/PERFORMANCE.md gains the
  law its siblings already had (NIGHT-audit-1's docs find).** The
  private-research-4 family's two other laws — the guaranteed-minimum
  law and the CAKE-shaped flow-isolation law — each landed in
  PERFORMANCE.md's law block the session they shipped, but the
  campaign's ranked #1 innovation (ECN-first policing, schemas v19
  and v21) had its budget law living only in ebpf/src/ecn.rs's
  module doc, docs/USAGE.md's operational view, and
  docs/KERNEL_COMPATIBILITY.md's helper contract — the closed-form
  bound, the debt cap's GSO-admit-floor rationale, the call-site
  law (the allow-path pay that keeps a CE-ignoring hammer at
  drop-lane parity instead of starving the lane below policy), and
  the per-socket fleet closure (N x per-connection, no collapse
  term) had no row in the doc readers open for exactly those laws.
  The new section carries the invariant chain verbatim
  (delivered <= rate*t + burst + 64 KiB), the two-wave shipping
  history (v19 cgroup lanes, v21 the per-socket closure), the pins
  inventory (14 rootless rows across ecn_tests.rs and
  ecn_socket_tests.rs, counts verified against the tree before the
  claim), and the DRR lane's pool-stream pay posture — the faucet
  every leaf and flow draw through.

- **Schema v21 — the per-socket convergence closure: the per-socket
  lane joins the ECN-first family, mark before drop per connection.**
  The v19 ECN-first lane shipped every budgeted lane's marking EXCEPT
  the per-socket one, deferred on a named question (ebpf/src/ecn.rs's
  scope note): "a server's N connections each halving their windows
  on per-connection marks is an aggregate-collapse shape that needs
  its own convergence analysis before it ships." The analysis ran
  rootless the house way BEFORE the wiring — the fleet sims in the
  new test/ebpf/limiter/ecn_socket_tests.rs: N connections on one
  tick clock (the synchronized worst case the fear named), each with
  its own credit stream and debt word. The answer: per-connection
  budgets are independent, so each connection converges on its own
  stream and the aggregate rides N x per-connection with NO collapse
  term — the fleet's aggregate stays above 90% of N x rate while
  every connection sits inside its own budget law, the marking fleet
  beats the same fleet under the per-socket drop policer (the lane's
  shipped shape, windows collapsing with retransmit debt), and a
  CE-ignoring hammer on one connection stays inside its own budget
  law while its neighbors converge untouched. The wiring: the debt
  word lives INSIDE SocketBucket (now 40 bytes: core, gen_stamp,
  ecn_debt) instead of the budget-keyed debt map the cgroup lanes
  ride — per-connection state in the per-connection bucket, the u64
  cookie keying unable to carry the generation prefix the map
  family's repair-6 discipline rides, and the generation belt zeroes
  the debt with the tokens on a policy mutation (a fresh budget
  never inherits the predecessor's debt, structural); the LRU ages
  the whole bucket out together, one posture. The rescue runs inside
  the lane (one map lookup, the helper binding reached through the
  crate root), the debt pays on the allow path only out of the
  stream's leftover (the ecn.rs call-site law verbatim), and the
  budget law is the closed form unchanged — delivered_i <= rate*t +
  burst + one 64 KiB super-packet, so the aggregate honest bound is
  N x that (the lane's documented "rate x concurrent sockets" shape
  plus the one-time per-connection ECN slack). Non-ECT traffic (the
  RFC 3168 majority) refuses the helper and drops exactly as before
  — the legacy verdict, untouched. Schema bump v20 -> v21 in both
  halves (the kernel const, the userspace mirror, the types pin);
  the ebpf-prebuilt/ objects and manifest regenerated (the limiter
  object 55,992 -> 57,480 bytes); docs/USAGE.md's per-socket
  section and docs/KERNEL_COMPATIBILITY.md's helper section carry
  the contract.

- **The quick-row closure v2 — the claims engine's GIL was the quick
  lane's real throttle (the live CI verdict on the first closure, and
  its close).** The first quick-row fixup (below) shipped settle and
  midpoint sampling; the four-leg Supermassive verdict came back with
  three legs red anyway — no-daemon 41.9%/47.6%, per-app 30.3%/34.0%,
  precision TCP 62.2%, token error 37.682%/8.04%/7.89% — and the
  "sampling jitter" residual story live-disproven: 37.682% is not
  jitter. The A/B that pinned the mechanism ran itself on those very
  legs: the limiter matrix's rate rows read 109.0% at 100mb and
  101.5% at 2mb on the same commit, same kernels, same single-flow
  discipline — while the claims rows read 62.2% and 30.3%. The one
  structural difference was the traffic engine: the matrix's client
  is a decoupled worker subprocess; the claims harness ran the data
  SOURCE as a thread sharing the harness process's single python GIL
  with the measuring client thread — and under a policer that drops
  (never queues), a GIL-coupled pair on a shared runner cannot feed
  the rate. The server is now a worker subprocess (raw-string body,
  the NIGHT-improve-13 discipline; READY handshake; port-race retry;
  reaped on stop; the child inherits the spawner's cgroup so the
  1:1 ingress-hook accounting keeps its shape), the witness blast
  stays self-contained inside its own worker, every measured rate
  row (no-daemon, per-app, precision TCP) rides the lib's one-sided
  `patient_rate_window` with the cushion `redrain` between samples
  (the matrix's own contract: in-band stops, over-band fails now,
  all-under fails after the attempts, every sample printed in the
  row detail), and the precision token row re-attempts its whole
  (settle + window) shape under-side bounded — the settle pays any
  banked cushion before the next window reads (the rider-L
  discipline), an over-band error fails on the attempt that produced
  it, and every attempt's error rides the row detail. The honest
  residual is now named for what it is: the instrument's own floor.
  Three new engine self-test pins (decoupled subprocess source, raw
  server body, reaped-on-stop, one-sided patience) — 28 rows green
  rootless; the four-leg live quick battery is the verifier of
  record. docs/CLAIMS_VERIFICATION.md carries the corrected residual
  story and the GIL find.
  [Round 3's verdict on the fix: the GIL close turned the three
  rate rows green on all four legs; the token row's two leftovers —
  a single flow's AIMD ceiling (95-96% of the rate on shared
  runners, patience cannot lift a source's own ceiling) and an
  unpaid-settle cushion remnant reading as phantom over-admission
  — closed by the quick-row closure v3: the precision instrument
  is now a 4-flow aggregate (the matrix's own high-rung law —
  "the aggregate, not one AIMD flow, is the instrument there") and
  the settle is provably paid (the fleet moves one default_burst
  before the first counter read, the drain_cushion contract). One
  CI round also burned on a band_check call mixing the positional
  and keyword spellings of its extra — a TypeError the rootless
  gates cannot see, because the self-test pins source text and
  never call-site execution; the self-test now executes both legal
  spellings as functional rows, 32 green.]
  [Round 6's verdict on v3: the provably-paid settle closed the
  over-side everywhere and the quick battery went fully green on
  best-musl; the token row's remaining under-side (4.0-6.1% on the
  other three legs) is the TOKEN BANK's own physics — the cushion
  is one default_burst, the AIMD dips bank tokens while the
  overshoots drain them, so admitted = refill - dBank and a window
  reads off by up to one burst: burst/(rate x window) = 10% at the
  quick 10s window, identical across one flow and the four-flow
  aggregate. The quick-row closure v3 (bcb3466) named the
  aggregate-instrument law; the derived bound (accounting_bound)
  closes the lane honestly: the PASS bound is the estimator floor
  plus the bank floor, printed with its derivation by the row, and
  the 0.00% CONTRACT stays untouched — the floor is the
  instrument's, not the limiter's.]

- **The two quick-mode claims rows closed — the measurement harness
  was the bug, not the enforcement (the quick-row fixup).** The CI
  claims battery runs `proof-claims.py --quick` on every qualifying
  push, and two of its rows failed on short windows for reasons the
  full-mode matrix never saw: the no-daemon row measured 43.5% of
  its configured rate and the precision row measured a 4.9% error
  against its 2% bound. Both diagnosed to harness physics. The
  no-daemon row's 4s quick window was measuring a COLD policer —
  the first epochs of a fresh attach are the startup transient
  (the flow bucket banks its carry epoch by epoch while TCP backs
  off its first losses), which the full 8s window amortizes and the
  quick window drowns in; the quick lane now settles past the
  transient (NO_DAEMON_SETTLE_QUICK, 2.0s unmeasured) before its
  measured window — the precision stage's own PRECISION_SETTLE
  discipline, because the row claims enforcement-alive steady
  state and steady state is what it measures. The precision row's
  estimator timed t0 after the first status-read spawn and t1
  after the second, making elapsed = window + spawn latency — a
  pure estimator bias the 30s full window amortized (0.069% on the
  cross-distro runs) but the 10s quick window exposed at 4.9%
  while the limiter itself stayed exact; the estimator now samples
  the kernel counter at each spawn's MIDPOINT (the unbiased
  estimator of the sampling instant), so the latency cancels on
  both ends and the printed residual becomes the sampling jitter
  the bound was always meant to judge. Both laws pinned rootlessly
  by new engine self-test source pins (25 rows green); the live
  quick battery on the four CI kernel-span legs is the verifier.
  docs/CLAIMS_VERIFICATION.md's claim-4 row and the honest
  residuals carry the updated residual story. [The jitter half of
  this entry's residual story was later disproven by the live legs
  and closed by the quick-row closure v2 above — the settle and
  midpoint laws stand.]

- **Actions-pin health `auto` mode — skip-if-latest silence plus a
  contributor-carried auto-heal (NIGHT-improve-40 fixup 1, the
  write seat of the actions-pin health contract).**
  `git config zelynic.actionsHealthCheck auto` (or the
  `ZELYNIC_ACTIONS_HEALTH=auto` one-shot) buys two behaviors on the
  commit-time pin check: a current verdict exits 0 with zero output
  (warn/strict keep their one-line report), and a clean-behind
  verdict (fully parsed; the rc=2 indeterminate class never heals)
  re-verifies cold — a 6h-old cached behind is not a write mandate
  — then runs `actions-version-sweep.sh --apply` under its own
  budget (`ZELYNIC_ACTIONS_HEAL_TIMEOUT`, default 60s), stages
  `.github/workflows/` into the index, and fails the commit ONCE:
  review `git diff --cached`, re-commit, and the re-commit reads
  the healed pins as current and stays silent. No auto-amend, no
  push, no standing credential — the manual flow's
  maintainer-review discipline is kept whole, only its typing is
  removed. The safety proof is delta-shaped: the sweep's own
  guard_diff compares the whole tree against HEAD and would flag
  the contributor's staged work at pre-commit time by design (its
  contract is the manual heal on a clean tree), so the auto path
  snapshots the changed-file set and the non-workflow patch hash
  around the apply, accepts the heal only when the sweep provably
  reached its write stage (the verdict line or guard_diff's own
  FAIL marker — both print only after apply_edits ran), and
  restores the workflow files from a pre-apply backup on every
  failure shape — API drop mid-apply, overrun, out-of-bounds
  write, unparsable result — before falling back to the warn
  table. Honest trades: one re-commit per heal event (the price of
  review discipline), and a 6h cache window that can delay a heal
  by at most 6h (the same slack the read side always carried).
  check-commit-gate.sh's FAIL wording, CONTRIBUTING.md, and
  docs/MAINTENANCE.md section 5 carry the contract.

- **Schema v20, CAKE-shaped flow isolation — the DRR lane's leaf
  stops being one shared bucket for every socket the cgroup
  holds.** The pool arc made the LEAF fair (charger-core-1c /
  dinner-28 / repair-3/4/6/7); the packet-arrival race simply moved
  inside it: a shared bucket is FCFS at packet granularity, and the
  rootless isolation battery measured the honest shape BEFORE any
  kernel saw the lane — the race's victims are the weaker DEMANDERS
  (a second download delivered 524 KB of its 1.5 MB fair share
  under the shared leaf, 2.9:1 against the first; the three-flow
  shape breaks the battery's own anti-monopoly bound at 2.1x fair),
  while the truly quiet flows ride the GRO-granularity banking's
  leftover crumbs and admit either way (the sketched starvation
  does not reproduce — documented, not hidden). The close mirrors
  the DRR laws one level down, keyed by the socket cookie the hook
  already names (zero new kernel helpers): every attributed packet
  spends from its own flow bucket drawing from the leaf under the
  learned flow count, the drawee peak, and the epoch ledger with
  its quantum-capped carry — measured close: 2.9:1 becomes 1.1:1,
  every battery bound holds, and the lone flow keeps the whole
  budget. The CAKE signature rides the take law: a flow quiet for
  an epoch draws its packet's OWN bytes (the reserved small
  quantum — measured zero stranding, takes == deliveries byte for
  byte), a flow drawing this epoch takes the quantum. Two design
  catches the battery filed before the wiring existed, both
  load-bearing in ebpf/src/drr.rs's v20 section: the sparse
  evidence is the flow bucket's draw STAMP (a ledger-anchored test
  leaves a lone ledger-off flow reading sparse forever — a bulk
  flow of small packets would draw per packet), and the OFF lane's
  take is the learned-share FRACTION leaf/(learned+2) (the share
  word's peak decay reads MAX for the epochs between a decay and
  its re-ratchet — a lane-law-only take there drains the leaf whole
  once per transient epoch). Six new datapath-internal maps
  (flow_bucket/share/ledger per direction, the leaf_bucket family's
  contract); cookie == 0 rides the leaf lane verbatim; the
  per-socket and strict-multi lanes untouched by documented scope;
  the honest tradeoff stated in docs/PERFORMANCE.md's flow-isolation
  law section (a mixed leaf rides the same 65%-130% band — the
  reservation's cost, bounded). Pins:
  test/ebpf/limiter/cake_tests.rs (the law bounds) +
  cake_isolation_tests.rs (the find, the close, the edges, the A/B
  fingerprint). 717 unit + 47 integration green.

- **The CI battery's catch on 5a3e23a, closed the same session:
  THE SOURCE BUFFER LAW.** The live Supermassive matrix measured
  1411 packets dropped under a NON-BINDING 12 GB/s policy (zero
  before the lane, zero is the row's own law) and the 100kb trickle
  row sagging to 64.8% — one root cause: the dense flow take's
  availability cap drained the leaf WHOLE, so the leaf rode at ~0
  instead of riding HIGH the way it was designed (packet-sized
  spends, quantum-sized draws), and the pool's micro-credit
  oscillation reached every admit decision. The residue law's
  half-split, mirrored one level down, is the close: a dense take
  caps at HALF the leaf (the leaf keeps its admit buffer; the flow
  bucket banks toward its admit across draws the way the leaf
  itself always banked toward the GSO floor at trickle rates); a
  sparse take keeps the whole-leaf right (its demand IS the packet
  — 200 bytes may take the leaf's last 200, the bulk sibling's
  cascade refills behind it). Pinned as a law
  (the_dense_take_never_drains_the_leaf_whole); the rootless
  battery's fairness pins ride unchanged through the fix — the
  buffer law changes the micro-scale the sims do not model, the
  scale only the live kernel can reach. The third design lesson
  this lane paid for, all three engraved in ebpf/src/drr.rs's v20
  section. Two follow-up runs refined the law to its final form.
  f73ecda measured the plain half-split still leaving the take at
  the packet's own order at the micro-credit steady state (1122
  drops, the admit a coin flip at the boundary): the half-split now
  engages only when the leaf holds TWO packets' worth or more —
  below that the take is whole and the admit DETERMINISTIC. 606358a
  measured the last shape: the lone flow's OFF-lane fraction
  (leaf/(learned+2)) under-sized takes at low binding rates — at
  2 MB/s the fraction sits AT the packet's own order, and the
  under-sized take turned every boundary cycle into a
  drop-with-bank that collapsed TCP to 37% of a policy it should
  have ridden — so the OFF lane now carries a PACKET FLOOR (the
  take never sits below the packet it serves when the leaf covers
  it, CAKE's own MTU-floor discipline one level down), conditioned
  on the LONE/COLD shape (learned < 2): a decayed-peak transient
  keeps the fraction (the unconditional floor lifted trickle
  transients to the full quantum, four epochs of allowance per
  draw). Four lessons, all engraved in ebpf/src/drr.rs's v20
  section and pinned in the cake test family.

- **NIGHT-private-research-4, the guaranteed-minimum audit — verdict:
  the DRR pool already carries the full floor/ceiling/borrowing
  contract, so this task ships the owner-facing framing instead of
  redundant code (the owner's own peak rule: don't over-engineer a
  reached peak).** Audited against the shipped datapath before any
  new code: the contending app's guaranteed minimum is the pool's
  per-epoch allowance split across the drawee PEAK (the decaying
  distinct-asker high-water), carried quantum-capped so a starved
  leaf banks toward the 64 KiB GSO admit — the absolute floor at
  tiny shares; the ceiling is the anti-monopoly bound (worst <=
  fair x 1.75 + quantum); the borrowing is work-conserving and
  honest (idle allowances flow to whoever asks through the residue
  law, the lone-active leaf keeps the whole budget, and the pool
  never creates budget — borrowed bytes were saved bytes); the
  handoff re-keys on every policy mutation so a fresh budget
  inherits nothing. Every clause is pinned rootlessly
  (drr_ledger_tests' no-starve, anti-monopoly, collapse-guard,
  lone-leaf, and handoff rows) and proven on the CI battery. The
  framing lives in docs/PERFORMANCE.md's new "The
  guaranteed-minimum law" section, including the honest boundary: a
  per-app floor ABOVE the fair share (a reserved no-borrow lane) is
  a new policy surface the owner alone decides to open.

- **NIGHT-private-research-4, snapshot/restore — "GitOps for
  bandwidth" without a daemon, the owner-approved persistence ask.**
  The pins already survive process exit; what they cannot survive is
  a reboot — bpffs starts empty, and with it every policy. Two
  one-shot verbs close the gap: `zelynic snapshot` serializes the
  live policy census to /var/lib/zelynic/limits.json (atomic
  write, keyed by NAME — cgroup IDs change across reboots; grouping
  re-joins through the map's group id; the per-socket flag rides
  along), and `zelynic restore` re-applies every entry through the
  strict family's own apply machinery (pre-flight, rollback ledger,
  memo invalidation, the attach ladder a fresh boot needs). The
  honesty contract is the strict-all precedent: names not running
  yet are reported as skipped, never silently missed, never an abort
  for the fleet — restore is idempotent and picks up late starters
  on re-run. The snapshot pins the POLICY, not the bucket state
  (tokens, carries, ECN debt are transients the fresh buckets
  re-derive; the burst re-derives from the rate's default law, the
  only value the CLI can write). Both verbs honor --print-json (the
  document IS the state file's JSON); the pure transforms (the
  census join with honest skip naming, the solo/group plan collapse,
  the serde round-trip, the schema-tag refusal) are pinned rootlessly
  by test/commands/persist_tests.rs, and the curated --help plus its
  drift pins carry the pair. Zero new flags; the systemd oneshot
  pairing stays the operator's choice, documented in USAGE.

- **NIGHT-private-research-4, ECN-first policing (schema v19) — the
  limiter that doesn't hurt.** The owner-approved innovation from the
  private-research-4 ranking: the budgeted lanes' drop verdict becomes
  a LAST RESORT. When the kernel helper `bpf_skb_ecn_set_ce` can set
  the CE codepoint on an over-budget packet's IPv4 or IPv6 header
  (ECT-capable, checksum handled by the kernel, exposed to cgroup_skb
  since kernel 5.1 — well under the 5.13 verified floor; helper ID 97,
  triple-pinned against the uapi enum, aya-obj's parser table, and the
  generated bindings the call shape mirrors), the packet is DELIVERED
  CE-marked instead of dropped and its bytes charge an ECN debt word
  in the two new pinned LRU maps `ecn_debt_dl/ul` (keyed by the
  generation-prefixed budget key, the repair-6 discipline). The debt
  is paid back out of the lane's OWN token stream, on the allow path
  only, from the leftover each delivery leaves behind — and that
  call-site placement is the design's load-bearing wall: the rootless
  simulation in test/ebpf/limiter/ecn_tests.rs caught, BEFORE any
  kernel ever saw this code, that a naive pay-on-every-packet form
  drains the token stock toward the debt and starves the lane BELOW
  the policy (a CE-ignoring hammer pins the debt at its cap and turns
  the entire refill stream into debt service). The allow-path pay
  makes the semantics exactly right per sender shape: a CE-reactive
  sender (TCP with ECN negotiated, QUIC with ECT) converges on the
  mark without losing a single packet — the A/B pin shows strictly
  better goodput than the legacy drop lane under identical demand
  feedback, with zero last-resort losses; a CE-ignoring sender sees
  the 64 KiB debt (one GSO super-packet, the drr.rs admit-floor law)
  saturate once and the lane settle into EXACT drop-lane parity —
  never worse than the legacy policer. The budget law stays closed
  for every shape: delivered <= rate*t + burst + one 64 KiB
  super-packet (the ecn.rs proof chain — no time-based decay, so no
  second rate stream a cheating sender could farm). A non-ECT packet
  (the RFC 3168 majority) is refused by the helper and drops exactly
  as before; the per-socket lane keeps its drop shape by documented
  scope (per-connection CE marking is an aggregate-collapse shape for
  servers that needs its own convergence analysis); the rate-0 block
  verdict never rescues (blocked means blocked). The ledger
  correction (math.rs book_rescue) moves a rescued packet's booking
  from the dropped column to the allowed one through the same
  fetch_add lowering the BPF backend provably selects — subtraction
  as two's-complement addition, the AtomicLoad lesson applied
  preemptively. The usual one-time re-apply contract: pinned v18
  programs reload into the ECN-first object, active limits are
  dropped once, re-apply after upgrade.

### Changed

- **feat(gate): NIGHT-improve-44 task d — the LOC law flipped: the
  Rust cap is 600, tree-wide by file type, no exemptions, no
  markers, no mercy; the scripts cap stays 1000 with the policy's
  remedy named — over 1K should split into modules.**
  check-loc.sh autodetects the file type and walks the whole git
  index (git-tracked plus untracked-but-present, so a new over-cap
  file fails before the commit): every *.rs file anywhere — src/,
  test/, ebpf/src/, build.rs + build/*.rs, and any future home —
  against the 600 hard cap. The // LOC_EXEMPT: marker is retired
  for Rust: over the cap means split, the same hour, precision
  kept. The era's proof is the task series itself — the eight
  over-600 files (build.rs 1,475; limiter.rs 1,323; drr.rs 1,014;
  cli/mod.rs 723; quic.rs 694; math.rs 671; commands/mod.rs 622;
  drr_flow.rs 606) all split under this same improve-44, and the
  tree now counts 238 .rs files with zero over the cap; the four
  transitional markers (build.rs, surface.rs, render.rs,
  help_pins.rs — every one under 600 after the splits) are
  deleted, not grandfathered. check-policy.py narrows the same
  way: the rust-marker arm is gone, the hash-marker arm stays for
  the scripts' tracked debt. The scripts gate (check-scripts-loc.sh)
  keeps the 1000 cap and now leads with the split-into-modules
  policy — the six python batteries' markers are honest IOUs
  (13.3k LOC of verification infrastructure; each split is its own
  NIGHT task with its own micro-commit cycle, the RULES.md law
  unchanged). docs/RULES.md and src/RULES.md carry the new law;
  the historical "past the 500-LOC cap" prose in the older split
  notes stays verbatim (those splits happened in the 500 era —
  history, not law).

- **refactor: NIGHT-improve-44 task c — the eBPF five under the 600
  cap: limiter.rs (1,323) carved into the schema ledger, the
  enforcement helpers, and the try_enforce verdict path; drr.rs
  (1,014) split at its own section banners (the epoch ledger, the
  guarantee law, the flow lane's law); quic.rs, math.rs, and
  drr_flow.rs each shed one cohesive family — the prebuilt objects
  rebuilt, same sizes, the parity lane re-pinned.** The split rides
  the #[path]-nested-module + glob re-export pattern the tree
  already set (limiter.rs's own sibling wirings): the moved sections
  re-export through their parent (drr::guaranteed_allowance,
  quic::parse_l4, math::tokens_cas resolve as they always did) so
  every consumer — the bin root AND the rootless test tree's twin
  inclusions — compiled without one call-site edit. limiter.rs keeps
  the maps, the entry programs, and the panic handler (378); schema.rs
  carries the v1..v24 doc ledger and SCHEMA_VERSION (351, the
  userspace sync pin repointed to its new home); enforce_helpers.rs
  the map pointer probes, the ring verdict, the ECN rescue, the
  window gate (280); enforce.rs try_enforce itself (371). drr.rs
  keeps the base and the learned-share draw (438) with drr_epoch.rs
  (164), drr_guarantee.rs (177), and drr_flow_law.rs (279) nested
  under it; quic_l4.rs (170) under quic.rs (542); math_atomics.rs
  (198) under math.rs (494); drr_flow_draw.rs (157) under
  drr_flow.rs (465). The dual-compiled files (the test-tree twins)
  learned the two-rustfmt law the hard way: mixed-case import runs
  cannot be ordered to satisfy both the stable and the nightly
  formatter, so math_atomics.rs globs its parent's namespace and the
  other twins keep same-case runs. The sync pin
  (src/ebpf/limiter/schema.rs) follows the anchor to ebpf/src/
  schema.rs; the architecture pin's core-only twin list grows
  math_atomics.rs. The refreshed prebuilt objects are the same
  sizes (observer 3,216 B, limiter 79,872 B) — the split was
  structure-only and the ELF section sizes say so; the manifest
  re-pins the tree per the parity contract. THE CI CATCH
  (night-repair-2's lesson repeated): the first push of the split
  carried eleven unused-import warnings — imports whose CALLS moved
  to the new modules but whose use statements stayed at the old
  homes — warnings the local build (no RUSTFLAGS) shows and passes,
  warnings CI's RUSTFLAGS="-D warnings" (inherited into the nested
  eBPF build verbatim, the strip-host-poison contract's own words)
  turned into nine red jobs. The fix pass removed every one (the
  aya helper trio, the math five, the rate_ring pair, socket_flow
  and drr_flow themselves, the schema anchor import — the const is
  the parity ANCHOR the userspace sync pin reads as source text,
  never executed — plus the speculative imports the compile-error
  rounds had added ahead of the resolution); the nested build now
  emits zero warnings and the parity lane re-pinned with the
  objects at the same sizes again.

- **refactor: NIGHT-improve-44 task b — build.rs split by its own
  retired plan: the NIGHT-improve-31 phase map executed (validate,
  flags, preflight) plus the vcs chain, the 1,475-line build script
  carved into five files with zero build-dependencies.** The plan
  lived in the file's own header since the improve-31 audit (the
  debt carrying its retirement plan: "the supply-chain argument
  exempts a CRATE split, not a FILE split — a build script is also
  a plain crate root, so #[path]-included modules split it with
  zero new dependencies"); improve-44's 600-era is the trigger the
  plan asked for. build/validate.rs (297 — the NIGHT-hunt-29 ELF
  structural validators and the little-endian readers), build/
  flags.rs (234 — the NIGHT-hunt-28 host-poison RUSTFLAGS surgery
  and the bpf-v3 force), build/preflight.rs (269 — the NIGHT-host-1
  toolchain and PATH probes), build/vcs.rs (138 — the commit-sha
  chain: git, GITHUB_SHA, the registry vcs document, the shared
  normalizer), and build.rs itself as the orchestration spine (485
  — main, the ebpf-object build, the registry prebuilt staging, the
  nested-build driver, the damaged-artifact self-heal, the
  build-time formatters). The test module distributed with its
  subjects (each module carries its own #[cfg(test)] mod), the
  standalone runner contract holds (`rustc --edition 2021 --test
  build.rs` resolves the #[path] modules: 17 passed, 1 ignored, the
  same suite), and the include list grows build/*.rs so a registry
  tarball still builds (cargo package --list verified: the four
  modules ride the tarball beside build.rs).

- **refactor: NIGHT-improve-44 task a — the userspace 600-line cap
  splits: the CLI declaration and the dispatch helpers carved out
  of their over-cap mod.rs units (the no-mercy era's first two
  stones).** src/cli/mod.rs (723, five years of splits landing on
  one file) splits one last time the same way styles.rs and
  scope.rs went before it: the Cli struct and its globals to
  cli/root.rs (140), the Commands enum to cli/surface.rs (578),
  mod.rs left as pure wiring (49 — module declarations and the
  re-exports that keep crate::cli::Cli / crate::cli::Commands /
  super:: call sites resolving identically; the clap grammar byte-
  unchanged, --help verified identical modulo the improve-45
  section). src/commands/mod.rs (622) sheds its dispatch-shared
  surfaces to commands/dispatch_common.rs (185 — the apply-verb
  epilogue, the root gate, the no-match hard-error contract, the
  dormant refusal, the unpin cleanup, and the epilogue/no-match
  pins that test them), the dispatch match itself untouched at
  mod.rs 455 — the one-surface doctrine survives the cap, the
  helpers were never part of it. Both lanes compile clean under
  clippy -D warnings; the full batteries pass (ebpf 812+48,
  dormant 119+43); surface.rs carries the transitional LOC_EXEMPT
  (578 over the 500 era, under the 600 era this task series lands
  with its final commit).

- **docs: NIGHT-improve-45 — the Pro mode section: every hidden and
  advanced flag documented completely on the --help reference.** The
  single-tier help surface carried the globals and the core rate
  grammar, but the advanced per-verb family was hidden by omission:
  the --during grammar and the guarantee bracket family
  (--floor/--ceil and the four per-direction twins) had ZERO
  mentions on the reference — flags the parser accepts that the
  one reference never names, the exact hole the owner's ask
  closes. The new section (between Rate formats and Target
  formats, the same brand-purple heading discipline) groups the
  advanced surface by the verb family that owns each flag: time
  windows (--during DUR, the duration-only law stated with the
  removed window/date shapes named: s m h d mn y, 1s..10y, months
  30d, years 365d), the guaranteed share (--floor the priority
  floor, --ceil the lone-drawer cap, the per-direction spellings
  and their one-spelling-per-side law), the enforcement shape
  (--per-socket, --no-probe), the guard override (--force-this,
  what it lifts), and the deep-inspection knobs (--depth, --focus
  SEC, --interval SEC with their bounds and defaults). The
  completeness is machine-held: help_pins.rs grows
  test_help_pro_mode_documents_every_advanced_flag — a 13-flag
  drift pin (every advanced spelling must appear on --help, plus
  the duration-only law's own line) so a future flag cannot ship
  hidden again; the section-list pin carries "Pro mode:" beside
  the other section headings. The globals stay in their own
  section (unchanged); the hidden internal probe roles stay hidden
  (the hidden-vocabulary contract's security posture is not a
  flag surface).

- **docs: NIGHT-improve-43 — the changelog trimmed to the fresh
  post-v20 record, the v20 era frozen at the release blob.** The
  live CHANGELOG.md carried 10,095 lines with every entry since
  the v11 campaign accumulating under [Unreleased] — the v20.0.0
  release commit (b743d9c, 2026-10-04) bumped the version without
  sectioning the changelog, so the fresh post-release entries and
  the nine thousand lines of era record rode one file. The trim
  splits it the way the file's own header always promised:
  CHANGELOG-V20-ERA.md now carries the v11-line entries through
  the v20.0.0 stable release (the changelog blob as it stood at
  b743d9c — 9,217 lines, the frozen-record class the gates
  exclude together with the live file), and this file carries
  only what shipped after the release: 26 entries, 972 lines,
  [Unreleased] plus the History map. One line of the era blob
  differs from the raw b743d9c bytes — the NIGHT-audit-2
  name-case fix ("the cosmic dragon architecture"; the one-name
  law check-name-case.py machine-enforces, which would refuse the
  frozen file otherwise; the deviation is recorded in the History
  section). The era-file class follows the V11-ERA precedent
  verbatim: no framing header, no disclaimer, the gates' frozen
  record arms extended (check-headers.sh, inject-disclaimer.sh,
  check-language.sh, the gatekeeper's markdownlint excludes and
  emoji skip set, docs/RULES.md's disclaimer law). Entry
  integrity verified by count: 291 `- **` entries before the
  split = 26 fresh + 265 era after, zero lost, zero duplicated.

- **The engine name is one name now — `the cosmic dragon`
  (night-audit-2, the owner's consistency call: from "cosmic
  dragon/etc inconsistency" to one spelling).** The audit found the
  architecture and engine name in four casings across the tree —
  title-case (x27), bare lowercase without the article (x11),
  lowercase name with a capitalized dragon (x3), and the two
  already-correct instances — every prose mention now reads `the cosmic dragon`
  (the engine) / `the cosmic dragon architecture` (the
  architecture): the name lowercase in every context the way the
  name zelynic itself is (BRANDING.md 3.1's nginx/curl law), the
  definite article in prose exactly as the README tagline always
  carried it, the article capitalizing only as a sentence or
  heading's first word. What the law deliberately does NOT re-case:
  the identifier families (`COSMIC_DRAGON_*` consts and filenames,
  the cosmostrix `cosmic_dragon_engine` module paths), the GPG
  signing identity `Rezky Cahya Sahputra (cosmic dragon)` (real
  key data), cosmostrix's own artifacts quoted verbatim (the
  "Cosmic Dragon Guard - Release" workflow name), the retired `-V`
  literal `Architecture: Cosmic Dragon (pure eBPF)` (byte-exact
  history), and the owner-approved voice fragments ("cold, silent,
  cosmic dragon" — a motto, not a noun phrase). The law is
  codified as BRANDING.md 3.3 and machine-enforced the same hour:
  `scripts/gates/check-name-case.py` (the zelynic name gate) now
  scans the two-word phrase on the same every-tracked-file
  discipline, self-clean by building its own literal exceptions at
  runtime — the gate's first run caught the two instances the
  manual sweep missed (QA.md's engine bullet, the README doc index
  link), the proof the enforcement earns its seat. The ecosystem
  list rides the same law (QA.md Q8: cosmic dragon, chroma dragon,
  crystal dragon — the owner's three engines, lowercase together).

- **`--during` is duration-only (the owner's revision of the
  night-during grammar): the flag takes ONE shape — a duration
  from the apply instant, `<N><unit>` with units s, m, h, d, mn, y
  and bounds 1s..10y (`--during 1h` auto-expires after one hour,
  `--during 20d` after twenty days; months 30 days, years 365,
  the fixed-calendar contract unchanged).** The window form
  (`09:00-17:00`) and the date form (`2026-10-15`) are refused at
  parse time, the wording naming the removed shape and the
  duration that replaced it — the simplicity the owner asked for:
  no more `09:00-18:00/2026-10-15`, support only the timer. What
  deliberately does NOT change: rows written by older builds keep
  their promised behavior (the kernel verdict core's read-side
  belt still honors the DAILY and SPAN kinds — a pinned map is
  never narrowed by a grammar change), and `restore` still
  re-translates a state file's wall-form windows verbatim, so an
  auto-expire promise survives the revision never converting into
  forever. The parse no longer reads a wall clock (a duration
  needs none, so the parse-before-execute ladder lost its one
  impure rung); the grammar pins flipped with it — the removed
  shapes refuse by name in during_user_tests.rs, and the restore
  lane's translation pins stand unchanged beside them.

### Fixed

- **docs: NIGHT-gate-1 — the wholesale gate's red markdownlint
  lane, two audit docs' rendering hazards, closed without
  touching their facts.** The last three Gate-keepers runs
  (466-468) failed exactly one gate: markdownlint, on lint debt
  two older audit docs carried — every push since their landing
  reddened the wholesale workflow while the supermassive and CI
  legs stayed green, the quiet kind of red that trains the eye
  to ignore the badge. The two shapes, each fixed at the root,
  not by the auto-fixer (whose mechanical edits would have
  CHANGED the facts the docs exist to carry — stripping the
  four leading spaces the hex value proves, and glueing the
  probe pair's comma): NIGHT_DEPTHBORE_1's code span with
  leading spaces (MD038) becomes an HTML code element with
  explicit no-break spaces — the hex string beside it still
  names the four 0x20 bytes, the visual now shows them too;
  NIGHT_IMPROVE_46's bare double-underscore pair (MD037 —
  markdown read the probe names as bold markers, the same
  misrender GitHub itself would show) becomes two proper code
  spans, the names rendering as the literal identifiers they
  are. Verified locally with the CI-pinned
  markdownlint-cli2@0.18.1: the whole docs/audits/ tree reads
  24 files, 0 errors; codespell clean; the wholesale gate's one
  red lane is gone.

- **ci: NIGHT-repair-2 — the audit commit's own CI red, two
  regressions the local gates' skip lanes had hidden.** The
  night-improve-42 commit landed with its check-all and
  Gate-keepers legs red on GitHub while the tree looked green
  locally, each failure hiding behind a lane the local run skips:
  the dormant-lane test compile
  (`cargo test --no-default-features`, run_tests' own posture)
  left the new rescue_tests module compiling to nothing but its
  glob import — both pins inside are `#[cfg(feature = "ebpf")]`,
  so without the feature the module's only remaining item was the
  `use super::*` — and the CI leg's `RUSTFLAGS=-D warnings` turned
  that unused-import warning into the error that failed check-all
  (the local run has no such env, and the dormant-lane warning was
  cached silently after the first pass). The fix is the
  rates_shadow_tests precedent (commands/rates.rs, NIGHT-hunt-Z9):
  the module include now reads `#[cfg(all(test, feature = "ebpf"))]`
  — a module whose every pin is feature-gated joins the tree only
  when its pins do, and the comment above the include names the law.
  The second red was ruff F541 in the v4 battery's own runner
  (supermassive-test-v4.py:889): one f-string with no placeholder
  on a record() call the audit added — CI installs ruff 0.16.8,
  the local gate-keepers run had skipped it (ruff absent), so the
  one-character fix (drop the `f` prefix) never got the chance to
  be caught before the push. The best-specs legs' claims-proof
  failure on the same commit is NOT a code regression: the
  precision row's error (30.6% vs the 12% bound) is the live
  instrument's AIMD floor on that day's runner — the same row
  passed at 5458ccc (10.5%) with the identical kernel bytes, and
  the intervening commits touched docs, tests, and output colors
  only; the re-run is the verdict, not the code.

- **The restore's unreadable-window swallow (night-during-7's
  honesty catch, found in the duration-only revision's review).**
  `restore_plan` built each step's window with
  `during.as_ref().and_then(window_persist_to_spec)` — and a
  `during` form whose `kind` was neither "span" nor "daily"
  (a hand-edited or corrupted state file) made the pure half
  answer `None`, which the `and_then` swallowed into "no
  window": the row restored as a FOREVER-limit, silently
  dropping the auto-expire promise it carried — exactly the
  "auto-expires into forever" inversion the design brief's
  safety direction forbids (the executor's own comment promised
  "never converting into forever"; the wiring betrayed it for
  the one unreadable shape). The restore now validates every
  `during` form BEFORE the plan (`validate_persisted_windows`,
  the unknown-TAG posture one entry over): an entry whose kind
  the restore family cannot re-translate REFUSES the restore
  naming the row and the kind, never a best-guess parse and
  never a silent forever. Pure, rootless-pinned beside the tag
  refusal it mirrors (an_unknown_window_kind_refuses_the_
  restore_naming_the_row).

- **The future-date span that never slept (night-audit-1 task 17 —
  the dormancy law's translation hole, the depth review's own
  find).** Since night-during-4 landed the userspace half,
  `--during 2026-10-15` applied before that day translated its
  future start broken: `during_to_window` computed
  `start_mono = mono - saturating(wall - start_wall)`, and with a
  future start the inner subtraction saturates to zero, collapsing
  `start_mono` onto the APPLY instant — the row enforced from the
  moment it was applied and kept enforcing until the day's end
  instead of sleeping until the day arrived. A `--during
  2026-10-15` applied nine days early policed for ten days
  straight: the over-enforcement direction the FIRE_EARLY margin
  law exists to forbid. `span_dormant`, the "sleeps until" status
  line, and the probe's dormancy note could never trigger on a
  freshly applied date because no translated row was ever dormant.
  The parse family, the kernel verdict core, the sweep, and the
  persistence round-trip were all correct — the bug lived in the
  one translation every apply-family caller shares (policy.rs
  apply_single/apply_group, atomic.rs). The fix splits the
  direction: a future start translates FORWARD
  (`mono + (start_wall - wall)`, saturating) while a past start
  keeps the backward clamp-to-boot shape; the restore path heals
  through the same line (window_persist_to_spec re-translates via
  a fresh bridge, so a restored future date sleeps too). Pinned in
  during_user_tests.rs (future_date_span_sleeps_until_its_day: the
  start lands 9 days out, the row is dormant at the apply instant,
  the end is unchanged) beside the past-start and pre-boot clamps
  that were already pinned.

- **The `policy_window` read that refused every fresh apply
  (night-audit-1 task 16 — the supermassive battery's catch, the
  second live find of the 5.13 floor lane).** Since night-during-3
  landed schema v23, every strict-*/block-* apply on a cgroup with
  no window row died at the mutation ledger's pre-apply read:
  `failed to read cg:N policy window: key not found — apply rolled
  back (2 partial policies)` — six supermassive probes down (the
  limiter matrix, the AMMSP delta, the survival battery, the
  reload and race rigs, claims proof), all four legs, the same
  root. The forensic: aya 0.14's `HashMap::get` on an absent row
  NEVER produces the `SyscallError(ENOENT)` the shared
  `map_remove_means_absent` predicate matched — the sys layer
  folds the lookup syscall's -ENOENT into `Ok(None)` and the map
  layer surfaces `MapError::KeyNotFound` — so the night-during
  read path inherited a classifier written for the DELETE shape
  alone (the loader's socket-counter reads already knew the
  KeyNotFound law; the limiter's shared predicate did not). Only
  the micro-VM battery caught it because it is the only lane that
  exercises the real apply path as root. The predicate is now
  `map_error_means_absent`, matching BOTH absent shapes — the
  delete-path ENOENT and the read-path KeyNotFound — with the
  aya 0.14 story recorded at the definition and the widened
  family pinned in policy_tests.rs (KeyNotFound absent,
  EPERM/ENOMEM/EACCES/EINVAL and wrong-map-type still never
  absent). The sibling read lanes that survived by accident —
  `read_policy_raw`'s `.ok().flatten()` degrade, the probe's
  `.ok().flatten()` budget-truth read, `read_policy_group`'s
  swallowed `Err` — now classify honestly, so `read_pool_tokens`'
  documented "Ok(None) is the honest absence" contract finally
  holds on a fresh pin with idle traffic instead of silently
  skipping the probe's diagnostic clause.

- **The 5.13 verified floor's BPF_PROG_LOAD refusal, root-caused
  and closed (night-audit-1's code find — the CI matrix's own
  catch, supermassive runs 187+).** Since night-quic-2 landed
  schema v22, every strict-* apply inside the 5.13 micro-VM failed
  with EACCES at program load: the reload, race-condition, and
  claims suites were all the same root. The object-level forensic:
  the QUIC parser read its 96-byte window through re-sliced
  subslices and loop indices, so its loads addressed the stack at
  COMPOUND runtime offsets — and the 5.13 verifier, whose scalar
  range tracking predates the 5.14 precision rework, loses exactly
  that range class through register spills, refusing the program
  whole (the pre-v22 object carried zero such reads and loaded
  clean; the v22 object carried six). The fix makes the safety
  structural: the wiring lands packet bytes through TWO bounded
  bpf_skb_load_bytes reads — a 40-byte IP-header window, then a
  56-byte L4 window REBASED to the UDP header the first read's
  parse located — so every field the pure core touches sits at a
  compile-time-constant stack offset; the byte collectors unroll
  to literal offsets gated by scalar length checks, and the one
  runtime-positioned byte in the protocol (the SCID length, which
  sits after the variable-length DCID) rides a shift-extract over
  three const-offset u64 windows — pure ALU, no memory access at
  any runtime address. The rebuilt object scans at ZERO
  variable-offset stack accesses (328/512 stack bytes, the same
  helper set the floor already proved, stack budget unchanged at
  96 bytes per call site), the full rootless battery holds the
  same keys and refusals the v22 laws pinned, and
  docs/KERNEL_COMPATIBILITY.md now carries the law for the next
  lane that wants to parse packets. The same sweep cleared the
  eBPF dead-code compile break (the test-tree-only readers the
  -D warnings gate refused), the codespell house-word drift (six
  sites of the banned misspelling back to unparsable, the 805d9c6
  house word), the ect-probe format, the
  USAGE.md double blank, and the ebpf fmt wrap — the whole CI
  matrix green again on one push.

- **The socket lane's miss-posture comment, corrected to the posture
  the code runs (NIGHT-audit-1's code find).** ebpf/src/
  socket_flow.rs's get_socket_ptr claimed an insert failure's
  surviving re-lookup miss DROPS the packet ("the safe verdict,
  never an unlimited pass") — the leaf lane's fail-closed posture
  pasted one map family over — while the caller's None arm returns
  the ALLOW verdict under the C twin's documented fail-open
  bookkeeping contract (never drop on a map miss), the same
  posture cake_flow.rs's get_flow_ptr twin comment states
  correctly. Comment-only, zero behavioral change, but the lane
  has no coarser lane to fall through to, so its miss posture IS
  its safety story: a future maintainer auditing fail directions —
  or 'fixing' the code to match the wrong comment — would inherit
  a wrong map of the system. The rewritten comment states the real
  contract and names the sibling it mirrors; the ebpf-prebuilt
  lane refreshed with the tree pin per the parity gate's contract
  (the objects reproduced byte-identical, only the manifest moved).

## History

The changelog's per-era split, newest era first:

- This file — the fresh record: every entry since the v20.0.0
  stable release (b743d9c, 2026-10-04, "the legend is be honest").
  NIGHT-improve-43 (2026-10-06) cut the legacy bulk out so the
  live file carries only what shipped after the release.

- [docs/archive/CHANGELOG-V20-ERA.md](docs/archive/CHANGELOG-V20-ERA.md)
  — the v20 era: the v11-line entries through the v20.0.0 stable
  release, the changelog blob as it stood at the release commit
  b743d9c. NIGHT-improve-43's re-issue moved it from the repo root
  into docs/archive/ (the owner's mandate: the root keeps only
  the fresh record), where it carries the archive wrapper the
  PRE_V11 file established — license header, archive note, bottom
  disclaimer. One line inside differs from the raw blob: the
  NIGHT-audit-2 name-case fix ("the cosmic dragon architecture",
  the machine-enforced one-name law BRANDING.md 3.3 carries —
  check-name-case.py would refuse the frozen file otherwise) —
  plus the H1 retitled to self-identify the archive; every entry
  line is byte-identical to b743d9c's CHANGELOG.md.

- The frozen campaign history of the v11 development line — the
  NIGHT research campaign, 2026-09-17 to 2026-09-19, every entry
  from the v10.0.0 stable tag up to NIGHT-hunt-25 — lives in git
  history alone. It was split out of this file verbatim in
  NIGHT-docs-1 (`CHANGELOG-V11-ERA.md`, byte-identical to the
  pre-split blob at 1026c1f); NIGHT-dinner-19 (2026-09-28) removed
  that root file — a duplicate of history the active tree did not
  need. Read it with `git log --follow -- CHANGELOG-V11-ERA.md`
  (the file's full span, NIGHT-docs-1 through NIGHT-dinner-19) or
  against the pre-split CHANGELOG.md blob at 1026c1f.

- [docs/archive/CHANGELOG_PRE_V11.md](docs/archive/CHANGELOG_PRE_V11.md)
  — the pre-v11 release history: entries [1.0.0] (2026-01-01)
  through [7.0.0] (2026-07-11), the deleted v10-era file.
  NIGHT-hunt-18 removed it to git history alone; NIGHT-dinner-15
  (2026-09-28) restored the byte-identical blob into docs/archive/
  so the era is readable in every checkout. Entries there are
  verbatim historical records and are never rewritten.
