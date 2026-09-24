<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Zelynic Brand Guidelines

This document defines the visual identity and communication standards for the Zelynic project. It ensures consistent branding across all touchpoints — from the GitHub repository to the CLI output and documentation.

---

## 1. Brand Identity

**Zelynic** is a serious Linux bandwidth control system for process-aware monitoring, shaping, and validation. The brand reflects:

- **Technical Precision** — enforced by a pure eBPF datapath on cgroup v2
- **Reliability** — robust per-process network behavior control
- **Professionalism** — clean CLI, detailed diagnostics, and thorough validation
- **Clarity** — clean CLI output, box-mode monitoring (`eagle-eyes`)

---

## 2. Brand Color

**Zelynic brand purple: `#A855F7` (RGB 168, 85, 247)** — the cosmostrix
branding color format, shared across the owner's projects.

The color is rendered in whatever depth the terminal actually supports
(capability-aware, ported from the cosmostrix output contract):

| Capability | Detection | Encoding |
|---|---|---|
| TrueColor | `COLORTERM=truecolor/24bit`, `TERM` contains `-direct`/`-truecolor`, or truecolor-native terminal names (alacritty, kitty, ghostty, wezterm, foot, contour) | `ESC[38;2;168;85;247m` |
| 256-color | `TERM` contains `256color` | `ESC[38;5;135m` (closest xterm-256 cube match) |
| 16-color | `TERM` set but unrecognized | `ESC[35m` (magenta) |
| Mono | `NO_COLOR`, `CLICOLOR=0`, or not a TTY (unless `CLICOLOR_FORCE=1`) | plain text |

There is no `--no-color` CLI flag (NIGHT-hunt-5 owner mandate: purple
is branding, branding has no opt-out) — color is always on for
terminals, and the standard env vars above remain the only control
surface, exactly like cosmostrix.

Source of truth: `src/output/mod.rs` (`BRAND_PURPLE_RGB`, `brand_open()`).

Usage surfaces:

- `-V` / `--version` header (name + version + description) — regular weight
- `--help` banner and section headings — bold (single-tier help surface,
  NIGHT-improve-3: the former --help-all reference merged into --help);
  command group headings carry the same bold purple (NIGHT-improve-5:
  strict / limit / block / unstrict / monitor / system)
- clap error rendering — headers and Usage in bold purple via
  `clap_styles()` (`src/cli/mod.rs`); error labels bold red, tips white
- `status` / `eagle-eyes` / `recover` / `list-apps` banners — bold
- `--check-update` report banner — bold

Status colors use the same capability tiers (owner color contract,
NIGHT-hunt-5 — cosmostrix S-master-HUNT-5 lineage):

| Semantic | RGB | Used for |
|---|---|---|
| Brand purple | `#A855F7` | banners, section headings, Usage headers |
| Status green | `#50FA7B` | affirmative doctor verdicts (YES, SUPPORTED), up-to-date |
| Error red | `#FF5A5A` | `error:` labels and error bodies |
| Warning yellow | `#FFEB3C` | `!` warning labels, warnings, update-available |
| Suggestion white | `#DCEBFF` | `tip:` / `hint:` / did-you-mean lines, distinct from the error they fix |

All styled output degrades to plain text when piped so ANSI codes never
leak into scripts, logs, or JSON consumers. Every user-facing print goes
through the broken-pipe-safe macros (`println_safe!` / `eprintln_safe!`)
so piping into a short reader (`zelynic --help | head -2`) truncates
cleanly instead of panicking with exit 101.

Exit-code contract: clap usage errors exit 2; runtime failures exit 1.

### 2.1. Monitor layout (NIGHT-hunt-7)

The `eagle-eyes` monitor renders "boring but elegant flagship"
(owner contract): one bold-purple title bar filled to the full frame
width, regular-purple column headers, thin separators, right-aligned
numerics, and no per-cell noise (values are never packed as
`89 (1.2 MB)` — that is what the RATE column is for).

- Title bar: `╭─── zelynic eagle-eyes ────…───────╮`, bold purple —
  the frame's TOP border (NIGHT-boost-20): rounded corners
  connecting to the bar's own fill; identity only, the full-width
  fill owning both corners since NIGHT-engrave-3 retired the
  top-right key hint (the legend lives in the footer's status line
  alone).
- Column headers: `top process  download  upload  total`, regular
  purple (NIGHT-engrave-1: lowercase, the owner's exact titles).
  NIGHT-engrave-4: the `top process` title spans the whole identity
  region (rank cell + gap + label column) so it starts at the
  frame's canonical text column — the same line every footer and
  note row starts on — and the numeric titles close at the
  two-column right gutter, the mirror of the left: the table's
  figures end two columns before the right rail on BOTH edges,
  symmetric air (the owner's border-gap audit).
- Frame borders (NIGHT-boost-20; margins NIGHT-engrave-8): gradient
  side rails and a bright closing floor row — the active theme's
  brand color sweeping dark-bright-dark down the frame (the
  cosmostrix msg-border BD-02 triangle-wave contract,
  bright-anchored at the bottom). The box sits ONE column inside the
  terminal on each side — both rails exactly one column from the
  edges, the final terminal column never painted (terminal physics:
  a row that paints the last column leaves the cursor pending-wrap,
  where the trailing erase-to-EOL eats the right rail on some
  terminals) — so the frame renders identically everywhere.
- Rows and totals: terminal default color — the purple frame carries
  the brand so data stays maximally readable.
- The layout re-probes width AND height every frame (TIOCGWINSZ), so
  resizing the terminal adapts on the next refresh: columns degrade
  (RATE first), labels truncate with an ellipsis, and the
  row count follows the height (NIGHT-boost-1: no --limit, no cap —
  the window IS the budget) so frames never scroll.
- Refresh cadence: `--interval` (1s..60s, default 1s — realtime
  precision); the RATE column divides deltas by exactly that interval.
- Eagle-eyes detail (NIGHT-hunt-8; the two-level tree of
  NIGHT-boost-21): multi-tenant cgroups carry a
  `+N` process suffix — `cg:73386 (alacritty +3)` — and up to four
  detail lines naming the socket-holding processes inside. A
  one-socket process renders inline:
  `    └ curl (4242) → 142.250.191.78:443`; a multi-socket process
  expands its endpoints as indented children under a count-carrying
  header: `    └ firefox (4242) 3 sockets:` with `├`/`└` endpoint
  children (two shown in the ranked table, all of them in the focus
  view). UDP endpoints are tagged
  (`udp 8.8.8.8:53`), busy sockets flagged `[busy]`; remaining
  holders collapse into `+N more socket-holding processes`. Detail
  lines count against the height budget so frames never scroll.
- Footer block (NIGHT-engrave-4, the owner's dashboard rebuild; the
  NIGHT-engrave-6 speed pair seated below the story row): the
  bottom block reads in the owner's exact line order — `top consumer
  is curl` (the name brand purple, the engrave-1 contract: the one
  living thing in the grey block), `478 packets + 1 cgroups` (grey,
  session horizon), `total usage internet in 1h:20s = 10.2 GB` (grey,
  SI decimal — the same ladder every byte figure rides),
  `total max dl | ul = 20.2 GB/s | 1.0 GB/s` and `total avg dl | ul =
  10.2 GB/s | 1.1 MB/s` (grey — the session speed pair: the peak
  and the average per direction, same watched scope and same clock
  as the total row above them, honest `0 B/s` zeroes at rest),
  `limit target with 'sudo zelynic ss curl 100kb'` (grey prefix,
  the quoted command in the ACTIVE theme's brand tier since
  NIGHT-engrave-7 — purple under netrunner, the theme's own accent
  under itself: the frame's two living accents, the consumer's name
  and the command to act on it), the status line, and the build stamp
  (purple). Purple grid and stamp, brand-tier consumer name and
  command, grey everything else: subordinate information
  dimmer than the data it annotates, actionable accents brighter.

#### 2.1.1. The report-table family (NIGHT-engrave-5)

The eagle-eyes table style is the ONE table style: `sudo zelynic
status` and `zelynic list-apps` (the REPORT surfaces — command
output that is a table) answer to the same contract the monitor's
table carries, in the surface classes below. The owner's audit
caught status as the last uppercase holdout: `CGROUP / DOWNLOAD /
UPLOAD / ALLOWED / DROPPED` over a plain hyphen separator; both
report tables now render the monitor's exact family.

- Title bar: `╭─── zelynic status ─…─╮` / `╭─── zelynic list-apps ─…─╮`
  — the flagship title bar, spanning the table's own width (the
  status branch frames — clean, stale pins — span the terminal
  width: no table to size to), followed by the breathing gap.
- Column headers: lowercase, regular purple (`cgroup download
  upload allowed dropped`; `process procs sockets cgroup id uid`).
- Grid: the monitor's own purple grid (render/footer.rs
  `grid_line`, one border family across every zelynic table),
  full-width and flush with the left edge — the `|---` shape.
- Data rows: status green (the eagle table's calm tier) — every
  status row is a live enforced limit, the affirmative state.
- Prose lines: grey, lowercase (`watchdog: 30s remaining`,
  `active limits: N dl, N ul`, the list-apps census line); warn
  yellow for the expired-watchdog verdict and the stale-pins
  finding; suggestion white for the quoted recovery command. The
  branch frames carry the same chrome: title, gap, story, gap,
  stamp.
- Verdict VALUES keep their case (BLOCKED, the `--print-json`
  watchdog states) — titles are furniture, verdicts are states.

Surface classes (the style map): flagship frames (eagle-eyes,
status) and the discovery table (list-apps) carry the eagle table
contract above; the signature stamp belongs to the flagship pair
(NIGHT-boost-5's original list). Action prose — the enforcement
verbs' stderr confirmations — keeps sentence case (an action log,
not a report). The reference surfaces (help, doctor, errors) keep
their own established idioms (the "━━━" banner family and the
labeled error renderer).

### 2.2. Monitor themes (NIGHT-boost-18, improve-27; NIGHT-engrave-7)

**Background contract (NIGHT-boost-26, live since NIGHT-boost-32)**:
the frame's BACKGROUND follows the TERMINAL, never the builtin
palettes — a grey-themed terminal renders a grey eagle-eyes frame,
a dark one a dark frame. At monitor open the terminal is asked for
its background (the standard OSC 11 query, a 100 ms bounded ask)
and every frame row paints that exact triple at TrueColor depth
(the nearest xterm-cube cell at 256). The follow is LIVE
(NIGHT-boost-32): the monitor re-asks every couple of seconds and
absorbs the answer from its input drain — zero blocking, so a
mid-session background change (alacritty's live config reload) is
followed within one ask instead of freezing the open-time color,
and a slow SSH answer costs no stall. Only the grid lines, data,
and info keep the theme's FOREGROUND vocabulary — the table above
governs glyphs, not the canvas they sit on. Terminals that do not
answer (or the shallow 16-color/Mono depths) render exactly as
before: no background escape, the terminal's own default showing
through.

The eagle-eyes monitor cycles eleven palettes with `t` (forward,
modulo wraparound — the uppercase `T` twin was retired by
NIGHT-engrave-2 at the owner's "better only simple 't'" call).
Themes are SCOPED to the live monitor: nothing outside the
alt-screen key handler ever writes the theme state, so every other
surface (help, errors, status, list-apps) always renders the default
and the CLI's byte output is unchanged. The default is `netrunner`,
whose encodings are byte-identical to the constants the color layer
carried before themes existed.

Cycle order and palettes (source of truth:
`src/output/theme.rs`, the `slot!` table):

| # | Theme | Brand | Ok | Warn | Hot | Grey |
|---|---|---|---|---|---|---|
| 1 | `netrunner` (default) | `#A855F7` | `#50FA7B` | `#FFEB3C` | `#FF3B30` | `#8B8B8B` |
| 2 | `night_cyber` | `#00E5FF` | `#00FF9F` | `#FFC857` | `#FF2E63` | `#6B7A8F` |
| 3 | `forest` | `#7CB342` | `#69F0AE` | `#FDD835` | `#D84315` | `#7D8B6E` |
| 4 | `spaceflight` | `#4FC3F7` | `#64FFDA` | `#FFD740` | `#FF5252` | `#90A4AE` |
| 5 | `carbon` | `#D6D6D6` | `#AAFFB2` | `#F5C518` | `#FF4D4D` | `#9E9E9E` |
| 6 | `atomic` | `#FF6D00` | `#00E676` | `#FFEA00` | `#FF1744` | `#B0BEC5` |
| 7 | `cafe` | `#C68B59` | `#A8C686` | `#E8B54D` | `#C0392B` | `#B5A89C` |
| 8 | `server` | `#6E9BC5` | `#33D17A` | `#F2A33C` | `#E5484D` | `#9AA5B1` |
| 9 | `moonlight` | `#B8CCE8` | `#9FD8B5` | `#E8D48B` | `#D98A8A` | `#A6B0C2` |
| 10 | `hacker` | `#33FF33` | `#00E5A8` | `#FFE14D` | `#FF4757` | `#8FA88F` |
| 11 | `depth_sea` | `#1FBFAD` | `#5FD78A` | `#E8C56A` | `#FF6B6B` | `#7E9AA6` |

The NIGHT-engrave-7 frontier five (the owner's realism mandate —
scene-accurate, not toy): `cafe` is the warm coffee-house (roasted
caramel brand, honey amber, burnt-sienna heat, taupe
subordinates); `server` is the datacenter rack (steel-blue brand,
LED-green status, amber warning LED, alarm-red heat, brushed-steel
subordinates); `moonlight` is the pale cool night (moonlit blue,
mist green, pale gold, dusk-rose heat — a pale palette that never
screams); `hacker` is the phosphor terminal (P1-green brand on
black, mint status, terminal yellow, alert red); `depth_sea` is
the deep ocean (bioluminescent teal, kelp green, sand gold, coral
heat). Their 256-depth fallbacks follow the same computed
contract: brand/ok on the NEAREST xterm cube match (cafe 173/150,
server 68/78, moonlight 152/151, hacker 83/43, depth_sea 37/78),
warn/hot on the visibility precedents (cafe's honey amber joins
night_cyber's khaki 221 and its burnt sienna keeps the pure red
corner 196; server's amber LED rides its true 215 with the alarm
red one rung under carbon's at 167; moonlight's pale gold and dusk
rose take their nearest rungs 186/174; hacker's terminal yellow
takes the saturated corner 220 and its pink-leaning alert red the
197 atomic precedent; depth_sea's sand gold and coral take 185/203),
and the 16-color picks keep the pairwise-distinct contract with the
brand on a bright slot where the identity must outrank data (cafe
93, server 94, moonlight 94, hacker 92; depth_sea's cyan needs no
bright escape — its ok is green, no collision).

Each slot of every theme carries all three capability encodings
(TrueColor RGB, xterm-256 index, 16-color SGR) plus their bold
twins, generated by the `slot!` macro from the same numbers this
table documents — the table and the docs cannot drift apart
silently (the catalog pins hold the lockstep).

The NIGHT-boost-23 masterclass audit pinned the fallback contract
the table now follows: the brand/ok slots take the NEAREST xterm
cube match (hue must read true — forest's leaf-green brand had
rendered olive 71, carbon's pale-mint ok had rendered saturated
spring green 48 at 28x the nearest error, carbon's silver brand had
dimmed onto the grey ramp's 188 rung 250, below its own 16-color
fallback's hierarchy); warn/hot keep the visibility precedent — the
saturated corner wins while the hue family holds, and per-theme hue
truths land where the palette earns them (night_cyber's soft-amber
warn on the khaki rung 221, forest's burnt-orange crown on its true
166, carbon's soft red on 203, atomic's pink-leaning crown on 197);
16-color distinctness within a theme is absolute (no two slots share
an SGR — forest's brand takes bright green 92 clear of ok's 32,
atomic's brand takes bright yellow 93 clear of warn's 33, the brand
always the bright slot so the frame's identity outranks its data);
the grey slot degrades to the neutral grey ramp (245 / bright black
90) in every theme — subordinate text stays subordinate whatever the
accent becomes.

The border gradient interpolates in LINEAR LIGHT since NIGHT-boost-23
(the exact IEC 61966-2-1 sRGB transfer, decode-blend-encode): the
naive sRGB lerp darkened perceptual midtones — the ramp banded near
the dark anchor and rushed through bright — while the gamma-correct
midpoint renders at the brightness the arithmetic claims. The
anchors (brand, the 42% dark floor) and the triangle wave (the BD-02
contract) are unchanged; only the blend between them got honest.

The capability ladder itself auto-falls-back (truecolor -> 256 cube
-> 16 palette -> mono) per terminal, and `--color-mode`
(NIGHT-boost-23, the cosmostrix contract: 0/16/8|256/24|32) forces a
depth for terminals whose environment lies about truecolor — see
USAGE.md. A cycled frame names its theme in the footer's
status line (`1s realtime - theme atomic - q quit - t theme`, the
NIGHT-engrave-2 legend) — and since NIGHT-engrave-3 that row is the
key hints' only home (the title's top-right hint retired then and
stayed retired through the engrave-4 footer rebuild); a theme
change repaints within the same 50ms wake, never
at the next refresh tick. Error red
and suggestion white are hardwired: they belong to the CLI error
surface, which never themes.

---

## 3. Name Usage

### 3.1. Correct forms

| Context | Format |
|---|---|
| Running text / prose | Zelynic |
| Titles / headings | Zelynic |
| Code / CLI | `zelynic` (lowercase) |

### 3.2. Incorrect forms

- ~~ZeLynic~~ (no internal capitalization)
- ~~Oxy~~ (legacy name, do not use for new mentions)
- ~~ZelynicX~~ (derivative form)

---

## 4. Logo

### 4.1. Logo file

The official logo is located at [`assets/zelynic-logo-master.png`](assets/zelynic-logo-master.png).

### 4.2. Usage rules

- **Clear space**: maintain padding equal to at least 25% of the logo height on all sides
- **Aspect ratio**: always preserve the original aspect ratio — do not stretch or distort

---

## 5. Tone of Voice

Zelynic's communication should be technical, authoritative, and direct.

- **Factual** — describe capabilities and validation status clearly (e.g., "Validated on Arch/CachyOS")
- **Concise** — respect the user's time in CLI output and documentation
- **Transparent** — explain backend choices and requirements (root, kernel versions)

---

## 6. Third-party Usage

External projects or articles referencing Zelynic should:

- Use the correct project name: Zelynic
- Link to the official repository: <https://github.com/oxyzenQ/zelynic>
- Acknowledge it as a Rust-based CLI tool
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
