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

- Title bar: `╭─── zelynic eagle-eyes ────…─ t theme - q quit ─╮`,
  bold purple — the frame's TOP border (NIGHT-boost-20): rounded
  corners connecting to the bar's own fill, right-aligned key hint
  when width allows; identity only since NIGHT-engrave-2 (the legend
  moved to the footer's status line).
- Column headers: `top process  download  upload  total`, regular
  purple (NIGHT-engrave-1: lowercase, the owner's exact titles).
- Frame borders (NIGHT-boost-20): gradient side rails and a bright
  closing floor row — the active theme's brand color sweeping
  dark-bright-dark down the frame (the cosmostrix msg-border BD-02
  triangle-wave contract, bright-anchored at the bottom).
- Rows and totals: terminal default color — the purple frame carries
  the brand so data stays maximally readable.
- The layout re-probes width AND height every frame (TIOCGWINSZ), so
  resizing the terminal adapts on the next refresh: columns degrade
  (RATE first), labels truncate with an ellipsis, and the
  row count follows the height (NIGHT-boost-1: no --limit, no cap —
  the window IS the budget) so frames never scroll.
- Refresh cadence: `--interval` (1s..60s, default 1s — realtime
  precision); the RATE column divides deltas by exactly that interval.
- Eagle-eyes detail (NIGHT-hunt-8): multi-tenant cgroups carry a
  `+N` process suffix — `cg:73386 (alacritty +3)` — and up to three
  indented detail lines naming the socket-holding processes inside:
  `    └ curl (4242) → 142.250.191.78:443`. UDP endpoints are tagged
  (`udp 8.8.8.8:53`), busy sockets flagged `[busy]`; remaining
  holders collapse into `+N more socket-holding processes`. Detail
  lines count against the height budget so frames never scroll.

### 2.2. Monitor themes (NIGHT-boost-18, improve-27)

The eagle-eyes monitor cycles six palettes with `t` (forward,
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

Each slot carries all three capability encodings (TrueColor RGB,
xterm-256 index, 16-color SGR) plus their bold twins, generated by
the `slot!` macro from the same numbers this table documents — the
table and the docs cannot drift apart silently. The 256/16 fallbacks
favor visibility over exact match (the warn-yellow precedent); the
grey slot degrades to the neutral grey ramp (245 / bright black 90)
in every theme — subordinate text stays subordinate whatever the
accent becomes. A cycled frame names its theme in the footer's
status line (`1s realtime - theme atomic - q quit - t theme`, the
NIGHT-engrave-2 legend below the limit suggestions) and the title
hint teaches the key (`t theme - q quit`); a theme change repaints
within the same 50ms wake, never at the next refresh tick. Error red
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
