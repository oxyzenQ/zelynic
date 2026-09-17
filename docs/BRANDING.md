# Zelynic Brand Guidelines

This document defines the visual identity and communication standards for the Zelynic project. It ensures consistent branding across all touchpoints — from the GitHub repository to the CLI output and documentation.

---

## 1. Brand Identity

**Zelynic** is a serious Linux bandwidth control system for process-aware monitoring, shaping, and validation. The brand reflects:

- **Technical Precision** — enforced by a pure eBPF datapath on cgroup v2
- **Reliability** — robust per-process network behavior control
- **Professionalism** — clean CLI, detailed diagnostics, and thorough validation
- **Clarity** — clean CLI output, box-mode monitoring (`observe` / `top`)

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
| Mono | `NO_COLOR`, `CLICOLOR=0`, `--no-color`, or not a TTY (unless `CLICOLOR_FORCE=1`) | plain text |

Source of truth: `src/output/mod.rs` (`BRAND_PURPLE_RGB`, `brand_open()`).

Usage surfaces:

- `-V` / `--version` header (name + version + description) — regular weight
- `--help-all` banner and section headings — bold
- `list-apps` banner — bold

Status colors (green `#50FA7B`, red `#FF5A5A`, yellow `#FFEB3C`) use the
same capability tiers for doctor verdicts and warnings. All styled output
degrades to plain text when piped so ANSI codes never leak into scripts,
logs, or JSON consumers.

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
