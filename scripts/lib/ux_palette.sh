# shellcheck shell=bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# The shell brand palette — the bash twin of src/output/color.rs
# (night-cafe-1): every script surface (build, setup, gates,
# harnesses, labs) renders the SAME tiers the CLI renders, at the
# depth the terminal actually supports, and plain text when piped.
#
# Tier contract (the owner's color contract, the NIGHT-hunt-5
# lineage):
#   UX_BRAND  brand purple #A855F7 — banners and section rails
#   UX_OK     status green #50FA7B — affirmative verdicts, PASS lines
#   UX_ERR    error red #FF5A5A — failures, refusals, violations
#   UX_WARN   warning yellow #FFEB3C — cautions and non-fatal drift
#   UX_GREY   calm grey #8B8B8B — labels and grammar ("context, not
#             content": the INFO and step-marker labels ride it)
#   UX_WHITE  crystal white #DCEBFF — emphasized data lines
#   UX_RESET  the reset (empty in mono, so piped output never carries
#             stray escape bytes)
#
# Depth ladder (mirrors detect_capability in src/output/color.rs,
# probed once at source time):
#   NO_COLOR set, or CLICOLOR=0                     -> mono
#   stdout not a TTY (unless CLICOLOR_FORCE=1)      -> mono
#   COLORTERM truecolor/24bit, TERM -direct/-truecolor,
#   or a truecolor-native terminal name             -> RGB escapes
#   TERM carries 256color                           -> the 256 rungs
#   anything else                                   -> the 16 rungs
#
# The RGB triples, the 256 rungs (135/84/203/220/245/255) and the
# 16-color rungs (35/32/31/33/90/97) are the CLI's own documented
# fallbacks (src/output/color.rs, src/output/theme.rs slot! macro) —
# every tier matches the CLI byte-for-byte at every depth.
#
# No shebang on purpose: this file is sourced, never executed, so the
# 644 permission rule applies (harness_lib.sh precedent).

_zux_mono=0
if [ -n "${NO_COLOR:-}" ] || [ "${CLICOLOR:-}" = "0" ]; then
	_zux_mono=1
fi
if [ "$_zux_mono" -eq 0 ]; then
	if [ "${CLICOLOR_FORCE:-}" = "1" ]; then
		: # the force outranks the TTY probe (the CLI's env contract)
	elif [ -t 1 ]; then
		: # a real terminal
	else
		_zux_mono=1
	fi
fi

_zux_depth=""
if [ "$_zux_mono" -eq 0 ]; then
	_zux_ct="${COLORTERM:-}"
	_zux_term="${TERM:-}"
	case "$_zux_ct" in
	*truecolor*|*24bit*) _zux_depth="rgb" ;;
	esac
	if [ -z "$_zux_depth" ]; then
		case "$_zux_term" in
		*-direct*|*-truecolor*) _zux_depth="rgb" ;;
		*alacritty*|*kitty*|*ghostty*|*wezterm*|*foot*|*contour*) _zux_depth="rgb" ;;
		*256color*) _zux_depth="c256" ;;
		esac
	fi
	if [ -z "$_zux_depth" ]; then
		_zux_depth="c16"
	fi
fi

if [ "$_zux_mono" -eq 1 ]; then
	UX_BRAND=""
	UX_OK=""
	UX_ERR=""
	UX_WARN=""
	UX_GREY=""
	UX_WHITE=""
	UX_RESET=""
elif [ "$_zux_depth" = "rgb" ]; then
	UX_BRAND=$'\x1b[38;2;168;85;247m'
	UX_OK=$'\x1b[38;2;80;250;123m'
	UX_ERR=$'\x1b[38;2;255;90;90m'
	UX_WARN=$'\x1b[38;2;255;235;60m'
	UX_GREY=$'\x1b[38;2;139;139;139m'
	UX_WHITE=$'\x1b[38;2;220;235;255m'
	UX_RESET=$'\x1b[0m'
elif [ "$_zux_depth" = "c256" ]; then
	UX_BRAND=$'\x1b[38;5;135m'
	UX_OK=$'\x1b[38;5;84m'
	UX_ERR=$'\x1b[38;5;203m'
	UX_WARN=$'\x1b[38;5;220m'
	UX_GREY=$'\x1b[38;5;245m'
	UX_WHITE=$'\x1b[38;5;255m'
	UX_RESET=$'\x1b[0m'
else
	UX_BRAND=$'\x1b[35m'
	UX_OK=$'\x1b[32m'
	UX_ERR=$'\x1b[31m'
	UX_WARN=$'\x1b[33m'
	UX_GREY=$'\x1b[90m'
	UX_WHITE=$'\x1b[97m'
	UX_RESET=$'\x1b[0m'
fi

# Compatibility aliases — the legacy label names the tier now, so a
# sourcing script's existing usage sites keep working while the bytes
# ride the brand palette:
#   RED -> UX_ERR, GREEN -> UX_OK, YELLOW -> UX_WARN,
#   BLUE -> UX_GREY, CYAN -> UX_GREY, NC -> UX_RESET.
# shellcheck disable=SC2034 # consumed by the sourcing scripts
RED="$UX_ERR"
# shellcheck disable=SC2034
GREEN="$UX_OK"
# shellcheck disable=SC2034
YELLOW="$UX_WARN"
# shellcheck disable=SC2034
BLUE="$UX_GREY"
# shellcheck disable=SC2034
CYAN="$UX_GREY"
# shellcheck disable=SC2034
NC="$UX_RESET"

unset _zux_mono _zux_depth _zux_ct _zux_term
