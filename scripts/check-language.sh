#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# PLATFORM: UNIX-only (Linux). zelynic is a Linux-only tool.
#
# ZELYNIC LANGUAGE DISCIPLINE CHECK (NIGHT-hunt-19)
#
# Owner rule: the repository is English-only — comments, docs, script
# text, and string literals alike (chat may be mixed-language;
# committed artifacts never are). The emoji sweep (gate-keepers.sh
# section 8) already blocks emoji-class codepoints; this gate closes
# the two leak paths that sweep cannot see:
#
#   1. Non-Latin scripts (CJK ideographs, kana, Hangul, Cyrillic,
#      Greek, Arabic, Hebrew, Thai, Devanagari, fullwidth forms, the
#      zero-width joiner) in any text file. Intentional Unicode
#      coverage data self-declares with a marker comment — the same
#      discipline as // LOC_EXEMPT: (no hardcoded allowlist in this
#      script, the exemption lives with the file it exempts):
#
#        // NON_LATIN_FIXTURE: <one-line justification>   (rs)
#        # NON_LATIN_FIXTURE: <one-line justification>    (sh/py)
#
#   2. Indonesian vocabulary — the real-world leak vector: the owner
#      works in mixed-language chat, and a directive quoted verbatim
#      into a comment or doc is exactly how non-English lands in an
#      otherwise English tree (the frozen NIGHT-improve-1 commit
#      body is the historical example). The word set is informal-
#      register, case-sensitive, word-bounded, and curated for zero
#      false positives on this repository's English: words colliding
#      with English usage or metric names (gini the Gini coefficient,
#      label, bro as a quoted idiom, two-letter particles like
#      di/ke) are deliberately excluded. No marker exempts this
#      check — fixtures are CJK/Cyrillic, never Indonesian prose.
#
# Excluded from both checks: .git/, target/, assets/, dist/,
# node_modules/, __pycache__/ (build output, binary assets, and
# compiled bytecode — a .pyc embeds its source's UTF-8 string
# constants and would re-flag them as prose), *.lock, the two
# CHANGELOG files (frozen historical records — archive content is
# never rewritten, the same exclusion policy as every other gate),
# and this script itself (the word set below would match its own
# detector definition). Commit messages follow the same English-only
# rule but are not tree content at gate time — CI and review own
# that surface.
#
# Usage: scripts/check-language.sh
#
# Output: one line per finding (kind, file:line, snippet), capped at
# 20 with an overflow count; a summary line; exit 0 clean / exit 1
# on any finding.
#
# Platform: UNIX-only (python3 stdlib). Not for Windows cmd.exe.

set -euo pipefail

python3 - <<'PYEOF'
import os
import re
import sys

# Non-Latin script codepoint ranges — coverage, not enumeration (the
# same philosophy as the emoji sweep: block the classes that matter).
NON_LATIN_RANGES = (
    (0x0370, 0x03FF),  # Greek (incl. Coptic)
    (0x0400, 0x04FF),  # Cyrillic
    (0x0530, 0x058F),  # Armenian
    (0x0590, 0x05FF),  # Hebrew
    (0x0600, 0x06FF),  # Arabic
    (0x0900, 0x097F),  # Devanagari
    (0x0E00, 0x0E7F),  # Thai
    (0x1100, 0x11FF),  # Hangul Jamo
    (0x1780, 0x17FF),  # Khmer
    (0x3040, 0x30FF),  # Hiragana + Katakana
    (0x3400, 0x4DBF),  # CJK Extension A
    (0x4E00, 0x9FFF),  # CJK Unified Ideographs
    (0xAC00, 0xD7AF),  # Hangul Syllables
    (0xF900, 0xFAFF),  # CJK Compatibility Ideographs
    (0xFB50, 0xFDFF),  # Arabic Presentation Forms-A
    (0xFE70, 0xFEFF),  # Arabic Presentation Forms-B
    (0xFF01, 0xFF9F),  # Fullwidth forms + halfwidth kana
    (0x200D, 0x200D),  # Zero-Width Joiner
)

# Indonesian informal register, case-sensitive and word-bounded. Every
# entry is verified absent from the current tree and disjoint from
# English technical vocabulary, so a hit is a true positive.
INDONESIAN_WORDS = (
    "absurb", "adalah", "aduh", "aja", "ampun", "anjay", "anjir",
    "anjrit", "apa", "astaga", "banget", "banyak", "belom", "bener",
    "beneran", "bgt", "bikin", "blm", "bnyk", "bodoh", "bre", "buset",
    "butuh", "capek", "cepet", "coba", "cobain", "cok", "cpt", "cuma",
    "cuy", "dan", "dapet", "deh", "dgn", "digunakan", "dikit", "dipake",
    "dong", "dulu", "emang", "emg", "elo", "elu", "ga", "gampang",
    "gausa", "gapapa", "gara2", "gatel", "gila", "gimana", "gni", "gk",
    "gmn", "goblok", "gpp", "gtu", "gua", "gue", "gw", "harusnya",
    "hanya", "hilang", "ilang", "jg", "jgn", "juga", "kalo", "kalau",
    "kami", "kamu", "karena", "kayak", "kayaknya", "kecepatan",
    "kepake", "kek", "keren", "klo", "koneksi", "krn", "lambat",
    "langsung", "lho", "makasi", "makasih", "masalah", "mati",
    "memang", "mantap", "merupakan", "ngak", "nganggo", "nggak",
    "nih", "njir", "nyari", "nyoba", "nyesel", "pakai", "pake",
    "perlu", "pun", "punya", "ribet", "santai", "saya", "sialan",
    "sih", "simpel", "skrip", "smua", "solusi", "sudah", "sdh",
    "sepertinya", "serius", "sumpah", "supaya", "susah", "tapi",
    "terus", "tolol", "tlong", "tolong", "trims", "trus", "tuh",
    "udah", "udh", "usah", "utk", "versi", "waduh", "wkwk", "woy",
    "ya", "yaudah", "ydh", "yg",
)

INDONESIAN_RE = re.compile(r"\b(?:" + "|".join(INDONESIAN_WORDS) + r")\b")

SKIP_DIRS = {
    ".git",
    "target",
    "assets",
    "dist",
    "node_modules",
    "__pycache__",  # compiled bytecode embeds source string constants
}
SKIP_FILES = {
    "CHANGELOG.md",          # frozen historical record
    "CHANGELOG-V11-ERA.md",  # frozen historical record
    "check-language.sh",     # this detector's own word set
}
SKIP_SUFFIXES = (".png", ".lock")
MARKER = "NON_LATIN_FIXTURE:"


def is_non_latin(cp):
    return any(lo <= cp <= hi for lo, hi in NON_LATIN_RANGES)


files = []
for root, dirnames, filenames in os.walk("."):
    dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
    for name in sorted(filenames):
        if name in SKIP_FILES or name.endswith(SKIP_SUFFIXES):
            continue
        files.append(os.path.join(root, name))

findings = []
for path in files:
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except (UnicodeDecodeError, OSError):
        continue  # binary or unreadable — not language content
    exempt = MARKER in text
    for lineno, line in enumerate(text.splitlines(), 1):
        if any(is_non_latin(ord(ch)) for ch in line) and not exempt:
            findings.append(
                "  non-Latin script: %s:%d: %s"
                % (path, lineno, line.strip()[:80])
            )
        word = INDONESIAN_RE.search(line)
        if word:
            findings.append(
                "  Indonesian (%s): %s:%d: %s"
                % (word.group(0), path, lineno, line.strip()[:80])
            )

for f in findings[:20]:
    print(f)
if len(findings) > 20:
    print("  ... and %d more finding(s) not listed" % (len(findings) - 20))

print(
    "language gate: %d file(s) checked, %d finding(s)"
    % (len(files), len(findings))
)
sys.exit(1 if findings else 0)
PYEOF
