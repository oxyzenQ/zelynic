<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# local tools

Local tooling notes for the repo's own assets — the commands the owner
runs by hand when an asset changes, written down so the next asset pass
does not re-derive them.

### rounded corners for the logo (assets/zelynic-logo-master.png)

The master logo ships 1254x1254; the README renders it at width 260.
For a rounded-square variant (68 px corner radius on the master size):

```sh
magick assets/zelynic-logo-master.png \( -size 1254x1254 xc:none -fill white -draw 'roundrectangle 0,0 1253,1253 68,68' \) -alpha off -compose CopyOpacity -composite assets/zelynic-logo-rounded.png
```

### for demo on terminal use this size

The README demo frames and the recorded terminal captures use an
alacritty window at 120 columns by 40 lines:

```sh
alacritty -o "window.dimensions.columns=120" -o "window.dimensions.lines=40"
```

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
