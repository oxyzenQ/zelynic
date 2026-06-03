# Release Checklist

Use this checklist when preparing a stable Zelynic release.

## Version And Tagging

- Version bump command uses raw SemVer:
  `./set-version.sh X.Y.Z`
- Tag format:
  `vX.Y.Z`
- Release title format:
  `Zelynic vX.Y.Z <Codename/summary>`

Do not pass a leading `v` to `set-version.sh`; it adds the `v` only for release
labels and tags.

## Changelog Baseline

The full changelog compare must use the previous stable release tag:

```text
https://github.com/oxyzenQ/zelynic/compare/vPREVIOUS...vCURRENT
```

For v2.5.0, the correct compare URL is:

```text
https://github.com/oxyzenQ/zelynic/compare/v2.4.0...v2.5.0
```

The previous stable baseline for v2.5.0 is `v2.4.0`.

Snapshot or helper tags such as `v2.0.0-stable-snapshot` must not be used as the
stable release baseline.

## Final Gate

Before tagging, run:

```bash
./build.sh check-all
cargo run -- --version
cargo run -- backend doctor
cargo run -- refresh --help
git diff --check
```

Confirm `cargo run -- --version` prints the expected version, then commit and
push the release prep before creating the tag.
