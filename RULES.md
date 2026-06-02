# Zelynic Project Rules

## File Size

- Core/code files must stay under `1000` lines of code.
- This applies to source and core files such as `*.rs`, `*.c`, `*.h`, `*.css`,
  `*.py`, and `*.sh`.
- This excludes `*.md`, `*.txt`, generated files, lockfiles, assets, release
  artifacts, `.git/`, and `target/`.
- `src/main.rs` has a soft target of `100-300` LOC in a mature project and
  should remain bootstrap/wiring only.
- `src/cli.rs` may be larger when it is mostly declarative Clap definitions.

## Manual Workflow

Use a test-first loop:

1. Run the relevant test/check.
2. Review the output.
3. Fix the issue or continue only after understanding the result.

Do not guess past failing checks.

## Release Honesty

- The validated limiter path is `zelynic strict`.
- The `zelynic run` path is experimental planning/preflight groundwork.
- Do not overclaim live `systemd-run` behavior.
- `zelynic run --execute` must remain non-mutating until live execution is
  deliberately implemented and validated.
