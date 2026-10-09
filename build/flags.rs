// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// NIGHT-improve-31 phase 2, executed by NIGHT-improve-44: the
// RUSTFLAGS surgery — the host-poison strip (NIGHT-hunt-28) and the
// bpf-v3 force — plus the leak-shape tests that pin them.
/// Everything else survives verbatim, so CI's `RUSTFLAGS="-D
/// warnings"` contract keeps covering the ebpf crate. This is
/// deliberately narrower than aya-build 0.2.0 upstream, which
/// replaces the variable wholesale with its own fixed flag set
/// (`--cfg=bpf_target_arch`, `-Cdebuginfo=2`, `-Clink-arg=--btf`) and
/// thereby discards any inherited contract — zelynic's nested build
/// instead keeps the inheritance minus the poison.
pub(crate) fn strip_host_poison_rustflags(cmd: &mut std::process::Command) {
    if let Some(value) = std::env::var_os("CARGO_ENCODED_RUSTFLAGS") {
        match strip_host_poison(&value.to_string_lossy(), "\u{1f}") {
            Some(filtered) => {
                cmd.env("CARGO_ENCODED_RUSTFLAGS", filtered);
            }
            None => {
                cmd.env_remove("CARGO_ENCODED_RUSTFLAGS");
            }
        }
    }
    if let Some(value) = std::env::var_os("RUSTFLAGS") {
        match strip_host_poison(&value.to_string_lossy(), " ") {
            Some(filtered) => {
                cmd.env("RUSTFLAGS", filtered);
            }
            None => {
                cmd.env_remove("RUSTFLAGS");
            }
        }
    }
}

/// NIGHT-boost-38: force the v3 BPF codegen level onto the nested
/// build, whatever survived the poison strip.
///
/// The SMP-safe token bucket (ebpf/src/math.rs) compiles its
/// read-modify-write steps down to the BPF_ATOMIC ISA (fetch-add /
/// cmpxchg, Linux 5.12+), and the LLVM BPF backend selects those
/// instructions — and successfully lowers the whole atomic chain —
/// only at cpu v3 or higher. bpf-linker takes its codegen level from
/// rustc's `-C target-cpu`, so the flag must ride RUSTFLAGS.
///
/// Why not rely on ebpf/.cargo/config.toml's `[build] rustflags`
/// alone: a set environment variable SHADOWS config rustflags
/// entirely, and every CI workflow that drives a pro-* alias exports
/// RUSTFLAGS ("-D warnings -C target-cpu=native" in ci.yml, the
/// matrix baselines in release.yml, the v3/v4 legs of
/// maintenance.yml). The strip above already removed the host-poison
/// `target-cpu` tokens; this pass then appends the bpfel v3 flag to
/// whichever rustflags variable remains on the command. With no env
/// rustflags at all (the plain `cd ebpf && cargo build` route, or
/// setup.sh's alias whose flags ride `--config`, not env) the
/// command carries neither variable and the config file supplies the
/// same flag — one value, two delivery routes, both documented.
///
/// v3 bytecode is alu32 (kernel 5.1+), far inside the 5.13 verified
/// floor; the flag changes nothing for code that uses no atomics
/// (the observer object is byte-identical either way).
pub(crate) fn force_bpf_v3_rustflags(cmd: &mut std::process::Command) {
    const FLAG: &str = "-Ctarget-cpu=v3";
    // Snapshot the two rustflags channels the poison strip may have
    // left on the command (explicit sets only — an inherited-but-
    // untouched variable is not in get_envs, and that case needs no
    // amendment: the config file supplies the flag).
    let mut encoded: Option<std::ffi::OsString> = None;
    let mut plain: Option<std::ffi::OsString> = None;
    for (key, value) in cmd.get_envs() {
        // None = an explicit env_remove from the poison strip: the
        // variable is deliberately gone, leave it that way.
        let Some(value) = value else { continue };
        if key.to_str() == Some("CARGO_ENCODED_RUSTFLAGS") {
            encoded = Some(value.to_os_string());
        } else if key.to_str() == Some("RUSTFLAGS") {
            plain = Some(value.to_os_string());
        }
    }
    if let Some(mut value) = encoded {
        // The encoded variable wins over RUSTFLAGS in cargo, so when
        // both survived the strip this is the one to amend
        // (separator: 0x1F).
        value.push("\u{1f}");
        value.push(FLAG);
        cmd.env("CARGO_ENCODED_RUSTFLAGS", value);
    } else if let Some(mut value) = plain {
        value.push(" ");
        value.push(FLAG);
        cmd.env("RUSTFLAGS", value);
    }
    // Neither variable set: the nested cargo reads the v3 flag from
    // ebpf/.cargo/config.toml — nothing to do.
}

/// Filter one rustflags value split on `sep` (the 0x1F separator for
/// CARGO_ENCODED_RUSTFLAGS, a space for RUSTFLAGS).
///
/// Returns None when every token was host poison — the caller then
/// removes the variable so the nested cargo falls back to
/// ebpf/.cargo/config.toml (which sets no rustflags). Returns the
/// ORIGINAL, byte-identical string when nothing matched — a clean
/// value is never rewritten, so quoting oddities in the space form
/// survive untouched. Only a value that actually contained poison is
/// rebuilt by rejoining the survivors, and a poison token can never
/// contain whitespace, so the rebuild cannot corrupt quoting either.
///
/// Poison tokens, in both the fused (`-Ctarget-cpu=native`) and
/// pair (`-C` + `target-cpu=native`) spellings:
///   - `target-cpu=` — becomes bpf-linker's `--cpu <host-cpu>`, invalid
///   - `target-feature=` — host feature set, meaningless-to-harmful for bpfel
///   - `link-arg=` — host linker args (mold/lld/fuse-ld) on bpf-linker's line
fn strip_host_poison(value: &str, sep: &str) -> Option<String> {
    let tokens: Vec<&str> = value.split(sep).collect();
    let mut kept: Vec<&str> = Vec::with_capacity(tokens.len());
    let mut i = 0;
    while i < tokens.len() {
        if is_host_poison_token(tokens[i]) {
            i += 1;
            continue;
        }
        // Pair spelling: "-C" followed by the flag with an "=" payload.
        if tokens[i] == "-C"
            && let Some(next) = tokens.get(i + 1)
            && (next.starts_with("target-cpu=")
                || next.starts_with("target-feature=")
                || next.starts_with("link-arg="))
        {
            i += 2;
            continue;
        }
        kept.push(tokens[i]);
        i += 1;
    }
    if kept.len() == tokens.len() {
        Some(value.to_string())
    } else if kept.is_empty() {
        None
    } else {
        Some(kept.join(sep))
    }
}

/// Fused-spelling poison check (`-Ctarget-cpu=...` as ONE token).
fn is_host_poison_token(token: &str) -> bool {
    token.starts_with("-Ctarget-cpu=")
        || token.starts_with("-Ctarget-feature=")
        || token.starts_with("-Clink-arg=")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIGHT-hunt-28: the rustflags sanitizer must reproduce the exact
    /// leak the owner's Zen 3 host hit — the alias-shaped
    /// CARGO_ENCODED_RUSTFLAGS (`-C\x1ftarget-cpu=native`) is entirely
    /// poison, so the variable is removed (None), while every clean
    /// token survives byte-identically.
    #[test]
    fn host_poison_stripping_matches_the_live_leak_shapes() {
        // The exact value the pro-native-gnu alias produces (verified
        // live by dumping the build script env): pure poison -> None.
        assert_eq!(
            strip_host_poison("-C\u{1f}target-cpu=native", "\u{1f}"),
            None
        );

        // The pro-native-musl shape: CPU + feature, both poison -> None.
        assert_eq!(
            strip_host_poison(
                "-C\u{1f}target-cpu=native\u{1f}-C\u{1f}target-feature=+crt-static",
                "\u{1f}"
            ),
            None
        );

        // Poison plus CI's contract: the -D warnings pair survives.
        assert_eq!(
            strip_host_poison("-C\u{1f}target-cpu=native\u{1f}-D\u{1f}warnings", "\u{1f}"),
            Some("-D\u{1f}warnings".to_string())
        );

        // The plain build's value (root .cargo/config.toml): clean
        // passthrough, byte-identical.
        assert_eq!(
            strip_host_poison("-C\u{1f}codegen-units=1", "\u{1f}"),
            Some("-C\u{1f}codegen-units=1".to_string())
        );

        // build.sh's fast-linker export (mold hosts): link-arg is
        // poison for bpf-linker even in the pair spelling.
        assert_eq!(
            strip_host_poison(
                "-C\u{1f}link-arg=-fuse-ld=mold\u{1f}-D\u{1f}warnings",
                "\u{1f}"
            ),
            Some("-D\u{1f}warnings".to_string())
        );

        // The space-separated RUSTFLAGS form: clean value passes
        // through untouched (quoting survives because no rewrite
        // happens), poison is removed by space token.
        assert_eq!(
            strip_host_poison("-D warnings -C codegen-units=1", " "),
            Some("-D warnings -C codegen-units=1".to_string())
        );
        assert_eq!(
            strip_host_poison("-C target-cpu=native -D warnings", " "),
            Some("-D warnings".to_string())
        );

        // Fused single-token spellings.
        assert_eq!(strip_host_poison("-Ctarget-cpu=native", "\u{1f}"), None);
        assert_eq!(strip_host_poison("-Ctarget-feature=avx2", " "), None);

        // A trailing lone "-C" (malformed value) must survive intact
        // rather than panic or eat the next token.
        assert_eq!(
            strip_host_poison("-D warnings -C", " "),
            Some("-D warnings -C".to_string())
        );

        // "-C" followed by a NON-poison payload is kept whole.
        assert_eq!(
            strip_host_poison("-C\u{1f}debug-assertions=on", "\u{1f}"),
            Some("-C\u{1f}debug-assertions=on".to_string())
        );
    }
}
