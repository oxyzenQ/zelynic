// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// The registry-prebuilt lane's manifest verification
// (night-dragon-maintenance-0, the sibling zejtron build/prebuilt.rs
// shape): a crates.io tarball carries no ebpf/ tree (cargo's package
// walk cannot carry the detached nested workspace), so the feature's
// two objects ride the tarball as the maintainer-built
// ebpf-prebuilt/zelynic-{observer,limiter} with their provenance
// manifest. This module verifies the manifest pins against the
// staged bytes before anything is embedded.
//
// The hard rule: the manifest's object blake3 MUST match the staged
// bytes before anything is staged — a stale or tampered lane panics
// naming both hashes, never silently embeds an object the manifest
// does not describe. The structural ELF validation (the same law the
// source-built lane applies to its freshly built objects) runs
// first, so a truncated or damaged object fails on its shape before
// its identity is even questioned. The manifest is
// generator-controlled (scripts/release/refresh-prebuilt.sh — the
// ONE WRITER — writes it), so the parser anchors on that exact
// shape: no TOML crate, std only, and build.rs keeps its
// std-only law via build/blake3.rs.
//
// The digest algorithm is blake3 (schema 2, night-dragon-maintenance-0
// — upgraded from the sha256 the schema-1 manifest pinned).

/// One [[object]] row of ebpf-prebuilt/manifest.toml: the pin a
/// registry extract verifies its staged bytes against.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PrebuiltPin {
    pub(crate) name: String,
    pub(crate) blake3: String,
    pub(crate) size: u64,
}

/// Parse EVERY [[object]] row out of the generator-controlled
/// manifest text, in document order. The anchors are
/// line-start-exact, so the header's ebpf_tree_blake3 key (a longer
/// name sharing the blake3 suffix) can never satisfy the object
/// anchor, and comments cannot satisfy any of the three. Each row
/// needs all three keys answered and a 64-hex-character hash pin — a
/// manifest that fails either shape is not a lane, and the caller
/// refuses it by name.
pub(crate) fn parse_prebuilt_manifest(text: &str) -> Vec<PrebuiltPin> {
    let mut rows: Vec<PrebuiltPin> = Vec::new();
    let mut name: Option<String> = None;
    let mut blake3: Option<String> = None;
    let mut size: Option<u64> = None;
    let mut flush = |name: &mut Option<String>,
                     blake3: &mut Option<String>,
                     size: &mut Option<u64>| {
        if let (Some(name), Some(blake3), Some(size)) = (name.take(), blake3.take(), size.take()) {
            rows.push(PrebuiltPin { name, blake3, size });
        }
    };
    for line in text.lines() {
        let line = line.trim_start();
        if line.starts_with("[[object]]") {
            flush(&mut name, &mut blake3, &mut size);
            continue;
        }
        if name.is_none() {
            name = quoted_value(line, "name = \"").map(str::to_owned);
        }
        if blake3.is_none() {
            blake3 = quoted_value(line, "blake3 = \"").map(str::to_owned);
        }
        if size.is_none() {
            size = line
                .strip_prefix("size = ")
                .and_then(|rest| rest.trim().parse::<u64>().ok());
        }
    }
    flush(&mut name, &mut blake3, &mut size);
    rows.retain(|row| row.blake3.len() == 64 && row.blake3.bytes().all(|b| b.is_ascii_hexdigit()));
    rows
}

/// The prebuilt lane's contract, factored out pure: the staged bytes
/// must match the manifest pin's size and blake3. The Err text names
/// the exact drift (both hashes on a hash mismatch) — it rides the
/// panic verbatim.
pub(crate) fn verify_prebuilt_bytes(data: &[u8], pin: &PrebuiltPin) -> Result<(), String> {
    if data.len() as u64 != pin.size {
        return Err(format!(
            "object size drift: the manifest pins {} bytes but the staged object is {} \
             bytes",
            pin.size,
            data.len()
        ));
    }
    let actual = crate::blake3::blake3_hex(data);
    if actual != pin.blake3 {
        return Err(format!(
            "object blake3 drift: the manifest pins {} but the staged object hashes to {}",
            pin.blake3, actual
        ));
    }
    Ok(())
}

/// The quoted-string read behind the line anchors: `key` is the full
/// literal prefix (e.g. `name = "`), the value runs to the closing
/// quote. None when the line does not carry the anchor or a closing
/// quote — the caller treats None as "this line is not my key".
pub(crate) fn quoted_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key)?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

// ── The two registry-lane entries, moved verbatim from build.rs ──
// (the NIGHT-improve-44 no-mercy 600-line cap: a pure move, no
// semantic change — the functions live beside the pin verification
// they drive, the module the law names for them).

/// NIGHT-ask-2: stage the two prebuilt eBPF objects for a registry
/// source extract — the lane that makes `cargo install zelynic`
/// full-featured on a plain stable toolchain.
///
/// The objects are the maintainer-built release artifacts tracked in
/// ebpf-prebuilt/ (generated by scripts/release/refresh-prebuilt.sh,
/// which drives this repo's own validated build pipeline and records
/// provenance in ebpf-prebuilt/manifest.toml). They are the SAME
/// bytes the GitHub Release binaries embed, so a registry install and
/// a release tarball have identical kernel compatibility — the
/// CO-RE objects carry no host assumptions.
///
/// Every object passes the same NIGHT-hunt-29 structural validation
/// the nested lane applies (`read_validated_ebpf_object`), then lands
/// in OUT_DIR under the exact names the loaders' include_bytes!
/// concat paths expect — the embedding pipeline downstream of this
/// point is byte-for-byte the nested lane's. A missing or damaged
/// prebuilt object panics with the honest diagnosis: the crate is
/// INCOMPLETE (the prebuilt lane did not survive packaging), and the
/// remedies are the git checkout build and the GitHub Release binary.
pub(crate) fn stage_registry_prebuilt_objects(manifest_dir: &std::path::Path) {
    let prebuilt_dir = manifest_dir.join("ebpf-prebuilt");
    // Watched only on the lane that consumes it: a git checkout
    // builds its objects from ebpf/ and never reads this directory,
    // so refreshing the prebuilt lane must not rebuild such trees.
    println!("cargo:rerun-if-changed={}", prebuilt_dir.display());
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    // night-dragon-maintenance-0: the manifest pins are verified
    // against the staged bytes BEFORE anything is embedded — a stale
    // or tampered lane panics naming both hashes, never silently
    // embeds bytes the manifest does not describe (the sibling
    // zejtron build/prebuilt.rs law). The pins are blake3, computed
    // by the std-only build/blake3.rs.
    let manifest_text =
        std::fs::read_to_string(prebuilt_dir.join("manifest.toml")).unwrap_or_else(|e| {
            panic!(
                "the prebuilt lane's provenance manifest {} is unreadable ({e}) — the \
             registry tarball is incomplete without it; report this as a packaging bug",
                prebuilt_dir.join("manifest.toml").display()
            )
        });
    let pins = parse_prebuilt_manifest(&manifest_text);
    for name in ["zelynic-observer", "zelynic-limiter"] {
        let data = crate::validate::read_validated_ebpf_object(&prebuilt_dir.join(name))
            .unwrap_or_else(|problem| {
                panic!(
                    "the ebpf feature was requested from a registry tarball (no ebpf/ \
                 workspace rides a registry package — cargo's package walk cannot \
                 carry nested packages), and the prebuilt object {name} is missing or \
                 damaged ({problem}). This crate is INCOMPLETE: the ebpf-prebuilt/ lane \
                 that makes `cargo install zelynic` full-featured did not survive \
                 packaging. Report it, and meanwhile build from a git checkout (git \
                 clone https://github.com/oxyzenQ/zelynic, then cargo build --release \
                 --features ebpf) or install the flagship binary from GitHub Releases \
                 — see docs/VERIFY_RELEASE.md for both channels"
                )
            });
        let pin = pins.iter().find(|row| row.name == name).unwrap_or_else(|| {
            panic!(
                "the prebuilt lane's manifest.toml carries no parsable [[object]] row for \
                 {name} (name/blake3/size) — the manifest is generator-controlled by \
                 scripts/release/refresh-prebuilt.sh; a hand-edited or truncated \
                 manifest is a broken lane, and the build refuses it by name"
            )
        });
        verify_prebuilt_bytes(&data, pin).unwrap_or_else(|drift| {
            panic!(
                "the prebuilt eBPF lane is stale: {drift}. The bytes on disk are not the \
                 bytes the manifest pins — regenerate the lane with \
                 ./scripts/release/refresh-prebuilt.sh before building; embedding \
                 unverified bytes is never an option"
            )
        });
        let dst = out_dir.join(name);
        std::fs::write(&dst, &data)
            .unwrap_or_else(|e| panic!("failed to stage {} into OUT_DIR: {e}", dst.display()));
    }
    // The lane stamp consumed by info::ebpf_lane(): `zelynic -V`
    // answers "eBPF objects: registry-prebuilt", and the provenance
    // (source tree pin, toolchain, linker) rides the shipped
    // ebpf-prebuilt/manifest.toml.
    println!("cargo:rustc-env=ZELYNIC_EBPF_LANE=registry-prebuilt");
}

/// The build-time arm of the prebuilt-lane freshness contract
/// (night-dragon-maintenance-0, the sibling zejtron
/// auto_heal_prebuilt_lane shape, adapted honestly to this repo's
/// laws): any edit under ebpf/ stales the manifest's tree pin, and
/// every ebpf-feature build on a git checkout announces it — a
/// production alias (`cargo pro-linux-amd64-v3-musl` and siblings) or
/// a plain `cargo build` never silently builds against a lane that
/// no longer describes its sources.
///
/// Advisory by construction, for a zelynic-specific reason: the
/// sibling's writer builds the object NESTED (its own target
/// directory), so its build-time heal can run the full rewrite from
/// inside build.rs; zelynic's writer deliberately routes through the
/// ROOT pipeline (`cargo build --release --locked --features ebpf` —
/// the NIGHT-ask-2 single-source-of-build-truth law), and that root
/// build already holds cargo's target/ lock while this build script
/// runs — an in-build rewrite would deadlock on its own rebuild.
/// The commit gate (scripts/gates/check-commit-gate.sh) is the
/// enforcement arm: it auto-heals the stale lane through the one
/// writer and stages the refresh into the commit, so "edit ebpf/,
/// commit" carries a fresh lane with no manual step.
///
/// In-sync lanes pay one script spawn (a verdict over a few small
/// hashes) per build; the verdict is skipped entirely on registry
/// extracts and packaged copies (no writer, no .git) and under the
/// ZELYNIC_SKIP_PREBUILT_REGEN escape hatch, shared with the commit
/// gate.
pub(crate) fn check_prebuilt_lane_freshness(manifest_dir: &std::path::Path) {
    let script = manifest_dir.join("scripts/release/refresh-prebuilt.sh");
    if !script.is_file() || !manifest_dir.join(".git").exists() {
        return;
    }
    if std::env::var_os("ZELYNIC_SKIP_PREBUILT_REGEN").is_some() {
        return;
    }
    // The digest tool probe: the regenerator refuses to answer without
    // its pinned b3sum (its own gate exits before any verdict), and a
    // missing tool is NOT a stale lane — the distinction matters
    // because the warning says "stale". On a host without the tool
    // (a miri runner, a fresh contributor checkout) the check is a
    // silent no-op: this build embeds the SOURCE-BUILT objects and
    // needs nothing from the lane, and the commit gate is the hard
    // stop that names the fix. The two install dirs are probed
    // explicitly because the build-script env does not always carry
    // them on PATH (the pre-commit-hook lesson).
    let mut b3sum_candidates: Vec<std::path::PathBuf> = vec![std::path::PathBuf::from("b3sum")];
    if let Ok(home) = std::env::var("HOME") {
        let home = std::path::PathBuf::from(home);
        b3sum_candidates.push(home.join(".cargo/bin/b3sum"));
        b3sum_candidates.push(home.join(".local/bin/b3sum"));
    }
    let digest_tool = b3sum_candidates.iter().any(|candidate| {
        std::process::Command::new(candidate)
            .arg("--version")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    });
    if !digest_tool {
        return;
    }
    let verdict = std::process::Command::new("bash")
        .arg(&script)
        .arg("--check")
        .output();
    let Ok(out) = verdict else {
        return;
    };
    if out.status.success() {
        return;
    }
    println!(
        "cargo:warning=zelynic: the ebpf-prebuilt lane is stale (an edit under ebpf/); \
         the commit gate will regenerate it through the one writer at commit time, \
         or run ./scripts/release/refresh-prebuilt.sh now"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-for-byte the shape refresh-prebuilt.sh writes (comments
    /// trimmed, keys and order preserved).
    const CANONICAL: &str = r#"# generated header comment
schema = 2
generated = "2026-10-26T20:00:42Z"
toolchain = "nightly-2026-09-18"
bpf_linker = "0.11.1"
ebpf_tree_blake3 = "0e65357ad18de5c263839690f7f69af0719cab41b5e03d59e033ce06ee985be7"
built_by = "oxyzenQ <130107241+oxyzenQ@users.noreply.github.com>"

[[object]]
name = "zelynic-observer"
blake3 = "d00e5f61acccaf927577f9e80e41e8829668d104c49ad2e95a621cd2b053a92e"
size = 3216

[[object]]
name = "zelynic-limiter"
blake3 = "b5d6e3a6eedc43ca8e487d2be5528a3d7e20bf02a98dfcb8286539edbb066ca0"
size = 79872
"#;

    #[test]
    fn canonical_manifest_parses_to_both_object_rows() {
        let pins = parse_prebuilt_manifest(CANONICAL);
        assert_eq!(pins.len(), 2, "the lane carries two objects");
        assert_eq!(pins[0].name, "zelynic-observer");
        assert_eq!(
            pins[0].blake3,
            "d00e5f61acccaf927577f9e80e41e8829668d104c49ad2e95a621cd2b053a92e"
        );
        assert_eq!(pins[0].size, 3216);
        assert_eq!(pins[1].name, "zelynic-limiter");
        assert_eq!(pins[1].size, 79872);
    }

    #[test]
    fn the_tree_hash_header_key_never_satisfies_the_object_anchor() {
        // The header carries ebpf_tree_blake3 = "..." BEFORE the
        // [[object]] rows; the anchor is "blake3 = \"" at line start,
        // so the tree pin must not be mistaken for an object pin.
        let pins = parse_prebuilt_manifest(CANONICAL);
        for pin in &pins {
            assert_ne!(
                pin.blake3, "0e65357ad18de5c263839690f7f69af0719cab41b5e03d59e033ce06ee985be7",
                "the tree pin leaked into an object row"
            );
        }
    }

    #[test]
    fn a_missing_object_key_drops_the_row() {
        // No hash row for the second object: that row is not a lane,
        // only the first parses — the caller's name-match then refuses
        // the manifest for the missing object instead of hallucinating
        // a pin.
        let broken = CANONICAL.replace("blake3 = \"b5d6e3a6", "xblake3 = \"b5d6e3a6");
        let pins = parse_prebuilt_manifest(&broken);
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].name, "zelynic-observer");
    }

    #[test]
    fn a_non_hex_hash_pin_drops_the_row() {
        let broken = CANONICAL.replace(
            "blake3 = \"d00e5f61acccaf927577f9e80e41e8829668d104c49ad2e95a621cd2b053a92e\"",
            "blake3 = \"not-a-hash\"",
        );
        let pins = parse_prebuilt_manifest(&broken);
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].name, "zelynic-limiter");
    }

    #[test]
    fn size_drift_is_named_with_both_sides() {
        let pin = PrebuiltPin {
            name: "zelynic-observer".to_owned(),
            blake3: "d00e5f61acccaf927577f9e80e41e8829668d104c49ad2e95a621cd2b053a92e".to_owned(),
            size: 3216,
        };
        let err = verify_prebuilt_bytes(&[0u8; 100], &pin).unwrap_err();
        assert!(err.contains("3216") && err.contains("100"), "{err}");
    }

    #[test]
    fn hash_drift_is_named_with_both_hashes() {
        let pin = PrebuiltPin {
            name: "zelynic-observer".to_owned(),
            blake3: "d00e5f61acccaf927577f9e80e41e8829668d104c49ad2e95a621cd2b053a92e".to_owned(),
            size: 3,
        };
        let err = verify_prebuilt_bytes(b"abc", &pin).unwrap_err();
        assert!(err.contains("blake3 drift"), "{err}");
        // The drift names the pinned hash AND the actual one.
        assert!(err.contains("d00e5f61"), "{err}");
        assert!(err.contains(&crate::blake3::blake3_hex(b"abc")), "{err}");
    }

    #[test]
    fn the_matching_lane_verifies_clean() {
        let data = b"abc";
        let pin = PrebuiltPin {
            name: "zelynic-observer".to_owned(),
            blake3: crate::blake3::blake3_hex(data),
            size: 3,
        };
        assert_eq!(verify_prebuilt_bytes(data, &pin), Ok(()));
    }
}
