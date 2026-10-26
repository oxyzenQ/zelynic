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
