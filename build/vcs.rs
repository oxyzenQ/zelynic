// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// NIGHT-improve-44 executes the NIGHT-improve-31 split plan: the
// commit-sha chain (git / env / the registry vcs document) and its
// normalizer, the root main() resolution chain's own concern.

/// First step of the commit-sha chain: `git rev-parse --short=7 HEAD`
/// (NIGHT-ask-1, cosmostrix lineage). Returns `None` when git is
/// absent, fails (no `.git` — a registry extract), or answers
/// something other than usable hex (a detached submodule can answer
/// the literal `HEAD` here; the shared normalizer rejects that).
pub(crate) fn git_short_sha() -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sha = String::from_utf8(out.stdout).ok()?;
    normalize_short_sha(sha.trim())
}

/// Second step of the commit-sha chain: a full sha from CI env
/// (`GITHUB_SHA`), normalized to the same 7-char short shape so `-V`
/// renders one stable width across all three sources.
pub(crate) fn env_short_sha(var: &str) -> Option<String> {
    normalize_short_sha(&std::env::var(var).ok()?)
}

/// Parses the `sha1` field out of a `.cargo_vcs_info.json` document.
/// Pure string extraction — build.rs stays dependency-free (std
/// only), so there is no JSON crate here. The document shape is
/// stable: `{"git":{"sha1":"<40 hex>","dirty":bool},"path_in_vcs":""}`
/// (the `dirty` flag may be absent on clean publishes; field order is
/// not guaranteed, so the parse anchors on the `"sha1"` key, not on
/// byte offsets).
fn parse_vcs_sha_json(text: &str) -> Option<String> {
    let key = "\"sha1\"";
    let key_at = text.find(key)?;
    let after_key = &text[key_at + key.len()..];
    let colon_at = after_key.find(':')?;
    let value = after_key[colon_at + 1..].trim_start();
    let value = value.strip_prefix('"')?;
    let end = value.find('"')?;
    normalize_short_sha(&value[..end])
}

/// Third step of the commit-sha chain: read `.cargo_vcs_info.json`
/// from the package root (cargo materializes the file beside the
/// manifest when it packs the crate, so CARGO_MANIFEST_DIR is where
/// an extracted registry source carries it). Returns `None` when the
/// file is missing (ordinary dev builds — the normal case) or when
/// it carries no usable sha.
pub(crate) fn packaged_vcs_sha() -> Option<String> {
    let manifest_dir =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(manifest_dir.join(".cargo_vcs_info.json")).ok()?;
    parse_vcs_sha_json(&text)
}

/// Shared chain normalizer (NIGHT-ask-1): a sha is usable when it is
/// 7..=40 ASCII hex characters; the short form is the first 7,
/// lowercased — git short shas print lowercase, `GITHUB_SHA` and the
/// vcs document are full lowercase 40-hex, so one canonical 7-char
/// shape covers all three sources. Rejects everything else (`HEAD`,
/// empty, truncated, non-hex noise).
fn normalize_short_sha(s: &str) -> Option<String> {
    let n = s.trim();
    let len = n.len();
    if !(7..=40).contains(&len) || !n.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let short: String = n.chars().take(7).collect();
    Some(short.to_ascii_lowercase())
}

/// NIGHT-improve-1 phase 3: build the pure-Rust eBPF objects.

#[cfg(test)]
mod tests {
    use super::*;

    // ── NIGHT-ask-1: the commit-sha chain (git / env / vcs document) ──

    #[test]
    fn vcs_sha_json_parses_the_canonical_document() {
        // Byte-for-byte the shape cargo writes when it packs a crate
        // from a dirty tree (the `dirty` flag rides along).
        let doc = r#"{"git":{"sha1":"a1adb97b91fbb32bd5f22bd85b8dbf2870ea53c1","dirty":true},"path_in_vcs":""}"#;
        assert_eq!(parse_vcs_sha_json(doc).as_deref(), Some("a1adb97"));
    }

    #[test]
    fn vcs_sha_json_tolerates_field_order_and_dirty_absence() {
        // Clean publishes omit `dirty`; key order is not contractual.
        // Uppercase hex exercises the shared lowercasing too.
        let doc = r#"{"path_in_vcs":"","git":{"sha1":"44BE809B91FBB32BD5F22BD85B8DBF2870EA53C1"}"#;
        assert_eq!(parse_vcs_sha_json(doc).as_deref(), Some("44be809"));
    }

    #[test]
    fn vcs_sha_json_rejects_malformed_documents() {
        // No sha1 key at all (the file exists but is not a vcs doc).
        assert_eq!(parse_vcs_sha_json(r#"{"git":{}}"#), None);
        // Value not a quoted string — the anchored parse must not
        // hallucinate a sha out of trailing bytes.
        assert_eq!(parse_vcs_sha_json(r#"{"git":{"sha1":123}}"#), None);
        // A "sha1" TEXT buried inside another string's value must not
        // distract the anchor: the token searched for is the quoted
        // KEY `"sha1"` exactly, and `sha1-not-here` (no closing quote
        // after the digits) does not match it — the parse still finds
        // the real key and returns its value.
        assert_eq!(
            parse_vcs_sha_json(r#"{"path_in_vcs":"sha1-not-here","git":{"sha1":"a1adb97"}}"#)
                .as_deref(),
            Some("a1adb97")
        );
    }

    #[test]
    fn normalize_short_sha_shapes_the_three_chain_sources() {
        // Full 40-hex (GITHUB_SHA / the vcs document) -> first 7,
        // lowercased.
        assert_eq!(
            normalize_short_sha("A1ADB97B91FBB32BD5F22BD85B8DBF2870EA53C1").as_deref(),
            Some("a1adb97")
        );
        // Already-short git output passes through, lowercased.
        assert_eq!(normalize_short_sha("44Be809").as_deref(), Some("44be809"));
        // The submodule `HEAD` answer, too-short, and empty are None.
        assert_eq!(normalize_short_sha("HEAD"), None);
        assert_eq!(normalize_short_sha("abc123"), None);
        assert_eq!(normalize_short_sha(""), None);
    }
}
