// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The `sig` command surface — the four-depth signature report
//! (night-signature-advanced-1).
//!
//! The owner runs sibling tools across the fleet (zejtron and
//! cosmostrix print the same four-depth shape), so `zelynic sig`
//! renders the same verdict ladder over zelynic's own provenance
//! layers:
//!
//!   D0  runtime-identity — the lane-honest masked manifest
//!       materializes and carries the marker and the identity shape.
//!   D1  embedded-marker — the masked authors layer materializes and
//!       binds to the manifest identity (coherent pair).
//!   D2  anchor-integrity — the embedded blake3 anchor recomputes from
//!       the materialized payload (the cryptographic seal).
//!   D3  binary-self-hash — blake3 over the running executable image.
//!
//! Numbering note (the cosmostrix contract, kept verbatim): these
//! D0-D3 are the four VERIFICATION depths (the cross-tool parity
//! labels). The `-V` Depth-matrix line's d0:-d3: tokens are the four
//! STORAGE layers (masked manifests, masked authors, FNV fingerprints,
//! blake3 anchor) — a different axis. The two numbering systems are
//! documented here so a reader never has to guess which axis a `D2`
//! refers to.
//!
//! The first three depths are the `-V` Depth-matrix line rendered per
//! depth; they reuse [`provenance_view`]'s single pass (the invariant
//! documented in `src/info/signature.rs` — the report shows exactly
//! the bytes the integrity folds verify). D3 is exclusive to this
//! command: it reads the whole image and must stay off the `-V` path.
//!
//! # Honest limits of D3
//!
//! A self-hash cannot embed its own digest (the chicken-and-egg law of
//! hashing), so D3 is a FINGERPRINT, not a self-verifying seal: it is
//! the value to compare against a published release hash (or a
//! previously recorded local hash) to prove the exact image running.
//! `pass` means the image was read in full and hashed; the comparison
//! is the caller's. The docs and the report text below say this
//! plainly — no fake "verified against itself" claim anywhere.
//!
//! # Exit contract
//!
//! The report exits 1 on [`SigVerdict::Tampered`] — this tree's
//! runtime-fatal code (clap usage errors exit 2, runtime failures exit
//! 1; the sibling tools gate on their own code under the same law) —
//! so a script can gate on the verdict without parsing the text. The
//! report itself stays side-effect free; the dispatcher flushes before
//! the hard exit because the verdict IS the error surface and a
//! swallowed buffer would hide it.

use std::io::Read;

// The provenance lane's surface functions ride info's pub(crate)
// re-exports (the modules themselves stay private to info — one
// import point per the tree's visibility discipline).
use crate::info::{build_hash, build_time, identity_of, manifest_fingerprint, provenance_view};
use crate::output::brand_bold;

/// Verdict of the depth ladder.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SigVerdict {
    /// Every depth passed.
    Authentic,
    /// At least one depth failed; the report names which.
    Tampered,
}

/// One rendered depth row: `D{n} <name>  {pass|FAIL} — {detail}`.
struct DepthRow {
    name: &'static str,
    passed: bool,
    detail: String,
}

/// blake3 over the running executable image, read in chunks (the
/// release artifact is a multi-MB musl binary; streaming keeps the
/// allocation flat). `Err` names the failure honestly (unreadable
/// image, mid-read error) and fails the depth instead of guessing.
fn binary_self_hash() -> Result<String, String> {
    let path =
        std::env::current_exe().map_err(|e| format!("cannot locate the running image: {e}"))?;
    let mut file =
        std::fs::File::open(&path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0usize;
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("read error on {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n;
    }
    if total == 0 {
        return Err("image is empty".to_string());
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest.as_bytes() {
        hex.push_str(&format!("{byte:02x}"));
    }
    Ok(hex)
}

/// Run the four-depth ladder and render the full report block.
///
/// The banner is the one colored line — brand purple, bold, the
/// doctor/update banner tier (the owner's purple mark: the signature
/// IS the brand mark, NIGHT-hunt-5's engraving law) — and the depth
/// rows stay plain so the text greps cleanly
/// (`zelynic sig | grep "D2 anchor-integrity"`). The text is stable by
/// contract (tests pin its shape, like the `-V` report): boxed header,
/// four depth rows, an identity field block, then the verdict.
/// Computing the verdict is separated from printing so tests can hold
/// the text without capturing stdout.
#[must_use]
pub(crate) fn sig_report() -> (String, SigVerdict) {
    let view = provenance_view();

    // D0: the lane-honest manifest materialized and carries the
    // identity shape (marker + identity + year).
    let identity = identity_of(&view.manifest);
    let d0_shape_ok = !identity.is_empty();

    // D1: the authors layer materialized and binds to the identity.
    let binding_ok = identity_of(&view.manifest)
        .strip_suffix(" 2026")
        .is_some_and(|core| view.authors.starts_with(core));

    // D2: the cryptographic anchor (already recomputed in the same
    // single pass that produced the display bytes — `verified` folds
    // fingerprints, binding, and anchor).
    let anchor_ok = view.verified;

    // D3: the running image's own blake3 fingerprint.
    let self_hash = binary_self_hash();

    let rows = [
        DepthRow {
            name: "runtime-identity",
            passed: d0_shape_ok,
            detail: identity.clone(),
        },
        DepthRow {
            name: "embedded-marker",
            passed: binding_ok,
            detail: "the masked authors layer binds to the manifest identity".to_string(),
        },
        DepthRow {
            name: "anchor-integrity",
            passed: anchor_ok,
            detail: format!("b3:{} recomputes from the masked payload", view.anchor_hex),
        },
        DepthRow {
            name: "binary-self-hash",
            passed: self_hash.is_ok(),
            detail: match &self_hash {
                Ok(hex) => format!("b3:{hex}"),
                Err(e) => format!("unavailable: {e}"),
            },
        },
    ];

    let depths_passed = rows.iter().filter(|r| r.passed).count();
    let verdict = if depths_passed == rows.len() {
        SigVerdict::Authentic
    } else {
        SigVerdict::Tampered
    };

    let mut text = String::new();
    text.push_str(&brand_bold("━━━ zelynic signature — depth matrix ━━━"));
    text.push('\n');
    for (i, row) in rows.iter().enumerate() {
        let status = if row.passed { "pass" } else { "FAIL" };
        text.push_str(&format!(
            "D{} {:<18} {} — {}\n",
            i, row.name, status, row.detail
        ));
    }
    text.push('\n');
    text.push_str(&format!("identity    {identity}\n"));
    text.push_str(&format!(
        "fingerprint fp={:016x} (fnv1a64, dual-layer)\n",
        manifest_fingerprint()
    ));
    text.push_str(&format!("anchor      b3:{}\n", view.anchor_hex));
    text.push_str(&format!("commit      {}\n", build_hash()));
    text.push_str(&format!("build-time  {}\n", build_time()));
    text.push('\n');
    text.push_str(&format!(
        "verdict: SIGNATURE: {} ({depths_passed}/{} depths verified)\n",
        if verdict == SigVerdict::Authentic {
            "AUTHENTIC"
        } else {
            "TAMPERED"
        },
        rows.len()
    ));
    text.push_str("note: the self-hash is a fingerprint to compare against a\n");
    text.push_str("published release hash; it cannot embed its own digest.\n");

    (text, verdict)
}

/// Print the report (the `sig` dispatch calls this, then exits 1 on
/// tamper so scripts can gate on the exit code).
pub(crate) fn run() {
    let (text, verdict) = sig_report();
    println_safe!("{text}");
    if verdict == SigVerdict::Tampered {
        // Flush the report before the hard exit: the verdict IS the
        // error surface, and a swallowed buffer would hide it.
        use std::io::Write;
        let _ = std::io::stdout().flush();
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pristine_build_reports_authentic_four_of_four() {
        let (text, verdict) = sig_report();
        assert_eq!(verdict, SigVerdict::Authentic);
        assert!(
            text.contains("SIGNATURE: AUTHENTIC (4/4 depths verified)"),
            "{text}"
        );
        for row in [
            "D0 runtime-identity",
            "D1 embedded-marker",
            "D2 anchor-integrity",
            "D3 binary-self-hash",
        ] {
            assert!(text.contains(row), "missing depth row {row}:\n{text}");
        }
    }

    #[test]
    fn report_names_the_owner_identity() {
        let (text, _) = sig_report();
        assert!(
            text.contains("identity    rezky_nightky (oxyzenQ) 2026"),
            "identity field must materialize the masked layers:\n{text}"
        );
        assert!(
            text.contains("anchor      b3:"),
            "anchor field present:\n{text}"
        );
        assert!(
            text.contains("fingerprint fp=") && text.contains(" (fnv1a64, dual-layer)"),
            "fingerprint field present:\n{text}"
        );
    }

    #[test]
    fn self_hash_hashes_the_test_image() {
        // In the test build the "running image" is the test harness
        // binary; the only honest invariant available here is that the
        // hash succeeds and is 64 lowercase hex chars (or fails with a
        // named error on exotic hosts — both are honest outcomes).
        match binary_self_hash() {
            Ok(hex) => {
                assert_eq!(hex.len(), 64);
                assert!(
                    hex.chars()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
                );
            }
            Err(e) => assert!(!e.is_empty(), "failure must name a reason"),
        }
    }

    #[test]
    fn report_shape_is_stable() {
        let (text, verdict) = sig_report();
        // The banner is the brand-bold purple tier; when the test
        // surface is not color-capable it degrades to plain text — the
        // shape law only pins the glyphs and the field block.
        assert!(text.contains("━━━ zelynic signature — depth matrix ━━━"));
        assert!(text.contains("verdict: SIGNATURE: "));
        assert!(text.contains("note: the self-hash is a fingerprint"));
        assert!(text.contains("commit      ") && text.contains("build-time  "));
        assert!(matches!(
            verdict,
            SigVerdict::Authentic | SigVerdict::Tampered
        ));
    }
}
