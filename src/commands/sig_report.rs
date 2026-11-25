// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The `sig` command surface — the six-depth signature report
//! (night-signature-advanced-1; D4 added by night-depth-hardening-Z2,
//! D5 by night-solid-defense-2).
//!
//! The owner runs sibling tools across the fleet (zejtron and
//! cosmostrix print the same depth-ladder shape), so `zelynic sig`
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
//!   D4  object-integrity — blake3 over each embedded eBPF object,
//!       compared against the digest build.rs stamped into the binary
//!       at build time (night-depth-hardening-Z2). The binary proves
//!       the kernel programs it carries are the ones its build pinned
//!       (the source-built bytes or the ebpf-prebuilt manifest's pins,
//!       per lane) — an object patched inside the artifact fails by
//!       name and the verdict goes TAMPERED. This is the camera's own
//!       seal: D0-D2 prove the ownership claim, D3 the whole image,
//!       D4 the ring-0 payload specifically — the most sensitive asset
//!       in the binary, running in kernel space.
//!   D5  commit-signature — the commit the binary claims is GPG-
//!       signed by the PINNED maintainer key, verified at build time
//!       against the repo's own pinned public key in an isolated
//!       keyring (night-solid-defense-2; the policy lives in
//!       [`sig_commit_sig`]). This is the row that binds the provenance
//!       claim to the release channel: with the maintainer key verified
//!       out-of-band and releases cut from signed tags, D5 closes the
//!       key → tag → commit → binary chain — the binary swapped on the
//!       wire can no longer replay its claims unanswered.
//!
//! Numbering note (the cosmostrix contract, kept verbatim): the
//! D0-D3 depth rows are the VERIFICATION depths the sibling tools
//! share; D4 is zelynic's own fifth row (the eBPF estate has no
//! sibling counterpart to verify) and D5 its sixth (the commit
//! binding, the supply-chain layer no sibling carries yet). The
//! `-V` Depth-matrix line's d0:-d3: tokens are the four STORAGE
//! layers (masked manifests, masked authors, FNV fingerprints,
//! blake3 anchor) — a different axis, and the object-digest stamps
//! and the commit-signature stamp ride no -V token: they are
//! build-time seals reported through this ladder. The two numbering
//! systems are documented here so a reader never has to guess which
//! axis a `D2` refers to.
//!
//! The first three depths are the `-V` Depth-matrix line rendered per
//! depth; they reuse [`provenance_view`]'s single pass (the invariant
//! documented in `src/info/signature.rs` — the report shows exactly
//! the bytes the integrity folds verify). D3, D4 and D5 are exclusive
//! to this command: D3 reads the whole image, D4 hashes the embedded
//! kernel objects, D5 reports the build-time commit-signature
//! verdict, and none of the three belongs on the `-V` path.
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
//! The report exits 1 on any non-Authentic verdict
//! ([`SigVerdict::Tampered`] and, since night-dragon-fly-4,
//! [`SigVerdict::Unsigned`] — the any-failed-depth contract names the
//! exit, not the verdict class) — this tree's
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
use crate::info::{
    build_hash, build_time, identity_of, manifest_fingerprint, provenance_view, vcs_commit_sig,
};
use crate::output::brand_bold;

use super::sig_commit_sig::{commit_signature_state, commit_signature_verdict};

/// Verdict of the depth ladder.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SigVerdict {
    /// Every depth passed.
    Authentic,
    /// The commit-signature depth is the ONE failure and its stamp
    /// state is `unsigned` (night-dragon-fly-4): a missing GPG
    /// binding is a missing provenance link, not a modification —
    /// every integrity depth above verifies. Still exits 1 (the
    /// documented any-failed-depth contract).
    Unsigned,
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

/// night-depth-hardening-Z2: one embedded object's identity check —
/// blake3 over the exact bytes the binary embeds, against the digest
/// build.rs stamped at build time. Pure, so the tamper test can drive
/// it with a flipped byte and the D4 row can render its verdict. `Ok`
/// carries the digest; `Err` names the object AND both hashes — a
/// tampered artifact answers "which object and what drift", never a
/// bare false. Feature-gated: the mechanism exists only where the
/// embedded objects do (the dormant build has no camera to audit).
#[cfg(feature = "ebpf")]
fn object_matches_digest(name: &str, bytes: &[u8], pinned: &str) -> Result<String, String> {
    let hex = blake3::hash(bytes).to_hex().to_string();
    if hex == pinned {
        Ok(hex)
    } else {
        Err(format!(
            "object {name} hashes to b3:{hex} but the build stamped b3:{pinned} — the \
             embedded kernel program is not the one the build pinned"
        ))
    }
}

/// D4 object-integrity (night-depth-hardening-Z2): verify every
/// embedded eBPF object against its build-time digest stamp. A
/// full-life build checks both objects; the dormant lane carries no
/// objects and says so instead of passing silently. The stamps ride
/// `option_env!` with a fail-closed missing case (the estate's
/// build-stamp convention — `src/info/build.rs`): a build whose
/// script failed to stamp produces a binary whose D4 depth FAILS with
/// the reason named — an unsealed camera is an unverified camera,
/// never a silent pass.
#[cfg(feature = "ebpf")]
fn object_integrity() -> (bool, String) {
    let checks: [(&str, &[u8], Option<&str>); 2] = [
        (
            "zelynic-observer",
            crate::ebpf::loader::OBSERVER_ELF,
            option_env!("ZELYNIC_EBPF_OBJ_DIGEST_OBSERVER"),
        ),
        (
            "zelynic-limiter",
            crate::ebpf::limiter::types::LIMITER_ELF,
            option_env!("ZELYNIC_EBPF_OBJ_DIGEST_LIMITER"),
        ),
    ];
    let mut all_ok = true;
    let mut parts = Vec::with_capacity(checks.len());
    for (name, bytes, pinned) in checks {
        match pinned {
            Some(pinned) => match object_matches_digest(name, bytes, pinned) {
                Ok(hex) => parts.push(format!("{name} b3:{hex}")),
                Err(problem) => {
                    all_ok = false;
                    parts.push(problem);
                }
            },
            None => {
                all_ok = false;
                parts.push(format!(
                    "{name}: no build-time digest stamp — fail-closed, the camera \
                     carries no seal to verify"
                ));
            }
        }
    }
    (all_ok, parts.join("; "))
}

/// The dormant lane's honest D4: no embedded objects exist, so there
/// is nothing to verify and nothing to hide — the row passes with the
/// reason stated, never with a fake seal.
#[cfg(not(feature = "ebpf"))]
fn object_integrity() -> (bool, String) {
    (
        true,
        "dormant lane — no embedded eBPF objects to seal".to_string(),
    )
}

/// Run the six-depth ladder and render the full report block.
///
/// The banner is the one colored line — brand purple, bold, the
/// doctor/update banner tier (the owner's purple mark: the signature
/// IS the brand mark, NIGHT-hunt-5's engraving law) — and the depth
/// rows stay plain so the text greps cleanly
/// (`zelynic sig | grep "D5 commit-signature"`). The text is stable by
/// contract (tests pin its shape, like the `-V` report): boxed header,
/// six depth rows, an identity field block, then the verdict.
/// Computing the verdict is separated from printing so tests can hold
/// the text without capturing stdout.
#[must_use]
pub(crate) fn sig_report() -> (String, SigVerdict) {
    let view = provenance_view();

    // D0: the lane-honest manifest materialized and carries the
    // identity shape (marker + identity, yearless since
    // night-ux-orion-3).
    let identity = identity_of(&view.manifest);
    let d0_shape_ok = !identity.is_empty();

    // D1: the authors layer materialized and binds to the identity.
    // identity_of renders the clean core (the defensive trailing-year
    // strip never fires on the yearless truths), so the binding
    // compares against it directly - the inline year strip was a
    // second, drift-prone copy of that law.
    let binding_ok = !identity.is_empty() && view.authors.starts_with(&identity);

    // D2: the cryptographic anchor (already recomputed in the same
    // single pass that produced the display bytes — `verified` folds
    // fingerprints, binding, and anchor).
    let anchor_ok = view.verified;

    // D3: the running image's own blake3 fingerprint.
    let self_hash = binary_self_hash();

    // D4: the embedded kernel programs' own identities against the
    // build's digest stamps (night-depth-hardening-Z2). The stamps are
    // compile-time env; the bytes are the embedded objects — the
    // runtime re-hash is the binary auditing its own ring-0 payload.
    let (objects_ok, objects_detail) = object_integrity();

    // D5: the commit-signature binding (night-solid-defense-2). The
    // stamp is the build's own verified verdict over the claimed
    // commit; the policy (pinned fingerprint, honest sentences for
    // every state) lives in sig_commit_sig.rs.
    let sig_stamp = vcs_commit_sig();
    let (sig_ok, sig_detail) = commit_signature_verdict(sig_stamp, build_hash());
    let sig_state = commit_signature_state(sig_stamp);

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
        DepthRow {
            name: "object-integrity",
            passed: objects_ok,
            detail: objects_detail,
        },
        DepthRow {
            name: "commit-signature",
            passed: sig_ok,
            detail: sig_detail,
        },
    ];

    let depths_passed = rows.iter().filter(|r| r.passed).count();
    // night-dragon-fly-4: the verdict splits the unsigned class out
    // of TAMPERED — an unsigned commit is a missing provenance link,
    // not a modification (the live battery's own find: a pristine
    // local build read "SIGNATURE: TAMPERED" for a plain no-GPG
    // commit). UNSIGNED fires only when the commit-signature depth
    // is the ONE failure and the stamp state says `unsigned`; any
    // integrity-depth failure, a foreign key, or a failed
    // cryptographic check stays TAMPERED — those are tampering-class,
    // not absent-provenance-class.
    let verdict = if depths_passed == rows.len() {
        SigVerdict::Authentic
    } else if depths_passed + 1 == rows.len() && !sig_ok && sig_state == "unsigned" {
        SigVerdict::Unsigned
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
    // night-ux-orion-2: the contact row rides the materialized authors
    // layer's own email segment (the D1 claim's angle-bracket tail) -
    // one plaintext source, zero new constants.
    if let Some((_, email)) = view.authors.rsplit_once('<') {
        let email = email.trim_end_matches('>');
        text.push_str(&format!("contact     {email}\n"));
    }
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
        match verdict {
            SigVerdict::Authentic => "AUTHENTIC",
            SigVerdict::Unsigned => "UNSIGNED",
            SigVerdict::Tampered => "TAMPERED",
        },
        rows.len()
    ));
    // night-dragon-fly-4: the unsigned class carries its own note —
    // the verdict names the missing link honestly, and the self-hash
    // note below stays the closing line for every verdict.
    if verdict == SigVerdict::Unsigned {
        text.push_str(
            "note: an unsigned commit is a missing provenance link, not a\n\
             modification — every integrity depth above verifies; releases\n\
             still bind to signed commits/tags.\n",
        );
    }
    text.push_str("note: the self-hash is a fingerprint to compare against a\n");
    // night-depth-infra-1: no trailing newline here — println_safe!
    // writes the terminal one itself, and the doubled byte this line
    // used to carry was the census's only output-hygiene catch.
    text.push_str("published release hash; it cannot embed its own digest.");

    (text, verdict)
}

/// Print the report (the `sig` dispatch calls this, then exits 1 on
/// tamper so scripts can gate on the exit code).
pub(crate) fn run() {
    let (text, verdict) = sig_report();
    println_safe!("{text}");
    if verdict != SigVerdict::Authentic {
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
    use crate::commands::sig_commit_sig::PINNED_MAINTAINER_KEY_FPR;

    #[test]
    fn pristine_build_reports_the_stamped_signature_truth() {
        let (text, verdict) = sig_report();
        // The ladder's honesty law (night-solid-defense-2): the D5
        // row reports the BUILD's own verified verdict, so a tree on
        // an unsigned main reads FAIL "no GPG signature" (5/6) and
        // a tree whose HEAD is signed by the pinned maintainer key
        // reads AUTHENTIC 6/6 — both are the pristine truth for
        // their build, and the report must never claim otherwise.
        let stamp = crate::info::vcs_commit_sig();
        let sig_verified = stamp
            .strip_prefix("verified:")
            .is_some_and(|fpr| fpr == PINNED_MAINTAINER_KEY_FPR);
        if sig_verified {
            assert_eq!(verdict, SigVerdict::Authentic, "{text}");
            assert!(
                text.contains("SIGNATURE: AUTHENTIC (6/6 depths verified)"),
                "{text}"
            );
        } else {
            // night-dragon-fly-4: the verdict splits the unsigned
            // class — a no-GPG build reads UNSIGNED (the missing
            // provenance link, its own note line), every other
            // failure state stays TAMPERED.
            let state = commit_signature_state(stamp);
            if state == "unsigned" {
                assert_eq!(verdict, SigVerdict::Unsigned, "{text}");
                assert!(
                    text.contains("SIGNATURE: UNSIGNED (5/6 depths verified)"),
                    "{text}"
                );
            } else {
                assert_eq!(verdict, SigVerdict::Tampered, "{text}");
            }
            let d5 = text
                .lines()
                .find(|line| line.starts_with("D5 commit-signature"))
                .unwrap_or_else(|| panic!("the D5 row must exist:\n{text}"));
            assert!(
                d5.contains(" FAIL "),
                "an unstamped-truth build must fail D5 by name:\n{text}"
            );
        }
        for row in [
            "D0 runtime-identity",
            "D1 embedded-marker",
            "D2 anchor-integrity",
            "D3 binary-self-hash",
            "D4 object-integrity",
            "D5 commit-signature",
        ] {
            assert!(text.contains(row), "missing depth row {row}:\n{text}");
        }
    }

    /// night-depth-hardening-Z2: the D4 row must carry the digest
    /// verdicts by object name — a pristine build shows both objects
    /// sealed with their build-stamped digests.
    #[cfg(feature = "ebpf")]
    #[test]
    fn d4_row_names_both_objects_and_their_digests() {
        let (text, _) = sig_report();
        assert!(
            text.contains("D4 object-integrity"),
            "D4 row present:\n{text}"
        );
        assert!(
            text.contains("zelynic-observer b3:") && text.contains("zelynic-limiter b3:"),
            "both objects named with their digests:\n{text}"
        );
    }

    /// night-depth-hardening-Z2 tamper test — the CI-visible proof the
    /// task named: the exact bytes the binary embeds, ONE byte flipped,
    /// must FAIL against the build-stamped digest, naming the object
    /// and both hashes. The pristine comparison in the same test holds
    /// the honest twin: the probe flips in memory, the artifact does
    /// not. Runs on every push in the rootless test lane; the same
    /// mechanism fails the D4 row (verdict TAMPERED, exit 1) when a
    /// real artifact carries a patched object.
    #[cfg(feature = "ebpf")]
    #[test]
    fn one_flipped_object_byte_fails_by_name() {
        let pristine = crate::ebpf::loader::OBSERVER_ELF;
        // `env!`, not `option_env!(...).expect(...)` (clippy::option_env_unwrap,
        // deny-by-default under -D warnings since the e406c47 pass): a test
        // build compiles only where build.rs stamped the digest, so the
        // compile-time macro is the honest shape — a build without the stamp
        // fails HERE, at its own compile, instead of at run time.
        let pinned = env!("ZELYNIC_EBPF_OBJ_DIGEST_OBSERVER");

        // The artifact's own bytes pass against their stamp.
        assert!(
            object_matches_digest("zelynic-observer", pristine, pinned).is_ok(),
            "pristine bytes must verify"
        );

        // One flipped byte must fail BY NAME.
        let mut bytes = pristine.to_vec();
        let before = bytes[0];
        bytes[0] ^= 0x01;
        assert_ne!(bytes[0], before, "the flip must change the byte");
        let err = object_matches_digest("zelynic-observer", &bytes, pinned).unwrap_err();
        assert!(err.contains("zelynic-observer"), "names the object: {err}");
        assert!(err.contains("b3:"), "names both hashes: {err}");
        assert!(err.contains("stamped"), "names the drift shape: {err}");
    }

    #[test]
    fn report_names_the_owner_identity() {
        let (text, _) = sig_report();
        assert!(
            text.contains("identity    rezky_nightky (oxyzenQ)"),
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
            SigVerdict::Authentic | SigVerdict::Unsigned | SigVerdict::Tampered
        ));
    }
}
