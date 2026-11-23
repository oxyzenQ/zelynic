// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The D5 commit-signature policy (night-solid-defense-2): the
//! runtime half of the GPG commit binding, pure over the build-time
//! stamp so every verdict class is unit-testable without a keyring.
//!
//! The gap this row closes (the supply-chain hole the owner's
//! adversarial review named): D0-D2 prove the ownership claim, D3
//! fingerprints the whole image, D4 seals the embedded kernel
//! objects — but the `commit` line the report carries was a CLAIM,
//! not a bound fact. A binary swapped on the release channel
//! replays its own claims and the ladder had no row that could
//! disagree. D5 closes exactly that: build.rs verified the commit
//! the binary was built from against the PINNED maintainer public
//! key (the repo's own tracked copy, imported into an isolated
//! throwaway keyring — never the building user's), and this row
//! turns that verdict into the ladder's sixth depth. The
//! out-of-band twin: a consumer who verified the maintainer key
//! (keyservers, GitHub, docs/VERIFY_RELEASE.md) verifies the SIGNED
//! TAG the release was cut from, the tag names the commit, and D5
//! proves the binary really was built from a commit signed by that
//! same key — the chain from key to tag to commit to binary closes
//! with no channel left to MITM silently.
//!
//! The pinned fingerprint is the SAME file build/gpg.rs reads —
//! `include_str!` on both sides, one source of truth, zero drift
//! between the verifier and the reporter.

/// The maintainer's pinned primary key fingerprint (ed25519,
/// `F5324E0967F104D58CE025F347A50AEF4B65AAC2`, long id
/// `47A50AEF4B65AAC2` — the identity that signs the release
/// archives per docs/VERIFY_RELEASE.md). Single-sourced from
/// `assets/gpg/pinned-maintainer-fpr.txt` (no trailing newline: the
/// include is the value).
pub(crate) const PINNED_MAINTAINER_KEY_FPR: &str =
    include_str!("../../assets/gpg/pinned-maintainer-fpr.txt");

/// The D5 verdict: `(passed, detail)` for the sig ladder's
/// commit-signature row. Every state of the build-time stamp maps to
/// an honest sentence; only a verified match against the pinned
/// fingerprint passes — unsigned, foreign-key, broken, missing and
/// unknown all FAIL, naming their shape (the estate's
/// fails-by-name law).
#[must_use]
pub(crate) fn commit_signature_verdict(stamp: &str, commit_sha: &str) -> (bool, String) {
    let (state, evidence) = match stamp.split_once(':') {
        Some((state, evidence)) => (state, Some(evidence)),
        None => (stamp, None),
    };
    match state {
        "verified" => {
            let fpr = evidence.unwrap_or_default();
            if fpr == PINNED_MAINTAINER_KEY_FPR {
                (
                    true,
                    format!(
                        "commit {commit_sha} carries a GPG signature by the pinned \
                         maintainer key {} (verified against the repo's pinned public \
                         key at build time)",
                        short_fpr(fpr)
                    ),
                )
            } else {
                // A VALIDSIG that is not the pin: the signature is
                // real but the signer is not the maintainer — the
                // MITM shape, named by fingerprint.
                (
                    false,
                    format!(
                        "commit {commit_sha} is signed by {} — NOT the pinned \
                         maintainer key {}",
                        short_fpr(fpr),
                        short_fpr(PINNED_MAINTAINER_KEY_FPR)
                    ),
                )
            }
        }
        "wrong-key" => (
            false,
            format!(
                "commit {commit_sha} carries a valid GPG signature by {} — NOT the \
                 pinned maintainer key {}",
                short_fpr(evidence.unwrap_or("an unknown key")),
                short_fpr(PINNED_MAINTAINER_KEY_FPR)
            ),
        ),
        "no-key" => (
            false,
            format!(
                "commit {commit_sha} carries a signature the pinned maintainer key \
                 does not cover{} — not the maintainer's signature",
                evidence
                    .map(|fpr| format!(" (signed by {fpr})"))
                    .unwrap_or_default()
            ),
        ),
        "bad-signature" => (
            false,
            format!(
                "commit {commit_sha} carries a GPG signature that FAILED the \
                 cryptographic check"
            ),
        ),
        "unsigned" => (
            false,
            format!(
                "commit {commit_sha} carries NO GPG signature — the provenance \
                 chain stops at an unbound commit; bind releases to signed \
                 commits/tags"
            ),
        ),
        "no-vcs" => (
            false,
            "built from a source snapshot without VCS evidence — the commit \
             signature cannot be verified here"
                .to_string(),
        ),
        "unavailable" => (
            false,
            "signature evidence exists but the build machine could not verify \
             (git/gpg unavailable at build time)"
                .to_string(),
        ),
        // "unstamped" and anything a future stamp grammar emits but
        // this binary does not know: fail closed, never a silent
        // pass (the D4 missing-stamp law).
        other => (
            false,
            format!("no commit-signature verdict ({other}) — fail-closed"),
        ),
    }
}

/// The display shape for fingerprints: 16-hex long id when the input
/// carries at least that much, else the input as-is (an honest
/// shorter token beats a truncated lie).
fn short_fpr(fpr: &str) -> String {
    if fpr.len() >= 16 {
        fpr[fpr.len() - 16..].to_string()
    } else {
        fpr.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PINNED: &str = PINNED_MAINTAINER_KEY_FPR;

    /// The pin itself is load-bearing: a 40-hex fingerprint, and the
    /// long id's tail matches the key asset the docs name.
    #[test]
    fn the_pinned_fingerprint_is_the_documented_shape() {
        assert_eq!(PINNED.len(), 40, "a full OpenPGP fingerprint is 40 hex");
        assert!(
            PINNED.bytes().all(|b| b.is_ascii_hexdigit()),
            "hex only: {PINNED}"
        );
        assert!(
            PINNED.ends_with("47A50AEF4B65AAC2"),
            "the long id docs/VERIFY_RELEASE.md publishes: {PINNED}"
        );
    }

    #[test]
    fn verified_by_the_pinned_key_passes_naming_the_key() {
        let (passed, detail) = commit_signature_verdict(&format!("verified:{PINNED}"), "089badd");
        assert!(passed, "{detail}");
        assert!(
            detail.contains("089badd") && detail.contains("47A50AEF4B65AAC2"),
            "names the commit and the key: {detail}"
        );
    }

    /// The signing-subkey world: gpg's VALIDSIG reports the SUBKEY
    /// when a subkey signed; build.rs already resolves to the
    /// primary before stamping, so a stamped fpr that is not the
    /// pinned primary is a foreign signer — even a well-formed one.
    #[test]
    fn verified_by_a_foreign_fingerprint_fails_by_name() {
        let foreign = "A".repeat(39) + "2";
        let (passed, detail) = commit_signature_verdict(&format!("verified:{foreign}"), "089badd");
        assert!(!passed, "a foreign signer must fail: {detail}");
        assert!(
            detail.contains("NOT the pinned maintainer key"),
            "names the tamper shape: {detail}"
        );
    }

    #[test]
    fn wrong_key_fails_naming_both_keys() {
        let (passed, detail) = commit_signature_verdict(
            "wrong-key:0123456789abcdef0123456789abcdef01234567",
            "ab12cd3",
        );
        assert!(!passed);
        assert!(
            detail.contains("89abcdef01234567"),
            "the foreign key: {detail}"
        );
        assert!(detail.contains("47A50AEF4B65AAC2"), "the pin: {detail}");
    }

    #[test]
    fn no_key_with_evidence_names_the_foreign_signer() {
        let (passed, detail) =
            commit_signature_verdict("no-key:0123456789abcdef0123456789abcdef01234567", "ab12cd3");
        assert!(!passed);
        assert!(detail.contains("signed by 0123456789abcdef0123456789abcdef01234567"));
        // The bare state (ERRSIG carried no full fpr) still fails.
        let (passed, _) = commit_signature_verdict("no-key", "ab12cd3");
        assert!(!passed);
    }

    #[test]
    fn unsigned_fails_as_the_incomplete_chain() {
        let (passed, detail) = commit_signature_verdict("unsigned", "ab12cd3");
        assert!(!passed);
        assert!(
            detail.contains("NO GPG signature") && detail.contains("ab12cd3"),
            "the row states the gap: {detail}"
        );
    }

    #[test]
    fn degraded_states_fail_their_honest_sentences() {
        for stamp in ["bad-signature", "no-vcs", "unavailable", "unstamped", ""] {
            let (passed, detail) = commit_signature_verdict(stamp, "ab12cd3");
            assert!(!passed, "{stamp} must fail");
            assert!(!detail.is_empty(), "{stamp} must say why");
        }
    }
}
