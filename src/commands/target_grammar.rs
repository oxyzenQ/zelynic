// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The masterclass target grammar (NIGHT-improve-53) — the '::' list
//! law the unified verbs (strict / block / unstrict) route by.
//!
//! Lineage: NIGHT-blade-18 made the colon list a grammar (the
//! best-effort scan died — empty segments silently dropped apps, '/'
//! and punctuation-only segments could never be a comm);
//! NIGHT-hunt-30 made the multi verbs list verbs (a one-target list
//! is the single verb's lane); NIGHT-improve-53 merges the VERBS —
//! strict-single + strict-multi are one `strict`, the block and
//! unstrict pairs likewise — so the separator DOUBLES: the container
//! native grammar (docker://nginx, k8s://prod/web-abc) and the cg:
//! display prefix own the single ':', and '::' is the only byte
//! sequence that can never collide with them.
//!
//! The routing law itself is one substring test ([`target_is_list`]):
//! a '::' anywhere in the target means the group lane, everything
//! else is the single lane. The single lane keeps its own grammar
//! (validate_single_target in safety.rs — the empty-target boundary).

use anyhow::Result;

/// NIGHT-improve-53: does this target string carry the list
/// separator? The unified verbs route on this one test — a '::'
/// anywhere means the group lane, everything else is the single
/// lane.
///
/// Deliberately substring-plain: `cg:1234` and the container URIs
/// (`docker://nginx`, `k8s://prod/web-abc`) carry single colons
/// only, so they can never trip it — a `::` in the wild is always
/// an intentional list (or a typo the grammar rungs below name).
pub(crate) fn target_is_list(target_str: &str) -> bool {
    target_str.contains("::")
}

/// The '::'-list grammar for the unified verbs' group lane
/// (strict / block / unstrict).
///
/// What the grammar refuses, each with the mistake named:
///   - a container URI anywhere in the list (`docker://nginx::brave`)
///     — containers are the single lane: the group lane shares ONE
///     bucket across members, and a container workload belongs to
///     its own apply, not a shared one (charger-core-2's contract,
///     carried over the separator change);
///   - an EMPTY member (`a::::b`, `a::`) — the dropped app was never
///     limited (blade-18's law, one separator later);
///   - fewer than 2 DISTINCT members (`brave::brave`) — hunt-30's
///     "single is single, multi is multi", now read as "one target
///     needs no separator" since the verbs merged;
///   - a member carrying a single ':' outside the `cg:` prefix
///     (`brave:curl::steam` — the old single-colon list muscle
///     memory) — that ':' is the prefix grammar's own byte;
///   - a member containing `/` (`a/`) — comm can never contain a
///     path separator (blade-18);
///   - a punctuation-only member (`;`) — no alphanumeric characters
///     means no possible comm, and unquoted in a shell this exact
///     byte splits commands (blade-18, the owner's fatal example).
///
/// What stays deliberately legal: numeric and `cg:<id>` members
/// (their semantics belong to the cgroup-id guard, not this
/// grammar), and alnum-bearing garbage like `$(reboot)` — the
/// no-execution proof the single-target battery pins (the payload
/// is echoed verbatim as data, never executed, never silently
/// dropped).
///
/// Returns the validated members (trimmed, in order). The all-empty
/// list keeps the historical "No targets specified" shape with the
/// family's own example command.
pub(crate) fn validate_multi_targets(targets_str: &str, example: &str) -> Result<Vec<String>> {
    // charger-core-2, carried over the separator change: a container
    // URI anywhere in the list is a named mistake — the group lane
    // shares one bucket across its members, and a container workload
    // owns its own apply. The refusal names the real lane instead of
    // letting the '/' check below complain about a URI fragment.
    if targets_str.contains("://") {
        return Err(anyhow::anyhow!(
            "container targets (docker://<name>, k8s://<namespace>/<pod>) do not ride lists — \
             the group lane shares one bucket\n  \
             tip: apply each container on its own: one target, no '::' separator"
        ));
    }

    let segments: Vec<String> = targets_str
        .split("::")
        .map(|s| s.trim().to_string())
        .collect();

    if segments.iter().all(|s| s.is_empty()) {
        return Err(anyhow::anyhow!(
            "No targets specified. Use a '::'-separated list.\n  \
             Example: {example}"
        ));
    }

    if segments.iter().any(|s| s.is_empty()) {
        return Err(anyhow::anyhow!(
            "empty target in the list — '{targets_str}' (check the '::' separators)"
        ));
    }

    // NIGHT-hunt-30 (single is single, multi is multi), read through
    // the improve-53 merge: the verbs are one now, so a list that
    // carries ONE distinct target is not the wrong verb anymore — it
    // is the right verb wearing a separator it did not need. The
    // parse still names the count and both exits as tips.
    let distinct: std::collections::BTreeSet<&str> = segments.iter().map(|s| s.as_str()).collect();
    if distinct.len() < 2 {
        let verb = example.split_whitespace().nth(1).unwrap_or("strict");
        return Err(anyhow::anyhow!(
            "{verb} lists need 2 or more distinct targets — '{targets_str}' carries one\n  \
             tip: a single target needs no separator — 'zelynic {verb} {}'\n  \
             tip: or add members to the list. Example: {example}",
            segments[0]
        ));
    }

    for seg in &segments {
        // NIGHT-improve-53: a single ':' inside a member is the
        // prefix grammar's own byte (cg:<id>, the container URIs the
        // refusal above already owns) — anything else is the old
        // single-colon list muscle memory half-migrated, and naming
        // it here keeps the mistake from dying as a late no-match on
        // a process name that can never exist.
        if seg.contains(':') && !seg.starts_with("cg:") {
            return Err(anyhow::anyhow!(
                "list member '{seg}' carries a single ':' — members separate with '::' \
                 (single ':' is the cg: prefix and container grammar)"
            ));
        }
        if seg.contains('/') {
            return Err(anyhow::anyhow!(
                "target '{seg}' is not a valid app name (contains '/')"
            ));
        }
        if !seg.chars().any(|c| c.is_alphanumeric()) {
            return Err(anyhow::anyhow!("target '{seg}' is not a valid app name"));
        }
    }

    Ok(segments)
}

// The grammar pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired across trees exactly like the safety
// battery — moved out of safety_tests.rs with the fn itself at the
// improve-53 split (the masterclass grammar is its own theme, and
// both files were near the 600-line cap).
#[cfg(all(test, feature = "ebpf"))]
#[path = "../../test/commands/target_grammar_tests.rs"]
mod tests;
