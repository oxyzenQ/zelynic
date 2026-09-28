// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The update-check cooldown (NIGHT-critical-infra-1 — the
//! AI-agent-swarm threat model's one implemented mitigation).
//!
//! The scenario that motivated this: an autonomous agent with
//! zelynic in its executable allowlist but WITHOUT raw shell
//! access (the permission-gated agent sandboxes expose binaries,
//! not bash) can still be prompt-injected into a check-update
//! loop. Before the cooldown, every iteration was a full curl
//! spawn against api.github.com — a request storm the host's IP
//! answers for, and the one place where agent SCALE changes the
//! harm class (see the AI-Agent-Swarm Threat Model section in
//! docs/SAFETY_ANALYSIS.md: every local surface serializes or
//! bounds; the outbound fetch was the only unbounded one).
//!
//! The contract, in one paragraph: the update check performs at
//! most ONE completed network exchange per hour per user. A
//! per-user timestamp records when the last exchange completed;
//! an invocation inside the window answers with a disclosed
//! throttle verdict and exit 0, never a second fetch. Every
//! failure fails OPEN — an unreadable, absent, or garbage stamp
//! means the check proceeds. The stamp is runtime throttle state,
//! not configuration: XDG_RUNTIME_DIR (the per-user 0700 tmpfs
//! systemd provides) is the primary lane; the /tmp fallback
//! (uid-suffixed, world-readable directory) is accepted-risk — a
//! local user CAN pre-plant a future timestamp to suppress
//! another user's update CHECKS, a disclosed, informational-surface
//! DoS in the same trust class SECURITY.md already scopes out
//! (the attacker with /tmp write access against a user's own
//! session); the throttle verdict prints the remaining time so
//! the suppression is visible, and removing the file restores the
//! surface. The stamp is written only after curl exits 0 — a real
//! exchange happened, success or HTTP error — so transient
//! infra failures (DNS, timeout) never suppress a retry.

use std::path::PathBuf;

/// One completed exchange per hour per user — the window matches the
/// GitHub API's own hourly unauthenticated rate-limit unit: the
/// throttle is sized to the remote's cadence, not to a guess.
pub(crate) const UPDATE_COOLDOWN_SECS: u64 = 3600;

/// The per-user stamp path (pure — unit-pinned for both lanes).
///
/// XDG_RUNTIME_DIR (set by systemd/logind on modern Linux) is a
/// per-user 0700 tmpfs: only the invoking user can read or plant
/// the stamp, which makes it the correct trust boundary for
/// per-user runtime state. When it is unset (containers, non-session
/// contexts), the /tmp fallback carries the uid in the name so
/// different users never share each other's throttle; the
/// world-writable directory itself is the accepted-risk lane
/// documented above.
#[must_use]
pub(crate) fn stamp_path(xdg_runtime_dir: Option<&str>, uid: u32) -> PathBuf {
    match xdg_runtime_dir {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir).join("zelynic-update.stamp"),
        _ => PathBuf::from(format!("/tmp/.zelynic-update-{uid}")),
    }
}

/// Seconds remaining in the cooldown window, or `None` when the
/// window has elapsed and a new fetch is allowed (pure).
///
/// `Some(remaining)` strictly means `remaining > 0` — the boundary
/// instant (age exactly one window) and everything past it read
/// `None`, so the caller's `if let Some` arm is the whole throttle
/// decision. A stamp in the future (clock skew, or the documented
/// /tmp plant) saturates the age to zero — the full window remains,
/// and the throttle verdict discloses it.
#[must_use]
pub(crate) fn cooldown_remaining(now_secs: u64, last_fetch_secs: u64) -> Option<u64> {
    let age = now_secs.saturating_sub(last_fetch_secs);
    UPDATE_COOLDOWN_SECS
        .checked_sub(age)
        .filter(|remaining| *remaining > 0)
}

/// Read the last-fetch timestamp from the stamp file. Any failure
/// — absent, unreadable, non-numeric, torn write — is `None`: the
/// cooldown fails open, a broken stamp never blocks a check.
pub(crate) fn read_stamp(path: &std::path::Path) -> Option<u64> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

/// Record `now_secs` as the last completed exchange. Write errors
/// are ignored (fail-open): an unwritable stamp costs a redundant
/// fetch, never a suppressed check.
pub(crate) fn write_stamp(path: &std::path::Path, now_secs: u64) {
    let _ = std::fs::write(path, now_secs.to_string());
}

// NIGHT-critical-infra-1: the cooldown pins live under the single
// test/ tree (cosmostrix Pattern C), #[path]-wired like the
// recover verdict pins from the same audit campaign.
#[cfg(test)]
#[path = "../../test/cli/update_cooldown_tests.rs"]
mod cooldown_tests;
