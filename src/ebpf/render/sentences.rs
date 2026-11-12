// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The depth report's enforcement prose (night-blade-5 lineage) —
//! split from report.rs at the 600-line law (the depth_json
//! sibling-split lineage): the verdict word, the summary sentence,
//! the lanes verdict, the one pluralizer, and the direction word —
//! the pure sentence builders the human report and the JSON
//! projection share.

use crate::ebpf::limiter::types::POLICY_FLAG_PER_SOCKET;
use crate::ebpf::limiter::{PolicyRaw, format_count, format_rate};

use super::report::Enforcement;

/// One direction's verdict word for the summary line: a zero rate is
/// the block family's signature, an absent row is unlimited.
fn direction_word(policy: &Option<PolicyRaw>) -> &'static str {
    match policy {
        Some(p) if p.rate_bps == 0 => "blocked",
        Some(_) => "rate",
        None => "unlimited",
    }
}

/// The machine verdict word for JSON: "unlimited" | "blocked" |
/// "limited" (mixed shapes collapse to "limited" — the per-direction
/// bps fields carry the detail).
#[must_use]
pub fn enforcement_word(enforcement: &Enforcement) -> &'static str {
    match enforcement {
        Enforcement::Unlimited => "unlimited",
        Enforcement::Limited { download, upload } => {
            match (direction_word(download), direction_word(upload)) {
                ("unlimited", "unlimited") => "unlimited",
                (a, b) if a == "blocked" && b == "blocked" => "blocked",
                _ => "limited",
            }
        }
    }
}

/// The one noun-pluralizer (night-ux-2, pure): "1 process" reads
/// whole, "1 processes" reads like a bug. The count itself rides
/// format_count (the SI ladder); this helper carries only the noun.
#[must_use]
pub(crate) fn pluralize<'a>(n: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if n == 1 { singular } else { plural }
}

/// The summary line's human sentence: "limited — dl 100.0 KB/s · ul
/// blocked", "blocked", or "unlimited (no policy for this cgroup)"
/// (pure).
///
/// night-ux-2 (the owner's live-run residue): the enforcement line is
/// the SAME line for every limited cgroup. The former `(shaping)`
/// window tag retired for three reasons — it misnamed the mechanism
/// (zelynic DROPS at the hard cap, a policer's act; "shaping" means
/// queue-delay smoothing), it was redundant (the accounting line
/// right below names the drop share, the kernel's own ledger), and
/// it split identical cgroups into two different wordings in one
/// report. Whether the limit bit during the measurement window is
/// the accounting line's answer, on the line the reader is already
/// reading.
///
/// night-ux-1 (the owner's 200kb-on-Brave session): the unlimited
/// sentence names WHY it is unlimited — no policy rows name this
/// cgroup (the [`Enforcement::Unlimited`] arm's own definition) — so
/// a reader who just set a policy on a DIFFERENT cgroup reads the
/// absence as the honest state it is ("no policy HERE"), never as
/// "my policy isn't working". The limited arms keep their shape
/// (a policy exists there; the sentence names its figures).
#[must_use]
pub fn enforcement_sentence(enforcement: &Enforcement) -> String {
    match enforcement {
        Enforcement::Unlimited => "unlimited (no policy for this cgroup)".to_string(),
        Enforcement::Limited { download, upload } => {
            // charger-core-3c: a per-socket policy's figure names its
            // unit ("/socket") — an unmarked rate would read as the
            // cgroup cap the policy does not carry (the status
            // marker's twin, hunted on the depth surface).
            let render = |p: &Option<PolicyRaw>| match p {
                Some(raw) if raw.rate_bps == 0 => "blocked".to_string(),
                Some(raw) if raw.flags & POLICY_FLAG_PER_SOCKET != 0 => {
                    format!("{} /socket", format_rate(raw.rate_bps))
                }
                Some(raw) => format_rate(raw.rate_bps),
                None => "unlimited".to_string(),
            };
            match (direction_word(download), direction_word(upload)) {
                ("unlimited", "unlimited") => "unlimited".to_string(),
                (a, b) if a == "blocked" && b == "blocked" => "blocked".to_string(),
                _ => format!("limited — dl {} · ul {}", render(download), render(upload)),
            }
        }
    }
}

/// The enforcement LANES verdict (night-netrunner-4, night-ux-2
/// wording, the deep report's "RECWN/ECN/Pacing active?" row, pure):
/// the quota saver's three lanes as this cgroup's policy arms them —
/// RECWN shapes the download policy ("download only", the full word
/// — "(dl)" was engineer shorthand on a human surface), the ECN-first
/// lane is ARMED when the host carries the helper (attached and able
/// to mark — the mark count then says whether it HAS: "no marks yet"
/// while the ledger is empty, "N marks" once the CE ledger books
/// deliveries; singular for one, the pluralize law) and honestly
/// "unavailable" when the host lacks the helper, and the pacing lane
/// commands the upload policy's rate onto its sockets. None for an
/// unlimited target (no lanes to name — absence, not an empty
/// promise).
#[must_use]
pub fn lanes_sentence(
    enforcement: &Enforcement,
    ecn_set_ce: bool,
    ce_marked_packets: u64,
) -> Option<String> {
    let Enforcement::Limited { download, upload } = enforcement else {
        return None;
    };
    let mut parts: Vec<String> = Vec::new();
    if download.is_some() {
        parts.push("recwn (download only)".to_string());
    }
    if ecn_set_ce {
        if ce_marked_packets > 0 {
            parts.push(format!(
                "ecn armed, {} {}",
                format_count(ce_marked_packets),
                pluralize(ce_marked_packets as usize, "mark", "marks")
            ));
        } else {
            parts.push("ecn armed, no marks yet".to_string());
        }
    } else {
        parts.push("ecn unavailable".to_string());
    }
    if let Some(up) = upload
        && up.rate_bps > 0
    {
        parts.push(format!("pacing {}", format_rate(up.rate_bps)));
    }
    (!parts.is_empty()).then(|| parts.join(" \u{b7} "))
}
