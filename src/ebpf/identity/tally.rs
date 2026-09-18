// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Per-cgroup comm tally and the majority-vote representative
//! (NIGHT-hunt-10).
//!
//! Pure userspace: /proc facts in, one honest label out. Kept beside —
//! not inside — the IdentityMap walk so the vote is independently
//! unit-pinnable (and the walk file stays under the 500-line gate).

use std::collections::HashMap;

/// Per-cgroup comm tally for the majority vote (NIGHT-hunt-10).
#[derive(Debug, Clone, Copy)]
pub(super) struct CommStat {
    /// How many live processes in this cgroup carry this comm.
    pub(super) count: usize,
    /// Lowest PID seen with this comm (tie-break + uid source).
    pub(super) min_pid: u32,
    /// UID of that lowest PID.
    pub(super) min_pid_uid: u32,
}

/// Majority-vote representative for one cgroup (NIGHT-hunt-10).
///
/// The comm hosting the most processes names the cgroup; a perfect
/// tie falls back to the comm whose lowest PID is smallest —
/// deterministic because PIDs are unique. This replaces the
/// first-pid-wins rule, which let a lone chrome_crashpad label a
/// cgroup whose other ~30 processes were all brave: `status` showed
/// the browser's actual traffic carrier as "cg:18526
/// (chrome_crashpad)", and `unstrict 18526` then silently removed
/// brave's enforcement while the owner believed only a crash handler
/// had been freed.
///
/// Pure function over the tally so the vote is unit-pinned below.
pub(super) fn pick_representative(comm_stats: &HashMap<String, CommStat>) -> Option<(String, u32)> {
    comm_stats
        .iter()
        .max_by(|a, b| {
            // Most processes first; tie -> lowest min_pid ranks higher.
            (a.1.count)
                .cmp(&(b.1.count))
                .then_with(|| (b.1.min_pid).cmp(&(a.1.min_pid)))
        })
        .map(|(comm, stat)| (comm.clone(), stat.min_pid_uid))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIGHT-hunt-10, the owner's live case: cg:18526 carried ~30 brave
    /// processes plus one chrome_crashpad, and first-pid-wins let the
    /// lone crash handler name the whole cgroup — status then showed
    /// the browser's real traffic carrier as "(chrome_crashpad)" and
    /// unstricting it silently freed brave. The majority vote must
    /// name it brave.
    #[test]
    fn majority_vote_beats_first_pid_the_crashpad_case() {
        let mut stats: HashMap<String, CommStat> = HashMap::new();
        stats.insert(
            "brave".to_string(),
            CommStat {
                count: 30,
                min_pid: 1850,
                min_pid_uid: 1000,
            },
        );
        stats.insert(
            "chrome_crashpad".to_string(),
            CommStat {
                count: 1,
                min_pid: 900, // lower pid — the old rule's winner
                min_pid_uid: 1000,
            },
        );
        assert_eq!(
            pick_representative(&stats),
            Some(("brave".to_string(), 1000))
        );
    }

    /// Perfect tie (the mixed session cgroup: one alacritty, one curl):
    /// lowest min_pid wins, deterministically.
    #[test]
    fn majority_tie_breaks_on_lowest_pid() {
        let mut stats: HashMap<String, CommStat> = HashMap::new();
        stats.insert(
            "alacritty".to_string(),
            CommStat {
                count: 1,
                min_pid: 500,
                min_pid_uid: 1000,
            },
        );
        stats.insert(
            "curl".to_string(),
            CommStat {
                count: 1,
                min_pid: 800,
                min_pid_uid: 1000,
            },
        );
        assert_eq!(
            pick_representative(&stats),
            Some(("alacritty".to_string(), 1000))
        );
    }

    /// Process count dominates pid order: a 3-process comm beats a
    /// 1-process comm even when the singleton has the lower pid.
    #[test]
    fn majority_count_dominates_lower_min_pid() {
        let mut stats: HashMap<String, CommStat> = HashMap::new();
        stats.insert(
            "singleton".to_string(),
            CommStat {
                count: 1,
                min_pid: 100,
                min_pid_uid: 0,
            },
        );
        stats.insert(
            "trio".to_string(),
            CommStat {
                count: 3,
                min_pid: 900,
                min_pid_uid: 1000,
            },
        );
        assert_eq!(
            pick_representative(&stats),
            Some(("trio".to_string(), 1000))
        );
    }

    /// The representative's uid comes from the winning comm's lowest
    /// pid (display + system-app classification follow the majority).
    #[test]
    fn representative_uid_comes_from_the_winning_comm() {
        let mut stats: HashMap<String, CommStat> = HashMap::new();
        stats.insert(
            "root_helper".to_string(),
            CommStat {
                count: 1,
                min_pid: 100,
                min_pid_uid: 0,
            },
        );
        stats.insert(
            "user_app".to_string(),
            CommStat {
                count: 5,
                min_pid: 2000,
                min_pid_uid: 1000,
            },
        );
        assert_eq!(
            pick_representative(&stats),
            Some(("user_app".to_string(), 1000))
        );
    }

    /// No tally → no representative (the empty-map cgroup keeps the
    /// raw cg:{id} label fallback).
    #[test]
    fn empty_tally_has_no_representative() {
        assert_eq!(pick_representative(&HashMap::new()), None);
    }
}
