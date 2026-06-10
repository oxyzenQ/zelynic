// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
use anyhow::Result;
use std::process::Command;

use super::process::get_process_uid;
use super::NFT_TABLE;

/// Ensure required kernel modules for traffic control are loaded.
pub(crate) fn ensure_kernel_modules() -> Result<()> {
    let modules = [
        "sch_htb",
        "cls_fw",
        "sch_ingress",
        "nf_conntrack",
        "sch_fq_codel",
    ];

    for module in modules {
        let _ = Command::new("modprobe").arg(module).output();
    }

    Ok(())
}

/// Ensure netfilter conntrack is enabled for ct mark propagation.
pub(crate) fn ensure_conntrack() -> Result<()> {
    let _ = Command::new("modprobe").args(["nf_conntrack"]).output();

    let params = [
        ("net.netfilter.nf_conntrack_acct", "1"),
        ("net.netfilter.nf_conntrack_mark", "1"),
    ];

    for (key, val) in params {
        let _ = Command::new("sysctl")
            .args(["-w", &format!("{}={}", key, val)])
            .output();
    }

    Ok(())
}

/// Briefly interrupt existing target-UID sockets so new sockets are created
/// after the process has moved into the target cgroup.
pub(super) fn force_reconnect_existing_sockets(use_v2: bool, pids: &[u32]) {
    if !use_v2 {
        return;
    }

    let Some(uid) = pids.first().and_then(|pid| get_process_uid(*pid)) else {
        return;
    };

    let uid_str = uid.to_string();
    let uid_rule = format!("meta skuid {}", uid_str);

    let _ = Command::new("nft")
        .args([
            "add", "rule", "inet", NFT_TABLE, "output", &uid_rule, "drop",
        ])
        .output();

    std::thread::sleep(std::time::Duration::from_millis(300));

    if let Ok(list_out) = Command::new("nft")
        .args(["-a", "list", "chain", "inet", NFT_TABLE, "output"])
        .output()
    {
        let list_stdout = String::from_utf8_lossy(&list_out.stdout);
        for line in list_stdout.lines() {
            if line.contains(&uid_rule) {
                if let Some(pos) = line.rfind("handle ") {
                    let handle = line[pos + 7..].trim();
                    let _ = Command::new("nft")
                        .args([
                            "delete", "rule", "inet", NFT_TABLE, "output", "handle", handle,
                        ])
                        .output();
                    break;
                }
            }
        }
    }
}
