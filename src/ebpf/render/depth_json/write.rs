// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The depth document's writer half (night-dragon-maintenance-T1
//! (S1), split from depth_json.rs by the 600-line LOC law — the
//! docker_tests sibling-split lineage): each impl reproduces the
//! exact wire contract the serde derive emitted before the stack
//! left the graph. Field order is declaration order, plain Options
//! ride JSON null, the two Not::not booleans skip false, the
//! untagged enum rides bare. Field names are the pinned stable v11
//! scripting API.

use super::{
    BypassAuditJson, DepthDocJson, DepthEntryJson, DepthMissJson, DepthTargetJson, EndpointJson,
    EnforcementStatsJson, ProcJson, TrafficJson,
};

impl DepthDocJson {
    fn write_json(&self, out: &mut String) {
        use crate::json::write::write_array;

        out.push_str("{\"targets\":");
        write_array(out, self.targets.len(), |out, i| {
            self.targets[i].write_json(out);
        });
        out.push_str(",\"bypass_audit\":");
        match &self.bypass_audit {
            Some(audit) => audit.write_json(out),
            None => out.push_str("null"),
        }
        out.push('}');
    }

    /// The depth document as one compact JSON line.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(256 + self.targets.len() * 512);
        self.write_json(&mut out);
        out
    }
}

impl DepthEntryJson {
    fn write_json(&self, out: &mut String) {
        match self {
            Self::Report(report) => report.write_json(out),
            Self::Miss(miss) => miss.write_json(out),
        }
    }
}

impl DepthTargetJson {
    fn write_json(&self, out: &mut String) {
        use crate::json::write::{write_number, write_opt_number, write_opt_string, write_string};

        out.push_str("{\"target\":");
        write_string(out, &self.target);
        out.push_str(",\"cgroup_id\":");
        write_number(out, self.cgroup_id);
        out.push_str(",\"name\":");
        write_string(out, &self.name);
        out.push_str(",\"cgroup_path\":");
        write_opt_string(out, self.cgroup_path.as_deref());
        out.push_str(",\"uid\":");
        write_opt_number(out, self.uid);
        out.push_str(",\"user\":");
        write_opt_string(out, self.user.as_deref());
        out.push_str(",\"enforcement\":");
        write_string(out, self.enforcement);
        out.push_str(",\"download_bytes_per_sec\":");
        write_opt_number(out, self.download_bytes_per_sec);
        out.push_str(",\"upload_bytes_per_sec\":");
        write_opt_number(out, self.upload_bytes_per_sec);
        if self.download_per_socket {
            out.push_str(",\"download_per_socket\":true");
        }
        if self.upload_per_socket {
            out.push_str(",\"upload_per_socket\":true");
        }
        out.push_str(",\"group_id\":");
        write_opt_number(out, self.group_id);
        out.push_str(",\"enforcement_stats\":");
        match &self.enforcement_stats {
            Some(stats) => stats.write_json(out),
            None => out.push_str("null"),
        }
        out.push_str(",\"cgroup_memory_bytes\":");
        write_opt_number(out, self.cgroup_memory_bytes);
        out.push_str(",\"cgroup_cpu_usage_usec\":");
        write_opt_number(out, self.cgroup_cpu_usage_usec);
        out.push_str(",\"oldest_started_secs\":");
        write_opt_number(out, self.oldest_started_secs);
        out.push_str(",\"processes\":");
        write_number(out, self.processes);
        out.push_str(",\"socket_holders\":");
        write_number(out, self.socket_holders);
        out.push_str(",\"sockets\":");
        write_number(out, self.sockets);
        out.push_str(",\"traffic\":");
        match &self.traffic {
            Some(traffic) => traffic.write_json(out),
            None => out.push_str("null"),
        }
        out.push_str(",\"procs\":");
        crate::json::write::write_array(out, self.procs.len(), |out, i| {
            self.procs[i].write_json(out);
        });
        out.push_str(",\"endpoints\":");
        crate::json::write::write_array(out, self.endpoints.len(), |out, i| {
            self.endpoints[i].write_json(out);
        });
        out.push('}');
    }
}

impl ProcJson {
    fn write_json(&self, out: &mut String) {
        use crate::json::write::{write_number, write_opt_number, write_opt_string, write_string};

        out.push_str("{\"pid\":");
        write_number(out, self.pid);
        out.push_str(",\"comm\":");
        write_string(out, &self.comm);
        out.push_str(",\"uid\":");
        write_number(out, self.uid);
        out.push_str(",\"user\":");
        write_opt_string(out, self.user.as_deref());
        out.push_str(",\"ppid\":");
        write_number(out, self.ppid);
        out.push_str(",\"state\":");
        write_string(out, &self.state);
        out.push_str(",\"threads\":");
        write_number(out, self.threads);
        out.push_str(",\"rss_kb\":");
        write_number(out, self.rss_kb);
        out.push_str(",\"exe\":");
        write_opt_string(out, self.exe.as_deref());
        out.push_str(",\"exe_deleted\":");
        out.push_str(if self.exe_deleted { "true" } else { "false" });
        out.push_str(",\"kind\":");
        write_opt_string(out, self.kind);
        out.push_str(",\"script\":");
        write_opt_string(out, self.script.as_deref());
        out.push_str(",\"permission\":");
        write_opt_string(out, self.permission.as_deref());
        out.push_str(",\"cwd\":");
        write_opt_string(out, self.cwd.as_deref());
        out.push_str(",\"cmdline\":");
        write_opt_string(out, self.cmdline.as_deref());
        out.push_str(",\"started_ago_secs\":");
        write_opt_number(out, self.started_ago_secs);
        out.push_str(",\"started_epoch\":");
        write_opt_number(out, self.started_epoch);
        out.push('}');
    }
}

impl EndpointJson {
    fn write_json(&self, out: &mut String) {
        use crate::json::write::{write_number, write_opt_number, write_string};

        out.push_str("{\"pid\":");
        write_number(out, self.pid);
        out.push_str(",\"comm\":");
        write_string(out, &self.comm);
        out.push_str(",\"proto\":");
        write_string(out, self.proto);
        out.push_str(",\"remote\":");
        write_string(out, &self.remote);
        out.push_str(",\"state\":");
        write_string(out, self.state);
        out.push_str(",\"download_bytes\":");
        write_opt_number(out, self.download_bytes);
        out.push_str(",\"upload_bytes\":");
        write_opt_number(out, self.upload_bytes);
        // night-verdict-closure-T6 (H3): the dedupe key rides
        // TRAILING (the additive rule — existing consumers' prefix
        // matching is untouched): one inode = one socket held by
        // several fds; distinct inodes = distinct sockets even when
        // the (pid, proto, remote, state) tuple collides.
        out.push_str(",\"socket_inode\":");
        write_number(out, self.socket_inode);
        out.push('}');
    }
}

impl TrafficJson {
    fn write_json(&self, out: &mut String) {
        use crate::json::write::{write_array, write_number};

        out.push_str("{\"window_secs\":");
        write_number(out, self.window_secs);
        out.push_str(",\"download_bytes\":");
        write_number(out, self.download_bytes);
        out.push_str(",\"upload_bytes\":");
        write_number(out, self.upload_bytes);
        out.push_str(",\"endpoints\":");
        write_array(out, self.endpoints.len(), |out, i| {
            self.endpoints[i].write_json(out);
        });
        out.push('}');
    }
}

impl EnforcementStatsJson {
    fn write_json(&self, out: &mut String) {
        use crate::json::write::write_number;

        out.push_str("{\"packets_allowed\":");
        write_number(out, self.packets_allowed);
        out.push_str(",\"packets_dropped\":");
        write_number(out, self.packets_dropped);
        out.push_str(",\"bytes_allowed\":");
        write_number(out, self.bytes_allowed);
        out.push_str(",\"bytes_dropped\":");
        write_number(out, self.bytes_dropped);
        out.push('}');
    }
}

impl DepthMissJson {
    fn write_json(&self, out: &mut String) {
        use crate::json::write::write_string;

        out.push_str("{\"target\":");
        write_string(out, &self.target);
        out.push_str(",\"error\":");
        write_string(out, &self.error);
        out.push('}');
    }
}

impl BypassAuditJson {
    fn write_json(&self, out: &mut String) {
        use crate::json::write::{write_number, write_string};

        out.push_str("{\"window_secs\":");
        write_number(out, self.window_secs);
        out.push_str(",\"nic_tx_bytes\":");
        write_number(out, self.nic_tx_bytes);
        out.push_str(",\"nic_rx_bytes\":");
        write_number(out, self.nic_rx_bytes);
        out.push_str(",\"bpf_tx_bytes\":");
        write_number(out, self.bpf_tx_bytes);
        out.push_str(",\"bpf_rx_bytes\":");
        write_number(out, self.bpf_rx_bytes);
        out.push_str(",\"shadow_tx_bytes\":");
        write_number(out, self.shadow_tx_bytes);
        out.push_str(",\"shadow_rx_bytes\":");
        write_number(out, self.shadow_rx_bytes);
        out.push_str(",\"verdict\":");
        write_string(out, self.verdict);
        // night-verdict-closure-T3 (B4): the derived shadow
        // percentages ride TRAILING (the additive rule — existing
        // consumers' prefix matching is untouched), the same
        // whole-percent figures the text report's bypass section
        // prints.
        out.push_str(",\"shadow_tx_percent\":");
        write_number(out, self.shadow_tx_percent);
        out.push_str(",\"shadow_rx_percent\":");
        write_number(out, self.shadow_rx_percent);
        out.push('}');
    }
}
