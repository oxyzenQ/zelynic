// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The docker half of the container-native resolution (charger-
//! core-2, TIER A #5) — the Engine API over the unix socket and
//! the container's cgroup directory. Split from the parent module
//! at the 500-LOC owner cap; the walk and the cgroup-id resolution
//! live in the parent (the k8s lane shares them).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};

use super::{cgroup_id_of, find_cgroup_dir};

/// The docker Engine API endpoint and reply budget. The 4 MiB cap
/// holds ~2000 containers at the API's entry size — beyond that the
/// reply is refused instead of read unbounded.
const DOCKER_API_PATH: &str = "/v1.24/containers/json?all=1";
const DOCKER_REPLY_CAP: usize = 4 * 1024 * 1024;
/// Socket probes, in order: the canonical path, /run (the same file
/// on systems where /var/run is the symlink), then the rootless
/// daemon's $XDG_RUNTIME_DIR socket.
const DOCKER_SOCKETS: [&str; 2] = ["/var/run/docker.sock", "/run/docker.sock"];

/// One Engine API entry, reduced to the fields the match needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DockerEntry {
    pub(super) id: String,
    pub(super) names: Vec<String>,
}

/// Pure: the docker match verdict for one typed reference against
/// the API list — no match, one full id, or ambiguity (two entries
/// matched: a too-short id prefix, the only shape that can get
/// here — docker enforces unique names).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DockerMatch {
    None,
    One(String),
    Ambiguous(Vec<String>),
}

/// Pure: does one entry match the typed reference? By name (the
/// API prefixes names with '/', docker ps shows the stripped form),
/// or by id prefix (the docker CLI convention — the typed hex is a
/// prefix of the full 64-char id; at least 4 chars so a stray short
/// string cannot claim a match).
pub(super) fn docker_entry_matches(entry: &DockerEntry, typed: &str) -> bool {
    if typed.len() >= 4 && entry.id.starts_with(typed) {
        return true;
    }
    entry
        .names
        .iter()
        .any(|n| n.strip_prefix('/') == Some(typed))
}

/// Pure: the whole-list verdict.
pub(super) fn docker_match(entries: &[DockerEntry], typed: &str) -> DockerMatch {
    let matched: Vec<&DockerEntry> = entries
        .iter()
        .filter(|e| docker_entry_matches(e, typed))
        .collect();
    match matched.as_slice() {
        [] => DockerMatch::None,
        [one] => DockerMatch::One(one.id.clone()),
        many => DockerMatch::Ambiguous(
            many.iter()
                .map(|e| {
                    e.names
                        .first()
                        .map(|n| n.trim_start_matches('/').to_string())
                        .unwrap_or_else(|| e.id[..12.min(e.id.len())].to_string())
                })
                .collect(),
        ),
    }
}

/// The socket path to try, in probe order — the rootless daemon's
/// $XDG_RUNTIME_DIR socket rides last.
fn docker_socket_candidates() -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = DOCKER_SOCKETS.iter().map(PathBuf::from).collect();
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        candidates.push(PathBuf::from(xdg).join("docker.sock"));
    }
    candidates
}

/// One HTTP-over-unix-socket GET, read to EOF with a 2s deadline
/// either way — a hung daemon wedges nothing. HTTP/1.0 keeps the
/// reply unchunked (Go's net/http honors it), so the body is the
/// raw JSON after the header block.
fn docker_http_get(socket: &Path) -> Result<Vec<u8>> {
    let stream =
        UnixStream::connect(socket).map_err(|e| anyhow!("docker socket connect failed ({e})"))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(2)))?;
    let mut stream = stream;
    let request = format!("GET {DOCKER_API_PATH} HTTP/1.0\r\nHost: docker\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let mut reply = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        reply.extend_from_slice(&chunk[..n]);
        if reply.len() > DOCKER_REPLY_CAP {
            bail!(
                "docker API reply exceeded {} bytes — refused",
                DOCKER_REPLY_CAP
            );
        }
    }
    Ok(reply)
}

/// Split the HTTP reply at the header/body boundary and parse the
/// entries. The status line must carry 200 (a 404/500 is a daemon
/// answer, not a container miss — it surfaces as its own error).
pub(super) fn parse_docker_reply(reply: Vec<u8>) -> Result<Vec<DockerEntry>> {
    let split = reply
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("docker API reply had no header/body boundary"))?;
    let (head, body) = reply.split_at(split + 4);
    let head = String::from_utf8_lossy(head);
    let status_ok = head
        .lines()
        .next()
        .is_some_and(|l| l.contains(" 200 ") || l.ends_with(" 200"));
    if !status_ok {
        bail!(
            "docker API answered non-200: {}",
            head.lines().next().unwrap_or("(no status line)")
        );
    }
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| anyhow!("docker API reply is not JSON: {e}"))?;
    let arr = value
        .as_array()
        .ok_or_else(|| anyhow!("docker API reply is not a container list"))?;
    let mut entries = Vec::with_capacity(arr.len());
    for item in arr {
        let id = item
            .get("Id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let names = item
            .get("Names")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|n| n.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        entries.push(DockerEntry { id, names });
    }
    Ok(entries)
}

/// Resolve `docker://<name>` to the container's cgroup id.
pub(super) fn resolve_docker(name: &str, verbose: bool) -> Result<Vec<u32>> {
    let socket = docker_socket_candidates()
        .into_iter()
        .find(|p| p.exists())
        .ok_or_else(|| {
            anyhow!(
                "docker socket not found — is the docker daemon running?\n  \
                 tried: /var/run/docker.sock, /run/docker.sock, $XDG_RUNTIME_DIR/docker.sock"
            )
        })?;
    if verbose {
        eprintln_safe!("[container] docker API via {}", socket.display());
    }
    let entries = parse_docker_reply(docker_http_get(&socket)?)?;
    if verbose {
        eprintln_safe!(
            "[container] docker API listed {} container(s), matching '{name}'",
            entries.len()
        );
    }
    let full_id = match docker_match(&entries, name) {
        DockerMatch::One(id) => id,
        DockerMatch::None => {
            bail!("no container named '{name}' — checked running and stopped containers")
        }
        DockerMatch::Ambiguous(labels) => {
            bail!(
                "'{name}' matches {} containers ({}) — use the full 64-char id or the exact name",
                labels.len(),
                labels.join(", ")
            )
        }
    };

    let dir = find_cgroup_dir(&PathBuf::from("/sys/fs/cgroup"), &|p| {
        docker_cgroup_matches(p, &full_id)
    })
    .ok_or_else(|| {
        let short = &full_id[..12.min(full_id.len())];
        anyhow!(
            "container '{name}' (id {short}) has no cgroup under /sys/fs/cgroup — \
             unrecognized cgroup driver layout"
        )
    })?;
    let id = cgroup_id_of(&dir)
        .ok_or_else(|| anyhow!("container cgroup {} could not be stat()ed", dir.display()))?;
    if verbose {
        eprintln_safe!(
            "[container] docker://{name} → {} (cgroup cg:{id})",
            dir.display()
        );
    }
    Ok(vec![id])
}

/// Pure: is this directory the docker container's cgroup? Both
/// drivers' shapes: systemd's `docker-<full-id>.scope` (at any slice
/// depth, rootless included), and the cgroupfs driver's
/// `docker/<full-id>` (the id directory UNDER a docker directory).
pub(super) fn docker_cgroup_matches(path: &Path, full_id: &str) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if name == format!("docker-{full_id}.scope") {
        return true;
    }
    name == full_id
        && path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            == Some("docker")
}
