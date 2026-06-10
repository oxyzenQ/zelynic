// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::fs;
use std::process::Command;

use super::STATE_DIR;

/// Derive a stable HTB class ID (minor) from a target name.
///
/// Uses a simple hash of the sanitized target name, mapped into range 100..65535.
pub(crate) fn target_class_id(target: &str) -> u32 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    target.hash(&mut hasher);
    let hash = hasher.finish() as u32;
    // Map into range 100..65535 (avoid 0 and very low numbers, stay within u16)
    100 + (hash % 65435)
}
// ---------------------------------------------------------------------------
// TC transaction helper
// ---------------------------------------------------------------------------

/// The next available class ID counter file.
const CLASS_ID_FILE: &str = "/run/zelynic/.next_class_id";

/// Transactional tc command executor with rollback support.
pub(crate) struct TcTransaction {
    commands: Vec<(String, Vec<String>, Vec<String>)>,
    executed: Vec<(String, Vec<String>)>,
}

impl TcTransaction {
    pub(super) fn new() -> Self {
        Self {
            commands: Vec::new(),
            executed: Vec::new(),
        }
    }

    pub(super) fn add(&mut self, desc: &str, cmd_args: Vec<String>, rollback_args: Vec<String>) {
        self.commands
            .push((desc.to_string(), cmd_args, rollback_args));
    }

    pub(super) fn execute_with_diagnostics(mut self, diagnostics: bool) -> Result<()> {
        let commands = std::mem::take(&mut self.commands);

        for (desc, cmd_args, rollback_args) in commands {
            if diagnostics {
                println!(
                    "strict diagnostic: tc command ({}): tc {}",
                    desc,
                    cmd_args.join(" ")
                );
            }
            let output = Command::new("tc").args(&cmd_args).output();

            match output {
                Ok(o) if o.status.success() => {
                    if diagnostics {
                        println!("strict diagnostic: tc exit status: {}", o.status);
                        println!(
                            "strict diagnostic: tc stdout:\n{}",
                            String::from_utf8_lossy(&o.stdout).trim_end()
                        );
                        println!(
                            "strict diagnostic: tc stderr:\n{}",
                            String::from_utf8_lossy(&o.stderr).trim_end()
                        );
                    }
                    self.executed.push((desc.clone(), rollback_args));
                }
                Ok(o) => {
                    if diagnostics {
                        println!("strict diagnostic: tc exit status: {}", o.status);
                        println!(
                            "strict diagnostic: tc stdout:\n{}",
                            String::from_utf8_lossy(&o.stdout).trim_end()
                        );
                        println!(
                            "strict diagnostic: tc stderr:\n{}",
                            String::from_utf8_lossy(&o.stderr).trim_end()
                        );
                    }
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    if stderr.contains("File exists") {
                        continue;
                    }

                    eprintln!(
                        "{}: Command '{}' failed: {}",
                        "ERROR".red().bold(),
                        desc,
                        stderr
                    );
                    if !self.executed.is_empty() {
                        eprintln!(
                            "{}: Rolling back {} previously applied tc commands...",
                            "WARNING".yellow(),
                            self.executed.len()
                        );
                        for (_rb_desc, rb_args) in self.executed.iter().rev() {
                            let _ = Command::new("tc").args(rb_args).output();
                        }
                    }
                    bail!("tc command failed: {}", stderr);
                }
                Err(e) => {
                    eprintln!(
                        "{}: Failed to execute command '{}': {}",
                        "ERROR".red().bold(),
                        desc,
                        e
                    );
                    if !self.executed.is_empty() {
                        eprintln!(
                            "{}: Rolling back {} previously applied tc commands...",
                            "WARNING".yellow(),
                            self.executed.len()
                        );
                        for (_rb_desc, rb_args) in self.executed.iter().rev() {
                            let _ = Command::new("tc").args(rb_args).output();
                        }
                    }
                    bail!("failed to execute tc: {}", e);
                }
            }
        }

        Ok(())
    }
}
/// Get the next available TC class ID and increment the counter.
///
/// Uses file locking (`flock`) to prevent race conditions when multiple
/// `zelynic strict` invocations run concurrently.
pub fn next_class_id() -> Result<u32> {
    fs::create_dir_all(STATE_DIR).context("failed to create zelynic state directory")?;

    // Open (or create) the counter file with exclusive lock to prevent
    // concurrent zelynic processes from reading the same ID.
    use std::os::unix::io::AsRawFd;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(CLASS_ID_FILE)
        .context("failed to open class ID counter file")?;

    // flock(2) — exclusive lock, blocks until available
    let fd = file.as_raw_fd();
    unsafe {
        let ret = libc::flock(fd, libc::LOCK_EX);
        if ret != 0 {
            anyhow::bail!("failed to lock class ID file (flock)");
        }
    }

    let id = {
        let mut content = String::new();
        use std::io::Read;
        let _ = std::io::BufReader::new(&file).read_to_string(&mut content);
        content.trim().parse::<u32>().unwrap_or(100)
    };

    // Write back incremented counter
    use std::io::{Seek, SeekFrom, Write};
    let mut file = file;
    let _ = file.seek(SeekFrom::Start(0));
    let _ = file.set_len(0);
    let _ = file.write_all((id + 1).to_string().as_bytes());
    let _ = file.sync_all();

    // Release lock (happens automatically on file close/drop, but be explicit)
    unsafe {
        libc::flock(fd, libc::LOCK_UN);
    }

    Ok(id)
}

// ---------------------------------------------------------------------------
// TC qdisc/class setup
// ---------------------------------------------------------------------------

/// Set up the HTB qdisc root on the specified interface if not already present.
pub(crate) fn ensure_htb_qdisc(interface: &str) -> Result<()> {
    let check = Command::new("tc")
        .args(["qdisc", "show", "dev", interface])
        .output()
        .context("failed to check existing tc qdisc")?;

    let stdout = String::from_utf8_lossy(&check.stdout);
    if stdout.contains("qdisc htb 1:") {
        return Ok(());
    }

    let output = Command::new("tc")
        .args([
            "qdisc", "add", "dev", interface, "root", "handle", "1:", "htb", "default", "999",
        ])
        .output()
        .context("failed to create tc qdisc. Is the 'tc' command available?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("failed to create HTB qdisc on {}: {}", interface, stderr);
    }

    let output = Command::new("tc")
        .args([
            "class", "add", "dev", interface, "parent", "1:", "classid", "1:999", "htb", "rate",
            "100gbit", "ceil", "100gbit",
        ])
        .output()
        .context("failed to create default tc class")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("failed to create default tc class: {}", stderr);
    }

    Ok(())
}
