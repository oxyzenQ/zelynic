// SPDX-License-Identifier: GPL-3.0-only
/// Named bandwidth profile management module.
///
/// Provides persistent storage for named bandwidth limit profiles
/// that can be quickly applied to processes.
use anyhow::{bail, Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::limiter::apply_limit;

/// Generate a human-readable timestamp string.
/// Format: YYYY-MM-DD HH:MM:SS (local time)
fn chrono_now() -> String {
    use std::time::SystemTime;

    let now = SystemTime::now();
    let datetime = chrono::DateTime::<chrono::Local>::from(now);
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Directory for profile storage.
const PROFILE_DIR: &str = "/run/zelynic/profiles";
/// Profile database file.
const PROFILE_DB: &str = "/run/zelynic/profiles/profiles.json";

/// A named bandwidth profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthProfile {
    /// Profile name
    pub name: String,
    /// Download limit in bytes per second (None = unlimited)
    pub download_bps: Option<u64>,
    /// Upload limit in bytes per second (None = unlimited)
    pub upload_bps: Option<u64>,
    /// Human-readable download limit display
    pub download_display: Option<String>,
    /// Human-readable upload limit display
    pub upload_display: Option<String>,
    /// When the profile was created
    pub created_at: String,
}

/// Profile database.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProfileDb {
    /// Map of profile name to profile
    pub profiles: HashMap<String, BandwidthProfile>,
}

impl ProfileDb {
    /// Load the profile database from disk.
    pub fn load() -> Result<Self> {
        let db_path = Path::new(PROFILE_DB);

        if !db_path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(db_path)
            .with_context(|| format!("failed to read profile database from {}", PROFILE_DB))?;

        let db: ProfileDb =
            serde_json::from_str(&content).with_context(|| "failed to parse profile database")?;

        Ok(db)
    }

    /// Save the profile database to disk.
    pub fn save(&self) -> Result<()> {
        // Ensure profile directory exists
        fs::create_dir_all(PROFILE_DIR)
            .with_context(|| format!("failed to create profile directory {}", PROFILE_DIR))?;

        let json =
            serde_json::to_string_pretty(self).context("failed to serialize profile database")?;

        fs::write(PROFILE_DB, json)
            .with_context(|| format!("failed to write profile database to {}", PROFILE_DB))?;

        Ok(())
    }

    /// Get a profile by name.
    pub fn get(&self, name: &str) -> Option<&BandwidthProfile> {
        self.profiles.get(name)
    }

    /// Insert or update a profile.
    pub fn insert(&mut self, profile: BandwidthProfile) {
        self.profiles.insert(profile.name.clone(), profile);
    }

    /// Remove a profile by name.
    pub fn remove(&mut self, name: &str) -> Option<BandwidthProfile> {
        self.profiles.remove(name)
    }

    /// List all profile names.
    pub fn list(&self) -> Vec<&BandwidthProfile> {
        let mut profiles: Vec<_> = self.profiles.values().collect();
        // Sort by name for consistent display
        profiles.sort_by(|a, b| a.name.cmp(&b.name));
        profiles
    }
}

/// Save a new bandwidth profile.
pub fn save_profile(name: &str, download: Option<&str>, upload: Option<&str>) -> Result<()> {
    // Validate that at least one limit is specified
    if download.is_none() && upload.is_none() {
        bail!("at least one of --dl or --ul must be specified");
    }

    // Parse download limit
    let (dl_bps, dl_display) = match download {
        Some(rate_str) => {
            let rate = crate::units::BandwidthRate::parse(rate_str)
                .with_context(|| format!("invalid download rate: {}", rate_str))?;
            (Some(rate.bytes_per_sec), Some(rate_str.to_string()))
        }
        None => (None, None),
    };

    // Parse upload limit
    let (ul_bps, ul_display) = match upload {
        Some(rate_str) => {
            let rate = crate::units::BandwidthRate::parse(rate_str)
                .with_context(|| format!("invalid upload rate: {}", rate_str))?;
            (Some(rate.bytes_per_sec), Some(rate_str.to_string()))
        }
        None => (None, None),
    };

    // Load existing database
    let mut db = ProfileDb::load()?;

    // Check if profile already exists
    let exists = db.get(name).is_some();

    // Create profile
    let profile = BandwidthProfile {
        name: name.to_string(),
        download_bps: dl_bps,
        upload_bps: ul_bps,
        download_display: dl_display,
        upload_display: ul_display,
        created_at: chrono_now(),
    };

    // Save to database
    db.insert(profile);
    db.save()?;

    if exists {
        println!("{} Updated profile '{}'", "✓".green(), name.cyan());
    } else {
        println!("{} Created profile '{}'", "✓".green(), name.cyan());
    }

    // Show profile details
    if let Some(dl) = download {
        println!("  Download: {}", dl.yellow());
    }
    if let Some(ul) = upload {
        println!("  Upload: {}", ul.yellow());
    }

    Ok(())
}

/// Apply a saved profile to a process.
pub fn apply_profile(name: &str, target: &str, iface_override: Option<&str>) -> Result<()> {
    // Load profile database
    let db = ProfileDb::load()?;

    // Get the profile
    let profile = db
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("profile '{}' not found", name))?;

    // Convert to display strings for apply_limit
    let dl_ref = profile.download_display.as_deref();
    let ul_ref = profile.upload_display.as_deref();

    println!(
        "{} Applying profile '{}' to {}...",
        "→".cyan(),
        name.cyan(),
        target.yellow()
    );

    // Apply using existing limiter
    apply_limit(target, dl_ref, ul_ref, iface_override)
}

/// List all saved profiles.
pub fn list_profiles() -> Result<()> {
    let db = ProfileDb::load()?;
    let profiles = db.list();

    if profiles.is_empty() {
        println!("{} No profiles found.", "Info:".yellow());
        println!("  Create one with: zelynic profile save <name> --dl <rate> --ul <rate>");
        return Ok(());
    }

    println!("{}", "Saved Bandwidth Profiles".green().bold());
    println!();
    println!(
        "  {:<15} {:<15} {:<15} {}",
        "Name".bold(),
        "Download".bold(),
        "Upload".bold(),
        "Created".dimmed()
    );
    println!("  {}", "─".repeat(70).dimmed());

    for profile in profiles {
        let dl_str = profile.download_display.as_deref().unwrap_or("unlimited");
        let ul_str = profile.upload_display.as_deref().unwrap_or("unlimited");

        println!(
            "  {:<15} {:<15} {:<15} {}",
            profile.name.cyan(),
            dl_str.yellow(),
            ul_str.yellow(),
            profile.created_at.dimmed()
        );
    }

    println!();
    println!(
        "  {} Use 'zelynic profile apply <name> <target>' to apply a profile",
        "Tip:".cyan()
    );
    println!(
        "  {} Profiles are stored in {}",
        "Tip:".cyan(),
        PROFILE_DB.cyan()
    );

    Ok(())
}

/// Delete a saved profile.
pub fn delete_profile(name: &str) -> Result<()> {
    let mut db = ProfileDb::load()?;

    match db.remove(name) {
        Some(_) => {
            db.save()?;
            println!("{} Deleted profile '{}'", "✓".green(), name.cyan());
            Ok(())
        }
        None => {
            bail!("profile '{}' not found", name);
        }
    }
}
