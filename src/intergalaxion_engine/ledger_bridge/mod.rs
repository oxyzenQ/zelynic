// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Bridge between Intergalaxion Engine telemetry and the stable ledger.
//!
//! The ledger bridge translates eBPF telemetry events into ledger entries
//! that are compatible with the existing v3.1.0 ledger JSON schema. In I-0
//! no live bridge is active — this module only defines the translation model.

pub mod event_bridge;

#[allow(unused_imports)]
pub use event_bridge::*;

/// A pending bridge event that may be committed to the ledger in a future phase.
#[derive(Debug, Clone, Default)]
pub struct BridgeEvent {
    /// The source identity that produced this event.
    pub identity_label: String,
    /// Bytes received in this event window.
    pub rx_bytes: u64,
    /// Bytes transmitted in this event window.
    pub tx_bytes: u64,
    /// Whether this event has been committed to the ledger.
    pub committed: bool,
}

/// Result of attempting to bridge telemetry into the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum BridgeResult {
    /// Event was successfully translated and committed.
    Committed,
    /// Event was rejected (e.g., no active ledger session).
    Rejected(String),
    /// Bridge is not yet operational (I-0 state).
    #[default]
    NotOperational,
}
