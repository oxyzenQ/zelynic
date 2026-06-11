// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! In-memory event decoder model for the Intergalaxion Engine.
//!
//! Phase I-4 adds a pure in-memory decoder that transforms raw event
//! frames into typed `EbpfObserverEvent` values. No ring buffers are
//! opened. No live kernel events are read. No aya APIs are used. No
//! root is required. This module defines the *decode pipeline model*
//! only.

use super::event_schema::{EbpfEventSource, EbpfObserverEvent};

/// A raw event frame before decoding.
///
/// In a live system this would contain bytes read from a ring buffer.
/// In I-4 the frame is model-only — payload may be empty or contain
/// fixture data for testing the decoder pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EbpfRawEventFrame {
    /// Unique frame identifier within a session.
    pub frame_id: u64,
    /// Where this frame originated.
    pub source: EbpfEventSource,
    /// Raw byte payload (may be empty in model-only mode).
    pub payload: Vec<u8>,
    /// Human-readable label identifying the decode source.
    pub decode_source_label: String,
}

/// A decoded event frame containing a typed observer event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfDecodedEventFrame {
    /// Original frame identifier.
    pub frame_id: u64,
    /// The decoded observer event (model-only).
    pub event: EbpfObserverEvent,
    /// Whether decoding succeeded.
    pub decoded: bool,
    /// Decode error message, if decoding failed.
    pub decode_error: Option<String>,
}

impl Default for EbpfDecodedEventFrame {
    fn default() -> Self {
        Self {
            frame_id: 0,
            event: EbpfObserverEvent::default(),
            decoded: false,
            decode_error: Some(String::from("no payload to decode")),
        }
    }
}

/// Decode mode governing the decoder behavior.
///
/// All modes in I-4 are in-memory only. No live kernel events are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EbpfDecodeMode {
    /// Decoder operates on pure model data (default for I-4).
    #[default]
    ModelOnly,
    /// Decoder operates on deterministic fixture data for testing.
    StrictFixture,
    /// Live kernel decode is not supported in this phase.
    KernelLiveUnsupported,
}

impl EbpfDecodeMode {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ModelOnly => "model_only",
            Self::StrictFixture => "strict_fixture",
            Self::KernelLiveUnsupported => "kernel_live_unsupported",
        }
    }
}

/// Report produced by decoding a batch of raw event frames.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EbpfDecodeReport {
    /// The decode mode used.
    pub mode: EbpfDecodeMode,
    /// Total number of frames seen.
    pub frames_seen: usize,
    /// Total number of frames successfully decoded.
    pub frames_decoded: usize,
    /// Decode error messages from failed frames.
    pub decode_errors: Vec<String>,
    /// Successfully decoded observer events.
    pub events: Vec<EbpfObserverEvent>,
    /// Whether a live kernel read was performed (always false in I-4).
    pub live_kernel_read_performed: bool,
    /// Whether a ring buffer was opened (always false in I-4).
    pub ring_buffer_opened: bool,
    /// Whether any kernel mutation was performed (always false in I-4).
    pub mutation_performed: bool,
}

// ── Helper functions ──────────────────────────────────────────────────

/// Decode a single raw event frame into a decoded event frame.
///
/// In I-4 the decoder is model-only. Empty payloads fail honestly.
/// Non-empty payloads are decoded as model events with frame metadata
/// applied to the output `EbpfObserverEvent`.
pub fn decode_raw_event_frame(frame: &EbpfRawEventFrame) -> EbpfDecodedEventFrame {
    if frame.payload.is_empty() {
        return EbpfDecodedEventFrame {
            frame_id: frame.frame_id,
            event: EbpfObserverEvent::default(),
            decoded: false,
            decode_error: Some(String::from("empty payload: cannot decode")),
        };
    }

    // Model-only decode: create a typed event from frame metadata.
    // In a live system the payload bytes would be parsed according to
    // a wire format. In I-4 we produce a model event seeded from the
    // frame's metadata.
    let event = EbpfObserverEvent {
        event_id: frame.frame_id,
        source: frame.source,
        ..Default::default()
    };

    EbpfDecodedEventFrame {
        frame_id: frame.frame_id,
        event,
        decoded: true,
        decode_error: None,
    }
}

/// Decode a batch of raw event frames into a decode report.
///
/// Each frame is decoded independently. Failed decodes are recorded
/// as errors but do not halt processing of subsequent frames.
pub fn decode_raw_event_batch(frames: &[EbpfRawEventFrame]) -> EbpfDecodeReport {
    let mut events = Vec::new();
    let mut decode_errors = Vec::new();
    let mut frames_decoded = 0usize;

    for frame in frames {
        let decoded = decode_raw_event_frame(frame);
        if decoded.decoded {
            frames_decoded += 1;
            events.push(decoded.event);
        } else if let Some(err) = &decoded.decode_error {
            decode_errors.push(err.clone());
        }
    }

    EbpfDecodeReport {
        mode: EbpfDecodeMode::ModelOnly,
        frames_seen: frames.len(),
        frames_decoded,
        decode_errors,
        events,
        live_kernel_read_performed: false,
        ring_buffer_opened: false,
        mutation_performed: false,
    }
}
