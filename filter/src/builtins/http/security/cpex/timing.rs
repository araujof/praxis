// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Per-request CPEX timing records.
//!
//! Emits one structured `tracing` event per instrumented request at
//! target `cpex.timing`, combining the praxis-side stage durations with
//! the per-plugin / per-PDP breakdown surfaced by `cpex-core` in
//! [`cpex_core::executor::PipelineTimings`]. A `tracing-subscriber` JSON
//! layer (the demo gateway runs one) captures these lines so the
//! benchmark harness can aggregate them offline into per-stage
//! percentiles.
//!
//! All durations are integer nanoseconds — the workspace denies the
//! `as`-cast lints, so we avoid lossy float conversions here and let
//! the consumer scale.

use std::time::Instant;

use cpex::cpex_core::executor::PipelineTimings;

/// Start/stop wall-clock timer for one filter stage. Construction is a
/// single `Instant::now`; nothing is recorded unless the caller emits a
/// record, so leaving timers in place on the hot path is cheap.
pub(super) struct StageTimer {
    /// Instant captured at [`StageTimer::start`].
    start: Instant,
}

impl StageTimer {
    /// Begin timing from now.
    pub(super) fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Nanoseconds elapsed since [`StageTimer::start`], saturating at
    /// [`u64::MAX`] (a request would have to run ~584 years to overflow).
    pub(super) fn elapsed_ns(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
}

/// Praxis-side stage durations (nanoseconds) for one dispatched request.
/// Paired with the `cpex-core` per-plugin breakdown in [`emit_record`].
pub(super) struct StageNs {
    /// `build_cmf_extensions` — identity re-resolution + entity stamp.
    pub(super) build_extensions: u64,
    /// JSON-RPC parse + typed `ContentPart` construction.
    pub(super) parse: u64,
    /// The `CmfHook` dispatch (the whole plugin pipeline).
    pub(super) cmf_dispatch: u64,
    /// Request-body re-serialization (`0` when nothing was rewritten).
    pub(super) reserialize: u64,
}

/// Serialize the `cpex-core` per-plugin breakdown to a JSON array.
/// Empty when timing capture was not enabled in the policy document.
fn plugins_json(timings: Option<&PipelineTimings>) -> Vec<serde_json::Value> {
    timings
        .map(|t| {
            t.plugins
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "plugin": p.plugin_name,
                        "mode": p.mode,
                        "duration_ns": p.duration_ns,
                        "denied": p.denied,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Build the full nested timing record as a JSON value.
fn build_record(
    method: &str,
    entity: &str,
    decision: &str,
    stages: &StageNs,
    timings: Option<&PipelineTimings>,
) -> serde_json::Value {
    let pdp = timings
        .and_then(|t| t.pdp.as_ref())
        .map(|p| serde_json::json!({ "dialect": p.dialect, "duration_ns": p.duration_ns }));
    serde_json::json!({
        "method": method,
        "entity": entity,
        "decision": decision,
        "stage_ns": {
            "build_extensions": stages.build_extensions,
            "parse": stages.parse,
            "cmf_dispatch": stages.cmf_dispatch,
            "reserialize": stages.reserialize,
        },
        "executor_total_ns": timings.map(|t| t.total_ns),
        "plugins": plugins_json(timings),
        "pdp": pdp,
    })
}

/// Emit one `cpex.timing` record. The full breakdown is serialized to a
/// JSON string field (`record`) so a JSON tracing layer captures the
/// nested shape.
///
/// `decision` is `allow` or `deny`. `timings` is the `cpex-core`
/// per-plugin breakdown, present only when the policy document enabled
/// `plugin_settings.capture_timings`.
pub(super) fn emit_record(
    method: &str,
    entity: &str,
    decision: &str,
    stages: &StageNs,
    timings: Option<&PipelineTimings>,
) {
    let record = build_record(method, entity, decision, stages, timings);
    tracing::info!(target: "cpex.timing", record = %record, "cpex request timing");
}
