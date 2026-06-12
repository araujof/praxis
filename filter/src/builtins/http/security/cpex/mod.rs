// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! The CPEX security filter. Resolves multi-source agentic identity,
//! evaluates APL route-level policy, mints RFC 8693 delegated
//! credentials, scans for PII, emits audit records, and (under
//! `body_access: read_write`) rewrites request/response bodies.

mod cmf;
mod config;
mod error;
mod factories;
mod filter;
mod json_rpc;

pub use filter::CpexFilter;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::needless_raw_strings,
    reason = "tests"
)]
mod tests;
