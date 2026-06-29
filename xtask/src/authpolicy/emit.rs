// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Thin serializable mirrors of the transpiler's two emission targets: a
//! CPEX policy document and a Praxis `policy`-filter block.
//!
//! These intentionally do **not** reuse `cpex-core`'s own config structs:
//! the APL `policy:` steps a route carries are read out-of-band by the
//! apl-cpex visitor and are not fields on `cpex_core::config::RouteEntry`,
//! so a faithful emission needs its own shape. The emitted YAML is still
//! validated by round-tripping it through `cpex_core::config::parse_config`
//! in the golden tests (cpex-core tolerates the out-of-band keys).

use serde::Serialize;

// ---------------------------------------------------------------------------
// CPEX policy document
// ---------------------------------------------------------------------------

/// A CPEX policy document (the file a `policy` filter's `config_path`
/// points at).
#[derive(Debug, Serialize)]
pub(crate) struct CpexDoc {
    pub plugin_settings: PluginSettings,
    pub plugins: Vec<PluginEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<RouteOut>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PluginSettings {
    pub routing_enabled: bool,
}

/// One CPEX plugin entry. Only `identity/jwt` is emitted this iteration.
#[derive(Debug, Serialize)]
pub(crate) struct PluginEntry {
    pub name: String,
    pub kind: String,
    pub hooks: Vec<String>,
    /// `fail` so a bad/missing credential denies (fail-closed identity).
    pub on_error: String,
    pub config: JwtConfig,
}

/// `identity/jwt` plugin config (mirrors `JwtIdentityResolverConfig`).
#[derive(Debug, Serialize)]
pub(crate) struct JwtConfig {
    pub header: String,
    pub trusted_issuers: Vec<TrustedIssuer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_mapper: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct TrustedIssuer {
    pub issuer: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub audiences: Vec<String>,
    /// Never empty — explicit algorithm pinning (plan R21).
    pub algorithms: Vec<String>,
    pub decoding_key: DecodingKey,
}

/// Subset of `cpex` `DecodingKeySource` we emit (tagged by `kind`).
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum DecodingKey {
    JwksUrl { url: String },
    Secret { secret: String },
}

/// A CPEX route. `tool: "*"` is the Phase A stand-in for a generic-HTTP
/// authorization policy; Phase B (plan U3) moves this to a non-entity
/// evaluation path. The `policy` and `identity` keys are consumed by the
/// apl-cpex visitor; cpex-core tolerates them.
#[derive(Debug, Serialize)]
pub(crate) struct RouteOut {
    pub tool: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub identity: Vec<String>,
    /// Route activation guard (CEL), from `spec.when`. Carried by
    /// cpex-core's `RouteEntry.when`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policy: Vec<String>,
}

// ---------------------------------------------------------------------------
// Praxis policy-filter block
// ---------------------------------------------------------------------------

/// The Praxis `policy` filter entry the operator adds to a filter chain.
#[derive(Debug, Serialize)]
pub(crate) struct FilterBlock {
    pub filter: String,
    pub config_path: String,
    /// Phase B experimental enforcement mode (plan R16/U5).
    pub enforcement: String,
}
