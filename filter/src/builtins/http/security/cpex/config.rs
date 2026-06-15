// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Deserialized YAML configuration for the CPEX security filter.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// CpexFilterConfig
// -----------------------------------------------------------------------------

/// Configuration block for a `cpex` filter slot in a Praxis filter chain.
///
/// Praxis filter configs are flat: the filter's typed fields sit
/// directly under the `- filter:` entry alongside the structural keys
/// (`name`, `conditions`), not nested under a `config:` wrapper. See
/// `examples/configs/security/cpex.yaml` for a runnable example.
///
/// ```yaml
/// filters:
///   - filter: cpex
///     config_path: /etc/praxis/cpex.yaml
///     body_access: read_write   # optional; default read_only
///     require_mcp_metadata: true
/// ```
///
/// The referenced YAML is the CPEX policy document — plugins, routes,
/// and identity-source declarations. The filter loads it once at
/// construction and rejects misconfigured policy at server startup
/// (fail-fast rather than at first request).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpexFilterConfig {
    /// Filesystem path to the CPEX YAML policy document.
    pub config_path: String,

    /// Body-access tier. `ReadOnly` (default) lets APL inspect request
    /// and response bodies for routing / policy decisions but discards
    /// any mutations. `ReadWrite` enables the CMF → JSON-RPC
    /// re-serialization round-trip so APL field mutators
    /// (e.g. `args.ssn: redact(!perm.view_ssn)`) rewrite the upstream
    /// body and response. Pay the round-trip cost only when needed.
    #[serde(default)]
    pub body_access: BodyAccessMode,

    /// Fail-closed policy gate for misconfigured chains. When `true`
    /// (default), `on_request_body` rejects any request that reaches
    /// it without `mcp.method` filter-metadata. The metadata is set
    /// by praxis's built-in `mcp` filter, so its absence means either
    /// (a) the `mcp` filter is missing from the chain, or (b) it is
    /// ordered AFTER `cpex` instead of before. Either is a
    /// misconfiguration that would silently bypass CMF/APL policy.
    ///
    /// Set to `false` only when intentionally fronting non-MCP
    /// traffic through `cpex` for identity-only enforcement (legacy
    /// behavior).
    ///
    /// Note: MCP methods that legitimately carry no entity (e.g.
    /// `tools/list`, `initialize`, `prompts/list`) still pass —
    /// `require_mcp_metadata` only rejects when the metadata is
    /// missing entirely.
    #[serde(default = "default_true")]
    pub require_mcp_metadata: bool,

    /// Maximum time, in seconds, to wait for `PluginManager::initialize`
    /// at filter construction. Identity plugins fetch JWKS over HTTPS
    /// during init; a reachable-but-unresponsive identity provider
    /// would otherwise hang startup or hot-reload indefinitely. On
    /// expiry, filter construction returns an error and the server
    /// fails fast.
    ///
    /// 30s is generous for legitimate cold-cache JWKS fetches over the
    /// public internet, while short enough that misbehavior is noticed
    /// during the deploy.
    #[serde(default = "default_init_timeout_secs")]
    pub init_timeout_secs: u64,
}

/// `#[serde(default = ...)]` requires a free function for primitives
/// without a `Default` impl that returns the desired value. `true` is
/// the safer default for `require_mcp_metadata`.
fn default_true() -> bool {
    true
}

/// Default upper bound on `PluginManager::initialize` (seconds).
fn default_init_timeout_secs() -> u64 {
    30
}

/// What APL field-pipeline mutators on `args.<field>` and
/// `result.<field>` are allowed to do to the upstream body and
/// downstream response.
///
/// Mirrors `praxis_filter::BodyAccess` but lifts the decision to
/// operator configuration: the choice changes pipeline behavior (and
/// cost), so a per-filter knob is the right granularity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyAccessMode {
    /// Body is buffered for inspection / routing; mutations are
    /// discarded. APL `require()` predicates over body content
    /// (`args.amount > 1000`) work; `redact()` / `assign()` are
    /// silently dropped at the executor's write boundary.
    #[default]
    ReadOnly,

    /// Body is buffered + APL mutations to `args.*` and `result.*` are
    /// re-serialized back into the JSON-RPC body so the upstream and
    /// the downstream client see them. Costs one JSON parse +
    /// serialize per mutated request or response.
    ReadWrite,
}
