// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Plugin factory + PDP factory registrations bundled with the CPEX
//! filter.

use std::sync::Arc;

use apl_audit_logger::{AuditLoggerFactory, KIND as AUDIT_LOGGER_KIND};
use apl_cpex::{AplOptions, DispatchCache, MemorySessionStore, register_apl};
use apl_delegator_oauth::{KIND as OAUTH_DELEGATOR_KIND, OAuthDelegatorFactory};
use apl_identity_jwt::{JwtIdentityFactory, KIND as JWT_KIND};
use apl_pdp_cedar_direct::CedarDirectPdpFactory;
use apl_pii_scanner::{KIND as PII_SCANNER_KIND, PiiScannerFactory};
use cpex_core::manager::PluginManager;

// -----------------------------------------------------------------------------
// register_builtin_factories
// -----------------------------------------------------------------------------

/// Register the plugin factories this filter ships with:
///
///   * `identity/jwt`       — `apl-identity-jwt` (JWT identity resolver)
///   * `delegator/oauth`    — `apl-delegator-oauth` (RFC 8693 token exchange)
///   * `validator/pii-scan` — `apl-pii-scanner` (regex-based PII detection)
///   * `audit/logger`       — `apl-audit-logger` (structured audit emission)
///
/// PDP factories (`cedar-direct`) wire via [`register_apl_visitor`] —
/// a different registration surface (`PdpFactory` vs `PluginFactory`).
pub(super) fn register_builtin_factories(mgr: &Arc<PluginManager>) {
    mgr.register_factory(JWT_KIND, Box::new(JwtIdentityFactory));
    mgr.register_factory(OAUTH_DELEGATOR_KIND, Box::new(OAuthDelegatorFactory));
    mgr.register_factory(PII_SCANNER_KIND, Box::new(PiiScannerFactory));
    mgr.register_factory(AUDIT_LOGGER_KIND, Box::new(AuditLoggerFactory));
}

// -----------------------------------------------------------------------------
// register_apl_visitor
// -----------------------------------------------------------------------------

/// Wire the APL visitor onto the manager so it walks `routes:` blocks
/// at config-load time and installs `AplRouteHandler` annotations on
/// the hook table. The baseline is the visitor's default read-only
/// capability set (subject, roles, claims, etc.) — per-plugin caps
/// (`read_inbound_credentials` on the `OAuth` delegator, etc.) are
/// declared in the plugin's YAML `capabilities:` block and unioned
/// into the synthetic route handler by `apl-cpex`. This keeps
/// credential reads scoped to the plugin that declared the need rather
/// than leaking them to every predicate / PDP / step in the same
/// route.
///
/// Ships the `cedar-direct` PDP factory by default; alternative PDPs
/// (OPA, Cedarling, future engines) slot in similarly.
pub(super) fn register_apl_visitor(mgr: &Arc<PluginManager>) {
    register_apl(
        mgr,
        AplOptions {
            dispatch_cache: Arc::new(DispatchCache::new()),
            session_store: Arc::new(MemorySessionStore::new()),
            pdps: Vec::new(),
            pdp_factories: vec![Arc::new(CedarDirectPdpFactory::new())],
            base_capabilities: None,
        },
    );
}
