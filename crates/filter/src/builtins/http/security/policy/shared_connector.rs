// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The process-wide sub-request connector the policy engine's outbound
//! calls borrow.
//!
//! `PolicyFilter::new` drives `PolicyEngine::initialize()`, and that is
//! where the boot JWKS fetch happens — before the pipeline exists and
//! therefore before the shared [`SubRequestClient`] reaches any filter.
//! The filter-factory signature cannot carry a client, so the host
//! registers the connector here and the transport reads it when it first
//! needs a socket.
//!
//! A host registers once, before building pipelines:
//!
//! ```rust,ignore
//! use praxis_filter::set_policy_subrequest_connector;
//!
//! let client = praxis::build_subrequest_client(&config);
//! set_policy_subrequest_connector(client.connector());
//! ```
//!
//! [`SubRequestClient`]: praxis_core::subrequest::SubRequestClient

use std::sync::OnceLock;

use praxis_core::subrequest::SubRequestConnector;

/// The registered connector, or none when the host never registered one.
static POLICY_CONNECTOR: OnceLock<SubRequestConnector> = OnceLock::new();

/// Register the connector policy calls share with the data plane.
///
/// Call before pipelines are built. Every policy call made afterwards
/// borrows this connector, so the keepalive pool, the admission limit, and
/// the circuit-breaker registry are shared with proxy sub-requests.
///
/// Re-registering the pool that is already held succeeds and changes
/// nothing, which is what a config reload does. Registering a *different*
/// one returns `false` and keeps the first: a second pool is the thing
/// this registration exists to prevent.
pub fn set_policy_subrequest_connector(connector: &SubRequestConnector) -> bool {
    if std::ptr::eq(
        POLICY_CONNECTOR.get_or_init(|| connector.clone()).connector(),
        connector.connector(),
    ) {
        return true;
    }
    tracing::warn!(
        target: "policy.transport",
        "policy: a different sub-request connector is already registered; keeping the first"
    );
    false
}

/// The registered connector, if the host provided one.
pub(super) fn shared_policy_connector() -> Option<&'static SubRequestConnector> {
    POLICY_CONNECTOR.get()
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "tests")]
mod tests {
    use super::*;

    /// Set-once is process-wide, so the whole holder is one test: a
    /// second test registering a different connector could not observe
    /// its own value.
    #[test]
    fn the_first_registration_wins_and_is_what_readers_see() {
        assert!(shared_policy_connector().is_none(), "nothing registered yet");

        let first = SubRequestConnector::new(8, None);
        assert!(set_policy_subrequest_connector(&first));
        assert!(
            std::ptr::eq(
                shared_policy_connector().expect("registered").connector(),
                first.connector()
            ),
            "readers see the registered pool, not a fresh one"
        );

        assert!(
            set_policy_subrequest_connector(&first),
            "re-registering the held pool is what a reload does, and must not fail"
        );
        assert!(
            !set_policy_subrequest_connector(&SubRequestConnector::new(1, None)),
            "a different connector is refused"
        );
        assert!(
            std::ptr::eq(
                shared_policy_connector().expect("still registered").connector(),
                first.connector()
            ),
            "the refused registration did not replace the first"
        );
    }
}
