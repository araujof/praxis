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

use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwapOption;
use praxis_core::subrequest::SubRequestConnector;

/// Storage for the connector policy calls borrow.
///
/// Last registration wins. A host that builds a second runtime in one
/// process registers again before building its pipelines, and its filters
/// must borrow its own pool rather than the earlier runtime's admission
/// limit and breaker.
#[derive(Debug, Default)]
struct ConnectorHolder(ArcSwapOption<SubRequestConnector>);

impl ConnectorHolder {
    /// Store `connector`, replacing whatever was held.
    fn set(&self, connector: &SubRequestConnector) {
        self.0.store(Some(Arc::new(connector.clone())));
    }

    /// The held connector, if one was stored.
    fn get(&self) -> Option<SubRequestConnector> {
        self.0.load_full().map(|held| held.as_ref().clone())
    }
}

/// The registered connector, or none when the host never registered one.
fn policy_connector() -> &'static ConnectorHolder {
    static POLICY_CONNECTOR: OnceLock<ConnectorHolder> = OnceLock::new();
    POLICY_CONNECTOR.get_or_init(ConnectorHolder::default)
}

/// Register the connector policy calls share with the data plane.
///
/// Call before pipelines are built. Every policy call made afterwards
/// borrows this connector, so the keepalive pool, the admission limit, and
/// the circuit-breaker registry are shared with proxy sub-requests.
///
/// The last registration wins, which is what a second runtime in the same
/// process needs. A reload re-registers the pool already held and nothing
/// changes. A transport latches its client while its filter is being
/// constructed, so registering before each build is what keeps a runtime's
/// filters on that runtime's pool.
pub fn set_policy_subrequest_connector(connector: &SubRequestConnector) {
    policy_connector().set(connector);
}

/// The registered connector, if the host provided one.
///
/// Cloned rather than borrowed: the clone shares the pool's inner handle,
/// so it is a reference count rather than a second pool.
pub(super) fn shared_policy_connector() -> Option<SubRequestConnector> {
    policy_connector().get()
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn a_holder_hands_back_the_connector_it_was_given() {
        let holder = ConnectorHolder::default();
        assert!(holder.get().is_none(), "an empty holder holds nothing");

        let first = SubRequestConnector::new(8, None);
        holder.set(&first);
        assert!(
            std::ptr::eq(holder.get().expect("registered").connector(), first.connector()),
            "readers see the registered pool, not a fresh one"
        );
    }

    #[test]
    fn storing_the_held_connector_again_keeps_the_same_pool() {
        // What a config reload does: same pool, freshly wrapped client.
        let holder = ConnectorHolder::default();
        let held = SubRequestConnector::new(8, None);
        holder.set(&held);
        holder.set(&held);
        assert!(std::ptr::eq(
            holder.get().expect("registered").connector(),
            held.connector()
        ));
    }

    #[test]
    fn a_second_runtimes_connector_replaces_the_first() {
        // The reported case: a second runtime in one process must not have
        // its filters borrow the first runtime's pool, admission limit, and
        // breaker.
        let holder = ConnectorHolder::default();
        let first = SubRequestConnector::new(8, None);
        let second = SubRequestConnector::new(1, None);

        holder.set(&first);
        holder.set(&second);

        let held = holder.get().expect("registered");
        assert!(
            std::ptr::eq(held.connector(), second.connector()),
            "the later registration is what readers see"
        );
        assert!(
            !std::ptr::eq(held.connector(), first.connector()),
            "and it is not the earlier pool"
        );
    }

    /// Deliberately makes no claim about *which* connector is held.
    /// Registration is last-wins and this holder is process-wide, so any
    /// other test building a policy filter can replace it between the write
    /// and the read. Identity is covered on an owned holder above; what the
    /// process holder owes is that registering makes one readable at all.
    #[test]
    fn registering_makes_a_connector_readable_from_the_process_holder() {
        set_policy_subrequest_connector(&SubRequestConnector::new(4, None));
        assert!(
            shared_policy_connector().is_some(),
            "a registration must leave the reader something to find"
        );
    }
}
