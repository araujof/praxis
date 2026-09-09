// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The policy engine's outbound HTTP, carried over Praxis's own
//! sub-request client.
//!
//! The engine performs no HTTP itself: a JWKS fetch, an RFC 8693 token
//! exchange, and a CIBA backchannel call all go through a transport the
//! host installs. Installing this one means a `policy-engine` build has a
//! single HTTP stack — one keepalive pool per process, the proxy's TLS
//! trust configuration, and an egress path the operator can see — instead
//! of a second client with its own pool and its own trust store.
//!
//! # What policy calls now inherit
//!
//! `runtime.subrequest_pool_size`, `runtime.subrequest_max_connections`,
//! and `runtime.subrequest_circuit_breaker` apply to them, and they appear
//! in the sub-request latency histogram. The breaker is keyed per peer
//! address and SNI, so a failing upstream only opens the circuit for a
//! policy call that dials the very same address — and an open circuit is
//! refused before anything is sent, which is fail-closed and safe to
//! retry. `body_limits.max_response_bytes` deliberately does *not* apply:
//! the transport keeps its own 1 MiB ceiling so a tight proxy-wide
//! response limit cannot turn a JWKS fetch into an identity failure.
//! Per-request limits still win, since the client clamps to the smaller
//! of the two.
//!
//! Calls are HTTP/1.1 only — Pingora peers built here advertise no h2 —
//! and they carry no client certificate or private CA, because a policy
//! URL has no cluster TLS config to draw one from.
//!
//! # Egress
//!
//! The destination is resolved once, checked, and dialled as the literal
//! address that was checked, so there is no second lookup for DNS
//! rebinding to exploit. The rule table is the engine's own
//! [`private_address_reason`], shared with the transport it replaces so
//! the two cannot drift, and `allow_private_idp` remains the escape hatch
//! for a loopback or in-cluster identity provider. Only the one address
//! that gets dialled is judged: a host answering with both a public and a
//! private address is no longer refused outright, because the private one is
//! never reached. The address may come from the process DNS cache; that is
//! not a bypass, since the address checked is the address dialled either
//! way.
//!
//! # Retries
//!
//! Nothing here resends. Two of the engine's three callers issue
//! non-idempotent `POST`s, and only they know what is safe to repeat.
//! Pingora validates a pooled connection when it takes one and discards a
//! dead one, so a stale keepalive entry is not handed to a request. The
//! residual window is a peer closing between that check and our write,
//! which reports as an unknown outcome for the caller to reconcile.
//!
//! [`private_address_reason`]: ppe::praxis_policy_core::http_addr::private_address_reason

use std::{net::SocketAddr, sync::OnceLock, time::Duration};

use async_trait::async_trait;
use pingora_core::upstreams::peer::HttpPeer;
use ppe::praxis_policy_core::{
    http::{
        DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_RESPONSE_BYTES, HttpRequest, HttpResponse, HttpTransport,
        HttpTransportError,
    },
    http_addr::private_address_reason,
};
use praxis_core::{
    config::DEFAULT_SUBREQUEST_POOL_SIZE,
    connectivity::{ConnectionOptions, peer as peer_utils},
    subrequest::{SubRequest, SubRequestClient, SubRequestConnector, SubRequestError, SubResponse},
};

use super::shared_connector::shared_policy_connector;

/// Performs the policy engine's outbound HTTP over the proxy's connector.
///
/// Install one per engine with `PolicyEngine::set_http_transport`. The
/// client is built on first use, never at construction, so a transport
/// created on a short-lived initialization runtime does not bind its pool
/// to a runtime that is about to be dropped.
#[derive(Debug)]
pub(super) struct PolicyHttpTransport {
    /// Built on first call from the registered connector.
    client: OnceLock<SubRequestClient>,

    /// Whether private and loopback destinations are permitted.
    allow_private: bool,
}

impl PolicyHttpTransport {
    /// Build a transport that refuses, or permits, non-public destinations.
    pub(super) fn new(allow_private: bool) -> Self {
        Self {
            client: OnceLock::new(),
            allow_private,
        }
    }

    /// The client, built from the registered connector on first call.
    fn client(&self) -> &SubRequestClient {
        self.client.get_or_init(|| build_client(shared_policy_connector()))
    }

    /// Refuse a destination the shared address table rules out.
    fn check_egress(&self, address: SocketAddr, host: &str) -> Result<(), HttpTransportError> {
        match private_address_reason(&address.ip()).filter(|_| !self.allow_private) {
            None => Ok(()),
            Some(reason) => {
                tracing::warn!(
                    target: "policy.transport",
                    host,
                    address = %address,
                    reason,
                    "policy: refusing an outbound call to a non-public address"
                );
                Err(HttpTransportError::Rejected(reason.to_owned()))
            },
        }
    }
}

#[async_trait]
impl HttpTransport for PolicyHttpTransport {
    #[expect(
        clippy::large_stack_frames,
        clippy::large_futures,
        reason = "Pingora session types are large"
    )]
    async fn execute(&self, req: HttpRequest) -> Result<HttpResponse, HttpTransportError> {
        let target = Target::parse(&req.url)?;
        let address = peer_utils::resolve_address(&target.dial_authority)
            .await
            .map_err(|e| HttpTransportError::Connect(format!("resolve '{}': {e}", target.dial_authority)))?;
        self.check_egress(address, &target.host_header)?;

        let peer = target.peer(address, req.connect_timeout);
        let sub_request = target.sub_request(&req)?;

        tracing::debug!(
            target: "policy.transport",
            method = %req.method,
            url = %req.url,
            address = %address,
            "policy: dispatching an outbound call over the proxy connector"
        );

        self.client()
            .execute(&peer, &sub_request, req.max_response_bytes, req.timeout, None)
            .await
            .map(into_http_response)
            .map_err(|e| map_error(&e))
    }
}

/// Build the client a transport dispatches through.
///
/// Falls back to a private pool when the host registered nothing, so an
/// embedder who forgot the registration still gets working policy calls —
/// with a warning naming the call that would remove the second pool.
fn build_client(shared: Option<&SubRequestConnector>) -> SubRequestClient {
    let connector = shared.cloned().unwrap_or_else(|| {
        tracing::warn!(
            target: "policy.transport",
            "policy: no shared sub-request connector registered, so policy calls use a second \
             connection pool; call praxis_filter::set_policy_subrequest_connector before building pipelines"
        );
        SubRequestConnector::new(DEFAULT_SUBREQUEST_POOL_SIZE, None)
    });
    SubRequestClient::with_max_response_bytes(connector, DEFAULT_MAX_RESPONSE_BYTES)
}

/// Convert a completed exchange into the engine's response type.
fn into_http_response(response: SubResponse) -> HttpResponse {
    HttpResponse::new(response.status, response.body).with_headers(response.headers)
}

/// Classify a sub-request failure for the engine.
///
/// The variant a caller acts on is `may_have_reached_peer`: a token
/// exchange that reports an unknown outcome is reconciled, one that
/// reports a clean refusal is retried.
fn map_error(error: &SubRequestError) -> HttpTransportError {
    match error {
        SubRequestError::InvalidRequest(message) => HttpTransportError::InvalidRequest(message.clone()),
        SubRequestError::AdmissionTimeout { max_connections } => HttpTransportError::Rejected(format!(
            "sub-request admission timeout (all {max_connections} slots busy)"
        )),
        SubRequestError::CircuitOpen { peer } => HttpTransportError::Rejected(format!("circuit open for peer {peer}")),
        SubRequestError::Connect(message) => HttpTransportError::Connect(message.clone()),
        SubRequestError::Io(message) => HttpTransportError::Io(message.clone()),
        SubRequestError::DeadlineExceeded => HttpTransportError::Timeout,
        SubRequestError::StreamIdleTimeout { idle_timeout } => {
            HttpTransportError::Io(format!("upstream stream idle for {idle_timeout:?}"))
        },
        SubRequestError::ResponseTooLarge { actual, limit } => HttpTransportError::ResponseTooLarge {
            actual: *actual,
            limit: *limit,
        },
        // Unclassified: the peer may have seen the request, so callers must reconcile.
        _ => HttpTransportError::Io(error.to_string()),
    }
}

/// A destination URL resolved into the pieces a dial needs.
#[derive(Debug)]
struct Target {
    /// `host:port`, IPv6 bracketed — the form address resolution and SNI
    /// derivation both expect.
    dial_authority: String,

    /// The `Host` header value: the authority exactly as the URL wrote it.
    host_header: String,

    /// Path and query, or `/` when the URL carried neither.
    uri: http::Uri,

    /// Whether to dial TLS.
    tls: bool,

    /// SNI hostname, empty for plaintext.
    sni: String,
}

impl Target {
    /// Split a policy URL into the pieces needed to dial it.
    ///
    /// # Errors
    ///
    /// Returns [`HttpTransportError::InvalidRequest`] for a URL this
    /// transport will not dial: an unparseable one, a scheme other than
    /// `http` or `https`, a missing host, embedded userinfo that would be
    /// dropped rather than sent, or an `https` URL naming an IP literal —
    /// which has no SNI, leaving certificate verification with no hostname
    /// to check.
    fn parse(url: &str) -> Result<Self, HttpTransportError> {
        let uri: http::Uri = url.parse().map_err(|e| invalid(format!("url '{url}': {e}")))?;
        let tls = dial_tls(url, uri.scheme_str())?;
        let authority = checked_authority(url, &uri)?;
        let host = authority.host();
        let dial_authority = format!("{host}:{}", uri.port_u16().unwrap_or(if tls { 443 } else { 80 }));

        if tls && is_ip_literal(host) {
            return Err(invalid(format!(
                "url '{url}' uses https with an IP literal, which carries no SNI for certificate verification"
            )));
        }

        Ok(Self {
            sni: if tls {
                peer_utils::derive_sni(&dial_authority)
            } else {
                String::new()
            },
            dial_authority,
            host_header: authority.as_str().to_owned(),
            uri: request_uri(&uri),
            tls,
        })
    }

    /// Build the peer to dial at an already-checked address.
    ///
    /// A connect bound is always set. Without one the overall deadline
    /// fires first and an unreachable peer reports a timeout, which a
    /// delegating caller must treat as a possibly-minted token; with one,
    /// the same failure reports a connect error it can safely retry.
    fn peer(&self, address: SocketAddr, connect_timeout: Option<Duration>) -> HttpPeer {
        let connect = connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT);
        let mut peer = HttpPeer::new(address, self.tls, self.sni.clone());
        peer_utils::apply_connection_options(
            &mut peer,
            &ConnectionOptions {
                connection_timeout: Some(connect),
                total_connection_timeout: Some(connect),
                ..ConnectionOptions::default()
            },
        );
        peer
    }

    /// Build the sub-request to send.
    ///
    /// # Errors
    ///
    /// Returns [`HttpTransportError::InvalidRequest`] when the authority
    /// cannot be a header value.
    fn sub_request(&self, req: &HttpRequest) -> Result<SubRequest, HttpTransportError> {
        let mut headers = req.headers.clone();
        // The client fills a missing `Host` with the socket address, which
        // is the wrong name for a virtual-hosted IdP.
        headers.insert(
            http::header::HOST,
            http::HeaderValue::from_str(&self.host_header)
                .map_err(|e| invalid(format!("host '{}' is not a valid header value: {e}", self.host_header)))?,
        );
        Ok(SubRequest {
            method: req.method.clone(),
            uri: self.uri.clone(),
            headers,
            body: req.body.clone(),
        })
    }
}

/// Whether a URL's scheme means dialling TLS.
///
/// # Errors
///
/// Returns [`HttpTransportError::InvalidRequest`] for a missing scheme or
/// one other than `http` or `https`.
fn dial_tls(url: &str, scheme: Option<&str>) -> Result<bool, HttpTransportError> {
    match scheme {
        Some("https") => Ok(true),
        Some("http") => Ok(false),
        Some(other) => Err(invalid(format!("url '{url}' has unsupported scheme '{other}'"))),
        None => Err(invalid(format!("url '{url}' has no scheme"))),
    }
}

/// A URL's authority, refused when it names no host or carries userinfo.
///
/// # Errors
///
/// Returns [`HttpTransportError::InvalidRequest`] in both refused cases.
fn checked_authority<'a>(url: &str, uri: &'a http::Uri) -> Result<&'a http::uri::Authority, HttpTransportError> {
    let authority = uri
        .authority()
        .filter(|authority| !authority.host().is_empty())
        .ok_or_else(|| invalid(format!("url '{url}' has no host")))?;
    // `Authority::host()` drops userinfo silently, so dialling would
    // discard credentials the operator wrote into the URL.
    if authority.as_str().contains('@') {
        return Err(invalid(format!("url '{url}' carries userinfo, which is not forwarded")));
    }
    Ok(authority)
}

/// The origin-form request target: path and query, or `/` when the URL
/// carried neither.
fn request_uri(url: &http::Uri) -> http::Uri {
    url.path_and_query()
        .and_then(|pq| http::Uri::builder().path_and_query(pq.clone()).build().ok())
        .unwrap_or_else(|| http::Uri::from_static("/"))
}

/// Whether a URI host is an IP literal rather than a DNS name.
fn is_ip_literal(host: &str) -> bool {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .parse::<std::net::IpAddr>()
        .is_ok()
}

/// Shorthand for the malformed-request case.
fn invalid(message: String) -> HttpTransportError {
    HttpTransportError::InvalidRequest(message)
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests;
