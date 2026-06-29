// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Kuadrant → CPEX CEL namespace remapping (plan R20).
//!
//! Kuadrant predicates reference an Envoy/Authorino attribute vocabulary
//! (`auth.identity.*`, `request.method/path/host`, `request.headers[...]`)
//! that does not exist verbatim in CPEX's evaluation bag. CPEX surfaces
//! identity claims as `claim.*` and the HTTP request line/headers on the
//! `HttpExtension` as `http.method` / `http.path` / `http.host` /
//! `http.request_headers.*` (the latter populated by the Praxis filter in
//! Phase B).
//!
//! This module rewrites the recognized prefixes to their CPEX equivalents
//! and then scans for any *un-remapped* reference into a source namespace
//! (`auth.*`, `request.*`, `context.*`, `metadata.*`). A leftover reference
//! is returned as a [`Remap::Gap`] so the translator reports it and refuses
//! to emit the expression — wrong-namespace CEL would otherwise compile
//! cleanly and fail **closed** (deny-all) at runtime, which is exactly the
//! silent failure R20 exists to prevent.
//!
//! The rewriting is intentionally lexical (prefix substitution + a header
//! scanner), not a full CEL parse. Its known limitations — string literals
//! that happen to contain a source token, and exotic indexing forms — are
//! documented in the Phase A feasibility gate; for the gate's purpose
//! (quantifying how much of a real corpus maps) a lexical pass is adequate
//! and never produces a *silently wrong* emission: anything it cannot
//! confidently rewrite becomes a gap, not a guess.

/// Result of remapping a single Kuadrant CEL predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Remap {
    /// Fully remapped to CPEX namespaces.
    Ok(String),
    /// An un-remappable reference remains; the string names it.
    Gap { reference: String },
}

/// Remap a Kuadrant CEL predicate into CPEX's bag vocabulary.
pub(crate) fn remap(expr: &str) -> Remap {
    // Order matters: rewrite the most specific prefixes first so that, e.g.,
    // `context.request.http.path` is consumed before a bare `request.`
    // scan could see it.
    let mut out = expr.to_owned();

    // Envoy-style `context.request.http.*` (used by older selectors).
    out = out.replace("context.request.http.method", "http.method");
    out = out.replace("context.request.http.path", "http.path");
    out = out.replace("context.request.http.host", "http.host");

    // Request line.
    out = out.replace("request.method", "http.method");
    out = out.replace("request.path", "http.path");
    out = out.replace("request.host", "http.host");

    // Headers: `request.headers['X']`, `request.headers["X"]`, and
    // `request.headers.X` → `http.request_headers.<lowercased>`.
    out = rewrite_headers(&out);

    // Identity claims: `auth.identity.<rest>` → `claim.<rest>`.
    out = out.replace("auth.identity.", "claim.");

    // Anything still pointing at a source namespace could not be mapped.
    if let Some(reference) = leftover_reference(&out) {
        return Remap::Gap { reference };
    }
    Remap::Ok(out)
}

/// Rewrite every `request.headers...` access in `expr` to the CPEX
/// `http.request_headers.<lowercased-name>` form. Unrecognized header
/// access shapes are left intact so [`leftover_reference`] flags them.
fn rewrite_headers(expr: &str) -> String {
    const NEEDLE: &str = "request.headers";
    let mut out = String::with_capacity(expr.len());
    let mut rest = expr;
    while let Some(pos) = rest.find(NEEDLE) {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + NEEDLE.len()..];
        if let Some((name, consumed)) = parse_header_access(after) {
            out.push_str("http.request_headers.");
            out.push_str(&name.to_ascii_lowercase());
            rest = &after[consumed..];
        } else {
            // Unrecognized shape — leave the needle in place so the scanner
            // advances and the leftover check still sees `request.headers`.
            out.push_str(NEEDLE);
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// Parse a header accessor immediately following `request.headers`.
///
/// Returns the header name and the number of bytes consumed from `after`.
/// Handles `['name']`, `["name"]`, and `.name`.
fn parse_header_access(after: &str) -> Option<(String, usize)> {
    let bytes = after.as_bytes();
    match bytes.first()? {
        b'[' => {
            let quote = *bytes.get(1)?;
            if quote != b'\'' && quote != b'"' {
                return None;
            }
            let close_quote = after.get(2..)?.find(quote as char)? + 2;
            // Expect `]` right after the closing quote.
            if after.as_bytes().get(close_quote + 1)? != &b']' {
                return None;
            }
            let name = after.get(2..close_quote)?.to_owned();
            Some((name, close_quote + 2))
        },
        b'.' => {
            let name: String = after[1..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            if name.is_empty() {
                return None;
            }
            let consumed = 1 + name.len();
            Some((name, consumed))
        },
        _ => None,
    }
}

/// Find the first leftover reference into a source (Kuadrant) namespace
/// that survived rewriting, if any.
fn leftover_reference(expr: &str) -> Option<String> {
    const SOURCES: [&str; 5] = ["auth.identity", "auth.metadata", "auth.", "request.", "context."];
    let mut best: Option<usize> = None;
    for needle in SOURCES {
        if let Some(pos) = expr.find(needle) {
            best = Some(best.map_or(pos, |b| b.min(pos)));
        }
    }
    let pos = best?;
    // Capture the dotted reference for a useful diagnostic.
    let reference: String = expr[pos..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '[' | ']' | '\'' | '"'))
        .collect();
    Some(reference)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, reason = "panic is idiomatic in test assertions")]
    use super::*;

    fn ok(expr: &str) -> String {
        match remap(expr) {
            Remap::Ok(s) => s,
            Remap::Gap { reference } => panic!("unexpected gap on `{expr}`: {reference}"),
        }
    }

    #[test]
    fn request_line_maps_to_http() {
        assert_eq!(ok("request.method == 'POST'"), "http.method == 'POST'");
        assert_eq!(
            ok("request.path.startsWith('/admin')"),
            "http.path.startsWith('/admin')"
        );
        assert_eq!(
            ok("request.host.endsWith('.example.com')"),
            "http.host.endsWith('.example.com')"
        );
    }

    #[test]
    fn envoy_context_form_maps() {
        assert_eq!(ok("context.request.http.path == '/x'"), "http.path == '/x'");
    }

    #[test]
    fn identity_claims_map_to_claim() {
        assert_eq!(ok("auth.identity.email_verified"), "claim.email_verified");
        assert_eq!(
            ok("auth.identity.realm_access.roles.exists(r, r == 'admin')"),
            "claim.realm_access.roles.exists(r, r == 'admin')"
        );
    }

    #[test]
    fn headers_bracket_and_dot_forms() {
        assert_eq!(
            ok("request.headers['X-Env'] == 'prod'"),
            "http.request_headers.x-env == 'prod'"
        );
        assert_eq!(
            ok("request.headers[\"X-Env\"] == 'prod'"),
            "http.request_headers.x-env == 'prod'"
        );
        assert_eq!(
            ok("request.headers.x_team == 'sec'"),
            "http.request_headers.x_team == 'sec'"
        );
    }

    #[test]
    fn unmapped_auth_metadata_is_gap() {
        match remap("auth.metadata['user-info'].active == true") {
            Remap::Gap { reference } => assert!(reference.starts_with("auth.metadata")),
            Remap::Ok(s) => panic!("expected gap, got {s}"),
        }
    }

    #[test]
    fn unknown_request_attribute_is_gap() {
        match remap("request.time > 0") {
            Remap::Gap { reference } => assert!(reference.starts_with("request.")),
            Remap::Ok(s) => panic!("expected gap, got {s}"),
        }
    }

    #[test]
    fn combined_expression_maps() {
        let got = ok("request.method == 'GET' && auth.identity.email_verified");
        assert_eq!(got, "http.method == 'GET' && claim.email_verified");
    }
}
