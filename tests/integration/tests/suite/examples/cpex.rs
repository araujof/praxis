// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Teryl Taylor

//! Functional integration test for the CPEX example config.
//!
//! Exercises the `examples/configs/security/cpex.yaml` filter chain
//! end-to-end: praxis is configured with the `mcp` → `cpex` → `router`
//! → `load_balancer` chain, an HTTP request is sent without an
//! `Authorization` header, and we assert the filter rejects with
//! HTTP 401 (the cpex identity gate's `auth_rejection` path).
//!
//! Why no happy-path test here: a positive case requires minting an
//! HS256 JWT and constructing a valid MCP JSON-RPC body that praxis's
//! built-in `mcp` filter accepts. The unit tests in
//! `filter/src/builtins/http/security/cpex/tests.rs` cover that path
//! against the filter trait directly. The intent here is the
//! CLAUDE.md "Adding a Filter" integration-test requirement: prove
//! the example config loads, the filter constructs from the policy
//! YAML, and the chain produces the documented error response.

use std::collections::HashMap;

use praxis_core::config::Config;
use praxis_test_utils::{
    example_config_path, free_port, http_send, parse_status, patch_yaml, start_backend_with_shutdown, start_proxy,
};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Load the CPEX praxis example, patch the relative `config_path`
/// reference into an absolute path, then patch ports. Returns a
/// fully-parsed [`Config`] ready for [`start_proxy`].
#[allow(clippy::needless_pass_by_value, reason = "callers construct the map inline")]
fn load_cpex_example(proxy_port: u16, port_map: HashMap<&str, u16>) -> Config {
    let praxis_yaml_path = example_config_path("security/cpex.yaml");
    let policy_yaml_path = example_config_path("security/cpex-policy.yaml");

    let raw = std::fs::read_to_string(&praxis_yaml_path).unwrap_or_else(|e| panic!("read {praxis_yaml_path}: {e}"));
    // The example uses a workspace-relative path for the policy file
    // because that's what an operator would write. The integration
    // test rewrites it to an absolute path so the filter resolves it
    // regardless of the test's working directory.
    let with_policy = raw.replace("examples/configs/security/cpex-policy.yaml", &policy_yaml_path);
    let patched = patch_yaml(&with_policy, proxy_port, &port_map);
    Config::from_yaml(&patched).unwrap_or_else(|e| panic!("parse security/cpex.yaml: {e}"))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn cpex_example_missing_authorization_rejects_401() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_cpex_example(proxy_port, HashMap::from([("127.0.0.1:3000", backend_guard.port())]));
    let proxy = start_proxy(&config);

    // POST with a well-formed MCP body but no Authorization header.
    // The identity hook chain denies, cpex returns auth_rejection (401
    // with WWW-Authenticate + X-Cpex-Violation headers).
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#;
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST /mcp HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            body.len(),
        ),
    );

    assert_eq!(
        parse_status(&raw),
        401,
        "missing Authorization should hit the cpex identity gate; raw response:\n{raw}",
    );
    assert!(
        raw.to_lowercase().contains("www-authenticate: bearer"),
        "401 must carry WWW-Authenticate per MCP auth spec; raw response:\n{raw}",
    );
    assert!(
        raw.to_lowercase().contains("x-cpex-violation:"),
        "rejection should surface the violation code via X-Cpex-Violation; raw response:\n{raw}",
    );
}
