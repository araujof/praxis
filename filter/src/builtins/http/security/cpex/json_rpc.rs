// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! JSON-RPC body parsing + typed CMF content-part builders.
//
// The builders/re-serializers branch on MCP method and conditionally
// touch nested envelope fields; `too_many_lines` and
// `cognitive_complexity` fire on the longer ones but the alternatives
// (per-method helpers) hurt readability of a tightly-coupled
// envelope shape.
#![allow(
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    reason = "envelope orchestration; splitting per-method obscures the JSON-RPC shape"
)]
//!
//! Praxis's `mcp` filter parses JSON-RPC bodies and stashes
//! `mcp.method` / `mcp.name` in `filter_metadata`, but it doesn't
//! materialize `params.arguments` (or `result.content`) into a typed
//! form that APL `args.*` / `result.*` predicates can evaluate. This
//! module does that second parse, builds the matching `ContentPart`,
//! and re-serializes mutated payloads back into JSON-RPC envelopes
//! when `body_access: read_write` is on.

use bytes::Bytes;
use cpex_core::cmf::{
    ContentPart, Message, PromptRequest, ResourceReference, ResourceType, ToolCall, ToolResult,
};

// -----------------------------------------------------------------------------
// JSON-RPC id extraction
// -----------------------------------------------------------------------------

/// Read the JSON-RPC `id` field as a string for use as a CMF
/// correlation id. JSON-RPC permits string or numeric ids; we
/// stringify either to a single canonical key. Returns an empty
/// string when the body is missing or malformed — the correlation
/// id isn't load-bearing for policy, only for audit linkage.
pub(super) fn json_rpc_id(body: &Bytes) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .map(|id| match id {
            serde_json::Value::String(s) => s,
            other => other.to_string(),
        })
        .unwrap_or_default()
}

/// Typed companion to [`json_rpc_id`]. Returns the raw `id` JSON value
/// from the request body — preserves the original shape (string or
/// number) so an MCP error envelope echoes back exactly what the
/// client sent. Returns `Value::Null` when the body is missing or
/// malformed; per JSON-RPC 2.0, an error response MAY use `null` when
/// the original id could not be determined.
pub(super) fn json_rpc_id_value(body: &Bytes) -> serde_json::Value {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .unwrap_or(serde_json::Value::Null)
}

// -----------------------------------------------------------------------------
// Request-side: body → typed ContentPart list
// -----------------------------------------------------------------------------

/// Build the typed CMF `ContentPart` list for an MCP method. Parses
/// `params` out of the JSON-RPC body so APL `args.*` / `prompt.args.*`
/// / `resource.*` predicates have something to evaluate against. On
/// malformed or absent body, falls back to an empty content list — the
/// caller can still dispatch CMF (entity coords drive routing), just
/// without typed args available to predicates.
pub(super) fn build_content_for_method(
    method: &str,
    entity_name: &str,
    correlation_id: &str,
    body: &Bytes,
) -> Vec<ContentPart> {
    let params: serde_json::Value = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("params").cloned())
        .unwrap_or(serde_json::Value::Null);

    match method {
        "tools/call" => {
            let arguments = params
                .get("arguments")
                .and_then(|v| v.as_object())
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default();
            vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: correlation_id.to_owned(),
                    name: entity_name.to_owned(),
                    arguments,
                    namespace: None,
                },
            }]
        }
        "prompts/get" => {
            let arguments = params
                .get("arguments")
                .and_then(|v| v.as_object())
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default();
            vec![ContentPart::PromptRequest {
                content: PromptRequest {
                    prompt_request_id: correlation_id.to_owned(),
                    name: entity_name.to_owned(),
                    arguments,
                    server_id: None,
                },
            }]
        }
        "resources/read" => {
            // For `resources/read`, `params.uri` is the resource
            // identifier; `mcp.name` is set to the same URI by praxis's
            // `mcp` filter (it treats `uri` as the "selector"). Carry
            // it through as the `ResourceReference`.
            let uri = params
                .get("uri")
                .and_then(|v| v.as_str())
                .unwrap_or(entity_name)
                .to_owned();
            vec![ContentPart::ResourceRef {
                content: ResourceReference {
                    resource_request_id: correlation_id.to_owned(),
                    uri,
                    name: None,
                    resource_type: ResourceType::Uri,
                    range_start: None,
                    range_end: None,
                    selector: None,
                },
            }]
        }
        _ => Vec::new(),
    }
}

// -----------------------------------------------------------------------------
// Request-side: re-serialize mutated payload back into the body
// -----------------------------------------------------------------------------

/// Re-serialize a JSON-RPC request body, replacing only the fields
/// APL mutated in the typed `MessagePayload`. Returns `Some(new_bytes)`
/// when the body changed, `None` when nothing needed rewriting
/// (no matching content part, malformed original, etc.).
///
/// Touched fields by MCP method:
///   * `tools/call`     → `params.arguments` (from the first
///                        `ContentPart::ToolCall.arguments`)
///   * `prompts/get`    → `params.arguments` (from the first
///                        `ContentPart::PromptRequest.arguments`)
///   * `resources/read` → `params.uri` (from
///                        `ContentPart::ResourceRef.uri`)
///
/// All other JSON-RPC envelope fields (`jsonrpc`, `id`, `method`,
/// `params.name`) pass through unchanged. This minimizes the
/// blast radius of the rewrite — operators relying on a byte-stable
/// envelope (signature validation, content-hash matching) only see
/// changes when APL actually mutated.
pub(super) fn reserialize_json_rpc_body(
    original: &Bytes,
    method: &str,
    message: &Message,
) -> Option<Bytes> {
    let mut envelope: serde_json::Value = serde_json::from_slice(original).ok()?;
    let params = envelope.get_mut("params")?;
    let params_obj = params.as_object_mut()?;

    match method {
        "tools/call" | "prompts/get" => {
            for part in &message.content {
                let new_args = match part {
                    ContentPart::ToolCall { content } if method == "tools/call" => {
                        Some(&content.arguments)
                    }
                    ContentPart::PromptRequest { content } if method == "prompts/get" => {
                        Some(&content.arguments)
                    }
                    _ => None,
                };
                if let Some(args) = new_args {
                    let new_args_value: serde_json::Value = args
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect::<serde_json::Map<_, _>>()
                        .into();
                    params_obj.insert("arguments".to_owned(), new_args_value);
                    return Some(Bytes::from(serde_json::to_vec(&envelope).ok()?));
                }
            }
            None
        }
        "resources/read" => {
            for part in &message.content {
                if let ContentPart::ResourceRef { content } = part {
                    params_obj.insert(
                        "uri".to_owned(),
                        serde_json::Value::String(content.uri.clone()),
                    );
                    return Some(Bytes::from(serde_json::to_vec(&envelope).ok()?));
                }
            }
            None
        }
        _ => None,
    }
}

// -----------------------------------------------------------------------------
// Response-side: body → typed ContentPart list (post-phase)
// -----------------------------------------------------------------------------

/// Build the typed CMF `ContentPart` list from a JSON-RPC *response*
/// body — the post-phase mirror of [`build_content_for_method`]. Today
/// only `tools/call` produces a structured `ToolResult`; `prompts/get`
/// and `resources/read` return TBD shapes the filter can extend later.
///
/// The actual tool data lives in MCP's `result.content[].text` (a
/// JSON-stringified payload, per the MCP Tools spec) and/or
/// `result.structuredContent` (newer 2025-06-18 shape). We try
/// `structuredContent` first; on miss, parse the first text block's
/// contents as JSON; on parse-miss, wrap the raw text as
/// `{ "text": "<raw>" }` so APL `result.text` predicates still resolve.
pub(super) fn build_response_content_for_method(
    method: &str,
    entity_name: &str,
    correlation_id: &str,
    body: &Bytes,
) -> Vec<ContentPart> {
    if method != "tools/call" {
        return Vec::new();
    }
    let envelope: serde_json::Value = match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let Some(result) = envelope.get("result") else {
        return Vec::new();
    };
    let is_error = result
        .get("isError")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    let content_value = if let Some(structured) = result.get("structuredContent") {
        structured.clone()
    } else {
        result
            .get("content")
            .and_then(|c| c.as_array())
            .and_then(|arr| {
                arr.iter()
                    .find(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
            })
            .and_then(|block| block.get("text").and_then(|t| t.as_str()))
            .map_or(serde_json::Value::Null, |s| {
                serde_json::from_str::<serde_json::Value>(s)
                    .unwrap_or_else(|_| serde_json::json!({ "text": s }))
            })
    };

    vec![ContentPart::ToolResult {
        content: ToolResult {
            tool_call_id: correlation_id.to_owned(),
            tool_name: entity_name.to_owned(),
            content: content_value,
            is_error,
        },
    }]
}

// -----------------------------------------------------------------------------
// Response-side: re-serialize mutated payload back into the body
// -----------------------------------------------------------------------------

/// Re-serialize a JSON-RPC response body, replacing only the fields
/// the post-phase APL pipeline mutated. Mirror of
/// [`reserialize_json_rpc_body`] for the response side.
///
/// Writes the mutated `ContentPart::ToolResult.content` back into BOTH
/// `result.content[0].text` (as a JSON-stringified payload — the legacy
/// MCP shape every client supports) AND `result.structuredContent`
/// (the typed shape; only set if the original response had it). Keeps
/// unstructured + structured consumers in sync.
pub(super) fn reserialize_json_rpc_response_body(
    original: &Bytes,
    method: &str,
    message: &Message,
) -> Option<Bytes> {
    if method != "tools/call" {
        return None;
    }
    let mut envelope: serde_json::Value = serde_json::from_slice(original).ok()?;
    let result = envelope.get_mut("result")?;
    let result_obj = result.as_object_mut()?;

    let new_content = message.content.iter().find_map(|part| match part {
        ContentPart::ToolResult { content } => Some(content.content.clone()),
        _ => None,
    })?;

    if let Some(content_arr) = result_obj
        .get_mut("content")
        .and_then(|c| c.as_array_mut())
        && let Some(first_text) = content_arr.iter_mut().find(|b| {
            b.get("type").and_then(|t| t.as_str()) == Some("text")
        })
        && let Some(text_obj) = first_text.as_object_mut()
    {
        text_obj.insert(
            "text".to_owned(),
            serde_json::Value::String(serde_json::to_string(&new_content).ok()?),
        );
    }

    // Only mirror to structuredContent when the original had it.
    if result_obj.contains_key("structuredContent") {
        result_obj.insert("structuredContent".to_owned(), new_content);
    }

    Some(Bytes::from(serde_json::to_vec(&envelope).ok()?))
}
