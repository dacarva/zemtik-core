use std::future::Future;
use std::pin::Pin;

use anyhow::{Context, anyhow};
use serde_json::Value;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Multi-provider LLM backend abstraction.
///
/// `api_key` is the resolved client token (from Authorization header or config fallback).
/// - `OpenAiBackend`: uses `api_key` as Bearer auth for outbound call (BYOK model).
/// - `AnthropicBackend`: ignores `api_key`; uses `self.api_key` (ZEMTIK_ANTHROPIC_API_KEY)
///   as x-api-key header. This asymmetry is intentional — Anthropic uses the operator key,
///   not a per-request client token.
// INVARIANT: AnthropicBackend never uses the client's incoming Bearer token.
// Auth is always from ZEMTIK_ANTHROPIC_API_KEY (x-api-key header, operator-configured).
pub trait LlmBackend: Send + Sync {
    /// Send a chat completion request. Returns `(http_status_code, OpenAI-shape response Value)`.
    /// Input `body` is OpenAI request format. AnthropicBackend translates before forwarding.
    fn complete<'a>(
        &'a self,
        body: &'a Value,
        api_key: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<(u16, Value)>>;

    /// Streaming variant. Returns the raw `reqwest::Response` for SSE passthrough.
    /// `OpenAiBackend` overrides with direct forward. `AnthropicBackend` translates format
    /// before forwarding (returns Anthropic SSE stream, not OpenAI SSE).
    fn forward_raw<'a>(
        &'a self,
        body: &'a Value,
        api_key: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<reqwest::Response>> {
        let _ = (body, api_key);
        Box::pin(async move {
            anyhow::bail!("streaming not supported for this backend in v1")
        })
    }
}

// ---------------------------------------------------------------------------
// OpenAiBackend — BYOK model, passes incoming Bearer token to OpenAI
// ---------------------------------------------------------------------------

pub struct OpenAiBackend {
    client: reqwest::Client,
    base_url: String,
}

impl OpenAiBackend {
    pub fn new(client: reqwest::Client, base_url: String) -> Self {
        Self { client, base_url }
    }
}

impl LlmBackend for OpenAiBackend {
    fn complete<'a>(
        &'a self,
        body: &'a Value,
        api_key: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<(u16, Value)>> {
        Box::pin(async move {
            let url = format!("{}/v1/chat/completions", self.base_url);
            let resp = self
                .client
                .post(&url)
                .bearer_auth(api_key)
                .json(body)
                .send()
                .await
                .context("OpenAI request failed")?;
            let status = resp.status().as_u16();
            let body: Value = resp.json().await.context("parse OpenAI response")?;
            Ok((status, body))
        })
    }

    fn forward_raw<'a>(
        &'a self,
        body: &'a Value,
        api_key: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<reqwest::Response>> {
        Box::pin(async move {
            let url = format!("{}/v1/chat/completions", self.base_url);
            let resp = self
                .client
                .post(&url)
                .bearer_auth(api_key)
                .json(body)
                .send()
                .await
                .context("OpenAI streaming request failed")?;
            Ok(resp)
        })
    }
}

// ---------------------------------------------------------------------------
// AnthropicBackend — operator key model, translates OpenAI ↔ Anthropic format
// ---------------------------------------------------------------------------

pub struct AnthropicBackend {
    client: reqwest::Client,
    // INVARIANT: Always from ZEMTIK_ANTHROPIC_API_KEY (operator-configured).
    // Never set from the client's incoming Authorization header.
    api_key: String,
    model: String,
    base_url: String,
}

impl AnthropicBackend {
    pub fn new(
        client: reqwest::Client,
        api_key: String,
        model: String,
        base_url: String,
    ) -> Self {
        Self { client, api_key, model, base_url }
    }

    fn translate_to_anthropic(&self, body: &Value) -> anyhow::Result<(Value, String)> {
        let messages = body
            .get("messages")
            .and_then(|m| m.as_array())
            .cloned()
            .unwrap_or_default();

        if messages.is_empty() {
            anyhow::bail!("no messages in request");
        }

        // Extract system role messages → top-level "system" field
        let mut system_parts: Vec<String> = Vec::new();
        let mut non_system: Vec<Value> = Vec::new();
        for msg in &messages {
            let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("");
            if role == "system" {
                if let Some(content) = msg.get("content") {
                    let text = content_to_text(content);
                    if !text.is_empty() {
                        system_parts.push(text);
                    }
                }
            } else {
                non_system.push(msg.clone());
            }
        }

        if non_system.is_empty() {
            anyhow::bail!("no user messages after system extraction");
        }

        let merged = merge_consecutive_same_role(non_system);

        // Map model — non-claude-* → self.model
        let incoming_model = body.get("model").and_then(|m| m.as_str()).unwrap_or("");
        let resolved_model = if incoming_model.starts_with("claude-") {
            incoming_model.to_owned()
        } else {
            eprintln!(
                "[LLM] INFO: model '{}' substituted with '{}' (ZEMTIK_ANTHROPIC_MODEL)",
                incoming_model, self.model
            );
            self.model.clone()
        };

        let max_tokens = body
            .get("max_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(8192);

        let mut anthropic_body = serde_json::json!({
            "model": resolved_model,
            "max_tokens": max_tokens,
            "messages": merged,
        });
        if !system_parts.is_empty() {
            anthropic_body["system"] = Value::String(system_parts.join("\n\n"));
        }

        Ok((anthropic_body, resolved_model))
    }
}

impl LlmBackend for AnthropicBackend {
    fn complete<'a>(
        &'a self,
        body: &'a Value,
        _api_key: &'a str, // INTENTIONALLY IGNORED — see INVARIANT
    ) -> BoxFuture<'a, anyhow::Result<(u16, Value)>> {
        Box::pin(async move {
            let (anthropic_body, resolved_model) = self.translate_to_anthropic(body)?;

            let url = format!("{}/v1/messages", self.base_url);
            let resp = self
                .client
                .post(&url)
                // INVARIANT: Use self.api_key (operator key), never the incoming client token
                .header("x-api-key", &self.api_key)
                .header("anthropic-version", "2023-06-01")
                .json(&anthropic_body)
                .send()
                .await
                .context("Anthropic API request failed")?;

            let status = resp.status();
            let status_u16 = status.as_u16();

            // D12: pass through non-2xx status and body verbatim.
            // Check status before consuming body — non-JSON error bodies (HTML 502, gateway errors)
            // would otherwise return Err() and surface as 502 with no upstream context.
            if !status.is_success() {
                let resp_body: Value = resp.json().await.unwrap_or_else(|_| {
                    serde_json::json!({"error": {"type": "upstream_error", "message": "upstream returned non-JSON error body"}})
                });
                return Ok((status_u16, resp_body));
            }

            let resp_body: Value = resp.json().await.context("parse Anthropic response")?;

            // Check for tool_use blocks (function calling) — not supported in v1.
            // Return 501 with a clear message rather than a silent 500.
            if let Some(blocks) = resp_body.get("content").and_then(|c| c.as_array()) {
                if blocks.iter().any(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_use")) {
                    return Ok((501u16, serde_json::json!({
                        "error": {
                            "type": "not_implemented",
                            "message": "Anthropic function calling (tool_use) is not supported in v1. \
                                        Remove tools[] from your request or use text-only prompts."
                        }
                    })));
                }
            }

            // Find first content[].type == "text" block (D10)
            let content_text = resp_body
                .get("content")
                .and_then(|c| c.as_array())
                .and_then(|blocks| {
                    blocks.iter().find(|b| {
                        b.get("type").and_then(|t| t.as_str()) == Some("text")
                    })
                })
                .and_then(|b| b.get("text"))
                .and_then(|t| t.as_str())
                .ok_or_else(|| anyhow!("Anthropic response has no text content block"))?
                .to_owned();

            let prompt_tokens = resp_body
                .get("usage")
                .and_then(|u| u.get("input_tokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let completion_tokens = resp_body
                .get("usage")
                .and_then(|u| u.get("output_tokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            // Normalize to OpenAI response shape.
            // _zemtik_resolved_model: internal field used by proxy call sites to populate
            // zemtik_meta.resolved_model. Stripped before returning to the client.
            let normalized = serde_json::json!({
                "id": resp_body.get("id").cloned().unwrap_or(Value::String(String::new())),
                "object": "chat.completion",
                "model": resolved_model,
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": content_text,
                    },
                    "finish_reason": match resp_body
                        .get("stop_reason")
                        .and_then(|r| r.as_str())
                        .unwrap_or("stop")
                    {
                        "end_turn" | "stop_sequence" => "stop",
                        "max_tokens" => "length",
                        other => other,
                    },
                }],
                "usage": {
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": prompt_tokens + completion_tokens,
                },
                "_zemtik_resolved_model": resolved_model,
            });

            Ok((200u16, normalized))
        })
    }

    fn forward_raw<'a>(
        &'a self,
        body: &'a Value,
        _api_key: &'a str, // INTENTIONALLY IGNORED — see INVARIANT
    ) -> BoxFuture<'a, anyhow::Result<reqwest::Response>> {
        Box::pin(async move {
            let (mut anthropic_body, _resolved_model) = self.translate_to_anthropic(body)?;
            // Enable streaming in the Anthropic request
            anthropic_body["stream"] = Value::Bool(true);

            let url = format!("{}/v1/messages", self.base_url);
            let resp = self
                .client
                .post(&url)
                // INVARIANT: Use self.api_key (operator key), never the incoming client token
                .header("x-api-key", &self.api_key)
                .header("anthropic-version", "2023-06-01")
                .json(&anthropic_body)
                .send()
                .await
                .context("Anthropic streaming request failed")?;
            Ok(resp)
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract plain text from an OpenAI message content value.
/// String content is returned as-is. Content-part arrays are joined (text parts only).
/// Other structured values are skipped (produce empty string).
fn content_to_text(content: &Value) -> String {
    match content {
        Value::String(s) => s.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|p| {
                if p.get("type").and_then(|t| t.as_str()) == Some("text") {
                    p.get("text").and_then(|t| t.as_str()).map(|s| s.to_owned())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n\n"),
        _ => String::new(),
    }
}

/// Merge consecutive messages with the same role, joining content with "\n\n".
/// Anthropic rejects consecutive user or assistant messages.
/// Only merges when both adjacent messages have plain string content after extraction;
/// structured content (e.g. image_url parts) is pushed through unchanged so the
/// caller sees a 501 rather than silently receiving garbled JSON blobs.
fn merge_consecutive_same_role(messages: Vec<Value>) -> Vec<Value> {
    let mut result: Vec<Value> = Vec::new();
    for msg in messages {
        let role = msg
            .get("role")
            .and_then(|r| r.as_str())
            .unwrap_or("")
            .to_owned();

        // Only attempt merge when content is a plain string or an array of exclusively
        // text-type parts. Arrays with non-text parts (e.g. image_url) are pushed through
        // unchanged so multimodal content is not silently dropped.
        let content_val = msg.get("content");
        let is_plain = match content_val {
            Some(Value::String(_)) => true,
            Some(Value::Array(parts)) => parts.iter().all(|p| {
                p.get("type").and_then(|t| t.as_str()) == Some("text")
            }),
            _ => false,
        };

        if is_plain {
            let content = content_to_text(content_val.unwrap());
            if let Some(last) = result.last_mut() {
                let last_role = last
                    .get("role")
                    .and_then(|r| r.as_str())
                    .unwrap_or("")
                    .to_owned();
                if last_role == role {
                    if let Some(last_content) = last.get_mut("content") {
                        if let Some(existing) = last_content.as_str() {
                            *last_content =
                                Value::String(format!("{}\n\n{}", existing, content));
                            continue;
                        }
                    }
                }
            }
            result.push(serde_json::json!({"role": role, "content": content}));
        } else {
            // Structured (non-text) content: push through unchanged, skip merge.
            result.push(msg);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_merge_same_role_no_change() {
        let msgs = vec![
            json!({"role": "user", "content": "hello"}),
            json!({"role": "assistant", "content": "hi"}),
        ];
        let merged = merge_consecutive_same_role(msgs);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn test_merge_consecutive_user_messages() {
        let msgs = vec![
            json!({"role": "user", "content": "first"}),
            json!({"role": "user", "content": "second"}),
            json!({"role": "assistant", "content": "reply"}),
        ];
        let merged = merge_consecutive_same_role(msgs);
        assert_eq!(merged.len(), 2);
        assert_eq!(
            merged[0].get("content").and_then(|c| c.as_str()),
            Some("first\n\nsecond")
        );
    }

    #[test]
    fn test_merge_preserves_multimodal_content() {
        // Image-url parts must not be JSON-stringified; the message must pass through unchanged.
        let msgs = vec![
            json!({"role": "user", "content": [
                {"type": "image_url", "image_url": {"url": "https://example.com/img.png"}},
                {"type": "text", "text": "describe this"}
            ]}),
            json!({"role": "assistant", "content": "a cat"}),
        ];
        let merged = merge_consecutive_same_role(msgs);
        assert_eq!(merged.len(), 2);
        // Multimodal content must remain as an array, not a string.
        assert!(
            merged[0].get("content").and_then(|c| c.as_array()).is_some(),
            "multimodal content must be preserved as an array"
        );
    }

    #[test]
    fn test_merge_all_text_parts_arrays() {
        // Two consecutive user messages with all-text content-parts arrays should merge.
        let msgs = vec![
            json!({"role": "user", "content": [{"type": "text", "text": "first"}]}),
            json!({"role": "user", "content": [{"type": "text", "text": "second"}]}),
        ];
        let merged = merge_consecutive_same_role(msgs);
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged[0].get("content").and_then(|c| c.as_str()),
            Some("first\n\nsecond"),
            "all-text parts arrays must merge into a single string"
        );
    }

    #[test]
    fn test_merge_consecutive_system_not_included() {
        // system is filtered before this function; only user/assistant pass through
        let msgs = vec![
            json!({"role": "user", "content": "q1"}),
            json!({"role": "user", "content": "q2"}),
        ];
        let merged = merge_consecutive_same_role(msgs);
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged[0].get("content").and_then(|c| c.as_str()),
            Some("q1\n\nq2")
        );
    }
}
