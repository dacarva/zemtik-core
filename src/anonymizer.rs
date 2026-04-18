// Anonymizer v1 — PII detection, tokenization, vault, and deanonymization.
//
// Invariants (see CLAUDE.md):
// - std::sync::Mutex for VaultStore; never hold MutexGuard across .await
// - Vault lifecycle: remove-after-turn via scopeguard::defer! + TTL eviction
// - Tunnel mode: skip entirely (caller's responsibility to check before calling)
// - All user-role messages processed in a single gRPC batch call
// - System prompt injected as a separate message, never concatenated

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;
use tonic::transport::Channel;

use crate::entity_hashes::type_hash;

// ---------------------------------------------------------------------------
// Generated gRPC stubs (tonic + prost, from proto/anonymizer.proto)
// ---------------------------------------------------------------------------

pub mod proto {
    pub mod anonymizer {
        tonic::include_proto!("zemtik.anonymizer.v1");
    }
    pub mod health {
        tonic::include_proto!("grpc.health.v1");
    }
}

use proto::anonymizer::anonymizer_service_client::AnonymizerServiceClient;
use proto::anonymizer::{AnonymizeRequest, Message as ProtoMessage};
use proto::health::health_client::HealthClient;
use proto::health::HealthCheckRequest;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum AnonymizerError {
    #[error("PII sidecar unreachable at {addr}. Ensure the anonymizer service is running (docker compose up) or set ZEMTIK_ANONYMIZER_FALLBACK_REGEX=true to use regex-only mode.")]
    SidecarUnreachable { addr: String },

    #[error("PII sidecar is starting. GLiNER model load takes 10-30s. Check container health (docker compose ps) and retry, or wait for the 'anonymizer' service to report 'healthy'.")]
    SidecarStarting,

    #[error("PII sidecar call timed out after {ms}ms")]
    SidecarTimeout { ms: u64 },

    #[error("PII sidecar returned malformed response: {detail}")]
    MalformedResponse { detail: String },
}

// ---------------------------------------------------------------------------
// Vault types
// ---------------------------------------------------------------------------

/// A single token-to-original mapping for one entity.
#[derive(Debug, Clone)]
pub struct VaultEntry {
    pub token: String,
    pub original: String,
    pub entity_type: String,
}

/// Session-scoped vault: maps token → original text.
pub type Vault = Vec<VaultEntry>;

/// Metadata produced by anonymize_conversation.
#[derive(Debug, Clone, Default)]
pub struct AuditMeta {
    pub entities_found: usize,
    pub entity_types: Vec<String>,
    pub sidecar_used: bool,
    pub sidecar_ms: u64,
}

// ---------------------------------------------------------------------------
// VaultStore (shared across requests, std::sync::Mutex)
// ---------------------------------------------------------------------------

pub type VaultStore = Arc<Mutex<HashMap<String, (Vault, Instant)>>>;

pub fn new_vault_store() -> VaultStore {
    Arc::new(Mutex::new(HashMap::new()))
}

// ---------------------------------------------------------------------------
// Token construction
// ---------------------------------------------------------------------------

/// `[[Z:{type_hash_4hex}:{counter}]]`
pub fn make_token(type_hash_4hex: &str, counter: usize) -> String {
    format!("[[Z:{type_hash_4hex}:{counter}]]")
}

// ---------------------------------------------------------------------------
// Regex fast-path: LATAM + common PII (no sidecar needed)
// ---------------------------------------------------------------------------

static REGEX_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    // Patterns ordered from most specific to least specific to avoid false positives.
    vec![
        // Email — before general patterns
        ("EMAIL_ADDRESS", Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap()),
        // IBAN — very specific structure
        ("IBAN_CODE", Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b").unwrap()),
        // Colombian cédula: 79.123.456 or 79123456 (7-10 digits, optional dots)
        ("CO_CEDULA", Regex::new(r"\b\d{1,3}(?:\.\d{3}){1,2}\b|\b\d{7,10}\b").unwrap()),
        // Colombian NIT: 900.123.456-7
        ("CO_NIT", Regex::new(r"\b\d{3}\.\d{3}\.\d{3}-\d\b").unwrap()),
        // Chilean RUT: 12.345.678-9 or 12345678-9
        ("CL_RUT", Regex::new(r"\b\d{1,2}\.?\d{3}\.?\d{3}-[\dkK]\b").unwrap()),
        // Mexican CURP: 18 chars alphanumeric
        ("MX_CURP", Regex::new(r"\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]{2}\b").unwrap()),
        // Mexican RFC: 12-13 chars
        ("MX_RFC", Regex::new(r"\b[A-Z]{3,4}\d{6}[A-Z0-9]{3}\b").unwrap()),
        // Brazilian CPF: 000.000.000-00
        ("BR_CPF", Regex::new(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b").unwrap()),
        // Brazilian CNPJ: 00.000.000/0000-00
        ("BR_CNPJ", Regex::new(r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b").unwrap()),
        // Argentine DNI: 12.345.678 or 12345678
        ("AR_DNI", Regex::new(r"\b\d{2}\.\d{3}\.\d{3}\b|\b\d{7,8}\b").unwrap()),
        // Spanish NIF: 12345678A or X1234567A (NIE)
        ("ES_NIF", Regex::new(r"\b\d{8}[A-Z]\b|\b[XYZ]\d{7}[A-Z]\b").unwrap()),
        // Phone: +1 (555) 555-5555, +57 310 123 4567, etc.
        ("PHONE_NUMBER", Regex::new(r"\+?[\d\s\-().]{10,20}").unwrap()),
    ]
});

/// Apply regex patterns to `text` and replace matched entities with vault tokens.
/// Returns (anonymized_text, entries_added) where entries_added are new VaultEntry items.
pub fn regex_anonymize(
    text: &str,
    entity_types: &[&str],
    vault: &mut Vault,
    counter: &mut usize,
) -> String {
    let mut result = text.to_owned();
    for (etype, regex) in REGEX_PATTERNS.iter() {
        if !entity_types.contains(etype) {
            continue;
        }
        let hash = match type_hash(etype) {
            Some(h) => h,
            None => continue,
        };
        let mut new_result = String::new();
        let mut last_end = 0;
        for m in regex.find_iter(&result.clone()) {
            let original = m.as_str().to_owned();
            // Check if already tokenized (avoid double-tokenizing)
            if original.starts_with("[[Z:") {
                new_result.push_str(&result[last_end..m.end()]);
                last_end = m.end();
                continue;
            }
            // Find or assign counter
            let existing = vault.iter().find(|e| e.original == original && e.entity_type == *etype);
            let token = if let Some(e) = existing {
                e.token.clone()
            } else {
                *counter += 1;
                let token = make_token(hash, *counter);
                vault.push(VaultEntry {
                    token: token.clone(),
                    original: original.clone(),
                    entity_type: etype.to_string(),
                });
                token
            };
            new_result.push_str(&result[last_end..m.start()]);
            new_result.push_str(&token);
            last_end = m.end();
        }
        new_result.push_str(&result[last_end..]);
        result = new_result;
    }
    result
}

// ---------------------------------------------------------------------------
// gRPC client wrapper
// ---------------------------------------------------------------------------

pub type AnonymizerGrpcClient = AnonymizerServiceClient<Channel>;

/// Build a lazy gRPC channel. `connect_lazy()` defers TCP until the first call.
pub fn build_channel(addr: &str) -> Channel {
    Channel::from_shared(addr.to_owned())
        .expect("valid sidecar addr URI")
        .connect_lazy()
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum SidecarHealth {
    Serving,
    NotServing,
    Unreachable,
}

pub async fn check_sidecar_health(channel: Channel) -> SidecarHealth {
    let mut client = HealthClient::new(channel);
    match client.check(HealthCheckRequest { service: String::new() }).await {
        Ok(resp) => {
            // ServingStatus::SERVING = 1
            if resp.into_inner().status == 1 {
                SidecarHealth::Serving
            } else {
                SidecarHealth::NotServing
            }
        }
        Err(_) => SidecarHealth::Unreachable,
    }
}

// ---------------------------------------------------------------------------
// Core: anonymize_conversation
// ---------------------------------------------------------------------------

/// Anonymize all user-role messages in `messages` via the gRPC sidecar (or regex fallback).
///
/// Returns (anonymized_messages_json, vault, audit_meta).
/// `messages` is the raw JSON array from the chat completions body.
/// All user messages are sent in a single gRPC batch.
pub async fn anonymize_conversation(
    messages: &[Value],
    session_id: &str,
    client: Option<&mut AnonymizerGrpcClient>,
    entity_types_csv: &str,
    timeout_ms: u64,
    fallback_regex: bool,
    addr: &str,
) -> Result<(Vec<Value>, Vault, AuditMeta), AnonymizerError> {
    // Parse entity types from CSV
    let entity_types: Vec<&str> = entity_types_csv
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    // Extract user messages with their indices. Track whether content was originally
    // a parts array so we can write back correctly without destroying non-text parts.
    // (msg_index, extracted_text, is_parts_array)
    let user_msgs_owned: Vec<(usize, String, bool)> = messages
        .iter()
        .enumerate()
        .filter_map(|(i, m)| {
            let role = m.get("role")?.as_str()?;
            if role != "user" {
                return None;
            }
            let content_val = m.get("content")?;
            let (text, is_parts) = if let Some(s) = content_val.as_str() {
                (s.to_owned(), false)
            } else if let Some(parts) = content_val.as_array() {
                // content-parts array: concatenate all text parts
                let t = parts.iter()
                    .filter(|p| p.get("type").and_then(|t| t.as_str()) == Some("text"))
                    .filter_map(|p| p.get("text")?.as_str())
                    .collect::<Vec<_>>()
                    .join("");
                (t, true)
            } else {
                return None;
            };
            if text.is_empty() { None } else { Some((i, text, is_parts)) }
        })
        .collect();
    let user_msgs: Vec<(usize, &str)> = user_msgs_owned.iter().map(|(i, s, _)| (*i, s.as_str())).collect();

    // No user messages — no-op
    if user_msgs.is_empty() {
        return Ok((messages.to_vec(), Vec::new(), AuditMeta::default()));
    }

    let mut vault: Vault = Vec::new();
    let mut counter: usize = 0;
    let mut meta = AuditMeta::default();

    // Try gRPC sidecar first
    let sidecar_result = if let Some(grpc) = client {
        let proto_messages: Vec<ProtoMessage> = user_msgs
            .iter()
            .map(|(_, content)| ProtoMessage {
                role: "user".to_owned(),
                content: content.to_string(),
            })
            .collect();

        let request = AnonymizeRequest {
            messages: proto_messages,
            session_id: session_id.to_owned(),
            entity_types: entity_types_csv.to_owned(),
        };

        let deadline = std::time::Duration::from_millis(timeout_ms);
        let start = Instant::now();
        let call = tokio::time::timeout(deadline, grpc.anonymize(request)).await;
        meta.sidecar_ms = start.elapsed().as_millis() as u64;

        match call {
            Err(_elapsed) => Err(AnonymizerError::SidecarTimeout { ms: timeout_ms }),
            Ok(Err(status)) => {
                // Map tonic status to appropriate error
                match status.code() {
                    tonic::Code::Unavailable => Err(AnonymizerError::SidecarUnreachable { addr: addr.to_owned() }),
                    tonic::Code::Unimplemented => Err(AnonymizerError::SidecarStarting),
                    _ => Err(AnonymizerError::MalformedResponse { detail: status.code().description().to_owned() }),
                }
            }
            Ok(Ok(response)) => Ok(response.into_inner()),
        }
    } else {
        Err(AnonymizerError::SidecarUnreachable { addr: addr.to_owned() })
    };

    let anonymized_contents: Vec<String> = match sidecar_result {
        Ok(resp) => {
            meta.sidecar_used = true;
            // Build vault from spans
            for (msg_idx, anon_msg) in resp.messages.iter().enumerate() {
                let original = user_msgs.get(msg_idx).map(|(_, c)| *c).unwrap_or("");
                for span in &anon_msg.spans {
                    // Extract original text from byte offsets
                    let bytes = original.as_bytes();
                    let start = span.byte_start as usize;
                    let end = span.byte_end as usize;
                    if end > bytes.len() || start >= end {
                        continue;
                    }
                    let original_text = match std::str::from_utf8(&bytes[start..end]) {
                        Ok(s) => s.to_owned(),
                        Err(_) => continue,
                    };
                    let hash = match type_hash(&span.entity_type) {
                        Some(h) => h,
                        None => continue,
                    };
                    // Assign counter — same entity gets same counter
                    let existing = vault.iter().find(|e| e.original == original_text && e.entity_type == span.entity_type);
                    if existing.is_none() {
                        counter += 1;
                        let token = make_token(hash, counter);
                        vault.push(VaultEntry {
                            token,
                            original: original_text,
                            entity_type: span.entity_type.clone(),
                        });
                    }
                }
            }
            // Sort vault longest-first so compound names (e.g. "Jose Garcia") are replaced
            // before substrings (e.g. "Jose"), preventing partial token substitution.
            vault.sort_by(|a, b| b.original.len().cmp(&a.original.len()));
            // Build anonymized content strings from vault (apply all replacements)
            user_msgs.iter().map(|(_, content)| {
                let mut text = content.to_string();
                for entry in &vault {
                    text = text.replace(&entry.original, &entry.token);
                }
                text
            }).collect()
        }
        Err(e) => {
            if !fallback_regex {
                return Err(e);
            }
            // Regex fallback — only LATAM IDs and structured patterns, no PERSON/ORG
            let regex_types: Vec<&str> = entity_types
                .iter()
                .copied()
                .filter(|t| !matches!(*t, "PERSON" | "ORG" | "LOCATION"))
                .collect();

            user_msgs.iter().map(|(_, content)| {
                regex_anonymize(content, &regex_types, &mut vault, &mut counter)
            }).collect()
        }
    };

    meta.entities_found = vault.len();
    meta.entity_types = vault.iter().map(|e| e.entity_type.clone()).collect::<std::collections::HashSet<_>>().into_iter().collect();

    // Build lookup: message_index → (anonymized_text, is_parts_array)
    // Using message index (not user-message counter) fixes P1 index mismatch when
    // image-only user messages exist and get skipped in user_msgs_owned.
    let anon_by_idx: std::collections::HashMap<usize, (String, bool)> = user_msgs_owned
        .iter()
        .zip(anonymized_contents.iter())
        .map(|((msg_idx, _, is_parts), anon)| (*msg_idx, (anon.clone(), *is_parts)))
        .collect();

    // Rebuild messages array with anonymized user content
    let mut result_messages = messages.to_vec();
    for (msg_idx, msg) in result_messages.iter_mut().enumerate() {
        if let Some((anon_text, is_parts)) = anon_by_idx.get(&msg_idx) {
            if let Some(obj) = msg.as_object_mut() {
                if *is_parts {
                    // Preserve parts array structure: update text parts in-place,
                    // keep non-text parts (images, audio) unchanged.
                    if let Some(parts) = obj.get_mut("content").and_then(|c| c.as_array_mut()) {
                        let mut first_text_updated = false;
                        for part in parts.iter_mut() {
                            if part.get("type").and_then(|t| t.as_str()) == Some("text") {
                                if let Some(part_obj) = part.as_object_mut() {
                                    if !first_text_updated {
                                        // Write full anonymized text into first text part
                                        part_obj.insert("text".to_owned(), Value::String(anon_text.clone()));
                                        first_text_updated = true;
                                    } else {
                                        // Blank subsequent text parts (content already merged above)
                                        part_obj.insert("text".to_owned(), Value::String(String::new()));
                                    }
                                }
                            }
                        }
                    }
                } else {
                    obj.insert("content".to_owned(), Value::String(anon_text.clone()));
                }
            }
        }
    }

    Ok((result_messages, vault, meta))
}

// ---------------------------------------------------------------------------
// Deanonymize: replace tokens with originals in LLM response text
// ---------------------------------------------------------------------------

/// Scan `text` for vault tokens and replace them with the original entity text.
/// String scan — no fuzzy matching.
pub fn deanonymize(text: &str, vault: &Vault) -> String {
    let mut result = text.to_owned();
    for entry in vault {
        result = result.replace(&entry.token, &entry.original);
    }
    result
}

/// Count how many vault tokens from `vault` are absent from `text`
/// (dropped by the LLM — paraphrased or omitted).
pub fn count_dropped_tokens(text: &str, vault: &Vault) -> usize {
    vault.iter().filter(|e| !text.contains(&e.token)).count()
}

// ---------------------------------------------------------------------------
// System prompt for token preservation
// ---------------------------------------------------------------------------

pub const SYSTEM_PROMPT_INJECT: &str =
    "This text contains privacy tokens in the format [[Z:xxxx:n]].\n\
     Preserve every token exactly — do not expand, paraphrase, split, or omit them.\n\
     Treat them as opaque identifiers.";
