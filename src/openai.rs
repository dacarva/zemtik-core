use anyhow::Context;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::types::{OpenAiRequestLog, OpenAiResult, TokenUsage};

const OPENAI_API_URL: &str = "https://api.openai.com/v1/chat/completions";
const MODEL: &str = "gpt-5.4-nano";
const MAX_COMPLETION_TOKENS: u32 = 150;

const SYSTEM_PROMPT: &str = "You are a senior bank advisor. You have received a JSON payload \
    whose figures are cryptographically verified by a Zero-Knowledge \
    proof — the data has been mathematically proven not to have been \
    tampered with. Write exactly 2 sentences advising the client on \
    their spend. Do not ask for raw transaction data and do not \
    mention the ZK proof mechanism.";

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage<'a>>,
    max_completion_tokens: u32,
}

#[derive(Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: String,
}

#[derive(Deserialize)]
struct ChatResponse {
    model: String,
    choices: Vec<Choice>,
    usage: Usage,
}

#[derive(Deserialize)]
struct Choice {
    message: ResponseMessage,
}

#[derive(Deserialize)]
struct ResponseMessage {
    content: String,
}

#[derive(Deserialize)]
struct Usage {
    prompt_tokens: u32,
    completion_tokens: u32,
    total_tokens: u32,
}

/// Send a ZK-verified aggregate to OpenAI and receive a financial insight.
///
/// The payload contains ONLY the verified aggregate spend and public metadata —
/// zero raw transaction rows are transmitted. This is the privacy guarantee
/// that Zemtik provides: the LLM sees the cryptographic proof outcome, not
/// the underlying ledger data.
///
/// Returns `OpenAiResult` with the advisory text plus full request/response
/// metadata for audit logging.
pub async fn query_openai(
    aggregate: u64,
    category_name: &str,
    start_date: &str,
    end_date: &str,
) -> anyhow::Result<OpenAiResult> {
    let api_key = std::env::var("OPENAI_API_KEY")
        .or_else(|_| std::env::var("OPENAI_API_URL"))
        .context("OPENAI_API_KEY (or OPENAI_API_URL) environment variable not set")?;

    let client = Client::new();

    // Construct the JSON payload that the advisor receives.
    // This is the ONLY data transmitted — no raw rows, no client PII.
    let zk_payload = serde_json::json!({
        "category": category_name,
        "total_spend_usd": aggregate,
        "period_start": start_date,
        "period_end": end_date,
        "data_provenance": "ZEMTIK_VALID_ZK_PROOF",
        "raw_data_transmitted": false
    });

    let user_message = format!(
        "Here is a cryptographically verified financial summary for your analysis:\n\n{}",
        serde_json::to_string_pretty(&zk_payload)?
    );

    let request = ChatRequest {
        model: MODEL,
        messages: vec![
            ChatMessage {
                role: "system",
                content: SYSTEM_PROMPT.to_owned(),
            },
            ChatMessage {
                role: "user",
                content: user_message.clone(),
            },
        ],
        max_completion_tokens: MAX_COMPLETION_TOKENS,
    };

    let response = client
        .post(OPENAI_API_URL)
        .bearer_auth(&api_key)
        .json(&request)
        .send()
        .await
        .context("send request to OpenAI")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("OpenAI API error {}: {}", status, body);
    }

    let chat: ChatResponse = response
        .json()
        .await
        .context("deserialize OpenAI response")?;

    let content = chat
        .choices
        .into_iter()
        .next()
        .map(|c| c.message.content)
        .context("empty choices in OpenAI response")?;

    Ok(OpenAiResult {
        content,
        model: chat.model,
        usage: TokenUsage {
            prompt_tokens: chat.usage.prompt_tokens,
            completion_tokens: chat.usage.completion_tokens,
            total_tokens: chat.usage.total_tokens,
        },
        request_log: OpenAiRequestLog {
            model: MODEL.to_owned(),
            system_prompt: SYSTEM_PROMPT.to_owned(),
            user_message,
            max_completion_tokens: MAX_COMPLETION_TOKENS,
        },
    })
}
