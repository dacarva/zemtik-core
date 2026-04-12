use crate::config::SchemaConfig;
use crate::time_parser::{parse_time_range, TimeAmbiguousError};
use crate::types::IntentResult;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum IntentError {
    NoTableIdentified,
    TimeRangeAmbiguous,
}

impl std::fmt::Display for IntentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntentError::NoTableIdentified => write!(f, "no table identified in prompt"),
            IntentError::TimeRangeAmbiguous => write!(f, "time range is ambiguous"),
        }
    }
}

impl From<TimeAmbiguousError> for IntentError {
    fn from(_: TimeAmbiguousError) -> Self {
        IntentError::TimeRangeAmbiguous
    }
}

// ---------------------------------------------------------------------------
// IntentBackend trait
// ---------------------------------------------------------------------------

/// Trait for pluggable intent matching backends.
///
/// Two implementations ship in this crate:
/// - `RegexBackend`: wraps the original `.contains()` keyword matching (fast, no model).
/// - `EmbeddingBackend` (feature `embed`): cosine similarity over BGE-small-en embeddings.
pub trait IntentBackend: Send + Sync {
    /// Index the schema. Called once at proxy startup.
    fn index_schema(&mut self, schema: &SchemaConfig);

    /// Find the top-k matching table keys with similarity scores, sorted descending.
    /// Returns an empty vec if no tables have been indexed.
    fn match_prompt(&self, prompt: &str, k: usize) -> Vec<(String, f32)>;
}

// ---------------------------------------------------------------------------
// RegexBackend — wraps the original keyword/.contains() matching
// ---------------------------------------------------------------------------

/// Intent backend using case-insensitive substring/alias matching.
///
/// Returns at most one result per call at score 1.0, so the margin check in
/// `extract_intent_with_backend` is never triggered (backward-compatible behavior).
pub struct RegexBackend {
    schema: Option<SchemaConfig>,
}

impl RegexBackend {
    pub fn new() -> Self {
        RegexBackend { schema: None }
    }
}

impl Default for RegexBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl IntentBackend for RegexBackend {
    fn index_schema(&mut self, schema: &SchemaConfig) {
        self.schema = Some(schema.clone());
    }

    fn match_prompt(&self, prompt: &str, _k: usize) -> Vec<(String, f32)> {
        let schema = match &self.schema {
            Some(s) => s,
            None => return Vec::new(),
        };
        let lower = prompt.to_lowercase();

        // Collect all matching table keys
        let mut matches: Vec<(String, &str)> = Vec::new();
        for (key, tc) in &schema.tables {
            let key_lower = key.to_lowercase();
            let matched = lower.contains(&key_lower)
                || tc
                    .aliases
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .any(|a| lower.contains(&a.to_lowercase()));
            if matched {
                matches.push((key.clone(), tc.sensitivity.as_str()));
            }
        }

        // Deterministic sort: critical first, then alphabetical
        matches.sort_by(|a, b| {
            let rank = |s: &str| if s == "critical" { 0u8 } else { 1u8 };
            rank(a.1).cmp(&rank(b.1)).then_with(|| a.0.cmp(&b.0))
        });

        // Return only the top-1 match at score 1.0 (avoids margin-check ambiguity)
        matches
            .into_iter()
            .take(1)
            .map(|(key, _)| (key, 1.0_f32))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Deterministic substring gate (disambiguates embedding ties)
// ---------------------------------------------------------------------------

/// Tables whose schema key or any alias appears as a case-insensitive substring
/// of `prompt_lower` (same rules as `RegexBackend`).
fn tables_matching_substrings(prompt_lower: &str, schema: &SchemaConfig) -> Vec<String> {
    let mut matches = Vec::new();
    for (key, tc) in &schema.tables {
        let key_lower = key.to_lowercase();
        let matched = prompt_lower.contains(&key_lower)
            || tc
                .aliases
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .any(|a| prompt_lower.contains(&a.to_lowercase()));
        if matched {
            matches.push(key.clone());
        }
    }
    matches
}

// ---------------------------------------------------------------------------
// Core extraction logic
// ---------------------------------------------------------------------------

/// Extract intent using the provided backend and confidence threshold.
///
/// Rules:
/// 1. Truncate prompt to 2000 chars before matching.
/// 2. If **exactly one** table's key or alias appears as a substring of the prompt (same rules as
///    `RegexBackend`), use that table with confidence `1.0` and skip embedding/margin checks.
/// 3. Else call `backend.match_prompt(prompt, 3)`.
/// 4. If results are empty or `scores[0] < threshold` → `Err(NoTableIdentified)`.
/// 5. If at least 2 results and `scores[0] - scores[1] < 0.10` → `Err(NoTableIdentified)`
///    (ambiguous — not confident enough to route).
/// 6. Parse time range via `time_parser::parse_time_range`; ambiguous time → `Err(TimeRangeAmbiguous)`.
/// 7. Return `Ok(IntentResult)` with the top-1 table and confidence score.
pub fn extract_intent_with_backend(
    prompt: &str,
    schema: &SchemaConfig,
    backend: &dyn IntentBackend,
    threshold: f32,
) -> Result<IntentResult, IntentError> {
    // Truncate long prompts before embedding (truncate at char boundary, not byte boundary)
    let truncated;
    let prompt = if prompt.len() > 2000 {
        truncated = prompt
            .char_indices()
            .nth(2000)
            .map(|(i, _)| &prompt[..i])
            .unwrap_or(prompt);
        truncated
    } else {
        prompt
    };

    let prompt_lower = prompt.to_lowercase();
    let substring_hits = tables_matching_substrings(&prompt_lower, schema);

    // If exactly one table is named by key or alias in the prompt, trust that over
    // embedding cosine ties (e.g. "T&E expenses" vs payroll + travel both scoring high).
    if substring_hits.len() == 1 {
        let table = substring_hits[0].clone();
        let time_range = parse_time_range(prompt, schema.fiscal_year_offset_months)
            .map_err(IntentError::from)?;
        return Ok(IntentResult {
            category_name: table.clone(),
            table,
            start_unix_secs: time_range.start_unix_secs,
            end_unix_secs: time_range.end_unix_secs,
            confidence: 1.0,
            rewritten_query: None,
            rewrite_method: None,
        });
    }

    let matches = backend.match_prompt(prompt, 3);

    // Check top-1 score against threshold
    let (table, confidence) = match matches.first() {
        Some((t, s)) if *s >= threshold => (t.clone(), *s),
        _ => return Err(IntentError::NoTableIdentified),
    };

    // Margin check: if top-1 and top-2 are too close, reject as ambiguous
    if matches.len() >= 2 {
        let margin = confidence - matches[1].1;
        if margin < 0.10 {
            return Err(IntentError::NoTableIdentified);
        }
    }

    // Parse time range (uses LazyLock regexes — no per-call compile)
    let time_range =
        parse_time_range(prompt, schema.fiscal_year_offset_months).map_err(IntentError::from)?;

    Ok(IntentResult {
        category_name: table.clone(),
        table,
        start_unix_secs: time_range.start_unix_secs,
        end_unix_secs: time_range.end_unix_secs,
        confidence,
        rewritten_query: None,
        rewrite_method: None,
    })
}

/// Backward-compatible shim using `RegexBackend` with no threshold (matches any table).
///
/// Call sites outside proxy mode (CLI pipeline, tests) continue to work unchanged.
pub fn extract_intent(prompt: &str, schema: &SchemaConfig) -> Result<IntentResult, IntentError> {
    let mut backend = RegexBackend::new();
    backend.index_schema(schema);
    extract_intent_with_backend(prompt, schema, &backend, 0.0)
}
