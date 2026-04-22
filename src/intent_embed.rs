/// Embedding-based intent backend using fastembed + BGE-small-en (ONNX, CPU-only).
///
/// The schema index is built once at proxy startup from each table's:
/// - table key (e.g. "aws_spend")
/// - aliases (e.g. ["AWS", "amazon", "cloud spend"])
/// - description (one-sentence natural-language summary)
/// - example_prompts (5-10 synthetic queries)
///
/// At match time, the user prompt is embedded and compared to all index vectors
/// via cosine similarity. Each table's score = max score across its strings.
/// Top-k tables are returned sorted descending by score.
///
/// Requires `features = ["embed"]`. On init failure (no network, no model),
/// the caller should fall back to `RegexBackend`.
use std::path::Path;

use crate::config::SchemaConfig;
use crate::intent::IntentBackend;

// ---------------------------------------------------------------------------
// Shared helper
// ---------------------------------------------------------------------------

/// Truncate `s` to at most `max` Unicode scalar values, at a valid char boundary.
/// Returns the original slice if it is already within the limit.
pub fn truncate_chars(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((byte_pos, _)) => &s[..byte_pos],
        None => s,
    }
}

// ---------------------------------------------------------------------------
// EmbeddingBackend (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "embed")]
pub use embed_impl::EmbeddingBackend;

#[cfg(feature = "embed")]
mod embed_impl {
    use std::path::Path;

    use anyhow::Context;
    use fastembed::{EmbeddingModel, InitOptionsWithLength, TextEmbedding};

    use crate::config::SchemaConfig;
    use crate::intent::IntentBackend;

    /// Schema index entry: (table_key, embedding_vector)
    struct IndexEntry {
        table_key: String,
        embedding: Vec<f32>,
    }

    pub struct EmbeddingBackend {
        model: std::sync::Mutex<TextEmbedding>,
        /// All (table_key, embedding) pairs — multiple per table (key + aliases + desc + examples)
        index: Vec<IndexEntry>,
        /// Max chars of the user prompt to embed. The intent signal lives at the head of the
        /// message; truncating prevents document bodies from dominating cosine similarity.
        /// Default: 250. Configurable via ZEMTIK_INTENT_EMBED_PROMPT_MAX_CHARS.
        prompt_max_chars: usize,
    }

    impl EmbeddingBackend {
        /// Initialize with the BGE-small-en model, downloading it if not cached.
        ///
        /// On success, the model is cached at `models_dir/bge-small-en/`. Subsequent
        /// calls are instant. First download is ~130 MB and may take 30–120 seconds.
        pub fn new(models_dir: &Path, prompt_max_chars: usize) -> anyhow::Result<Self> {
            std::fs::create_dir_all(models_dir)
                .context("create models directory")?;

            let options = InitOptionsWithLength::new(EmbeddingModel::BGESmallENV15)
                .with_cache_dir(models_dir.to_path_buf())
                .with_show_download_progress(true);

            let model = TextEmbedding::try_new(options).context("init fastembed BGE-small-en")?;

            Ok(EmbeddingBackend { model: std::sync::Mutex::new(model), index: Vec::new(), prompt_max_chars })
        }

        fn embed_texts(&self, texts: &[String]) -> anyhow::Result<Vec<Vec<f32>>> {
            self.model
                .lock()
                .map_err(|e| anyhow::anyhow!("model mutex poisoned: {}", e))?
                .embed(texts, None)
                .context("embed texts")
        }

        fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
            let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
            let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
            let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
            if norm_a == 0.0 || norm_b == 0.0 {
                0.0
            } else {
                dot / (norm_a * norm_b)
            }
        }
    }

    impl IntentBackend for EmbeddingBackend {
        fn index_schema(&mut self, schema: &SchemaConfig) {
            self.index.clear();

            let mut texts: Vec<String> = Vec::new();
            let mut keys: Vec<String> = Vec::new();

            for (key, tc) in &schema.tables {
                // Table key itself
                texts.push(key.clone());
                keys.push(key.clone());

                // Aliases
                for alias in tc.aliases.as_deref().unwrap_or(&[]) {
                    texts.push(alias.clone());
                    keys.push(key.clone());
                }

                // Description
                if !tc.description.is_empty() {
                    texts.push(tc.description.clone());
                    keys.push(key.clone());
                }

                // Example prompts
                for ep in &tc.example_prompts {
                    texts.push(ep.clone());
                    keys.push(key.clone());
                }
            }

            if texts.is_empty() {
                return;
            }

            match self.embed_texts(&texts) {
                Ok(embeddings) => {
                    self.index = keys
                        .into_iter()
                        .zip(embeddings)
                        .map(|(table_key, embedding)| crate::intent_embed::embed_impl::IndexEntry {
                            table_key,
                            embedding,
                        })
                        .collect();

                    let table_count = schema.tables.len();
                    let embedding_count = self.index.len();
                    println!(
                        "[INTENT] Intent index built: {} tables, {} embeddings, model=BGE-small-en",
                        table_count, embedding_count
                    );
                }
                Err(e) => {
                    // Panic at startup — an empty index silently returns 400 for all requests
                    // with no operator-visible indication that the index is broken.
                    // Fail fast so the process does not start in a broken state.
                    panic!("[INTENT] FATAL: failed to build embedding index: {}. \
                        Check disk space and ONNX runtime. \
                        Set ZEMTIK_INTENT_BACKEND=regex to bypass the embedding backend.", e);
                }
            }
        }

        fn match_prompt(&self, prompt: &str, k: usize) -> Vec<(String, f32)> {
            if self.index.is_empty() {
                return Vec::new();
            }

            // Truncate to the instruction head only. Document bodies beyond this cap
            // contain domain terms that corrupt cosine similarity against table descriptions.
            // Truncate at char boundary, not byte boundary (avoids panic on multi-byte UTF-8).
            let truncated_buf;
            let prompt = if prompt.chars().count() > self.prompt_max_chars {
                truncated_buf = crate::intent_embed::truncate_chars(prompt, self.prompt_max_chars);
                truncated_buf
            } else {
                prompt
            };

            let query_embeddings = match self.embed_texts(&[prompt.to_owned()]) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("[WARN] EmbeddingBackend: embed_texts failed for query: {}", e);
                    return Vec::new();
                }
            };
            let query = &query_embeddings[0];

            // Score every index entry, then reduce to max score per table
            let mut table_scores: std::collections::HashMap<String, f32> =
                std::collections::HashMap::new();

            for entry in &self.index {
                let score = Self::cosine_similarity(query, &entry.embedding);
                let best = table_scores.entry(entry.table_key.clone()).or_insert(f32::NEG_INFINITY);
                if score > *best {
                    *best = score;
                }
            }

            // Sort by score descending, return top-k
            let mut results: Vec<(String, f32)> = table_scores.into_iter().collect();
            results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            results.truncate(k);
            results
        }
    }
}

// ---------------------------------------------------------------------------
// Stub for non-embed builds (regex-only feature)
// ---------------------------------------------------------------------------

/// Returns `None`. When the `embed` feature is disabled, this function is a no-op
/// placeholder. Callers should fall back to `RegexBackend`.
#[cfg(not(feature = "embed"))]
pub fn try_new_embedding_backend(
    _models_dir: &Path,
    _prompt_max_chars: usize,
) -> Option<Box<dyn IntentBackend>> {
    None
}

/// Attempt to create an `EmbeddingBackend`. Returns `None` if initialization fails
/// (model download error, ONNX load failure, etc.) — caller should log a warning and
/// fall back to `RegexBackend`.
#[cfg(feature = "embed")]
pub fn try_new_embedding_backend(
    models_dir: &Path,
    prompt_max_chars: usize,
) -> Option<Box<dyn IntentBackend>> {
    match EmbeddingBackend::new(models_dir, prompt_max_chars) {
        Ok(backend) => Some(Box::new(backend) as Box<dyn IntentBackend>),
        Err(e) => {
            eprintln!(
                "[INTENT] WARN: embedding model unavailable — falling back to regex intent extraction. \
                 Accuracy degraded. Run zemtik with network access to download model. Error: {}",
                e
            );
            None
        }
    }
}

// ---------------------------------------------------------------------------
// index_embedding_backend helper — builds schema index on a backend
// ---------------------------------------------------------------------------

/// Index the schema on a backend (convenience wrapper for proxy startup).
pub fn index_embedding_backend(backend: &mut dyn IntentBackend, schema: &SchemaConfig) {
    backend.index_schema(schema);
}
