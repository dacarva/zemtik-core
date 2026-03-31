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
// EmbeddingBackend (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "embed")]
pub use embed_impl::EmbeddingBackend;

#[cfg(feature = "embed")]
mod embed_impl {
    use std::path::Path;

    use anyhow::Context;
    use fastembed::{EmbeddingModel, InitOptions, TextEmbedding};

    use crate::config::SchemaConfig;
    use crate::intent::IntentBackend;

    /// Schema index entry: (table_key, embedding_vector)
    struct IndexEntry {
        table_key: String,
        embedding: Vec<f32>,
    }

    pub struct EmbeddingBackend {
        model: TextEmbedding,
        /// All (table_key, embedding) pairs — multiple per table (key + aliases + desc + examples)
        index: Vec<IndexEntry>,
    }

    impl EmbeddingBackend {
        /// Initialize with the BGE-small-en model, downloading it if not cached.
        ///
        /// On success, the model is cached at `models_dir/bge-small-en/`. Subsequent
        /// calls are instant. First download is ~130 MB and may take 30–120 seconds.
        pub fn new(models_dir: &Path) -> anyhow::Result<Self> {
            std::fs::create_dir_all(models_dir)
                .context("create models directory")?;

            let options = InitOptions::new(EmbeddingModel::BGESmallENV15)
                .with_cache_dir(models_dir.to_path_buf())
                .with_show_download_message(true);

            let model = TextEmbedding::try_new(options).context("init fastembed BGE-small-en")?;

            Ok(EmbeddingBackend { model, index: Vec::new() })
        }

        fn embed_texts(&self, texts: &[String]) -> anyhow::Result<Vec<Vec<f32>>> {
            self.model
                .embed(texts.to_vec(), None)
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
                    eprintln!("[INTENT] WARN: failed to build embedding index: {}", e);
                }
            }
        }

        fn match_prompt(&self, prompt: &str, k: usize) -> Vec<(String, f32)> {
            if self.index.is_empty() {
                return Vec::new();
            }

            // Truncate prompt before embedding
            let prompt = if prompt.len() > 2000 { &prompt[..2000] } else { prompt };

            let query_embeddings = match self.embed_texts(&[prompt.to_owned()]) {
                Ok(e) => e,
                Err(_) => return Vec::new(),
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
) -> Option<Box<dyn IntentBackend>> {
    None
}

/// Attempt to create an `EmbeddingBackend`. Returns `None` if initialization fails
/// (model download error, ONNX load failure, etc.) — caller should log a warning and
/// fall back to `RegexBackend`.
#[cfg(feature = "embed")]
pub fn try_new_embedding_backend(
    models_dir: &Path,
) -> Option<Box<dyn IntentBackend>> {
    match EmbeddingBackend::new(models_dir) {
        Ok(mut backend) => Some(Box::new(backend) as Box<dyn IntentBackend>),
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
