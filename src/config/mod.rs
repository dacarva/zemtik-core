use std::path::PathBuf;

pub mod schema;
pub(crate) mod env;

pub use schema::{AggFn, SchemaConfig, TableConfig, load_schema_config, validate_schema_config};
pub(crate) use schema::is_safe_identifier;
pub use env::{AppConfig, ZemtikMode, RewriterConfig, CliArgs, Command, load_from_sources};

/// Expand a leading `~` to the home directory so users can write `~/foo` in
/// config.yaml and env vars.  Paths that don't start with `~` are unchanged.
pub fn expand_tilde(s: &str) -> PathBuf {
    if let Some(rest) = s.strip_prefix("~/") {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        home.join(rest)
    } else if s == "~" {
        dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"))
    } else {
        PathBuf::from(s)
    }
}
