//! Dynamic tool registration from mcp_tools.json.
//!
//! Missing file → OK (use builtin tools only).
//! Present + malformed JSON → hard startup error.

use std::path::Path;

use anyhow::Context;

use crate::types::McpToolDef;

/// Load tool definitions from `mcp_tools.json`.
/// Returns an empty Vec if the file doesn't exist.
/// Returns Err with a human-readable message if the file is present but invalid.
pub fn load_mcp_tools(path: &Path) -> anyhow::Result<Vec<McpToolDef>> {
    if !path.exists() {
        return Ok(vec![]);
    }

    let bytes = std::fs::read(path)
        .with_context(|| format!("read mcp_tools.json at {}", path.display()))?;

    let tools: Vec<McpToolDef> = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse mcp_tools.json at {}: must be a JSON array of tool objects", path.display()))?;

    // Validate each tool definition
    for tool in &tools {
        if tool.name.is_empty() {
            anyhow::bail!("mcp_tools.json: tool name must not be empty");
        }
        if !tool.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            anyhow::bail!(
                "mcp_tools.json: tool name '{}' must be ASCII alphanumeric + underscore only",
                tool.name
            );
        }
        if !tool.input_schema.is_object() {
            anyhow::bail!(
                "mcp_tools.json: tool '{}' input_schema must be a JSON object",
                tool.name
            );
        }
    }

    Ok(tools)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn missing_file_returns_empty() {
        let path = std::path::Path::new("/nonexistent/mcp_tools.json");
        let tools = load_mcp_tools(path).unwrap();
        assert!(tools.is_empty());
    }

    #[test]
    fn valid_tools_file() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, r#"[{{"name":"my_tool","description":"Does stuff","input_schema":{{"type":"object","properties":{{}}}}}}]"#).unwrap();
        let tools = load_mcp_tools(f.path()).unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "my_tool");
    }

    #[test]
    fn malformed_json_returns_error() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "not valid json").unwrap();
        let result = load_mcp_tools(f.path());
        assert!(result.is_err());
    }

    #[test]
    fn invalid_tool_name_returns_error() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, r#"[{{"name":"bad name!","description":"x","input_schema":{{"type":"object"}}}}]"#).unwrap();
        let result = load_mcp_tools(f.path());
        assert!(result.is_err());
    }
}
