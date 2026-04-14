//! Tests for mcp_tools.rs — dynamic tool registration from mcp_tools.json.

use std::io::Write;
use tempfile::NamedTempFile;
use zemtik::mcp_tools::load_mcp_tools;

#[test]
fn missing_file_returns_empty() {
    let path = std::path::Path::new("/nonexistent/mcp_tools.json");
    let tools = load_mcp_tools(path).unwrap();
    assert!(tools.is_empty());
}

#[test]
fn valid_tools_file() {
    let mut f = NamedTempFile::new().unwrap();
    write!(
        f,
        r#"[{{"name":"my_tool","description":"Does stuff","input_schema":{{"type":"object","properties":{{}}}}}}]"#
    )
    .unwrap();
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
    write!(
        f,
        r#"[{{"name":"bad name!","description":"x","input_schema":{{"type":"object"}}}}]"#
    )
    .unwrap();
    let result = load_mcp_tools(f.path());
    assert!(result.is_err());
}
