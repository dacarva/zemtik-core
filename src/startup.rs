/// Startup validation: schema column checks, ZK tools detection, startup event log.
///
/// Called from two sites:
/// - `build_proxy_router` (once at server startup before accepting requests)
/// - `main.rs` ZEMTIK_VALIDATE_ONLY path (validate-then-exit, no server started)
///
/// All failures are WARNINGs — the proxy starts regardless. Pilot operators see the
/// validation block in startup logs and know exactly what to fix before the first query.
use std::sync::Arc;
use std::time::Duration;

use crate::config::{AppConfig, SchemaConfig, ZemtikMode};
use crate::types::{SchemaValidationResult, TableValidationResult, ZkToolsStatus};

/// Run all startup validations and return the combined result.
/// - SQLite backend → skip DB validation entirely (demo-only; always in-memory)
/// - ZEMTIK_SKIP_DB_VALIDATION=1 → skip all validation
/// - DATABASE_URL present → run Postgres column + row validation per table
/// - SUPABASE_URL only (no DATABASE_URL) → log warning, skip column validation
pub async fn run_startup_validation(
    config: &Arc<AppConfig>,
    schema: &SchemaConfig,
) -> SchemaValidationResult {
    // Check skip flag.
    let skip_db = std::env::var("ZEMTIK_SKIP_DB_VALIDATION")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);

    let backend = std::env::var("DB_BACKEND").unwrap_or_default();
    let is_supabase = backend.to_lowercase() == "supabase";

    // Check ZK tools presence.
    let nargo_ok = which("nargo");
    let bb_ok = which("bb");
    let zk_tools = ZkToolsStatus { nargo: nargo_ok, bb: bb_ok };

    // Warn when ZEMTIK_QUERY_REWRITER=1 in tunnel mode — rewriter is a no-op there.
    // Placed before the early return so the warning appears even when DB validation is skipped
    // (e.g., SQLite demo mode or ZEMTIK_SKIP_DB_VALIDATION=1).
    if config.query_rewriter_enabled && config.mode == ZemtikMode::Tunnel {
        eprintln!(
            "[REWRITER] ZEMTIK_QUERY_REWRITER=1 has no effect in tunnel mode.\n\
             \x20          Tunnel mode is passthrough — intent extraction does not run.\n\
             \x20          Remove ZEMTIK_QUERY_REWRITER from your tunnel deployment config."
        );
    }

    // Tunnel + Anthropic cross-provider warning. (Gemini+tunnel is rejected at startup in
    // build_proxy_router before run_startup_validation is ever called.)
    if config.mode == ZemtikMode::Tunnel && config.llm_provider == "anthropic" {
        eprintln!(
            "[WARN] Tunnel mode FORK 1 and FORK 2 both use ZEMTIK_OPENAI_BASE_URL regardless of\n\
             \x20     ZEMTIK_LLM_PROVIDER=anthropic. The tunnel is transparent passthrough — clients\n\
             \x20     must supply their own OpenAI key. Anthropic-native tunnel support deferred to v2."
        );
    }

    let llm_extra = vec![
        format!("llm_provider: {}", config.llm_provider),
        format!(
            "llm_model: {}",
            if config.llm_provider == "anthropic" {
                &config.anthropic_model
            } else if config.llm_provider == "gemini" {
                &config.gemini_model
            } else {
                &config.openai_model
            }
        ),
    ];

    if skip_db || !is_supabase {
        if skip_db {
            println!("[ZEMTIK] Schema validation skipped (ZEMTIK_SKIP_DB_VALIDATION=1)");
        } else {
            println!("[ZEMTIK] Schema validation skipped (SQLite backend — demo mode)");
        }
        print_llm_info(&llm_extra);
        return SchemaValidationResult {
            tables: vec![],
            zk_tools,
            skipped: true,
        };
    }

    // Warn about missing ZK tools only when validation is actually running (not in skip/SQLite modes).
    if !config.skip_circuit_validation && (!nargo_ok || !bb_ok) {
        let missing: Vec<&str> = [(!nargo_ok).then_some("nargo"), (!bb_ok).then_some("bb")]
            .into_iter()
            .flatten()
            .collect();
        eprintln!(
            "[PROXY] WARNING: ZK tools not installed: {}. \
             Tables with sensitivity=\"critical\" will return HTTP 500. \
             Set ZEMTIK_SKIP_CIRCUIT_VALIDATION=1 for FastLane-only mode, \
             or rebuild with INSTALL_ZK_TOOLS=true to enable ZK SlowLane.",
            missing.join(", ")
        );
    }

    // Validate example_prompts presence (warns when embedding backend falls back to regex).
    for (key, tc) in &schema.tables {
        if tc.example_prompts.is_empty() {
            eprintln!(
                "[PROXY] WARNING: table '{}': example_prompts missing — \
                 embedding backend will fall back to regex matching (lower intent accuracy).",
                key
            );
        }
    }

    // Check for DATABASE_URL.
    let database_url = std::env::var("DATABASE_URL").ok();
    if database_url.is_none() {
        eprintln!(
            "[PROXY] WARNING: column validation skipped — provide DATABASE_URL for Postgres \
             column and row validation. SUPABASE_URL alone (PostgREST) does not expose \
             information_schema."
        );
        // Still return a non-skipped result (ZK tools status is populated).
        let tables: Vec<TableValidationResult> = schema.tables.iter().map(|(key, tc)| TableValidationResult {
            table_key: key.clone(),
            physical_table: tc.resolved_table(key).to_owned(),
            status: "validation_skipped".to_owned(),
            row_count: None,
            warnings: vec!["DATABASE_URL not set — column validation unavailable".to_owned()],
        }).collect();
        print_validation_block(&tables, &zk_tools);
        print_llm_info(&llm_extra);
        return SchemaValidationResult { tables, zk_tools, skipped: false };
    }

    let database_url = database_url.unwrap();
    let mut table_results: Vec<TableValidationResult> = Vec::new();

    for (key, tc) in &schema.tables {
        let physical = tc.resolved_table(key).to_owned();
        let result = validate_table(&database_url, key, &physical, tc).await;
        table_results.push(result);
    }

    print_validation_block(&table_results, &zk_tools);
    print_llm_info(&llm_extra);
    write_startup_events(&table_results);

    SchemaValidationResult {
        tables: table_results,
        zk_tools,
        skipped: false,
    }
}

/// Validate a single table: existence + row count. Returns a TableValidationResult.
async fn validate_table(
    database_url: &str,
    table_key: &str,
    physical_table: &str,
    _tc: &crate::config::TableConfig,
) -> TableValidationResult {
    let mut warnings: Vec<String> = Vec::new();

    // Connect with 500ms timeout per table to avoid blocking startup on unreachable DB.
    let connect_result = tokio::time::timeout(
        Duration::from_millis(500),
        connect_postgres(database_url),
    ).await;

    let client = match connect_result {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            warnings.push(format!("DB connection failed: {}", e));
            return TableValidationResult {
                table_key: table_key.to_owned(),
                physical_table: physical_table.to_owned(),
                status: "connection_failed".to_owned(),
                row_count: None,
                warnings,
            };
        }
        Err(_) => {
            warnings.push("DB connection timed out (>500ms)".to_owned());
            return TableValidationResult {
                table_key: table_key.to_owned(),
                physical_table: physical_table.to_owned(),
                status: "connection_timeout".to_owned(),
                row_count: None,
                warnings,
            };
        }
    };

    // Defense-in-depth: re-validate the identifier before interpolating into SQL.
    // validate_schema_config() already checks this at config-load time, but an
    // extra guard here makes the construction site safe in isolation.
    if !crate::config::is_safe_identifier(physical_table) {
        return TableValidationResult {
            table_key: table_key.to_owned(),
            physical_table: physical_table.to_owned(),
            status: "invalid_identifier".to_owned(),
            row_count: None,
            warnings: vec![format!(
                "physical_table '{}' is not a safe SQL identifier — skipping query",
                physical_table
            )],
        };
    }

    // Check table existence + row count in one query.
    let query = format!(
        "SELECT COUNT(*) FROM {} LIMIT 1000001",
        physical_table
    );
    let row_result = tokio::time::timeout(
        Duration::from_millis(500),
        client.query_one(&query as &str, &[]),
    ).await;

    match row_result {
        Ok(Ok(row)) => {
            let count: i64 = row.get(0);
            if count == 0 {
                warnings.push(format!(
                    "table '{}' is empty — queries will return 0. \
                     If this is a single-tenant setup, verify data exists.",
                    physical_table
                ));
            }
            let status = if warnings.is_empty() { "ok" } else { "warning" };
            TableValidationResult {
                table_key: table_key.to_owned(),
                physical_table: physical_table.to_owned(),
                status: status.to_owned(),
                row_count: Some(count),
                warnings,
            }
        }
        Ok(Err(e)) => {
            let msg = e.to_string();
            if msg.contains("does not exist") || msg.contains("relation") {
                TableValidationResult {
                    table_key: table_key.to_owned(),
                    physical_table: physical_table.to_owned(),
                    status: "table_not_found".to_owned(),
                    row_count: None,
                    warnings: vec![format!("table '{}' not found in database", physical_table)],
                }
            } else {
                TableValidationResult {
                    table_key: table_key.to_owned(),
                    physical_table: physical_table.to_owned(),
                    status: "query_error".to_owned(),
                    row_count: None,
                    warnings: vec![format!("query error: {}", msg)],
                }
            }
        }
        Err(_) => {
            TableValidationResult {
                table_key: table_key.to_owned(),
                physical_table: physical_table.to_owned(),
                status: "query_timeout".to_owned(),
                row_count: None,
                warnings: vec!["row count query timed out (>500ms)".to_owned()],
            }
        }
    }
}

/// Connect to Postgres and return a client. Drives the connection in the background.
async fn connect_postgres(database_url: &str) -> anyhow::Result<tokio_postgres::Client> {
    use postgres_native_tls::MakeTlsConnector;
    let tls = MakeTlsConnector::new(
        native_tls::TlsConnector::new().map_err(|e| anyhow::anyhow!("TLS init: {}", e))?,
    );
    let (client, connection) = tokio_postgres::connect(database_url, tls)
        .await
        .map_err(|e| anyhow::anyhow!("connect: {}", e))?;
    tokio::spawn(async move { let _ = connection.await; });
    Ok(client)
}

/// Print the validation block as a single formatted chunk (not interleaved with other logs).
fn print_validation_block(tables: &[TableValidationResult], zk: &ZkToolsStatus) {
    let mut lines: Vec<String> = vec!["[ZEMTIK] Schema validation".to_owned()];
    for t in tables {
        let row_info = match t.row_count {
            Some(n) => format!("{} rows", n),
            None => "unknown rows".to_owned(),
        };
        let warn_info = if t.warnings.is_empty() {
            String::new()
        } else {
            format!(" — WARNING: {}", t.warnings.join("; "))
        };
        let status_icon = if t.status == "ok" { "OK" } else { &t.status };
        lines.push(format!(
            "  └ {}: {} — {}{}",
            t.table_key, row_info, status_icon, warn_info
        ));
    }
    let zk_line = format!(
        "  └ ZK tools: nargo={} bb={}",
        if zk.nargo { "✓" } else { "✗ (MISSING)" },
        if zk.bb { "✓" } else { "✗ (MISSING)" }
    );
    lines.push(zk_line);
    // Print as one block — println! is the only stdout we use here.
    println!("{}", lines.join("\n"));
}

/// Append a JSONL startup event for each validated table.
/// Silently skips on any error — startup events are best-effort.
fn write_startup_events(tables: &[TableValidationResult]) {
    let events_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join(".zemtik/startup_events.jsonl");

    let ts = chrono::Utc::now().to_rfc3339();
    let mut lines: Vec<String> = Vec::new();
    for t in tables {
        let entry = serde_json::json!({
            "ts": ts,
            "table": t.table_key,
            "physical_table": t.physical_table,
            "status": t.status,
            "row_count": t.row_count,
            "warnings": t.warnings,
        });
        if let Ok(s) = serde_json::to_string(&entry) {
            lines.push(s);
        }
    }
    if !lines.is_empty() {
        use std::io::Write;
        // Ensure parent directory exists before opening — ~/.zemtik/ may not yet
        // exist on first run or in a fresh Docker image.
        if let Some(parent) = events_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&events_path)
        {
            let _ = writeln!(f, "{}", lines.join("\n"));
        }
    }
}

/// Returns true if the binary is found on PATH.
/// Uses `--version` probe instead of `which` for portability (works on Windows too).
fn which(cmd: &str) -> bool {
    std::process::Command::new(cmd)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Print LLM backend info lines as a follow-on block after the validation table.
fn print_llm_info(lines: &[String]) {
    for line in lines {
        println!("  └ {}", line);
    }
}
