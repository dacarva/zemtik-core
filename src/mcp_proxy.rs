//! Zemtik MCP Attestation Proxy (v0.10.0).
//!
//! Two operating modes:
//! - STDIO (`zemtik mcp`): Claude Desktop spawns this as a subprocess.
//!   rmcp reads JSON-RPC from stdin, writes to stdout.
//! - SSE (`zemtik mcp-serve`): Streamable HTTP server on ZEMTIK_MCP_BIND_ADDR (default :4001).
//!   Also exposes GET /mcp/health, /mcp/audit, /mcp/summary.
//!
//! Both modes share the same FORK 1+2 pattern:
//!   FORK 1: Execute tool, return result immediately (zero latency change for user).
//!   FORK 2 (tokio::spawn): Sign (tool_name, input_hash, output_hash, ts) with BabyJubJub,
//!           append signed record to mcp_audit.db. 1-second timeout.
//!
//! Security:
//! - zemtik_read_file: denies any path under ~/.zemtik/ (key file protection). P0.
//! - zemtik_read_file: denies files > 10MB (OOM protection). Metadata check, no full read.
//! - zemtik_fetch: in SSE mode, blocks + audits requests to domains not in ZEMTIK_MCP_ALLOWED_FETCH_DOMAINS.
//!   In STDIO mode, logs bypass events but still executes (observability; local dev trust model).
//! - SSE mode: Bearer token auth on /mcp/audit, /mcp/summary via constant_time_eq.
//!   The /mcp tool endpoint itself has no HTTP-layer auth — bind to 127.0.0.1 (default) or
//!   place behind an authenticating reverse proxy for network-exposed deployments.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::{Json, Router};
use axum::routing::get;
use chrono::Utc;
use rmcp::{
    ServiceExt,
    RoleServer,
    handler::server::ServerHandler,
    model::{
        CallToolRequestParams, CallToolResult, Content, Implementation,
        ListToolsResult, PaginatedRequestParams, ProtocolVersion,
        ServerCapabilities, ServerInfo, Tool,
    },
    service::RequestContext,
    transport::stdio,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
        session::local::LocalSessionManager,
    },
};
use num_bigint::BigInt;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use std::sync::LazyLock;

/// BN254 scalar field order. SHA-256 outputs ~25% values outside this range; reduce mod r.
static BN254_FIELD_ORDER: LazyLock<BigInt> = LazyLock::new(|| {
    BigInt::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .expect("BN254 scalar field order")
});
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::keys::load_or_generate_key;
use crate::mcp_auth::check_mcp_auth;
use crate::types::{McpAuditRecord, McpMode};

// File size cap: 10MB
const FILE_SIZE_CAP: u64 = 10 * 1024 * 1024;
// Max preview chars
const PREVIEW_LEN: usize = 500;
// FORK 2 timeout
const FORK2_TIMEOUT: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------
// SSRF guard helpers (SEC-1)
// ---------------------------------------------------------------------------

pub fn is_private_or_loopback(addr: std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 0            // 0.0.0.0/8 — unspecified; routes to loopback on Linux
                || o[0] == 127   // 127.0.0.0/8 loopback
                || o[0] == 10    // 10.0.0.0/8 RFC 1918
                || (o[0] == 172 && (16..=31).contains(&o[1])) // 172.16.0.0/12 RFC 1918
                || (o[0] == 192 && o[1] == 168)               // 192.168.0.0/16 RFC 1918
                || (o[0] == 169 && o[1] == 254)               // 169.254.0.0/16 link-local / IMDS
                || (o[0] == 100 && (64..=127).contains(&o[1])) // 100.64.0.0/10 RFC 6598 CGNAT
                || o == [255, 255, 255, 255]                   // broadcast
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified() // :: — IPv6 unspecified address
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // RFC 4193 ULA: fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // RFC 4291 link-local: fe80::/10
                // IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) — unwrap and re-check as IPv4
                || v6.to_ipv4_mapped()
                    .is_some_and(|v4| is_private_or_loopback(std::net::IpAddr::V4(v4)))
        }
    }
}

/// Returns `Some(reason)` if the URL should be blocked to prevent SSRF.
/// Checks literal URL properties only (scheme, literal IP, known-bad hostname patterns).
/// DNS-based checks (rebinding prevention) are performed by `ssrf_dns_guard` (async).
pub fn ssrf_block_reason(url_str: &str) -> Option<String> {
    let url = match reqwest::Url::parse(url_str) {
        Ok(u) => u,
        Err(e) => return Some(format!("invalid URL: {e}")),
    };
    if url.scheme() != "https" {
        return Some(format!("scheme '{}' is not https", url.scheme()));
    }
    let host = url.host_str()?;
    // The url crate returns IPv6 hosts with brackets (e.g. "[::1]"); strip them
    // before parsing so IpAddr::from_str can handle them.
    let host_stripped = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = host_stripped.parse::<std::net::IpAddr>() {
        if is_private_or_loopback(ip) {
            return Some(format!("private/loopback IP blocked: {ip}"));
        }
    } else {
        let h = host.to_lowercase();
        if h == "localhost"
            || h.ends_with(".local")
            || h.ends_with(".internal")
            || h.ends_with(".localhost")
        {
            return Some(format!("private hostname blocked: {host}"));
        }
    }
    None
}

/// Resolves the host in `url_str` and checks every returned address against
/// `is_private_or_loopback`. Returns `(host, addrs)` on success so the caller
/// can pin those addresses into reqwest via `resolve_to_addrs`, preventing TOCTOU
/// (a second DNS lookup by reqwest cannot return a different, unvetted IP).
///
/// For literal-IP URLs no DNS query is issued; the IP is checked directly.
/// IPv4-mapped IPv6 addresses (e.g. `::ffff:127.0.0.1`) are unwrapped before checking.
pub async fn ssrf_dns_guard(
    url_str: &str,
) -> Result<(String, Vec<std::net::SocketAddr>), String> {
    use std::net::{IpAddr, SocketAddr};

    let url = reqwest::Url::parse(url_str).map_err(|e| format!("invalid URL: {e}"))?;
    let host = url.host_str().ok_or_else(|| "URL has no host".to_string())?;
    let port = url.port_or_known_default().unwrap_or(443);

    // url.host_str() wraps IPv6 literals in brackets (e.g. "[::1]"); strip them.
    let host_plain = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    let check_ip = |ip: IpAddr| -> Result<(), String> {
        // Unwrap IPv4-mapped IPv6 (::ffff:x.x.x.x) before the private-range check.
        let effective = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            other => other,
        };
        if is_private_or_loopback(effective) {
            Err(format!("private/loopback IP blocked: {effective}"))
        } else {
            Ok(())
        }
    };

    // Literal IP — no DNS needed.
    if let Ok(ip) = host_plain.parse::<IpAddr>() {
        check_ip(ip)?;
        return Ok((host_plain.to_string(), vec![SocketAddr::new(ip, port)]));
    }

    // Hostname — resolve and check every returned address.
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host_plain, port))
        .await
        .map_err(|e| format!("DNS resolution failed for {host_plain}: {e}"))?
        .collect();

    if addrs.is_empty() {
        return Err(format!("DNS resolved no addresses for {host_plain}"));
    }

    for addr in &addrs {
        check_ip(addr.ip())?;
    }

    Ok((host_plain.to_string(), addrs))
}

// ---------------------------------------------------------------------------
// Shared handler state
// ---------------------------------------------------------------------------

/// Shared state cloned into every handler instance.
#[derive(Clone)]
pub struct McpHandlerState {
    /// Raw 32-byte BabyJubJub key seed (for reconstruction in spawn_blocking).
    /// Wrapped in Zeroizing so the stack/heap copy is zeroed on drop.
    pub key_seed: Arc<Zeroizing<[u8; 32]>>,
    /// BabyJubJub public key hex (cached at startup for audit records).
    pub public_key_hex: String,
    /// MCP operating mode.
    pub mode: McpMode,
    /// Path to mcp_audit.db.
    pub audit_db_path: Arc<PathBuf>,
    /// HTTP client for zemtik_fetch.
    pub http_client: reqwest::Client,
    /// Fetch timeout.
    pub fetch_timeout: Duration,
    /// Allowed path prefixes (empty = allow-all in STDIO, deny-all in SSE).
    pub allowed_paths: Vec<String>,
    /// Allowed fetch domains (empty = allow-all in STDIO, deny-all in SSE).
    pub allowed_fetch_domains: Vec<String>,
    /// Whether running in STDIO (true) or SSE (false) mode.
    pub is_stdio: bool,
    /// ~/.zemtik/ directory — denied in zemtik_read_file.
    pub zemtik_home: PathBuf,
    /// Bearer API key for HTTP endpoints (SSE mode only).
    pub api_key: Option<String>,
    /// Pending FORK 2 JoinHandles (STDIO mode drain on shutdown).
    pub pending_fork2: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl McpHandlerState {
    /// Build from AppConfig. Loads/generates BabyJubJub key.
    pub fn from_config(config: &AppConfig, is_stdio: bool) -> anyhow::Result<Self> {
        let key = load_or_generate_key(&config.keys_dir)
            .map_err(|e| anyhow::anyhow!(
                "Zemtik MCP key load failed: {}\n\
                 Hint: ensure ~/.zemtik/keys/ is writable.",
                e
            ))?;

        // Derive public key hex from the BabyJubJub key
        let pub_key = key.public();
        let public_key_hex = format!("{}:{}", pub_key.x, pub_key.y);

        // Read seed bytes from the key file directly for use in spawn_blocking
        let key_path = config.keys_dir.join("bank_sk");
        let seed_bytes = std::fs::read(&key_path)
            .context("read key seed for MCP handler")?;
        anyhow::ensure!(seed_bytes.len() == 32, "key seed must be 32 bytes");
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&seed_bytes);

        // Canonicalize zemtik_home so that starts_with() works correctly on macOS
        // where /var/folders is a symlink to /private/var/folders. Without
        // canonicalization, path.canonicalize() returns the /private/... form but
        // zemtik_home stores the /var/... form, causing the P0 key-protection
        // check to silently pass (bypass).
        let raw_zemtik_home = config.keys_dir.parent()
            .unwrap_or(Path::new("/nonexistent"))
            .to_path_buf();
        let zemtik_home = raw_zemtik_home.canonicalize()
            .unwrap_or(raw_zemtik_home);

        let mode = if config.mcp_mode == "governed" {
            McpMode::Governed
        } else {
            McpMode::Tunnel
        };

        Ok(McpHandlerState {
            key_seed: Arc::new(seed),
            public_key_hex,
            mode,
            audit_db_path: Arc::new(config.mcp_audit_db_path.clone()),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(config.mcp_fetch_timeout_secs))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .context("build reqwest client")?,
            fetch_timeout: Duration::from_secs(config.mcp_fetch_timeout_secs),
            // Canonicalize allowed_paths at construction time so starts_with() comparisons
            // work correctly even when entries contain symlink components or relative paths.
            allowed_paths: config.mcp_allowed_paths.iter()
                .map(|p| {
                    let expanded = crate::config::expand_tilde(p);
                    expanded.canonicalize()
                        .map(|c| c.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| expanded.to_string_lossy().into_owned())
                })
                .collect(),
            allowed_fetch_domains: config.mcp_allowed_fetch_domains.clone(),
            is_stdio,
            zemtik_home,
            api_key: config.mcp_api_key.clone(),
            pending_fork2: Arc::new(std::sync::Mutex::new(Vec::new())),
        })
    }
}

// ---------------------------------------------------------------------------
// MCP Handler
// ---------------------------------------------------------------------------

/// Zemtik MCP server handler — implements ServerHandler via rmcp.
#[derive(Clone)]
pub struct ZemtikMcpHandler {
    state: Arc<McpHandlerState>,
}

impl ZemtikMcpHandler {
    pub fn new(state: Arc<McpHandlerState>) -> Self {
        Self { state }
    }
}

impl ServerHandler for ZemtikMcpHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .build(),
        )
        .with_protocol_version(ProtocolVersion::V_2024_11_05)
        .with_server_info(Implementation::from_build_env())
        .with_instructions(
            "Zemtik MCP Proxy: attests every tool call with BabyJubJub EdDSA. \
             Use zemtik_read_file to read files, zemtik_fetch to HTTP GET URLs.",
        )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::ErrorData> {
        let tools = builtin_tools();
        Ok(ListToolsResult {
            tools,
            next_cursor: None,
            meta: None,
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let tool_name: &str = &request.name;
        match tool_name {
            "zemtik_read_file" => self.handle_read_file(request).await,
            "zemtik_fetch" => self.handle_fetch(request).await,
            _ => Err(rmcp::ErrorData::new(
                rmcp::model::ErrorCode(-32601),
                format!("Unknown tool: {}", tool_name),
                None,
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Tool: zemtik_read_file
// ---------------------------------------------------------------------------

impl ZemtikMcpHandler {
    async fn handle_read_file(
        &self,
        request: CallToolRequestParams,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let start = Instant::now();

        // Extract path argument
        let path_str = request
            .arguments
            .as_ref()
            .and_then(|a| a.get("path"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| rmcp::ErrorData::new(
                rmcp::model::ErrorCode(-32602),
                "Missing required argument: path".to_string(),
                None,
            ))?
            .to_string();

        let state = Arc::clone(&self.state);
        let result = tokio::task::spawn_blocking(move || {
            read_file_blocking(&path_str, &state)
        })
        .await
        .map_err(|e| rmcp::ErrorData::new(
            rmcp::model::ErrorCode(-32603),
            format!("Internal error: {}", e),
            None,
        ))??;

        let duration_ms = start.elapsed().as_millis() as u64;

        // FORK 2: attest in background
        let result_json = serde_json::to_string(&result).unwrap_or_default();
        let tool_name = "zemtik_read_file".to_string();
        let input_json = serde_json::to_string(
            request.arguments.as_ref().unwrap_or(&serde_json::Map::new()),
        ).unwrap_or_default();

        self.attest_for_mode(tool_name, input_json, result_json.clone(), duration_ms).await?;

        Ok(CallToolResult::success(vec![Content::text(result_json)]))
    }

    async fn handle_fetch(
        &self,
        request: CallToolRequestParams,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let start = Instant::now();

        let url_str = request
            .arguments
            .as_ref()
            .and_then(|a| a.get("url"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| rmcp::ErrorData::new(
                rmcp::model::ErrorCode(-32602),
                "Missing required argument: url".to_string(),
                None,
            ))?
            .to_string();

        // Domain check.
        // In SSE mode: non-allowlisted domain → block + audit (deny-all semantics).
        // In STDIO mode: non-allowlisted domain → audit only, still execute
        //   (observability for local dev; operator controls the Claude Desktop env).
        let bypass = self.check_fetch_domain(&url_str);
        if bypass {
            eprintln!("[MCP] SSRF bypass event: url={} not in ZEMTIK_MCP_ALLOWED_FETCH_DOMAINS", url_str);
            let state = Arc::clone(&self.state);
            let url_clone = url_str.clone();
            let is_stdio = self.state.is_stdio;
            // Enqueue into pending_fork2 so STDIO shutdown drains it before exit.
            // Write is blocking SQLite — must run in spawn_blocking, not bare async.
            let handle = tokio::spawn(async move {
                let record = McpAuditRecord {
                    receipt_id: Uuid::new_v4().to_string(),
                    ts: Utc::now().to_rfc3339(),
                    tool_name: "zemtik_fetch_bypass".to_string(),
                    input_hash: sha256_hex(url_clone.as_bytes()),
                    output_hash: sha256_hex(b"bypass"),
                    preview_input: truncate(&url_clone, PREVIEW_LEN),
                    preview_output: "bypass_event".to_string(),
                    attestation_sig: String::new(),
                    public_key_hex: state.public_key_hex.clone(),
                    duration_ms: 0,
                    mode: if is_stdio { "bypass_stdio" } else { "bypass_blocked" }.to_string(),
                };
                let _ = tokio::time::timeout(
                    FORK2_TIMEOUT,
                    tokio::task::spawn_blocking(move || write_audit_record(&state.audit_db_path, &record)),
                ).await;
            });
            let mut handles = self.state.pending_fork2.lock().unwrap_or_else(|e| e.into_inner());
            handles.retain(|h| !h.is_finished());
            handles.push(handle);
            // In SSE mode, block the request entirely.
            if !self.state.is_stdio {
                return Err(rmcp::ErrorData::new(
                    rmcp::model::ErrorCode(-32002),
                    format!(
                        "fetch_domain_denied: {} is not in ZEMTIK_MCP_ALLOWED_FETCH_DOMAINS",
                        url_str
                    ),
                    None,
                ));
            }
        }

        // SSRF guard — two-stage:
        // Stage 1 (sync): reject bad schemes, literal private IPs, known-bad hostnames.
        if let Some(reason) = ssrf_block_reason(&url_str) {
            return Err(rmcp::ErrorData::new(
                rmcp::model::ErrorCode(-32002),
                format!("ssrf_blocked: {reason}"),
                None,
            ));
        }
        // Stage 2 (async): DNS-resolve the host, reject if any returned IP is private,
        // then pin the vetted addresses into the per-request client (TOCTOU prevention —
        // reqwest will use our pre-validated IPs instead of doing a second lookup).
        let (vetted_host, vetted_addrs) = match ssrf_dns_guard(&url_str).await {
            Ok(v) => v,
            Err(reason) => return Err(rmcp::ErrorData::new(
                rmcp::model::ErrorCode(-32002),
                format!("ssrf_blocked: {reason}"),
                None,
            )),
        };
        let client = reqwest::Client::builder()
            .timeout(self.state.fetch_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(&vetted_host, &vetted_addrs)
            .build()
            .unwrap_or_else(|_| self.state.http_client.clone());

        let fetch_result = tokio::time::timeout(
            self.state.fetch_timeout,
            client.get(&url_str).send(),
        )
        .await;

        let result = match fetch_result {
            Err(_timeout) => {
                return Ok(CallToolResult::error(vec![Content::text(
                    r#"{"error":"timeout","code":"fetch_timeout","message":"Request timed out"}"#,
                )]));
            }
            Ok(Err(e)) => {
                return Ok(CallToolResult::error(vec![Content::text(
                    serde_json::json!({"error":"fetch_failed","message":e.to_string()}).to_string(),
                )]));
            }
            Ok(Ok(resp)) => resp,
        };

        let status = result.status().as_u16();
        let body_bytes = match result.bytes().await {
            Ok(b) => b,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(
                    serde_json::json!({"error":"read_body_failed","message":e.to_string()}).to_string(),
                )]));
            }
        };

        let body_hash = sha256_hex(&body_bytes);
        let body_preview = truncate(&String::from_utf8_lossy(&body_bytes), PREVIEW_LEN);

        let result_val = serde_json::json!({
            "status": status,
            "body_hash": body_hash,
            "body_preview": body_preview,
        });

        let duration_ms = start.elapsed().as_millis() as u64;
        let result_json = result_val.to_string();
        let input_json = serde_json::to_string(
            request.arguments.as_ref().unwrap_or(&serde_json::Map::new()),
        ).unwrap_or_default();

        self.attest_for_mode("zemtik_fetch".to_string(), input_json, result_json.clone(), duration_ms).await?;

        Ok(CallToolResult::success(vec![Content::text(result_json)]))
    }

    /// Attest based on operating mode.
    /// Tunnel: fire-and-forget FORK 2 (zero latency added).
    /// Governed: await signing synchronously — return Err to caller if attestation fails.
    async fn attest_for_mode(
        &self,
        tool_name: String,
        input_json: String,
        output_json: String,
        duration_ms: u64,
    ) -> Result<(), rmcp::ErrorData> {
        match self.state.mode {
            McpMode::Tunnel => {
                self.fork2_attest(tool_name, input_json, output_json, duration_ms);
                Ok(())
            }
            McpMode::Governed => {
                let state = Arc::clone(&self.state);
                tokio::time::timeout(
                    FORK2_TIMEOUT,
                    tokio::task::spawn_blocking(move || {
                        sign_and_write(&state, tool_name, input_json, output_json, duration_ms)
                    }),
                )
                .await
                .map_err(|_| rmcp::ErrorData::new(
                    rmcp::model::ErrorCode(-32000),
                    "governed_attestation_timeout: signing did not complete within 1s".to_string(),
                    None,
                ))?
                .map_err(|e| rmcp::ErrorData::new(
                    rmcp::model::ErrorCode(-32000),
                    format!("governed_attestation_join_error: {}", e),
                    None,
                ))?
                .map_err(|e: anyhow::Error| rmcp::ErrorData::new(
                    rmcp::model::ErrorCode(-32000),
                    format!("governed_attestation_failed: {}", e),
                    None,
                ))
            }
        }
    }

    /// Spawn FORK 2: sign + write audit record with 1-second timeout.
    fn fork2_attest(
        &self,
        tool_name: String,
        input_json: String,
        output_json: String,
        duration_ms: u64,
    ) {
        let state = Arc::clone(&self.state);
        let handle = tokio::spawn(async move {
            let tool_name_for_log = tool_name.clone();
            let result = tokio::time::timeout(FORK2_TIMEOUT, async move {
                let state2 = Arc::clone(&state);

                tokio::task::spawn_blocking(move || {
                    sign_and_write(&state2, tool_name, input_json, output_json, duration_ms)
                })
                .await
                .map_err(|e| format!("spawn_blocking join: {}", e))?
                .map_err(|e: anyhow::Error| e.to_string())
            })
            .await;

            match result {
                Err(_timeout) => {
                    eprintln!("[MCP] FORK 2 timeout: tool={} (>1s)", tool_name_for_log);
                }
                Ok(Err(e)) => {
                    eprintln!("[MCP] FORK 2 error: tool={} err={}", tool_name_for_log, e);
                }
                Ok(Ok(_)) => {}
            }
        });
        let mut handles = self.state
            .pending_fork2
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Drain completed handles to prevent unbounded growth in SSE mode.
        handles.retain(|h| !h.is_finished());
        handles.push(handle);
    }

    /// Returns true if the domain is not in the allowlist (bypass event).
    /// Returns false if: allowlist is empty (allow-all in STDIO) OR domain is allowed.
    fn check_fetch_domain(&self, url: &str) -> bool {
        if self.state.allowed_fetch_domains.is_empty() {
            // Allow-all in STDIO mode, deny-all in SSE mode
            return !self.state.is_stdio;
        }
        let domain = extract_domain(url).unwrap_or_default();
        let allowed = self.state.allowed_fetch_domains.iter()
            .any(|d| domain == *d || domain.ends_with(&format!(".{}", d)));
        !allowed
    }
}

// ---------------------------------------------------------------------------
// Blocking helpers (run in spawn_blocking)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ReadFileResult {
    content_hash: String,
    preview: String,
    size_bytes: u64,
}

pub fn read_file_blocking(path_str: &str, state: &McpHandlerState) -> Result<ReadFileResult, rmcp::ErrorData> {
    let path = Path::new(path_str);

    // P0 security: deny access to ~/.zemtik/ (signing key protection)
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if canonical.starts_with(&state.zemtik_home) {
        return Err(rmcp::ErrorData::new(
            rmcp::model::ErrorCode(-32002),
            "file_access_denied: path is inside ~/.zemtik/ (key file protection)".to_string(),
            None,
        ));
    }

    // Path allowlist check.
    // Mirrors fetch domain logic: empty = allow-all in STDIO, deny-all in SSE.
    if state.allowed_paths.is_empty() {
        if !state.is_stdio {
            return Err(rmcp::ErrorData::new(
                rmcp::model::ErrorCode(-32002),
                "file_access_denied: ZEMTIK_MCP_ALLOWED_PATHS is required in SSE mode".to_string(),
                None,
            ));
        }
        // STDIO + empty allowlist → allow all (except the P0 key-protection above)
    } else {
        let path_str_norm = canonical.to_string_lossy();
        let allowed = state.allowed_paths.iter().any(|prefix| {
            path_str_norm.starts_with(prefix.as_str())
        });
        if !allowed {
            return Err(rmcp::ErrorData::new(
                rmcp::model::ErrorCode(-32002),
                "file_access_denied: path not in ZEMTIK_MCP_ALLOWED_PATHS".to_string(),
                None,
            ));
        }
    }

    // Metadata check and subsequent read use canonical — decision and access must be on the same file.
    let metadata = std::fs::metadata(&canonical).map_err(|e| rmcp::ErrorData::new(
        rmcp::model::ErrorCode(-32002),
        format!("file_not_found_or_permission_denied: {}", e),
        None,
    ))?;

    if metadata.len() > FILE_SIZE_CAP {
        return Err(rmcp::ErrorData::new(
            rmcp::model::ErrorCode(-32003),
            format!(
                "file_too_large: {} bytes exceeds 10MB cap",
                metadata.len()
            ),
            None,
        ));
    }

    // Bounded read: prevents TOCTOU — file may grow between metadata check and read.
    // We read at most FILE_SIZE_CAP+1 bytes; if we get more, the file grew past the cap.
    use std::io::Read as _;
    let file = std::fs::File::open(&canonical).map_err(|e| rmcp::ErrorData::new(
        rmcp::model::ErrorCode(-32002),
        format!("file_open_error: {}", e),
        None,
    ))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(FILE_SIZE_CAP + 1).read_to_end(&mut bytes).map_err(|e| rmcp::ErrorData::new(
        rmcp::model::ErrorCode(-32002),
        format!("file_read_error: {}", e),
        None,
    ))?;
    if bytes.len() as u64 > FILE_SIZE_CAP {
        return Err(rmcp::ErrorData::new(
            rmcp::model::ErrorCode(-32003),
            format!("file_too_large: read {} bytes exceeds 10MB cap", bytes.len()),
            None,
        ));
    }

    let content_hash = sha256_hex(&bytes);
    let preview = truncate(&String::from_utf8_lossy(&bytes), PREVIEW_LEN);

    Ok(ReadFileResult {
        content_hash,
        preview,
        size_bytes: bytes.len() as u64,
    })
}

/// Sign the tool call and write audit record to SQLite. Runs in spawn_blocking.
fn sign_and_write(
    state: &McpHandlerState,
    tool_name: String,
    input_json: String,
    output_json: String,
    duration_ms: u64,
) -> anyhow::Result<()> {
    let ts = Utc::now().to_rfc3339();
    let receipt_id = Uuid::new_v4().to_string();

    let input_hash = sha256_hex(input_json.as_bytes());
    let output_hash = sha256_hex(output_json.as_bytes());

    // Sign: message = tool_name + input_hash + output_hash + ts
    let message = format!("{}{}{}{}", tool_name, input_hash, output_hash, ts);
    let message_hash = sha256_bytes(message.as_bytes());

    // Move the seed bytes into import rather than cloning again — avoids a second unzeroized copy.
    // std::mem::take replaces the inner Vec with an empty one (which Zeroizing zeroes on drop).
    let mut seed: Zeroizing<Vec<u8>> = Zeroizing::new(state.key_seed.as_ref().to_vec());
    let key = babyjubjub_rs::PrivateKey::import(std::mem::take(&mut *seed))
        .map_err(|e| anyhow::anyhow!("import key: {}", e))?;

    let msg_raw = BigInt::from_bytes_le(num_bigint::Sign::Plus, &message_hash);
    let msg_bigint = msg_raw % &*BN254_FIELD_ORDER;

    let sig = key.sign(msg_bigint)
        .map_err(|e| anyhow::anyhow!("sign: {}", e))?;

    // sig_hex: r_b8.x and s as decimal strings joined with ":"
    let sig_hex = format!("{}:{}", sig.r_b8.x, sig.s);

    let record = McpAuditRecord {
        receipt_id,
        ts,
        tool_name,
        input_hash,
        output_hash,
        preview_input: truncate(&input_json, PREVIEW_LEN),
        preview_output: truncate(&output_json, PREVIEW_LEN),
        attestation_sig: sig_hex,
        public_key_hex: state.public_key_hex.clone(),
        duration_ms,
        mode: state.mode.as_str().to_string(),
    };

    write_audit_record(&state.audit_db_path, &record)
}

// ---------------------------------------------------------------------------
// SQLite audit DB
// ---------------------------------------------------------------------------

/// Open (or create) the MCP audit SQLite database.
pub fn open_mcp_audit_db(db_path: &Path) -> anyhow::Result<Connection> {
    if let Some(dir) = db_path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create dir {}", dir.display()))?;
    }
    let conn = Connection::open(db_path)
        .with_context(|| format!("open mcp_audit.db at {}", db_path.display()))?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
        .context("set WAL mode on mcp_audit.db")?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS mcp_audit (
            receipt_id      TEXT PRIMARY KEY,
            ts              TEXT NOT NULL,
            tool_name       TEXT NOT NULL,
            input_hash      TEXT NOT NULL,
            output_hash     TEXT NOT NULL,
            preview_input   TEXT,
            preview_output  TEXT,
            attestation_sig TEXT NOT NULL,
            public_key_hex  TEXT NOT NULL,
            duration_ms     INTEGER NOT NULL,
            mode            TEXT NOT NULL
        );",
    )
    .context("create mcp_audit table")?;
    Ok(conn)
}

/// Insert a single audit record. Opens + closes the connection each time (safe for concurrent use).
pub fn write_audit_record(db_path: &Path, record: &McpAuditRecord) -> anyhow::Result<()> {
    let conn = open_mcp_audit_db(db_path)?;
    conn.execute(
        "INSERT OR IGNORE INTO mcp_audit \
         (receipt_id, ts, tool_name, input_hash, output_hash, \
          preview_input, preview_output, attestation_sig, public_key_hex, \
          duration_ms, mode) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        rusqlite::params![
            record.receipt_id,
            record.ts,
            record.tool_name,
            record.input_hash,
            record.output_hash,
            record.preview_input,
            record.preview_output,
            record.attestation_sig,
            record.public_key_hex,
            record.duration_ms as i64,
            record.mode,
        ],
    )
    .context("insert mcp_audit record")?;
    Ok(())
}

/// List recent MCP audit records (newest first).
pub fn list_mcp_audit_records(db_path: &Path, limit: usize) -> anyhow::Result<Vec<McpAuditRecord>> {
    let conn = open_mcp_audit_db(db_path)?;
    let mut stmt = conn.prepare(
        "SELECT receipt_id, ts, tool_name, input_hash, output_hash, \
                preview_input, preview_output, attestation_sig, public_key_hex, \
                duration_ms, mode \
         FROM mcp_audit ORDER BY ts DESC LIMIT ?1",
    )?;
    let records = stmt
        .query_map(rusqlite::params![limit as i64], |row| {
            let duration_raw: i64 = row.get(9)?;
            let duration_ms = u64::try_from(duration_raw).unwrap_or_else(|_| {
                eprintln!("[MCP] audit DB: negative duration_ms {} clamped to 0", duration_raw);
                0
            });
            Ok(McpAuditRecord {
                receipt_id: row.get(0)?,
                ts: row.get(1)?,
                tool_name: row.get(2)?,
                input_hash: row.get(3)?,
                output_hash: row.get(4)?,
                preview_input: row.get::<_, Option<String>>(5)?.unwrap_or_default(),
                preview_output: row.get::<_, Option<String>>(6)?.unwrap_or_default(),
                attestation_sig: row.get(7)?,
                public_key_hex: row.get(8)?,
                duration_ms,
                mode: row.get(10)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(records)
}

// ---------------------------------------------------------------------------
// Dry-run validation
// ---------------------------------------------------------------------------

/// Validate key + create synthetic audit record. Exit 0 on success, 1 on failure.
pub fn run_dry_run(config: &AppConfig) -> anyhow::Result<()> {
    let key_path = config.keys_dir.join("bank_sk");
    if !key_path.exists() {
        println!("[MCP DRY-RUN] No key found at {} — will be generated on first real run.", key_path.display());
    }

    let state = McpHandlerState::from_config(config, true)?;

    let ts = Utc::now().to_rfc3339();
    let record = McpAuditRecord {
        receipt_id: Uuid::new_v4().to_string(),
        ts: ts.clone(),
        tool_name: "zemtik_dry_run".to_string(),
        input_hash: sha256_hex(b"dry_run_input"),
        output_hash: sha256_hex(b"dry_run_output"),
        preview_input: "dry_run_input".to_string(),
        preview_output: "dry_run_output".to_string(),
        attestation_sig: "dry_run_sig".to_string(),
        public_key_hex: state.public_key_hex.clone(),
        duration_ms: 0,
        mode: "dry_run".to_string(),
    };

    write_audit_record(&config.mcp_audit_db_path, &record)?;

    let pk = &state.public_key_hex;
    let pk_start = if pk.len() >= 8 { &pk[..8] } else { pk };
    let pk_end = if pk.len() >= 8 { &pk[pk.len().saturating_sub(8)..] } else { pk };

    println!("[MCP DRY-RUN] OK");
    println!("  Key:      {}", config.keys_dir.join("bank_sk").display());
    println!("  Pubkey:   {}...{}", pk_start, pk_end);
    println!("  Audit DB: {}", config.mcp_audit_db_path.display());
    println!("  Mode:     {}", config.mcp_mode);
    println!("\nClaude Desktop config:");
    println!(r#"  {{"mcpServers": {{"zemtik": {{"command": "zemtik", "args": ["mcp"]}}}}}}"#);

    Ok(())
}

// ---------------------------------------------------------------------------
// STDIO entry point
// ---------------------------------------------------------------------------

/// Run the MCP server in STDIO mode (Claude Desktop subprocess).
pub async fn run_mcp_stdio(config: AppConfig) -> anyhow::Result<()> {
    let state = Arc::new(McpHandlerState::from_config(&config, true)?);
    eprintln!("[MCP] Starting STDIO server (mode: {})", config.mcp_mode);
    eprintln!("[MCP] Audit DB: {}", config.mcp_audit_db_path.display());
    let pk = &state.public_key_hex;
    let pk_start = if pk.len() >= 16 { &pk[..16] } else { pk };
    eprintln!("[MCP] Public key: {}...", pk_start);

    let state_for_drain = Arc::clone(&state);
    let handler = ZemtikMcpHandler::new(state);
    let service = handler.serve(stdio()).await.inspect_err(|e| {
        eprintln!("[MCP] STDIO serve error: {:?}", e);
    })?;

    service.waiting().await?;

    // Drain pending FORK 2 handles so audit records are flushed before the
    // runtime exits (STDIO process shutdown race).
    let handles: Vec<_> = state_for_drain
        .pending_fork2
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .drain(..)
        .collect();
    for h in handles {
        let _ = tokio::time::timeout(FORK2_TIMEOUT, h).await;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// SSE (HTTP) entry point
// ---------------------------------------------------------------------------

/// Run the MCP server in SSE/HTTP mode on ZEMTIK_MCP_BIND_ADDR.
pub async fn run_mcp_serve(config: AppConfig) -> anyhow::Result<()> {
    // Hard startup error: ZEMTIK_MCP_API_KEY required in SSE mode (blank counts as absent)
    if config.mcp_api_key.as_ref().is_none_or(|k| k.trim().is_empty()) {
        anyhow::bail!(
            "ZEMTIK_MCP_API_KEY is required in mcp-serve mode. \
             Generate a key: openssl rand -hex 32"
        );
    }

    let state = Arc::new(McpHandlerState::from_config(&config, false)?);

    eprintln!("[MCP] Starting HTTP server on {} (mode: {})", config.mcp_bind_addr, config.mcp_mode);
    eprintln!("[MCP] Audit DB: {}", config.mcp_audit_db_path.display());
    eprintln!("[MCP] /mcp/audit and /mcp/summary require Bearer token.");

    // Warn when binding to a non-localhost address. The /mcp tool endpoint (zemtik_read_file,
    // zemtik_fetch) does not require authentication at the HTTP layer — only the audit/summary
    // endpoints do. Exposing this on a non-loopback interface means any network client can call
    // tools without credentials. Use a reverse proxy with auth if you need network exposure.
    let is_localhost = config.mcp_bind_addr.starts_with("127.0.0.1:")
        || config.mcp_bind_addr.starts_with("localhost:")
        || config.mcp_bind_addr.starts_with("[::1]:");
    if !is_localhost {
        eprintln!(
            "[MCP] WARNING: binding to {} — /mcp tool endpoints (zemtik_read_file, \
             zemtik_fetch) have no HTTP-layer auth. Add a reverse proxy with auth if \
             this address is reachable from untrusted networks.",
            config.mcp_bind_addr
        );
    }

    let state_clone = Arc::clone(&state);
    let ct = CancellationToken::new();

    let mcp_service = StreamableHttpService::new(
        move || Ok(ZemtikMcpHandler::new(Arc::clone(&state_clone))),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default().with_cancellation_token(ct.child_token()),
    );

    let router = Router::new()
        .route("/mcp/health", get(health_handler))
        .route("/mcp/audit", get(audit_handler))
        .route("/mcp/summary", get(summary_handler))
        .nest_service("/mcp", mcp_service)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.mcp_bind_addr)
        .await
        .with_context(|| format!("bind to {}", config.mcp_bind_addr))?;

    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            ct.cancel();
        })
        .await
        .context("mcp serve")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP audit handlers (SSE mode only)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok", "service": "zemtik-mcp"}))
}

async fn audit_handler(
    State(state): State<Arc<McpHandlerState>>,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
) -> Response {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    if !check_mcp_auth(auth_header, q.token.as_deref(), state.api_key.as_deref()) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"unauthorized"}))).into_response();
    }

    let records = match list_mcp_audit_records(&state.audit_db_path, 1000) {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":e.to_string()}))).into_response();
        }
    };

    let accept = headers.get("accept").and_then(|v| v.to_str().ok()).unwrap_or("");
    if accept.contains("text/html") {
        let html = render_audit_html(&records);
        return Html(html).into_response();
    }

    Json(records).into_response()
}

async fn summary_handler(
    State(state): State<Arc<McpHandlerState>>,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
) -> Response {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    if !check_mcp_auth(auth_header, q.token.as_deref(), state.api_key.as_deref()) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"unauthorized"}))).into_response();
    }

    let records = match list_mcp_audit_records(&state.audit_db_path, 10000) {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":e.to_string()}))).into_response();
        }
    };

    let tool_calls_total = records.len();
    let mut tool_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for r in &records {
        *tool_counts.entry(r.tool_name.as_str()).or_insert(0) += 1;
    }

    let tools_used: Vec<serde_json::Value> = tool_counts.iter()
        .map(|(name, count)| serde_json::json!({"name": name, "count": count}))
        .collect();

    let (first, last) = records.iter()
        .fold((None::<&str>, None::<&str>), |(first, last), r| {
            let ts = r.ts.as_str();
            let new_first = first.map(|f: &str| if ts < f { ts } else { f }).or(Some(ts));
            let new_last = last.map(|l: &str| if ts > l { ts } else { l }).or(Some(ts));
            (new_first, new_last)
        });

    Json(serde_json::json!({
        "tool_calls_total": tool_calls_total,
        "tools_used": tools_used,
        "date_range": {
            "first": first,
            "last": last,
        },
        "last_call_ts": last,
        "mode": state.mode.as_str(),
    }))
    .into_response()
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn render_audit_html(records: &[McpAuditRecord]) -> String {
    let rows: String = records.iter().map(|r| {
        format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}ms</td><td>{}</td></tr>",
            escape_html(&r.ts),
            escape_html(&r.tool_name),
            escape_html(&r.input_hash),
            escape_html(&r.output_hash),
            r.duration_ms,
            escape_html(&r.mode),
        )
    }).collect();

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
<title>Zemtik MCP Audit Log</title>
<style>
body {{ font-family: monospace; padding: 2em; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 6px 12px; text-align: left; }}
th {{ background: #f0f0f0; }}
</style>
</head>
<body>
<h1>Zemtik MCP Audit Log</h1>
<p>{} tool call(s)</p>
<table>
<thead><tr><th>Timestamp</th><th>Tool</th><th>Input Hash</th><th>Output Hash</th><th>Duration</th><th>Mode</th></tr></thead>
<tbody>{}</tbody>
</table>
</body>
</html>"#,
        records.len(),
        rows
    )
}

// ---------------------------------------------------------------------------
// Built-in tool definitions
// ---------------------------------------------------------------------------

fn builtin_tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "zemtik_read_file",
            "Read a file and return its content hash + preview. Zemtik attests the read.",
            {
                let mut m = serde_json::Map::new();
                m.insert("type".to_string(), serde_json::json!("object"));
                m.insert("properties".to_string(), serde_json::json!({
                    "path": {
                        "type": "string",
                        "description": "Absolute path to file"
                    }
                }));
                m.insert("required".to_string(), serde_json::json!(["path"]));
                m
            },
        ),
        Tool::new(
            "zemtik_fetch",
            "HTTP GET a URL and return response hash + preview. Zemtik attests the fetch.",
            {
                let mut m = serde_json::Map::new();
                m.insert("type".to_string(), serde_json::json!("object"));
                m.insert("properties".to_string(), serde_json::json!({
                    "url": {
                        "type": "string",
                        "description": "URL to fetch"
                    }
                }));
                m.insert("required".to_string(), serde_json::json!(["url"]));
                m
            },
        ),
    ]
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

pub fn sha256_hex(data: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(data)))
}

fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        // Find the largest char boundary at or before max bytes to avoid panicking
        // on multi-byte UTF-8 sequences.
        let boundary = s.char_indices()
            .map(|(i, _)| i)
            .take_while(|&i| i < max)
            .last()
            .unwrap_or(0);
        s[..boundary].to_string()
    }
}

fn extract_domain(url: &str) -> Option<String> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    // Strip path, query, and fragment
    let authority = without_scheme.split('/').next()?;
    // Strip userinfo (user:pass@host) — rfind handles colons in passwords
    let host_port = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    // Strip port
    let host = host_port.split(':').next()?;
    Some(host.to_lowercase())
}
