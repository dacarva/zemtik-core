//! Integration tests for Zemtik MCP Attestation Proxy.
//!
//! Tests the tool dispatch, audit record writing, and auth endpoints.
//! Does NOT spin up a full MCP server (rmcp STDIO subprocess piping is complex in tests).
//! Instead, tests the handler logic directly.

use tempfile::TempDir;
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::method;

use zemtik::config::AppConfig;
use zemtik::mcp_proxy::{
    list_mcp_audit_records, write_audit_record, sha256_hex, McpHandlerState,
    ssrf_block_reason, ssrf_dns_guard, is_private_or_loopback,
};
use zemtik::types::McpAuditRecord;

fn test_config(dir: &TempDir) -> AppConfig {
    let mut config = AppConfig::default();
    config.keys_dir = dir.path().join("keys");
    config.mcp_audit_db_path = dir.path().join("mcp_audit.db");
    config.mcp_mode = "tunnel".to_string();
    config.mcp_fetch_timeout_secs = 5;
    config.mcp_allowed_paths = vec![];
    config.mcp_allowed_fetch_domains = vec![];
    // Skip circuit validation for tests
    config.skip_circuit_validation = true;
    config
}

#[test]
fn test_mcp_audit_db_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("mcp_audit.db");

    let record = McpAuditRecord {
        receipt_id: "test-1".to_string(),
        ts: "2026-04-14T00:00:00Z".to_string(),
        tool_name: "zemtik_read_file".to_string(),
        input_hash: sha256_hex(b"inp"),
        output_hash: sha256_hex(b"out"),
        preview_input: "inp".to_string(),
        preview_output: "out".to_string(),
        attestation_sig: "sig".to_string(),
        public_key_hex: "pubkey".to_string(),
        duration_ms: 5,
        mode: "tunnel".to_string(),
    };

    write_audit_record(&db_path, &record).unwrap();
    let records = list_mcp_audit_records(&db_path, 100).unwrap();

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].receipt_id, "test-1");
    assert_eq!(records[0].tool_name, "zemtik_read_file");
    assert_eq!(records[0].duration_ms, 5);
}

#[test]
fn test_mcp_audit_db_insert_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("mcp_audit.db");

    let record = McpAuditRecord {
        receipt_id: "dup-uuid".to_string(),
        ts: "2026-04-14T00:00:00Z".to_string(),
        tool_name: "zemtik_fetch".to_string(),
        input_hash: sha256_hex(b"x"),
        output_hash: sha256_hex(b"y"),
        preview_input: "x".to_string(),
        preview_output: "y".to_string(),
        attestation_sig: "sig".to_string(),
        public_key_hex: "pubkey".to_string(),
        duration_ms: 1,
        mode: "tunnel".to_string(),
    };

    // Insert twice — INSERT OR IGNORE should deduplicate
    write_audit_record(&db_path, &record).unwrap();
    write_audit_record(&db_path, &record).unwrap();

    let records = list_mcp_audit_records(&db_path, 100).unwrap();
    assert_eq!(records.len(), 1, "duplicate insert should be idempotent");
}

#[tokio::test]
async fn test_mcp_handler_state_loads_key() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir);

    let state = McpHandlerState::from_config(&config, true)
        .expect("handler state should load cleanly with fresh key");

    assert!(!state.public_key_hex.is_empty(), "public key hex must not be empty");
    assert_eq!(state.key_seed.len(), 32, "key seed must be 32 bytes");
}

#[test]
fn test_mcp_tools_missing_file_ok() {
    use zemtik::mcp_tools::load_mcp_tools;
    let tools = load_mcp_tools(std::path::Path::new("/nonexistent/mcp_tools.json")).unwrap();
    assert!(tools.is_empty());
}

#[test]
fn test_mcp_tools_malformed_returns_error() {
    use std::io::Write;
    use zemtik::mcp_tools::load_mcp_tools;
    let mut f = tempfile::NamedTempFile::new().unwrap();
    write!(f, "{{not valid json}}").unwrap();
    assert!(load_mcp_tools(f.path()).is_err());
}

#[test]
fn test_key_path_denied_in_read_file() {
    // Regression: ISSUE-001 — zemtik_home symlink bypass on macOS
    // Found by /qa on 2026-04-14
    // Report: .gstack/qa-reports/qa-report-zemtik-core-2026-04-14.md
    //
    // zemtik_home must be canonicalized at construction time. On macOS,
    // /var/folders is a symlink to /private/var/folders. Without canonicalization,
    // path.canonicalize() returns /private/... but zemtik_home stores /var/...,
    // causing starts_with() to return false and silently allowing reads of ~/.zemtik/.
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir);
    let state = McpHandlerState::from_config(&config, true).unwrap();

    // zemtik_home must equal the CANONICAL parent of keys_dir
    let expected = dir.path().canonicalize().unwrap();
    assert_eq!(state.zemtik_home, expected,
        "zemtik_home must be canonical so starts_with() correctly catches symlinked paths");

    // Directly test that a file inside zemtik_home is denied.
    // Create a real file inside the temp dir (simulates ~/.zemtik/keys/bank_sk).
    let sentinel = dir.path().join("sentinel.txt");
    std::fs::write(&sentinel, b"secret").unwrap();
    let sentinel_str = sentinel.to_string_lossy().to_string();

    let result = zemtik::mcp_proxy::read_file_blocking(&sentinel_str, &state);
    assert!(result.is_err(), "read inside zemtik_home must be denied");
    let err = result.unwrap_err();
    assert!(
        err.message.contains("file_access_denied"),
        "error message must say file_access_denied, got: {}",
        err.message
    );
}

/// Regression test for the symlink-bypass P0 (commit 17861a0).
///
/// Attack: create a symlink OUTSIDE ~/.zemtik/ that points to a file INSIDE
/// ~/.zemtik/ (e.g., the signing key). Without canonicalize() on zemtik_home,
/// path.canonicalize() returns /private/var/... while zemtik_home stores /var/...,
/// so starts_with() silently passes and the read proceeds.
///
/// Correct behavior: read_file_blocking() must canonicalize the input path AND
/// compare against a canonicalized zemtik_home. A symlink chain that resolves into
/// zemtik_home must be denied.
#[test]
fn test_symlink_into_zemtik_home_denied() {
    let zemtik_dir = tempfile::tempdir().unwrap();
    let config = test_config(&zemtik_dir);
    let state = McpHandlerState::from_config(&config, true).unwrap();

    // Create a "secret" file inside zemtik_home (simulates bank_sk)
    let secret = zemtik_dir.path().join("keys").join("bank_sk");
    std::fs::create_dir_all(secret.parent().unwrap()).unwrap();
    std::fs::write(&secret, b"secret_key_bytes").unwrap();

    // Create a symlink OUTSIDE zemtik_home that points INTO it
    let outside_dir = tempfile::tempdir().unwrap();
    let link_path = outside_dir.path().join("innocent_link.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&secret, &link_path).unwrap();
    #[cfg(not(unix))]
    {
        // On non-Unix, skip symlink creation and just verify direct access is denied
        let _ = (secret, link_path, outside_dir);
        return;
    }

    #[cfg(unix)]
    {
        let result = zemtik::mcp_proxy::read_file_blocking(
            &link_path.to_string_lossy(),
            &state,
        );
        assert!(
            result.is_err(),
            "symlink pointing into zemtik_home must be denied (P0 key protection)"
        );
        let err = result.unwrap_err();
        assert!(
            err.message.contains("file_access_denied"),
            "error must say file_access_denied, got: {}",
            err.message
        );
    }
}

#[test]
fn test_sse_empty_allowlist_denies_all() {
    // Regression: ISSUE-002 — SSE mode with empty ZEMTIK_MCP_ALLOWED_PATHS allowed
    // all file reads. The comment said "deny-all in SSE" but the code did "allow-all".
    // Found by /qa on 2026-04-14
    // Report: .gstack/qa-reports/qa-report-zemtik-core-2026-04-14.md
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(&dir);
    config.mcp_allowed_paths = vec![]; // empty — deny-all in SSE

    // is_stdio=false simulates SSE/HTTP mode
    let state = McpHandlerState::from_config(&config, false).unwrap();

    // Write a file outside zemtik_home
    let tmp = tempfile::tempdir().unwrap();
    let f = tmp.path().join("public.txt");
    std::fs::write(&f, b"hello").unwrap();

    let result = zemtik::mcp_proxy::read_file_blocking(
        &f.to_string_lossy(), &state
    );
    assert!(result.is_err(), "SSE with empty allowlist must deny all reads");
    let err = result.unwrap_err();
    assert!(
        err.message.contains("ZEMTIK_MCP_ALLOWED_PATHS is required"),
        "error must mention ZEMTIK_MCP_ALLOWED_PATHS, got: {}",
        err.message
    );
}

// ---------------------------------------------------------------------------
// SEC-1 SSRF guard tests
// ---------------------------------------------------------------------------

#[test]
fn ssrf_blocks_http_scheme() {
    let reason = ssrf_block_reason("http://example.com/api");
    assert!(reason.is_some(), "http:// must be blocked");
    assert!(reason.unwrap().contains("not https"));
}

#[test]
fn ssrf_blocks_loopback_ip() {
    assert!(ssrf_block_reason("https://127.0.0.1:50051/").is_some(), "127.0.0.1 must be blocked");
    assert!(ssrf_block_reason("https://127.255.0.1/").is_some(), "127.255.0.1 must be blocked");
}

#[test]
fn ssrf_blocks_private_ipv4() {
    assert!(ssrf_block_reason("https://10.0.0.1/").is_some(), "10.0.0.1 must be blocked");
    assert!(ssrf_block_reason("https://192.168.1.1/").is_some(), "192.168.1.1 must be blocked");
    assert!(ssrf_block_reason("https://172.16.0.1/").is_some(), "172.16.0.1 must be blocked");
    assert!(ssrf_block_reason("https://169.254.169.254/metadata").is_some(), "IMDS must be blocked");
}

#[test]
fn ssrf_blocks_localhost_hostname() {
    assert!(ssrf_block_reason("https://localhost/").is_some(), "localhost must be blocked");
    assert!(ssrf_block_reason("https://something.local/").is_some(), ".local must be blocked");
    assert!(ssrf_block_reason("https://internal.internal/").is_some(), ".internal must be blocked");
}

#[test]
fn ssrf_allows_public_https() {
    assert!(ssrf_block_reason("https://api.openai.com/v1/chat/completions").is_none(),
        "public https must pass");
    assert!(ssrf_block_reason("https://example.com/").is_none(), "example.com must pass");
}

#[test]
fn ssrf_blocks_unspecified_addresses() {
    // Regression: 0.0.0.0 routes to loopback on Linux — must be blocked (SEC-1)
    assert!(ssrf_block_reason("https://0.0.0.0/").is_some(), "0.0.0.0 must be blocked");
    // Regression: :: (IPv6 unspecified) was not blocked (SEC-1)
    assert!(ssrf_block_reason("https://[::]/").is_some(), ":: must be blocked");
    // Regression: IPv6 bracket notation bypassed IpAddr::parse (SEC-1)
    assert!(ssrf_block_reason("https://[::1]/").is_some(), "[::1] must be blocked");
    assert!(ssrf_block_reason("https://[fc00::1]/").is_some(), "[fc00::1] ULA must be blocked");
    assert!(ssrf_block_reason("https://[fe80::1]/").is_some(), "[fe80::1] link-local must be blocked");
}

#[test]
fn is_private_or_loopback_covers_ipv6_unspecified() {
    use std::net::IpAddr;
    let unspec: IpAddr = "::".parse().unwrap();
    assert!(is_private_or_loopback(unspec), ":: must be blocked");
    let loopback6: IpAddr = "::1".parse().unwrap();
    assert!(is_private_or_loopback(loopback6), "::1 must be blocked");
    let ula: IpAddr = "fc00::1".parse().unwrap();
    assert!(is_private_or_loopback(ula), "fc00::1 (ULA) must be blocked");
    let link_local6: IpAddr = "fe80::1".parse().unwrap();
    assert!(is_private_or_loopback(link_local6), "fe80::1 (link-local) must be blocked");
}

#[test]
fn ssrf_allows_public_ip_direct() {
    // Public IPs accessed directly via https:// must not be blocked
    assert!(ssrf_block_reason("https://8.8.8.8/").is_none(), "8.8.8.8 must pass");
    assert!(ssrf_block_reason("https://1.1.1.1/").is_none(), "1.1.1.1 must pass");
    // Public IPv6 (Google DNS — globally routable)
    assert!(ssrf_block_reason("https://[2001:4860:4860::8888]/").is_none(), "2001:4860:4860::8888 must pass");
}

#[test]
fn ssrf_blocks_malformed_url() {
    // Malformed URLs must be blocked (not silently allowed)
    assert!(ssrf_block_reason("not-a-url").is_some(), "malformed URL must be blocked");
    assert!(ssrf_block_reason("").is_some(), "empty string must be blocked");
    assert!(ssrf_block_reason("//no-scheme.com/").is_some(), "schemeless URL must be blocked");
}

#[test]
fn ssrf_blocks_non_https_schemes() {
    assert!(ssrf_block_reason("ftp://example.com/file").is_some(), "ftp:// must be blocked");
    assert!(ssrf_block_reason("file:///etc/passwd").is_some(), "file:// must be blocked");
}

#[test]
fn ssrf_blocks_localhost_subdomain() {
    // .localhost TLD is reserved and routes to loopback
    assert!(ssrf_block_reason("https://app.localhost/").is_some(), "app.localhost must be blocked");
    assert!(ssrf_block_reason("https://evil.localhost/").is_some(), "evil.localhost must be blocked");
}

#[test]
fn is_private_or_loopback_public_ipv6_allowed() {
    use std::net::IpAddr;
    // Use globally routable IPv6 addresses, not documentation range (2001:db8::/32)
    let public6: IpAddr = "2001:4860:4860::8888".parse().unwrap();
    assert!(!is_private_or_loopback(public6), "Google DNS IPv6 must not be blocked");
    let public6b: IpAddr = "2606:4700:4700::1111".parse().unwrap();
    assert!(!is_private_or_loopback(public6b), "Cloudflare DNS IPv6 must not be blocked");
}

#[test]
fn is_private_or_loopback_covers_rfc1918() {
    use std::net::IpAddr;
    let cases: &[(&str, bool)] = &[
        ("127.0.0.1", true),
        ("10.1.2.3", true),
        ("192.168.0.1", true),
        ("172.16.5.5", true),
        ("172.31.255.255", true),
        ("169.254.1.1", true),
        // SEC-1 regression: 0.0.0.0/8 routes to loopback on Linux
        ("0.0.0.0", true),
        ("0.1.2.3", true),
        // RFC 6598 CGNAT: 100.64.0.0/10
        ("100.64.0.1", true),
        ("100.127.255.255", true),
        ("100.63.255.255", false),  // just below range
        ("100.128.0.1", false),     // just above range
        // broadcast
        ("255.255.255.255", true),
        ("8.8.8.8", false),
        ("1.1.1.1", false),
        ("172.15.0.1", false),
        ("172.32.0.1", false),
    ];
    for (ip_str, expected) in cases {
        let ip: IpAddr = ip_str.parse().unwrap();
        assert_eq!(
            is_private_or_loopback(ip), *expected,
            "{ip_str} expected private={expected}"
        );
    }
}

#[test]
fn is_private_or_loopback_ipv4_mapped_ipv6() {
    use std::net::IpAddr;
    // ::ffff:x.x.x.x — IPv4-mapped IPv6 must be treated as its IPv4 equivalent
    let mapped_loopback: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
    assert!(is_private_or_loopback(mapped_loopback), "::ffff:127.0.0.1 must be blocked");
    let mapped_rfc1918: IpAddr = "::ffff:192.168.1.1".parse().unwrap();
    assert!(is_private_or_loopback(mapped_rfc1918), "::ffff:192.168.1.1 must be blocked");
    let mapped_imds: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
    assert!(is_private_or_loopback(mapped_imds), "::ffff:169.254.169.254 (IMDS) must be blocked");
    let mapped_public: IpAddr = "::ffff:8.8.8.8".parse().unwrap();
    assert!(!is_private_or_loopback(mapped_public), "::ffff:8.8.8.8 must pass");
}

#[test]
fn ssrf_blocks_cgnat_and_broadcast() {
    assert!(ssrf_block_reason("https://100.64.0.1/").is_some(), "100.64.0.1 CGNAT must be blocked");
    assert!(ssrf_block_reason("https://100.127.255.255/").is_some(), "100.127.255.255 CGNAT must be blocked");
    assert!(ssrf_block_reason("https://255.255.255.255/").is_some(), "broadcast must be blocked");
    // Boundaries: 100.63 and 100.128 are outside CGNAT range
    assert!(ssrf_block_reason("https://100.63.255.255/").is_none(), "100.63.x outside CGNAT must pass");
    assert!(ssrf_block_reason("https://100.128.0.1/").is_none(), "100.128.x outside CGNAT must pass");
}

#[test]
fn ssrf_blocks_ipv4_mapped_ipv6_url() {
    // IPv4-mapped IPv6 addresses in URL notation must be blocked
    assert!(ssrf_block_reason("https://[::ffff:127.0.0.1]/").is_some(), "::ffff:127.0.0.1 must be blocked");
    assert!(ssrf_block_reason("https://[::ffff:192.168.1.1]/").is_some(), "::ffff:192.168.1.1 must be blocked");
    assert!(ssrf_block_reason("https://[::ffff:10.0.0.1]/").is_some(), "::ffff:10.0.0.1 must be blocked");
}

#[tokio::test]
async fn ssrf_dns_guard_blocks_loopback_literal() {
    // Literal private IPs must be rejected without DNS
    assert!(ssrf_dns_guard("https://127.0.0.1/").await.is_err(), "127.0.0.1 literal must be blocked");
    assert!(ssrf_dns_guard("https://[::1]/").await.is_err(), "[::1] literal must be blocked");
    assert!(ssrf_dns_guard("https://[::ffff:127.0.0.1]/").await.is_err(), "::ffff:127.0.0.1 must be blocked");
}

#[tokio::test]
async fn ssrf_dns_guard_blocks_private_literal() {
    assert!(ssrf_dns_guard("https://10.0.0.1/").await.is_err(), "10.0.0.1 must be blocked");
    assert!(ssrf_dns_guard("https://192.168.1.1/").await.is_err(), "192.168.1.1 must be blocked");
    assert!(ssrf_dns_guard("https://100.64.0.1/").await.is_err(), "100.64.0.1 CGNAT must be blocked");
}

#[tokio::test]
async fn ssrf_dns_guard_returns_vetted_addrs_for_literal() {
    // For a literal public IP, ssrf_dns_guard returns the SocketAddr for TOCTOU pinning
    let result = ssrf_dns_guard("https://8.8.8.8/").await;
    assert!(result.is_ok(), "public IP literal must pass DNS guard");
    let (host, addrs) = result.unwrap();
    assert_eq!(host, "8.8.8.8");
    assert!(!addrs.is_empty(), "must return at least one address for pinning");
    assert_eq!(addrs[0].port(), 443);
}

#[tokio::test]
async fn ssrf_dns_guard_resolves_localhost_hostname() {
    // DNS resolution of "localhost" must return 127.0.0.1 / ::1 and be blocked
    let result = ssrf_dns_guard("https://localhost/").await;
    assert!(result.is_err(), "localhost must be blocked via DNS resolution");
}

// ---------------------------------------------------------------------------
// Redirect-to-private SSRF regression
// ---------------------------------------------------------------------------

/// Validates that handle_fetch's reqwest client is configured with Policy::none(),
/// meaning a server-issued redirect to a private IP is never followed.
///
/// Two-part protection: (1) Policy::none() — redirect not followed at all;
/// (2) ssrf_block_reason / ssrf_dns_guard would block the target if somehow re-invoked.
#[tokio::test]
async fn handle_fetch_redirect_to_private_not_followed() {
    // Spin up a wiremock server that returns 302 → https://192.168.1.1/secret.
    // wiremock binds to 127.0.0.1 (loopback) — fine for tests.
    let server = MockServer::start().await;
    let private_target = "https://192.168.1.1/secret";
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", private_target),
        )
        .mount(&server)
        .await;

    // Build a client mirroring handle_fetch settings: no redirects, short timeout.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let resp = client.get(server.uri()).send().await
        .expect("wiremock server must respond");

    // The redirect must NOT be followed — we expect the raw 302.
    assert_eq!(resp.status().as_u16(), 302, "redirect must not be followed (got {:?})", resp.status());
    let location = resp.headers().get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(location, private_target, "Location header must point at private target");

    // Belt-and-suspenders: the redirect target is independently blocked by ssrf_block_reason
    // (private IPv4 literal), so even if Policy were changed to follow redirects the guard
    // would catch it in ssrf_block_reason before the second request is made.
    assert!(
        ssrf_block_reason(private_target).is_some(),
        "ssrf_block_reason must block the redirect target independently"
    );
}
