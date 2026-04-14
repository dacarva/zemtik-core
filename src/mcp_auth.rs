//! Bearer token authentication for Zemtik MCP HTTP endpoints.
//!
//! Accepts both:
//! - `Authorization: Bearer <key>` header (programmatic use)
//! - `?token=<key>` query parameter (browser-accessible)
//!
//! Uses constant_time_eq to prevent timing attacks.

use constant_time_eq::constant_time_eq;

/// Validate a request against the configured ZEMTIK_MCP_API_KEY.
///
/// Returns `true` if the key is valid, `false` otherwise.
/// Returns `false` (deny) when `expected_key` is None — callers must explicitly opt out of
/// auth if needed. The startup check in `run_mcp_serve` rejects a missing key before any
/// requests are served, so None reaching here is a programming error.
pub fn check_mcp_auth(
    auth_header: Option<&str>,
    token_param: Option<&str>,
    expected_key: Option<&str>,
) -> bool {
    let key = match expected_key {
        None => {
            eprintln!("[MCP] check_mcp_auth called with no key configured — denying");
            return false;
        }
        Some(k) => k,
    };

    // Try Authorization: Bearer <key>
    if let Some(header) = auth_header {
        if let Some(bearer) = header.strip_prefix("Bearer ") {
            if constant_time_eq(bearer.trim().as_bytes(), key.as_bytes()) {
                return true;
            }
        }
    }

    // Try ?token=<key> query param
    if let Some(token) = token_param {
        if constant_time_eq(token.trim().as_bytes(), key.as_bytes()) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_bearer_header() {
        assert!(check_mcp_auth(Some("Bearer mykey"), None, Some("mykey")));
    }

    #[test]
    fn valid_token_param() {
        assert!(check_mcp_auth(None, Some("mykey"), Some("mykey")));
    }

    #[test]
    fn invalid_key() {
        assert!(!check_mcp_auth(Some("Bearer wrong"), None, Some("mykey")));
    }

    #[test]
    fn no_key_configured_denies() {
        assert!(!check_mcp_auth(None, None, None));
    }
}
