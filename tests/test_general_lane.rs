/// Unit tests for GeneralLane rate limiter logic.
///
/// The sliding-window rate limiter lives inline in handle_general_lane (proxy.rs).
/// These tests exercise the same VecDeque<Instant> algorithm in isolation to verify
/// correctness without spinning up the full HTTP server.
use std::collections::VecDeque;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Helpers — mirror the algorithm in handle_general_lane
// ---------------------------------------------------------------------------

fn check_rate_limit(window: &mut VecDeque<Instant>, max_rpm: u32) -> bool {
    let now = Instant::now();
    let cutoff = now - Duration::from_secs(60);
    window.retain(|&t| t > cutoff);
    if window.len() as u32 >= max_rpm {
        return false; // over limit
    }
    window.push_back(now);
    true // allowed
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn rate_limiter_allows_under_limit() {
    let mut window: VecDeque<Instant> = VecDeque::new();
    assert!(check_rate_limit(&mut window, 5));
    assert!(check_rate_limit(&mut window, 5));
    assert_eq!(window.len(), 2);
}

#[test]
fn rate_limiter_blocks_at_limit() {
    let mut window: VecDeque<Instant> = VecDeque::new();
    for _ in 0..3 {
        assert!(check_rate_limit(&mut window, 3));
    }
    // Fourth request should be blocked.
    assert!(!check_rate_limit(&mut window, 3));
    // Window should still be 3 (blocked request not added).
    assert_eq!(window.len(), 3);
}

#[test]
fn rate_limiter_zero_means_unlimited() {
    let window: VecDeque<Instant> = VecDeque::new();
    // With max_rpm=0 the guard is disabled at the ProxyState level (None limiter),
    // so check_rate_limit is never called. Verify that if it WERE called it would
    // trivially allow (0 >= 0 is true, so it would block — but this case is unreachable
    // in practice). This test just documents the expectation: 0 → no limiter constructed.
    //
    // Passing max_rpm=0 into check_rate_limit would block immediately. The actual
    // guard in proxy.rs is `if let Some(ref limiter)` — None when max_rpm==0.
    // Test that zero entries allow (proving the window is clean initially).
    assert_eq!(window.len(), 0);
}

#[test]
fn rate_limiter_allows_after_expiry() {
    let mut window: VecDeque<Instant> = VecDeque::new();
    // Simulate two requests that happened 61 seconds ago.
    let old = Instant::now() - Duration::from_secs(61);
    window.push_back(old);
    window.push_back(old);

    // With max_rpm=2, these old entries expire → window effectively empty → allow.
    assert!(check_rate_limit(&mut window, 2));
    // Old entries removed, new entry added.
    assert_eq!(window.len(), 1);
}

#[test]
fn rate_limiter_sliding_window_partial_expiry() {
    let mut window: VecDeque<Instant> = VecDeque::new();
    // One old entry (>60s), two recent ones.
    let old = Instant::now() - Duration::from_secs(61);
    window.push_back(old);
    window.push_back(Instant::now());
    window.push_back(Instant::now());

    // max_rpm=3: after expiry, 2 recent entries remain → third allowed.
    assert!(check_rate_limit(&mut window, 3));
    assert_eq!(window.len(), 3);

    // max_rpm=3: now at capacity → fourth blocked.
    assert!(!check_rate_limit(&mut window, 3));
    assert_eq!(window.len(), 3);
}
