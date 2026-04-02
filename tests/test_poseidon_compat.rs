use zemtik::db::{fr_to_decimal, poseidon_of_string};

/// Verify that poseidon_of_string normalizes input (trim + lowercase)
/// before hashing. "AWS_Spend" must produce the same hash as "aws_spend".
#[test]
fn canonicalization_is_case_insensitive() {
    let h1 = fr_to_decimal(&poseidon_of_string("aws_spend").unwrap());
    let h2 = fr_to_decimal(&poseidon_of_string("AWS_Spend").unwrap());
    let h3 = fr_to_decimal(&poseidon_of_string("  AWS_SPEND  ").unwrap());
    assert_eq!(h1, h2, "lowercase and mixed-case must hash identically");
    assert_eq!(h1, h3, "leading/trailing whitespace must be trimmed");
}

/// Empty string must return an error (not a valid table key).
#[test]
fn empty_string_returns_error() {
    let result = poseidon_of_string("");
    assert!(result.is_err(), "expected Err for empty string, got Ok");
    let result_whitespace = poseidon_of_string("   ");
    assert!(
        result_whitespace.is_err(),
        "expected Err for whitespace-only string, got Ok"
    );
}

/// Non-ASCII bytes must return an error (table keys must be pure ASCII).
#[test]
fn non_ascii_input_returns_error() {
    let result = poseidon_of_string("résumé_data");
    assert!(
        result.is_err(),
        "expected Err for non-ASCII input, got Ok"
    );
}

/// Strings longer than 93 bytes must return an error (3 × 31-byte chunk limit).
#[test]
fn oversized_input_returns_error() {
    let long = "a".repeat(94);
    let result = poseidon_of_string(&long);
    assert!(result.is_err(), "expected Err for 94-byte input, got Ok");
}

/// Exactly 93 bytes must succeed (boundary condition).
#[test]
fn max_length_input_succeeds() {
    let exact = "a".repeat(93);
    let result = poseidon_of_string(&exact);
    assert!(result.is_ok(), "expected Ok for 93-byte input, got {:?}", result);
}

/// Hash must be non-zero for any non-empty input (no trivial collisions with 0).
#[test]
fn hash_is_nonzero_for_real_tables() {
    for name in &["aws_spend", "payroll", "travel"] {
        let decimal = fr_to_decimal(&poseidon_of_string(name).unwrap());
        assert_ne!(decimal, "0", "hash of '{}' must not be zero", name);
    }
}

/// Different table names must produce different hashes.
#[test]
fn different_tables_produce_different_hashes() {
    let h_aws = fr_to_decimal(&poseidon_of_string("aws_spend").unwrap());
    let h_pay = fr_to_decimal(&poseidon_of_string("payroll").unwrap());
    let h_trv = fr_to_decimal(&poseidon_of_string("travel").unwrap());
    assert_ne!(h_aws, h_pay, "aws_spend and payroll must hash differently");
    assert_ne!(h_aws, h_trv, "aws_spend and travel must hash differently");
    assert_ne!(h_pay, h_trv, "payroll and travel must hash differently");
}

/// Cross-language compatibility: Rust poseidon_of_string("aws_spend") matches
/// Noir bn254::hash_3([chunk0, 0, 0]) where chunk0 encodes "aws_spend" as a
/// 31-byte big-endian Field (bytes at LSB end, zero-padded on left).
///
/// Verified 2026-04-02:
///   nargo test test_poseidon_aws_spend --show-output (circuit/src/main.nr)
///   Output: bn254::hash_3(aws_spend) = 0x1ecc3bbe5523e327b8ecd4351ca6cb02c5fdca9b998ac9ffd4cb7004ce0e2c42
///   Decimal: 13930234593103417437301023604027864616458116991189568633666782149921267919938
#[test]
fn poseidon_matches_noir_aws_spend() {
    // Verified against Noir bn254::hash_3 output (2026-04-02).
    const EXPECTED: &str = "13930234593103417437301023604027864616458116991189568633666782149921267919938";
    let rust_decimal = fr_to_decimal(&poseidon_of_string("aws_spend").unwrap());
    assert_eq!(
        rust_decimal, EXPECTED,
        "poseidon-rs must match Noir bn254::hash_3 for cross-language compatibility"
    );
}
