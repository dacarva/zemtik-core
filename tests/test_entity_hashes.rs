//! Verifies that the canonical entity-type hashes in src/entity_hashes.rs
//! match the live SHA-256 computation, ensuring the table was not hand-edited
//! incorrectly and matches sidecar/entity_hashes.py.

use sha2::{Digest, Sha256};
use zemtik::entity_hashes::ENTITY_HASHES;

#[test]
fn canonical_hashes_match_sha256() {
    for (name, expected_hex) in ENTITY_HASHES {
        let digest = Sha256::digest(name.as_bytes());
        let computed = hex::encode(&digest[..2]); // first 2 bytes = 4 hex chars
        assert_eq!(
            computed, *expected_hex,
            "Hash mismatch for entity type '{name}': table has '{expected_hex}', SHA256 gives '{computed}'"
        );
    }
}

#[test]
fn all_16_types_present() {
    let expected_types = [
        "PERSON", "ORG", "LOCATION",
        "CO_CEDULA", "CO_NIT", "CL_RUT",
        "MX_CURP", "MX_RFC",
        "BR_CPF", "BR_CNPJ",
        "AR_DNI", "ES_NIF",
        "PHONE_NUMBER", "EMAIL_ADDRESS", "IBAN_CODE", "DATE_TIME",
    ];
    let table_types: Vec<&str> = ENTITY_HASHES.iter().map(|(n, _)| *n).collect();
    for t in &expected_types {
        assert!(table_types.contains(t), "Missing entity type: {t}");
    }
    assert_eq!(ENTITY_HASHES.len(), 16, "Expected exactly 16 entity types");
}
