/// Canonical SHA-256[:4hex] hashes for the 23 supported entity types.
///
/// Each entry is (entity_type_name, type_hash_4hex) where type_hash_4hex =
/// hex(SHA256(entity_type.as_bytes())[0..2]).  These values are generated
/// by `tests/test_entity_hashes.rs` and must match `sidecar/entity_hashes.py`
/// byte-for-byte.
pub const ENTITY_HASHES: &[(&str, &str)] = &[
    ("PERSON",        "e47f"),
    ("ORG",           "0e67"),
    ("LOCATION",      "ec4e"),
    ("CO_CEDULA",     "5b46"),
    ("CO_NIT",        "bba1"),
    ("CL_RUT",        "fe8c"),
    ("MX_CURP",       "87fb"),
    ("MX_RFC",        "95d9"),
    ("BR_CPF",        "d8f7"),
    ("BR_CNPJ",       "3834"),
    ("AR_DNI",        "f76d"),
    ("ES_NIF",        "fc3d"),
    ("PHONE_NUMBER",  "ca71"),
    ("EMAIL_ADDRESS", "a8d8"),
    ("IBAN_CODE",     "3f21"),
    ("DATE_TIME",     "322b"),
    ("MONEY",         "ed2f"),
    ("EC_RUC",        "20ab"),
    ("PE_RUC",        "124a"),
    ("BO_NIT",        "5121"),
    ("UY_CI",         "7f8a"),
    ("VE_CI",         "e41a"),
    ("PASSPORT",      "02bc"),
];

/// Look up the canonical 4-hex type hash for an entity type string.
/// Returns `None` for unknown types (caller should skip or warn).
pub fn type_hash(entity_type: &str) -> Option<&'static str> {
    ENTITY_HASHES
        .iter()
        .find(|(name, _)| *name == entity_type)
        .map(|(_, hash)| *hash)
}
