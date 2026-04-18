use zemtik::anonymizer::{
    deanonymize, make_token, regex_anonymize, count_dropped_tokens,
    Vault, VaultEntry, AuditMeta,
};
use zemtik::entity_hashes::type_hash;

// ─── make_token ─────────────────────────────────────────────────────────────

#[test]
fn make_token_format() {
    let tok = make_token("e47f", 1);
    assert_eq!(tok, "[[Z:e47f:1]]");
}

#[test]
fn make_token_counter_increments() {
    assert_eq!(make_token("e47f", 2), "[[Z:e47f:2]]");
    assert_eq!(make_token("e47f", 99), "[[Z:e47f:99]]");
}

// ─── canonical hash parity ───────────────────────────────────────────────────

#[test]
fn hash_canonical_person() {
    let h = type_hash("PERSON").expect("PERSON must be in hash table");
    // SHA256("PERSON")[:2] = e47f
    assert_eq!(h, "e47f", "PERSON hash must match canonical value");
}

#[test]
fn hash_canonical_co_cedula() {
    let h = type_hash("CO_CEDULA").expect("CO_CEDULA must be present");
    assert_eq!(h, "5b46");
}

#[test]
fn hash_unknown_type_returns_none() {
    assert!(type_hash("UNICORN").is_none());
}

// ─── deanonymize ─────────────────────────────────────────────────────────────

fn make_vault(entries: &[(&str, &str, &str)]) -> Vault {
    entries
        .iter()
        .map(|(tok, orig, etype)| VaultEntry {
            token: tok.to_string(),
            original: orig.to_string(),
            entity_type: etype.to_string(),
        })
        .collect()
}

#[test]
fn deanonymize_replaces_single_token() {
    let vault = make_vault(&[("[[Z:e47f:1]]", "Carlos García", "PERSON")]);
    let result = deanonymize("El contrato fue firmado por [[Z:e47f:1]].", &vault);
    assert_eq!(result, "El contrato fue firmado por Carlos García.");
}

#[test]
fn deanonymize_replaces_multiple_tokens() {
    let vault = make_vault(&[
        ("[[Z:e47f:1]]", "Carlos García", "PERSON"),
        ("[[Z:0e67:2]]", "ACME S.A.S.", "ORG"),
    ]);
    let text = "[[Z:e47f:1]] firmó con [[Z:0e67:2]].";
    let result = deanonymize(text, &vault);
    assert_eq!(result, "Carlos García firmó con ACME S.A.S..");
}

#[test]
fn deanonymize_same_entity_repeated() {
    let vault = make_vault(&[("[[Z:e47f:1]]", "María López", "PERSON")]);
    let text = "[[Z:e47f:1]] habló con [[Z:e47f:1]].";
    let result = deanonymize(text, &vault);
    assert_eq!(result, "María López habló con María López.");
}

#[test]
fn deanonymize_empty_vault_no_op() {
    let vault: Vault = vec![];
    let text = "texto sin tokens";
    assert_eq!(deanonymize(text, &vault), text);
}

#[test]
fn deanonymize_no_tokens_in_text() {
    let vault = make_vault(&[("[[Z:e47f:1]]", "Carlos", "PERSON")]);
    let text = "texto sin tokens";
    assert_eq!(deanonymize(text, &vault), text);
}

// ─── count_dropped_tokens ────────────────────────────────────────────────────

#[test]
fn count_dropped_tokens_none_dropped() {
    let vault = make_vault(&[("[[Z:e47f:1]]", "Carlos", "PERSON")]);
    let llm_response = "El texto menciona [[Z:e47f:1]] claramente.";
    assert_eq!(count_dropped_tokens(llm_response, &vault), 0);
}

#[test]
fn count_dropped_tokens_one_dropped() {
    let vault = make_vault(&[
        ("[[Z:e47f:1]]", "Carlos", "PERSON"),
        ("[[Z:0e67:2]]", "ACME", "ORG"),
    ]);
    // LLM response only contains token 1; token 2 was dropped
    let llm_response = "[[Z:e47f:1]] firmó el contrato.";
    assert_eq!(count_dropped_tokens(llm_response, &vault), 1);
}

// ─── regex_anonymize ─────────────────────────────────────────────────────────

#[test]
fn regex_anonymize_colombian_cedula() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "Cédula 79.123.456 registrada.";
    let result = regex_anonymize(text, &["CO_CEDULA"], &mut vault, &mut counter);
    assert!(!result.contains("79.123.456"), "cédula must be tokenized");
    assert!(result.contains("[[Z:"), "must contain token");
    assert_eq!(vault.len(), 1);
    assert_eq!(vault[0].entity_type, "CO_CEDULA");
}

#[test]
fn regex_anonymize_email() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "Contacto: usuario@empresa.com para más info.";
    let result = regex_anonymize(text, &["EMAIL_ADDRESS"], &mut vault, &mut counter);
    assert!(!result.contains("usuario@empresa.com"));
    assert_eq!(vault[0].entity_type, "EMAIL_ADDRESS");
}

#[test]
fn regex_anonymize_unknown_type_skipped() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "Cédula 79.123.456.";
    // Request PERSON only — CO_CEDULA should NOT match
    let result = regex_anonymize(text, &["PERSON"], &mut vault, &mut counter);
    assert_eq!(result, text, "text must be unchanged when type not requested");
    assert!(vault.is_empty());
}

#[test]
fn regex_anonymize_same_entity_same_token() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "email@test.com y email@test.com de nuevo";
    let result = regex_anonymize(text, &["EMAIL_ADDRESS"], &mut vault, &mut counter);
    // Both occurrences should be the same token
    let tok = &vault[0].token;
    let count = result.matches(tok.as_str()).count();
    assert_eq!(count, 2, "same entity must produce same token (counter not incremented twice)");
    assert_eq!(vault.len(), 1, "one vault entry for identical entity");
}

// ─── AuditMeta default ────────────────────────────────────────────────────────

#[test]
fn audit_meta_default_values() {
    let m = AuditMeta::default();
    assert_eq!(m.entities_found, 0);
    assert!(m.entity_types.is_empty());
    assert!(!m.sidecar_used);
    assert_eq!(m.sidecar_ms, 0);
}
