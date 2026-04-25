use zemtik::anonymizer::{
    deanonymize, make_token, regex_anonymize, count_dropped_tokens, count_tokens_injected,
    Vault, VaultEntry, AuditMeta, SYSTEM_PROMPT_INJECT,
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
fn regex_anonymize_colombian_cedula_10digit_dotted() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    // 10-digit cédula in dotted format (3 dot groups)
    let text = "Cédula 1.023.456.789 del titular.";
    let result = regex_anonymize(text, &["CO_CEDULA"], &mut vault, &mut counter);
    assert!(!result.contains("1.023.456.789"), "10-digit dotted cédula must be tokenized");
    assert!(result.contains("[[Z:"), "must contain token");
    assert_eq!(vault[0].entity_type, "CO_CEDULA");
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

// ─── regex_anonymize: additional LatAm entity types ─────────────────────────

#[test]
fn regex_anonymize_co_nit() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "NIT de la empresa: 900.123.456-7.";
    let result = regex_anonymize(text, &["CO_NIT"], &mut vault, &mut counter);
    assert!(!result.contains("900.123.456-7"), "NIT must be tokenized");
    assert_eq!(vault[0].entity_type, "CO_NIT");
}

#[test]
fn regex_anonymize_cl_rut() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "RUT del contribuyente: 12.345.678-9.";
    let result = regex_anonymize(text, &["CL_RUT"], &mut vault, &mut counter);
    assert!(!result.contains("12.345.678-9"), "RUT must be tokenized");
    assert_eq!(vault[0].entity_type, "CL_RUT");
}

#[test]
fn regex_anonymize_br_cpf() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "CPF do titular: 123.456.789-09.";
    let result = regex_anonymize(text, &["BR_CPF"], &mut vault, &mut counter);
    assert!(!result.contains("123.456.789-09"), "CPF must be tokenized");
    assert_eq!(vault[0].entity_type, "BR_CPF");
}

#[test]
fn regex_anonymize_br_cnpj() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "CNPJ: 12.345.678/0001-90.";
    let result = regex_anonymize(text, &["BR_CNPJ"], &mut vault, &mut counter);
    assert!(!result.contains("12.345.678/0001-90"), "CNPJ must be tokenized");
    assert_eq!(vault[0].entity_type, "BR_CNPJ");
}

#[test]
fn regex_anonymize_ar_dni() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "DNI del firmante: 12.345.678.";
    let result = regex_anonymize(text, &["AR_DNI"], &mut vault, &mut counter);
    assert!(!result.contains("12.345.678"), "DNI must be tokenized");
    assert_eq!(vault[0].entity_type, "AR_DNI");
}

#[test]
fn regex_anonymize_es_nif() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "NIF del representante: 12345678A.";
    let result = regex_anonymize(text, &["ES_NIF"], &mut vault, &mut counter);
    assert!(!result.contains("12345678A"), "NIF must be tokenized");
    assert_eq!(vault[0].entity_type, "ES_NIF");
}

#[test]
fn regex_anonymize_mx_curp() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "CURP: BADD110313HCMLNS09.";
    let result = regex_anonymize(text, &["MX_CURP"], &mut vault, &mut counter);
    assert!(!result.contains("BADD110313HCMLNS09"), "CURP must be tokenized");
    assert_eq!(vault[0].entity_type, "MX_CURP");
}

#[test]
fn regex_anonymize_mx_rfc() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "RFC del contribuyente: XAXX010101000.";
    let result = regex_anonymize(text, &["MX_RFC"], &mut vault, &mut counter);
    assert!(!result.contains("XAXX010101000"), "RFC must be tokenized");
    assert_eq!(vault[0].entity_type, "MX_RFC");
}

#[test]
fn regex_anonymize_phone_number() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "Llamar al +57 300 123 4567.";
    let result = regex_anonymize(text, &["PHONE_NUMBER"], &mut vault, &mut counter);
    assert!(!result.contains("+57 300 123 4567"), "phone must be tokenized");
    assert_eq!(vault[0].entity_type, "PHONE_NUMBER");
}

#[test]
fn regex_anonymize_iban_code() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "IBAN de la cuenta: CO1289354987654321098765.";
    let result = regex_anonymize(text, &["IBAN_CODE"], &mut vault, &mut counter);
    assert!(!result.contains("CO1289354987654321098765"), "IBAN must be tokenized");
    assert_eq!(vault[0].entity_type, "IBAN_CODE");
}

#[test]
fn regex_anonymize_date_time_is_sidecar_only() {
    // DATE_TIME is not in the Rust regex fallback — it's handled by Presidio in the sidecar.
    // Verify that requesting DATE_TIME via regex_anonymize is a no-op.
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "Firmado el 1 de marzo de 2024 en Bogotá.";
    let result = regex_anonymize(text, &["DATE_TIME"], &mut vault, &mut counter);
    assert_eq!(result, text, "DATE_TIME has no Rust regex — text must pass through unchanged");
    assert!(vault.is_empty());
}

// ─── regex_anonymize: already-tokenized skip guard ───────────────────────────

#[test]
fn regex_anonymize_already_tokenized_skip() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    // Pre-tokenized text must not be double-tokenized
    let pre = "[[Z:e47f:1]]";
    let result = regex_anonymize(pre, &["PERSON"], &mut vault, &mut counter);
    assert_eq!(result, pre, "already-tokenized text must pass through unchanged");
    assert_eq!(vault.len(), 0, "no vault entry for already-tokenized text");
}

// ─── count_dropped_tokens: all dropped ───────────────────────────────────────

#[test]
fn count_dropped_tokens_all_dropped() {
    let vault: Vault = vec![
        VaultEntry { token: "[[Z:e47f:1]]".to_string(), original: "Alice".to_string(), entity_type: "PERSON".to_string() },
        VaultEntry { token: "[[Z:e47f:2]]".to_string(), original: "Bob".to_string(), entity_type: "PERSON".to_string() },
    ];
    // LLM response contains neither token
    let dropped = count_dropped_tokens("The parties agreed to the terms.", &vault);
    assert_eq!(dropped, 2, "both tokens should be counted as dropped");
}

// ─── SYSTEM_PROMPT_INJECT constant ───────────────────────────────────────────

#[test]
fn system_prompt_inject_contains_token_format() {
    assert!(
        SYSTEM_PROMPT_INJECT.contains("[[Z:"),
        "SYSTEM_PROMPT_INJECT must reference the [[Z: token format"
    );
    assert!(
        SYSTEM_PROMPT_INJECT.contains("Preserve"),
        "SYSTEM_PROMPT_INJECT must instruct LLM to preserve tokens"
    );
    assert!(
        !SYSTEM_PROMPT_INJECT.is_empty(),
        "SYSTEM_PROMPT_INJECT must not be empty"
    );
}

// ─── regex_anonymize: pattern ordering — NIT/DNI before CO_CEDULA ────────────

#[test]
fn regex_anonymize_nit_not_tokenized_as_cedula() {
    // CO_NIT must run before CO_CEDULA. CO_CEDULA's dotted alternative
    // `\d{1,3}(?:\.\d{3}){2,3}` would match `900.123.456` from `900.123.456-7`
    // (the `-7` creates a word boundary after `456`). With CO_NIT first it
    // consumes the full token including the check digit.
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "NIT de la empresa: 900.123.456-7.";
    let result = regex_anonymize(text, &["CO_NIT", "CO_CEDULA"], &mut vault, &mut counter);
    assert_eq!(vault.len(), 1, "exactly one entity should be tokenized");
    assert_eq!(vault[0].entity_type, "CO_NIT", "900.123.456-7 must be CO_NIT not CO_CEDULA");
    assert!(result.contains("[[Z:"), "must contain token");
}

#[test]
fn regex_anonymize_ar_dni_not_tokenized_as_cedula() {
    // AR_DNI must run before CO_CEDULA. `12.345.678` matches both AR_DNI
    // (`\d{2}\.\d{3}\.\d{3}`) and CO_CEDULA's dotted alternative (2 dot groups).
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "DNI del firmante: 12.345.678 registrado.";
    let result = regex_anonymize(text, &["AR_DNI", "CO_CEDULA"], &mut vault, &mut counter);
    assert_eq!(vault.len(), 1, "exactly one entity should be tokenized");
    assert_eq!(vault[0].entity_type, "AR_DNI", "12.345.678 must be AR_DNI not CO_CEDULA");
    assert!(result.contains("[[Z:"), "must contain token");
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

// ─── count_tokens_injected ───────────────────────────────────────────────────

#[test]
fn count_tokens_injected_equals_vault_len() {
    let vault: Vault = vec![
        VaultEntry { token: "[[Z:e47f:1]]".to_string(), original: "Alice".to_string(), entity_type: "PERSON".to_string() },
        VaultEntry { token: "[[Z:ed2f:2]]".to_string(), original: "$2,500,000 COP".to_string(), entity_type: "MONEY".to_string() },
    ];
    assert_eq!(count_tokens_injected(&vault), 2);
}

#[test]
fn count_tokens_injected_empty_vault() {
    let vault: Vault = vec![];
    assert_eq!(count_tokens_injected(&vault), 0);
}

// ─── MONEY regex: comma-thousands + ISO prefix ───────────────────────────────

#[test]
fn regex_anonymize_money_comma_thousands() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "El precio de la transacción fue de $2,500,000,000 COP.";
    let result = regex_anonymize(text, &["MONEY"], &mut vault, &mut counter);
    assert_eq!(vault.len(), 1, "comma-thousands MONEY must be detected");
    assert_eq!(vault[0].entity_type, "MONEY");
    assert!(!result.contains("$2,500,000,000"), "amount must be tokenized");
}

#[test]
fn regex_anonymize_money_iso_prefix() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "Se pagaron COP 2.500.000 por los servicios.";
    let result = regex_anonymize(text, &["MONEY"], &mut vault, &mut counter);
    assert_eq!(vault.len(), 1, "ISO-prefix MONEY must be detected");
    assert_eq!(vault[0].entity_type, "MONEY");
    assert!(!result.contains("COP 2.500.000"), "amount must be tokenized");
}

#[test]
fn regex_anonymize_money_iso_prefix_no_match_embedded_word() {
    // "OPEN 100" must not be tokenized as MONEY via embedded "PEN 100" — \b prevents it.
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "OPEN 100 tickets for review.";
    regex_anonymize(text, &["MONEY"], &mut vault, &mut counter);
    assert_eq!(vault.len(), 0, "PEN embedded in OPEN must not be detected as MONEY");
}

#[test]
fn regex_anonymize_money_dot_thousands_unchanged() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "Monto: $120.000.000 USD.";
    regex_anonymize(text, &["MONEY"], &mut vault, &mut counter);
    assert_eq!(vault.len(), 1, "existing dot-thousands MONEY must still be detected");
    assert_eq!(vault[0].entity_type, "MONEY");
}

// ─── New LatAm national IDs ───────────────────────────────────────────────────

#[test]
fn regex_anonymize_ec_ruc_company() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "RUC de la empresa ecuatoriana: 1790012345001.";
    regex_anonymize(text, &["EC_RUC"], &mut vault, &mut counter);
    assert_eq!(vault.len(), 1, "EC_RUC company format must be detected");
    assert_eq!(vault[0].entity_type, "EC_RUC");
}

#[test]
fn regex_anonymize_pe_ruc() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "SUNAT RUC: 20123456789.";
    regex_anonymize(text, &["PE_RUC"], &mut vault, &mut counter);
    assert_eq!(vault.len(), 1, "PE_RUC must be detected");
    assert_eq!(vault[0].entity_type, "PE_RUC");
}

#[test]
fn regex_anonymize_ve_ci() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "Cédula venezolana V-12345678.";
    regex_anonymize(text, &["VE_CI"], &mut vault, &mut counter);
    assert_eq!(vault.len(), 1, "VE_CI must be detected");
    assert_eq!(vault[0].entity_type, "VE_CI");
}

#[test]
fn regex_anonymize_uy_ci_dash() {
    let mut vault: Vault = Vec::new();
    let mut counter = 0usize;
    let text = "CI uruguaya: 1234567-8.";
    regex_anonymize(text, &["UY_CI"], &mut vault, &mut counter);
    assert_eq!(vault.len(), 1, "UY_CI dash format must be detected");
    assert_eq!(vault[0].entity_type, "UY_CI");
}
