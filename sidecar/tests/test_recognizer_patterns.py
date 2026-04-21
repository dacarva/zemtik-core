"""Unit tests for custom PatternRecognizer regex patterns.

Tests each regex pattern directly without loading GLiNER/Presidio models.
This verifies the patterns match their intended formats and reject invalid ones.
"""
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# Regex patterns extracted from recognizers.py — must stay in sync.
PATTERNS = {
    "CO_CEDULA_DOTTED_LONG": r"(?<!\$)\b\d{1,3}(?:\.\d{3}){2,3}\b",
    "CO_CEDULA_PLAIN": r"\b[1-9]\d{6,9}\b",
    "CO_NIT_DOTTED": r"\b\d{3}\.\d{3}\.\d{3}-\d\b",
    "CO_NIT_PLAIN": r"\b\d{9}-\d\b",
    "AR_DNI_DOTTED": r"\b\d{2}\.\d{3}\.\d{3}\b",
    "AR_DNI_PLAIN": r"\b[1-9]\d{7}\b",
    "ES_NIF_NIF": r"\b\d{8}[A-HJ-NP-TV-Z]\b",
    "ES_NIF_NIE": r"\b[XYZ]\d{7}[A-HJ-NP-TV-Z]\b",
    "IBAN_LATAM_EU": r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
    "CL_RUT_DOTTED": r"\b\d{1,2}\.\d{3}\.\d{3}-[\dKk]\b",
    "CL_RUT_PLAIN": r"\b\d{7,8}-[\dKk]\b",
    "BR_CPF": r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b",
    "BR_CNPJ": r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b",
    "MX_CURP": r"\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b",
    "MX_RFC_PERSON": r"\b[A-Z]{4}\d{6}[A-Z0-9]{3}\b",
    "MX_RFC_COMPANY": r"\b[A-Z]{3}\d{6}[A-Z0-9]{3}\b",
    "ORG_BANK_NAME": r"\bBanco (?:de (?:la |los |las )?|del )[A-ZÁÉÍÓÚÑ][a-záéíóúñA-ZÁÉÍÓÚÑ]+\b",
    "ORG_LEGAL_SUFFIX": (
        r"\b(?:[A-ZÁÉÍÓÚÑ][A-Za-záéíóúñÁÉÍÓÚÑ]+\s+){1,5}"
        r"(?:S\.A\.S\.|S\.A\.|S\.R\.L\.|Ltda\.|Ltda|S\.de\s+R\.L\."
        r"|SAPI\s+de\s+CV|S\.A\.\s+de\s+C\.V\.|SpA|EIRL|E\.U\.)"
    ),
    "LOCATION_LATAM_AVENUE": (
        r"\bAv(?:enida|\.)?\s+[A-ZÁÉÍÓÚÑ][A-Za-záéíóúñÁÉÍÓÚÑ\s]+\d+(?:,\s*[A-ZÁÉÍÓÚÑ][A-Za-záéíóúñÁÉÍÓÚÑ\s]+)?"
    ),
    "LOCATION_LATAM_STREET": (
        r"\bCalle\s+\d+[A-Za-z]?\s*(?:#|No\.)\s*\d+[-" + "\u2013" + r"]\d+(?:,\s*[A-ZÁÉÍÓÚÑ][A-Za-záéíóúñÁÉÍÓÚÑ\s]+)?"
    ),
    "LOCATION_LATAM_CARRERA": (
        r"\bCarrera\s+\d+[A-Za-z]?\s*(?:#|No\.)\s*\d+[-" + "\u2013" + r"]\d+(?:,\s*[A-ZÁÉÍÓÚÑ][A-Za-záéíóúñÁÉÍÓÚÑ\s]+)?"
    ),
    "MONEY_LATAM": r"\$\d{1,3}(?:\.\d{3})+(?:\s*[A-Z]{3})?",
    "DATE_ES_TEXT": (
        r"\b\d{1,2} de (?:enero|febrero|marzo|abril|mayo|junio|julio|agosto"
        r"|septiembre|octubre|noviembre|diciembre) de \d{4}\b"
    ),
    "DATE_QUARTER": r"\bQ[1-4]\s+\d{4}\b",
}


def _match(pattern_key: str, text: str) -> bool:
    return bool(re.fullmatch(PATTERNS[pattern_key], text))


# ─── CO_CEDULA ────────────────────────────────────────────────────────────────

def test_co_cedula_dotted_matches():
    assert _match("CO_CEDULA_DOTTED_LONG", "79.123.456")
    assert _match("CO_CEDULA_DOTTED_LONG", "1.023.456")
    # 10-digit cédula (3 dot groups)
    assert _match("CO_CEDULA_DOTTED_LONG", "1.023.456.789")


def test_co_cedula_dotted_no_match_on_plain():
    assert not _match("CO_CEDULA_DOTTED_LONG", "79123456")


def test_co_cedula_no_match_dollar_prefixed():
    # $120.000.000 is a money amount — the lookbehind (?<!\$) must reject it
    assert not re.search(PATTERNS["CO_CEDULA_DOTTED_LONG"], "$120.000.000")


def test_co_cedula_plain_matches():
    assert _match("CO_CEDULA_PLAIN", "52987654")
    assert _match("CO_CEDULA_PLAIN", "1020304050")


# ─── CO_NIT ───────────────────────────────────────────────────────────────────

def test_co_nit_dotted_matches():
    assert _match("CO_NIT_DOTTED", "900.123.456-7")
    assert _match("CO_NIT_DOTTED", "901.987.654-2")


def test_co_nit_plain_matches():
    assert _match("CO_NIT_PLAIN", "900123456-7")


def test_co_nit_dotted_no_match_wrong_format():
    assert not _match("CO_NIT_DOTTED", "900.123.456")  # missing check digit


# ─── AR_DNI ───────────────────────────────────────────────────────────────────

def test_ar_dni_dotted_matches():
    assert _match("AR_DNI_DOTTED", "12.345.678")
    assert _match("AR_DNI_DOTTED", "34.567.890")


def test_ar_dni_plain_matches():
    assert _match("AR_DNI_PLAIN", "28765432")


def test_ar_dni_no_match_too_short():
    assert not _match("AR_DNI_DOTTED", "1.234.567")  # only 1+3+3 = 7 digits


# ─── ES_NIF / NIE ─────────────────────────────────────────────────────────────

def test_es_nif_matches():
    assert _match("ES_NIF_NIF", "12345678A")
    assert _match("ES_NIF_NIF", "87654321Z")


def test_es_nie_matches():
    assert _match("ES_NIF_NIE", "X1234567A")
    assert _match("ES_NIF_NIE", "Z9876543B")


def test_es_nif_no_match_wrong_letter():
    # Letters I, O, U are excluded
    assert not _match("ES_NIF_NIF", "12345678I")
    assert not _match("ES_NIF_NIF", "12345678O")


# ─── IBAN_CODE ────────────────────────────────────────────────────────────────

def test_iban_co_matches():
    assert _match("IBAN_LATAM_EU", "CO1289354987654321098765")


def test_iban_eu_matches():
    assert _match("IBAN_LATAM_EU", "DE89370400440532013000")
    assert _match("IBAN_LATAM_EU", "GB29NWBK60161331926819")


def test_iban_no_match_too_short():
    assert not _match("IBAN_LATAM_EU", "CO12345")  # only 7 chars after country+check


# ─── CL_RUT ───────────────────────────────────────────────────────────────────

def test_cl_rut_dotted_matches():
    assert _match("CL_RUT_DOTTED", "12.345.678-9")
    assert _match("CL_RUT_DOTTED", "7.654.321-K")
    assert _match("CL_RUT_DOTTED", "7.654.321-k")


def test_cl_rut_plain_matches():
    assert _match("CL_RUT_PLAIN", "15987654-3")
    assert _match("CL_RUT_PLAIN", "7654321-K")


def test_cl_rut_no_match_missing_dash():
    assert not _match("CL_RUT_DOTTED", "12.345.678")


# ─── BR_CPF ───────────────────────────────────────────────────────────────────

def test_br_cpf_matches():
    assert _match("BR_CPF", "123.456.789-09")
    assert _match("BR_CPF", "000.000.000-00")


def test_br_cpf_no_match_wrong_separator():
    assert not _match("BR_CPF", "123456789-09")
    assert not _match("BR_CPF", "123.456.789/09")


# ─── BR_CNPJ ──────────────────────────────────────────────────────────────────

def test_br_cnpj_matches():
    assert _match("BR_CNPJ", "12.345.678/0001-90")
    assert _match("BR_CNPJ", "11.222.333/0001-81")


def test_br_cnpj_no_match_wrong_format():
    assert not _match("BR_CNPJ", "12345678000190")


# ─── MX_CURP ──────────────────────────────────────────────────────────────────

def test_mx_curp_matches():
    assert _match("MX_CURP", "BADD110313HCMLNS09")
    assert _match("MX_CURP", "ROCA850101MMCDRR04")


def test_mx_curp_no_match_wrong_sex():
    assert not _match("MX_CURP", "BADD110313XCMLNS09")  # X is not H or M


# ─── MX_RFC ───────────────────────────────────────────────────────────────────

def test_mx_rfc_person_matches():
    assert _match("MX_RFC_PERSON", "XAXX010101000")
    assert _match("MX_RFC_PERSON", "GOGA821231GR8")


def test_mx_rfc_company_matches():
    assert _match("MX_RFC_COMPANY", "ABC010101XYZ")


# ─── ORG bank names ───────────────────────────────────────────────────────────

def test_org_bank_name_matches():
    assert _match("ORG_BANK_NAME", "Banco de Bogotá")
    assert _match("ORG_BANK_NAME", "Banco del Estado")
    assert _match("ORG_BANK_NAME", "Banco de la República")


def test_org_bank_name_no_match_missing_prefix():
    assert not _match("ORG_BANK_NAME", "Bogotá Bank")


# ─── DATE_TIME Spanish ────────────────────────────────────────────────────────

def test_date_es_text_matches():
    assert _match("DATE_ES_TEXT", "1 de marzo de 2024")
    assert _match("DATE_ES_TEXT", "22 de noviembre de 2023")
    assert _match("DATE_ES_TEXT", "31 de diciembre de 2025")


def test_date_es_text_no_match_wrong_month():
    assert not _match("DATE_ES_TEXT", "1 de march de 2024")


def test_date_quarter_matches():
    assert _match("DATE_QUARTER", "Q1 2024")
    assert _match("DATE_QUARTER", "Q4 2025")


def test_date_quarter_no_match_wrong_quarter():
    assert not _match("DATE_QUARTER", "Q5 2024")


# ─── ORG_LEGAL_SUFFIX ─────────────────────────────────────────────────────────

def test_org_legal_suffix_sas_matches():
    assert _match("ORG_LEGAL_SUFFIX", "ACME S.A.S.")
    assert _match("ORG_LEGAL_SUFFIX", "Inversiones S.A.")


def test_org_legal_suffix_srl_matches():
    assert _match("ORG_LEGAL_SUFFIX", "Innovaciones Digitales S.R.L.")


def test_org_legal_suffix_ltda_matches():
    assert _match("ORG_LEGAL_SUFFIX", "Construcciones Ltda.")


def test_org_legal_suffix_no_match_plain_word():
    assert not _match("ORG_LEGAL_SUFFIX", "empresa")


# ─── LOCATION patterns ────────────────────────────────────────────────────────

def test_location_avenue_matches():
    assert _match("LOCATION_LATAM_AVENUE", "Av. Corrientes 1234, CABA")
    assert _match("LOCATION_LATAM_AVENUE", "Avenida Santa Fe 456")


def test_location_street_matches():
    assert _match("LOCATION_LATAM_STREET", "Calle 72 # 10-34, Bogotá")
    assert _match("LOCATION_LATAM_STREET", "Calle 100 # 15-20")
    assert _match("LOCATION_LATAM_STREET", "Calle 30A No. 6-22")


def test_location_carrera_matches():
    assert _match("LOCATION_LATAM_CARRERA", "Carrera 15 # 93-47, Bogotá")
    assert _match("LOCATION_LATAM_CARRERA", "Carrera 7 # 32-16")
    assert _match("LOCATION_LATAM_CARRERA", "Carrera 12B No. 45-67")


# ─── MONEY ────────────────────────────────────────────────────────────────────

def test_money_latam_cop_matches():
    assert _match("MONEY_LATAM", "$120.000.000 COP")
    assert _match("MONEY_LATAM", "$60.000.000 COP")
    assert _match("MONEY_LATAM", "$1.500.000")


def test_money_latam_usd_matches():
    assert _match("MONEY_LATAM", "$50.000 USD")


def test_money_no_match_plain_dollar():
    # bare "$5" should not match — requires at least one .NNN group
    assert not _match("MONEY_LATAM", "$5")
