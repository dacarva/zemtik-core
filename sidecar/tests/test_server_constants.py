"""Unit tests for server.py module-level constants.

Verifies DEFAULT_ENTITY_TYPES, GLINER_ENTITY_TYPES, MIN_ENTITY_CHARS, and
GLINER_STOPWORDS without loading GLiNER/Presidio/gRPC at import time.
"""
import sys
import types
import os

import pytest

# Stub out heavy dependencies so server.py can be imported without the
# Docker environment (no grpc, no Presidio, no GLiNER).
for _mod in [
    "grpc",
    "grpc_health",
    "grpc_health.v1",
    "grpc_health.v1.health",
    "grpc_health.v1.health_pb2",
    "grpc_health.v1.health_pb2_grpc",
    "zemtik_dot_anonymizer_dot_v1_dot_anonymizer_pb2",
    "zemtik_dot_anonymizer_dot_v1_dot_anonymizer_pb2_grpc",
    "anonymizer_pb2",
    "anonymizer_pb2_grpc",
    "offsets",
]:
    if _mod not in sys.modules:
        sys.modules[_mod] = types.ModuleType(_mod)

# Provide the one symbol server.py actually uses from offsets at module scope.
sys.modules["offsets"].char_to_byte_offset = lambda text, idx: len(text[:idx].encode("utf-8"))  # type: ignore[attr-defined]

# server.py defines AnonymizerServicer as a subclass of this at module level.
class _BaseServicer:
    pass

sys.modules["zemtik_dot_anonymizer_dot_v1_dot_anonymizer_pb2_grpc"].AnonymizerServiceServicer = _BaseServicer  # type: ignore[attr-defined]
sys.modules["anonymizer_pb2_grpc"].AnonymizerServiceServicer = _BaseServicer  # type: ignore[attr-defined]

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from server import DEFAULT_ENTITY_TYPES, GLINER_ENTITY_TYPES, MIN_ENTITY_CHARS, GLINER_STOPWORDS, CORP_SUFFIXES
except ImportError as _e:
    pytest.skip(f"server.py could not be imported (missing dependency): {_e}", allow_module_level=True)


# ─── DEFAULT_ENTITY_TYPES ─────────────────────────────────────────────────────

def test_default_entity_types_includes_money():
    assert "MONEY" in DEFAULT_ENTITY_TYPES


def test_default_entity_types_includes_all_latam_ids():
    expected = {"CO_NIT", "CO_CEDULA", "AR_DNI", "CL_RUT", "BR_CPF", "BR_CNPJ", "MX_CURP", "MX_RFC", "ES_NIF"}
    assert expected.issubset(set(DEFAULT_ENTITY_TYPES))


def test_default_entity_types_includes_new_latam_ids():
    new_ids = {"EC_RUC", "PE_RUC", "BO_NIT", "UY_CI", "VE_CI"}
    assert new_ids.issubset(set(DEFAULT_ENTITY_TYPES)), f"missing: {new_ids - set(DEFAULT_ENTITY_TYPES)}"


def test_default_entity_types_includes_core_types():
    assert {"PERSON", "ORG", "LOCATION", "IBAN_CODE", "DATE_TIME"}.issubset(set(DEFAULT_ENTITY_TYPES))


def test_default_entity_types_no_duplicates():
    assert len(DEFAULT_ENTITY_TYPES) == len(set(DEFAULT_ENTITY_TYPES)), "duplicate entity types detected"


# ─── GLINER_ENTITY_TYPES ──────────────────────────────────────────────────────

def test_gliner_entity_types_excludes_location():
    # LOCATION excluded: urchade/gliner_multi_pii-v1 false-positives on Spanish
    # words ("La", "sociedad") — handled by Presidio regex instead.
    assert "LOCATION" not in GLINER_ENTITY_TYPES


def test_gliner_entity_types_excludes_all_regex_only_types():
    # Regex-only types must never be routed to GLiNER — GLiNER only handles neural NER.
    regex_only = {"LOCATION", "MONEY", "CO_NIT", "CO_CEDULA", "AR_DNI", "CL_RUT",
                  "BR_CPF", "BR_CNPJ", "MX_CURP", "MX_RFC", "ES_NIF", "IBAN_CODE", "DATE_TIME",
                  "EC_RUC", "PE_RUC", "BO_NIT", "UY_CI", "VE_CI"}
    for t in regex_only:
        assert t not in GLINER_ENTITY_TYPES, f"{t} must not be in GLINER_ENTITY_TYPES"


def test_gliner_entity_types_includes_person_and_org():
    assert "PERSON" in GLINER_ENTITY_TYPES
    assert "ORG" in GLINER_ENTITY_TYPES


def test_gliner_entity_types_is_frozenset():
    assert isinstance(GLINER_ENTITY_TYPES, frozenset)


# ─── MIN_ENTITY_CHARS ─────────────────────────────────────────────────────────

def test_min_entity_chars_default():
    # Default is 3 (env-configurable via ZEMTIK_MIN_ENTITY_CHARS).
    # 3 preserves short but valid names like "Ana" that a threshold of 4 would drop.
    assert MIN_ENTITY_CHARS == int(os.environ.get("ZEMTIK_MIN_ENTITY_CHARS", "3"))


def test_min_entity_chars_filters_short_entities():
    # Simulate the filter applied in AnonymizerServicer.Anonymize.
    # With default threshold 3: 2-char entities dropped, 3+ char kept.
    text = "ab cde fghi abcdefghij"
    raw_entities = [
        {"start": 0, "end": 2, "label": "ORG", "score": 0.9},      # 2 chars — dropped
        {"start": 3, "end": 6, "label": "ORG", "score": 0.9},      # 3 chars — kept
        {"start": 7, "end": 11, "label": "ORG", "score": 0.9},     # 4 chars — kept
        {"start": 12, "end": 22, "label": "PERSON", "score": 0.8}, # 10 chars — kept
    ]
    filtered = [
        e for e in raw_entities
        if (e["end"] - e["start"]) >= MIN_ENTITY_CHARS
        and text[e["start"]:e["end"]].lower().strip() not in GLINER_STOPWORDS
    ]
    assert len(filtered) == 3
    assert filtered[0]["start"] == 3
    assert filtered[1]["start"] == 7
    assert filtered[2]["start"] == 12


# ─── GLINER_STOPWORDS ─────────────────────────────────────────────────────────

def test_gliner_stopwords_is_frozenset():
    assert isinstance(GLINER_STOPWORDS, frozenset)


def test_gliner_stopwords_contains_spanish_determiners():
    for word in ("la", "el", "los", "las", "una", "un"):
        assert word in GLINER_STOPWORDS, f"'{word}' must be in GLINER_STOPWORDS"


def test_gliner_stopwords_filters_determiners():
    text = "la sociedad Ana López"
    raw_entities = [
        {"start": 0, "end": 2, "label": "ORG", "score": 0.9},       # "la" — stopword
        {"start": 3, "end": 11, "label": "ORG", "score": 0.9},      # "sociedad" — kept
        {"start": 12, "end": 21, "label": "PERSON", "score": 0.8},  # "Ana López" — kept
    ]
    filtered = [
        e for e in raw_entities
        if (e["end"] - e["start"]) >= MIN_ENTITY_CHARS
        and text[e["start"]:e["end"]].lower().strip() not in GLINER_STOPWORDS
    ]
    assert len(filtered) == 2
    assert text[filtered[0]["start"]:filtered[0]["end"]] == "sociedad"


# ─── CORP_SUFFIXES ────────────────────────────────────────────────────────────

def test_corp_suffixes_matches_sas():
    # "Andina de Inversiones y Capital S.A.S." — the suffix must match the trailing token.
    m = CORP_SUFFIXES.match(" S.A.S.")
    assert m is not None, "CORP_SUFFIXES must match ' S.A.S.'"
    assert m.group(0) == " S.A.S."


def test_corp_suffixes_matches_all_known_forms():
    for suffix in (" S.A.S.", " S.A.", " Ltda.", " S.R.L.", " E.I.R.L.", " EIRL", " SpA", " LLC", " Inc.", " Corp."):
        m = CORP_SUFFIXES.match(suffix)
        assert m is not None, f"CORP_SUFFIXES must match '{suffix}'"


def test_corp_suffixes_requires_leading_whitespace():
    # No space before suffix — must not match (suffix must trail a span, not lead).
    assert CORP_SUFFIXES.match("S.A.S.") is None


def test_corp_suffixes_expansion_logic():
    # Simulate the server.py ORG span expansion: given an ORG span ending just before
    # " S.A.S.", verify the expanded byte_end covers the full suffix.
    text = "Andina de Inversiones y Capital S.A.S."
    text_bytes = text.encode("utf-8")
    # Pretend GLiNER detected "Andina de Inversiones y Capital" (31 chars, 31 bytes ASCII)
    fake_byte_end = len("Andina de Inversiones y Capital".encode("utf-8"))
    suffix_window = text_bytes[fake_byte_end:fake_byte_end + 20].decode("utf-8", errors="replace")
    m = CORP_SUFFIXES.match(suffix_window)
    assert m is not None, "expansion must detect ' S.A.S.' after ORG span"
    new_byte_end = fake_byte_end + len(m.group(0).encode("utf-8"))
    assert text_bytes[:new_byte_end].decode("utf-8") == "Andina de Inversiones y Capital S.A.S."
