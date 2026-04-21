"""Unit tests for server.py module-level constants.

Verifies DEFAULT_ENTITY_TYPES, GLINER_ENTITY_TYPES, and MIN_ENTITY_CHARS
without loading GLiNER/Presidio/gRPC at import time.
"""
import sys
import types
import os

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

from server import DEFAULT_ENTITY_TYPES, GLINER_ENTITY_TYPES, MIN_ENTITY_CHARS


# ─── DEFAULT_ENTITY_TYPES ─────────────────────────────────────────────────────

def test_default_entity_types_includes_money():
    assert "MONEY" in DEFAULT_ENTITY_TYPES


def test_default_entity_types_includes_all_latam_ids():
    expected = {"CO_NIT", "CO_CEDULA", "AR_DNI", "CL_RUT", "BR_CPF", "BR_CNPJ", "MX_CURP", "MX_RFC", "ES_NIF"}
    assert expected.issubset(set(DEFAULT_ENTITY_TYPES))


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
                  "BR_CPF", "BR_CNPJ", "MX_CURP", "MX_RFC", "ES_NIF", "IBAN_CODE", "DATE_TIME"}
    for t in regex_only:
        assert t not in GLINER_ENTITY_TYPES, f"{t} must not be in GLINER_ENTITY_TYPES"


def test_gliner_entity_types_includes_person_and_org():
    assert "PERSON" in GLINER_ENTITY_TYPES
    assert "ORG" in GLINER_ENTITY_TYPES


def test_gliner_entity_types_is_frozenset():
    assert isinstance(GLINER_ENTITY_TYPES, frozenset)


# ─── MIN_ENTITY_CHARS ─────────────────────────────────────────────────────────

def test_min_entity_chars_value():
    assert MIN_ENTITY_CHARS == 4


def test_min_entity_chars_filters_short_entities():
    # Simulate the filter applied in AnonymizerServicer.Anonymize
    raw_entities = [
        {"start": 0, "end": 2, "label": "ORG", "score": 0.9},      # 2 chars — dropped
        {"start": 5, "end": 8, "label": "ORG", "score": 0.9},      # 3 chars — dropped
        {"start": 10, "end": 14, "label": "ORG", "score": 0.9},    # 4 chars — kept
        {"start": 20, "end": 30, "label": "PERSON", "score": 0.8}, # 10 chars — kept
    ]
    filtered = [e for e in raw_entities if (e["end"] - e["start"]) >= MIN_ENTITY_CHARS]
    assert len(filtered) == 2
    assert filtered[0]["start"] == 10
    assert filtered[1]["start"] == 20
