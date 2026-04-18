"""Verify that UTF-8 byte offset conversion is correct for accented Spanish/Portuguese names.

GLiNER returns Unicode character offsets. The sidecar must convert them to UTF-8 byte
offsets before serializing AuditSpan. Without this conversion, names with multi-byte
characters (José, García, Peña, São Paulo) produce incorrect spans silently.
"""
import sys
import os

# Allow importing from the sidecar package directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from offsets import char_to_byte_offset


def _spans_from_text(text: str, names: list[str]) -> list[tuple[int, int, str]]:
    """Find all occurrences of each name in text, return (byte_start, byte_end, name) tuples."""
    spans = []
    for name in names:
        start = 0
        while True:
            idx = text.find(name, start)
            if idx == -1:
                break
            spans.append((
                char_to_byte_offset(text, idx),
                char_to_byte_offset(text, idx + len(name)),
                name,
            ))
            start = idx + 1
    return spans


def _extract_at_byte_span(text: str, byte_start: int, byte_end: int) -> str:
    """Extract text from UTF-8 byte offsets."""
    return text.encode("utf-8")[byte_start:byte_end].decode("utf-8")


def test_ascii_name_offsets_unchanged():
    """ASCII-only names: char offsets == byte offsets."""
    text = "Contract signed by John Smith"
    char_start = text.index("John Smith")
    char_end = char_start + len("John Smith")
    byte_start = char_to_byte_offset(text, char_start)
    byte_end = char_to_byte_offset(text, char_end)
    assert byte_start == char_start, "ASCII char==byte offsets must match"
    assert byte_end == char_end, "ASCII char==byte offsets must match"
    assert _extract_at_byte_span(text, byte_start, byte_end) == "John Smith"


def test_jose_garcia_byte_offsets():
    """'José García' has 2-byte chars (é, á) — byte offsets differ from char offsets."""
    text = "El contrato de José García fue firmado."
    target = "José García"
    char_start = text.index(target)
    char_end = char_start + len(target)
    byte_start = char_to_byte_offset(text, char_start)
    byte_end = char_to_byte_offset(text, char_end)

    # Byte offsets must be >= char offsets because 'é' (U+00E9) is 2 UTF-8 bytes
    assert byte_start >= char_start, "byte_start must be >= char_start for accented text"
    assert byte_end > char_end, "byte_end must be > char_end when accented chars precede the span"

    # Critical: round-trip must recover the original text
    extracted = _extract_at_byte_span(text, byte_start, byte_end)
    assert extracted == target, f"Round-trip failed: expected {target!r}, got {extracted!r}"


def test_pena_name_byte_offsets():
    """'Peña' (ñ is U+00F1, 2 bytes) round-trips correctly."""
    text = "Firmado por Carlos Peña el día 1 de enero."
    target = "Carlos Peña"
    char_start = text.index(target)
    char_end = char_start + len(target)
    byte_start = char_to_byte_offset(text, char_start)
    byte_end = char_to_byte_offset(text, char_end)
    extracted = _extract_at_byte_span(text, byte_start, byte_end)
    assert extracted == target, f"Round-trip failed: expected {target!r}, got {extracted!r}"


def test_sao_paulo_byte_offsets():
    """'São Paulo' (ã is U+00E3, 2 bytes) round-trips correctly."""
    text = "A empresa com sede em São Paulo firmou o contrato."
    target = "São Paulo"
    char_start = text.index(target)
    char_end = char_start + len(target)
    byte_start = char_to_byte_offset(text, char_start)
    byte_end = char_to_byte_offset(text, char_end)
    extracted = _extract_at_byte_span(text, byte_start, byte_end)
    assert extracted == target, f"Round-trip failed: expected {target!r}, got {extracted!r}"


def test_multiple_accented_names_in_same_text():
    """Multiple accented entities in same text all round-trip correctly."""
    text = "El acuerdo entre María López y Raúl Ñáñez, representante de Construcciones Ñoño S.A., fue aprobado."
    names = ["María López", "Raúl Ñáñez", "Construcciones Ñoño S.A."]
    spans = _spans_from_text(text, names)
    assert len(spans) == len(names), f"Expected {len(names)} spans, got {len(spans)}"
    for byte_start, byte_end, expected_name in spans:
        extracted = _extract_at_byte_span(text, byte_start, byte_end)
        assert extracted == expected_name, (
            f"Round-trip failed for {expected_name!r}: got {extracted!r}"
        )


def test_char_to_byte_offset_pure_ascii():
    """For pure ASCII, char_to_byte_offset is the identity function."""
    text = "Hello world 123"
    for i in range(len(text) + 1):
        assert char_to_byte_offset(text, i) == i, f"char {i} should equal byte {i} in ASCII"


def test_char_to_byte_offset_multibyte():
    """Each accented character adds 1 extra byte vs its char position."""
    text = "éà"  # é=2 bytes, à=2 bytes
    assert char_to_byte_offset(text, 0) == 0
    assert char_to_byte_offset(text, 1) == 2   # after 'é' (2 bytes)
    assert char_to_byte_offset(text, 2) == 4   # after 'à' (2 bytes)
