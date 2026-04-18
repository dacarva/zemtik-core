"""UTF-8 byte offset utilities (no gRPC dependency)."""


def char_to_byte_offset(text: str, char_offset: int) -> int:
    """Convert a Unicode character offset to a UTF-8 byte offset."""
    char_offset = max(0, min(char_offset, len(text)))
    return len(text[:char_offset].encode("utf-8"))
