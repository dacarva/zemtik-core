"""UTF-8 byte offset utilities (no gRPC dependency)."""


def char_to_byte_offset(text: str, char_offset: int) -> int:
    """Convert a Unicode character offset to a UTF-8 byte offset."""
    return len(text[:char_offset].encode("utf-8"))
