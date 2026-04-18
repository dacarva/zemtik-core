"""Canonical entity-type hashes — re-exported for server.py imports."""
try:
    from .entity_hashes import type_hash, ENTITY_HASHES
except ImportError:
    from entity_hashes import type_hash, ENTITY_HASHES

__all__ = ["type_hash", "ENTITY_HASHES"]
