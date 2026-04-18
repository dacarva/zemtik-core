"""Canonical SHA-256[:4hex] hashes for the 16 supported entity types.

Must match src/entity_hashes.rs byte-for-byte.
Verify with: cargo run --bin zemtik -- anonymizer hashes | diff - <(python entity_hashes.py)
"""
import hashlib

ENTITY_HASHES: dict[str, str] = {
    "PERSON":        "e47f",
    "ORG":           "0e67",
    "LOCATION":      "ec4e",
    "CO_CEDULA":     "5b46",
    "CO_NIT":        "bba1",
    "CL_RUT":        "fe8c",
    "MX_CURP":       "87fb",
    "MX_RFC":        "95d9",
    "BR_CPF":        "d8f7",
    "BR_CNPJ":       "3834",
    "AR_DNI":        "f76d",
    "ES_NIF":        "fc3d",
    "PHONE_NUMBER":  "ca71",
    "EMAIL_ADDRESS": "a8d8",
    "IBAN_CODE":     "3f21",
    "DATE_TIME":     "322b",
}


def type_hash(entity_type: str) -> str | None:
    return ENTITY_HASHES.get(entity_type)


def print_canonical_hashes() -> None:
    for name, expected in ENTITY_HASHES.items():
        computed = hashlib.sha256(name.encode("utf-8")).hexdigest()[:4]
        status = "OK" if computed == expected else f"MISMATCH (got {computed})"
        print(f"{name}: {expected}  [{status}]")


if __name__ == "__main__":
    print_canonical_hashes()
