"""Custom Presidio PatternRecognizers for Latin American and Spanish PII types."""
from presidio_analyzer import Pattern, PatternRecognizer


def build_custom_recognizers():
    """Return list of custom recognizers for LatAm + ES structured IDs."""
    return [
        # CO_CEDULA: Colombian national ID
        # Formats: 79.123.456 | 1.023.456.789 | 52987654 | 1020304050
        PatternRecognizer(
            supported_entity="CO_CEDULA",
            supported_language="en",
            patterns=[
                Pattern("CO_CEDULA_DOTTED_LONG", r"\b\d{1,3}\.\d{3}\.\d{3}\b", 0.65),
                Pattern("CO_CEDULA_PLAIN", r"\b[1-9]\d{6,9}\b", 0.3),
            ],
            context=["cédula", "cedula", "c.c.", " cc ", "identificación", "documento de identidad"],
        ),

        # CO_NIT: Colombian tax ID — format: 900.123.456-7
        PatternRecognizer(
            supported_entity="CO_NIT",
            supported_language="en",
            patterns=[
                Pattern("CO_NIT_DOTTED", r"\b\d{3}\.\d{3}\.\d{3}-\d\b", 0.9),
                Pattern("CO_NIT_PLAIN", r"\b\d{9}-\d\b", 0.75),
            ],
            context=["nit", "n.i.t.", "registro mercantil"],
        ),

        # AR_DNI: Argentine DNI
        # Formats: 12.345.678 | 34.567.890 | 28765432
        PatternRecognizer(
            supported_entity="AR_DNI",
            supported_language="en",
            patterns=[
                Pattern("AR_DNI_DOTTED", r"\b\d{2}\.\d{3}\.\d{3}\b", 0.65),
                Pattern("AR_DNI_PLAIN", r"\b[1-9]\d{7}\b", 0.3),
            ],
            context=["dni", "d.n.i.", "documento nacional", "identidad"],
        ),

        # ES_NIF: Spanish NIF (8 digits + letter) or NIE (X/Y/Z + 7 digits + letter)
        PatternRecognizer(
            supported_entity="ES_NIF",
            supported_language="en",
            patterns=[
                Pattern("ES_NIF_NIF", r"\b\d{8}[A-HJ-NP-TV-Z]\b", 0.85),
                Pattern("ES_NIF_NIE", r"\b[XYZ]\d{7}[A-HJ-NP-TV-Z]\b", 0.85),
            ],
            context=["nif", "nie", "n.i.f.", "n.i.e.", "identificación fiscal"],
        ),

        # IBAN_CODE: covers LatAm + EU IBANs (15–34 chars, 2-letter country + 2 check digits)
        PatternRecognizer(
            supported_entity="IBAN_CODE",
            supported_language="en",
            patterns=[
                Pattern("IBAN_LATAM_EU", r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", 0.75),
            ],
            context=["iban", "cuenta bancaria", "cuenta corriente", "transferencia", "bank account"],
        ),

        # CL_RUT: Chilean tax ID
        # Formats: 12.345.678-9 | 7.654.321-K | 15987654-3
        PatternRecognizer(
            supported_entity="CL_RUT",
            supported_language="en",
            patterns=[
                Pattern("CL_RUT_DOTTED", r"\b\d{1,2}\.\d{3}\.\d{3}-[\dKk]\b", 0.9),
                Pattern("CL_RUT_PLAIN", r"\b\d{7,8}-[\dKk]\b", 0.8),
            ],
            context=["rut", "r.u.t.", "rol único tributario"],
        ),

        # BR_CPF: Brazilian individual tax ID — format: 000.000.000-00
        PatternRecognizer(
            supported_entity="BR_CPF",
            supported_language="en",
            patterns=[
                Pattern("BR_CPF", r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b", 0.9),
            ],
            context=["cpf", "c.p.f.", "cadastro de pessoas", "pessoa física", "físico"],
        ),

        # BR_CNPJ: Brazilian company tax ID — format: 00.000.000/0000-00
        PatternRecognizer(
            supported_entity="BR_CNPJ",
            supported_language="en",
            patterns=[
                Pattern("BR_CNPJ", r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b", 0.95),
            ],
            context=["cnpj", "c.n.p.j.", "cadastro nacional", "pessoa jurídica", "jurídico"],
        ),

        # MX_CURP: Mexican CURP — 18-char fixed structure
        # Format: 4 letters + 6 digits + H/M + 5 letters + 1 alphanum + 1 digit
        PatternRecognizer(
            supported_entity="MX_CURP",
            supported_language="en",
            patterns=[
                Pattern("MX_CURP", r"\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b", 0.95),
            ],
            context=["curp", "clave única", "registro de población"],
        ),

        # MX_RFC: Mexican RFC — 12 chars (company) or 13 chars (person)
        PatternRecognizer(
            supported_entity="MX_RFC",
            supported_language="en",
            patterns=[
                Pattern("MX_RFC_PERSON", r"\b[A-Z]{4}\d{6}[A-Z0-9]{3}\b", 0.85),
                Pattern("MX_RFC_COMPANY", r"\b[A-Z]{3}\d{6}[A-Z0-9]{3}\b", 0.8),
            ],
            context=["rfc", "r.f.c.", "registro federal", "contribuyente"],
        ),

        # ORG: bank names — "Banco de Bogotá", "Banco del Estado", etc.
        # GLiNER misses these generic names without legal suffixes.
        PatternRecognizer(
            supported_entity="ORG",
            supported_language="en",
            patterns=[
                Pattern(
                    "ORG_BANK_NAME",
                    r"\bBanco (?:de (?:la |los |las )?|del )[A-ZÁÉÍÓÚÑ][a-záéíóúñA-ZÁÉÍÓÚÑ]+\b",
                    0.8,
                ),
            ],
        ),

        # LOCATION: LatAm street address formats missed by GLiNER
        # Covers: "Av. Corrientes 1234, CABA", "Av. Santa Fe 456, CABA",
        #         "Calle 72 # 10-34, Bogotá", "Carrera 15 # 93-47, Bogotá"
        PatternRecognizer(
            supported_entity="LOCATION",
            supported_language="en",
            patterns=[
                Pattern(
                    "LOCATION_LATAM_AVENUE",
                    r"\bAv(?:enida|\.)?\s+[A-ZÁÉÍÓÚÑ][A-Za-záéíóúñÁÉÍÓÚÑ\s]+\d+(?:,\s*[A-ZÁÉÍÓÚÑ][A-Za-záéíóúñÁÉÍÓÚÑ\s]+)?",
                    0.75,
                ),
                Pattern(
                    "LOCATION_LATAM_STREET",
                    r"\bCalle\s+\d+\s*#\s*\d+[-–]\d+(?:,\s*[A-ZÁÉÍÓÚÑ][A-Za-záéíóúñÁÉÍÓÚÑ\s]+)?",
                    0.85,
                ),
                Pattern(
                    "LOCATION_LATAM_CARRERA",
                    r"\bCarrera\s+\d+\s*#\s*\d+[-–]\d+(?:,\s*[A-ZÁÉÍÓÚÑ][A-Za-záéíóúñÁÉÍÓÚÑ\s]+)?",
                    0.85,
                ),
            ],
            context=["dirección", "domicilio", "vive en", "ubicado en", "address"],
        ),

        # ORG fallback: company names ending in LatAm/ES legal suffixes missed by GLiNER
        # Catches: "ACME S.A.S.", "Inversiones S.A.", "Innovaciones Digitales S.R.L.", etc.
        PatternRecognizer(
            supported_entity="ORG",
            supported_language="en",
            patterns=[
                Pattern(
                    "ORG_LEGAL_SUFFIX",
                    r"\b(?:[A-ZÁÉÍÓÚÑ][A-Za-záéíóúñÁÉÍÓÚÑ]+\s+){1,5}"
                    r"(?:S\.A\.S\.|S\.A\.|S\.R\.L\.|Ltda\.|Ltda|S\.de\s+R\.L\."
                    r"|SAPI\s+de\s+CV|S\.A\.\s+de\s+C\.V\.|SpA|EIRL|E\.U\.)",
                    0.75,
                ),
            ],
        ),

        # DATE_TIME (Spanish): Spanish text dates missed by Presidio's English DateRecognizer
        # Covers "1 de marzo de 2024", "22 de noviembre de 2023", etc.
        PatternRecognizer(
            supported_entity="DATE_TIME",
            supported_language="en",
            patterns=[
                Pattern(
                    "DATE_ES_TEXT",
                    r"\b\d{1,2} de (?:enero|febrero|marzo|abril|mayo|junio|julio|agosto"
                    r"|septiembre|octubre|noviembre|diciembre) de \d{4}\b",
                    0.9,
                ),
                Pattern(
                    "DATE_QUARTER",
                    r"\bQ[1-4]\s+\d{4}\b",
                    0.85,
                ),
            ],
        ),
    ]
