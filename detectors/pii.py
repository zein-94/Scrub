# detectors/pii.py

import re
from typing import Any

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerResult
try:
    from presidio_analyzer.nlp_engine import NlpEngineProvider
except ImportError:
    from presidio_analyzer import NlpEngineProvider
from vault import Vault

# ─────────────────────────────────────────────
# False positive filters
# ─────────────────────────────────────────────

# Separator characters — lines made of these are structural, not entities
_SEPARATOR_CHARS = set('━─═—=_*#~│┃')

# Words/phrases that spaCy misidentifies as PERSON names
_NAME_DENYLIST = {
    # Section headers
    'personal', 'information', 'employment', 'details', 'medical',
    'vehicle', 'personal information', 'employment details',
    'medical information', 'vehicle information',
    # Field labels
    'full name', 'job title', 'full', 'title', 'nationality',
    'department', 'prepared', 'bank name', 'account name',
    # Document structure words
    'date issued', 'document reference', 'visa type',
}

# Words that spaCy misidentifies as LOCATION in document context
_LOCATION_DENYLIST = {
    'mobile',       # "Mobile (Work)" — it's a field label
    'emirates',     # "Emirates NBD" — it's a bank name, not a place
}

# Regex patterns that should never be treated as any entity
_STRUCTURAL_PATTERNS = [
    re.compile(r'^EMP\d+$'),           # Employee IDs
    re.compile(r'^[A-Z]{2,5}\d{1,6}$'), # Generic codes e.g. REF001, DOC2024
]


def _is_structural_false_positive(text: str, entity_type: str) -> bool:
    """Return True if a detected entity is clearly a structural false positive."""
    stripped = text.strip()

    # Separator lines — any span made entirely of separator/whitespace chars
    if stripped and all(c in _SEPARATOR_CHARS or c.isspace() for c in stripped):
        return True

    # Spans that contain separator characters at all (multiline separator+header)
    if any(c in _SEPARATOR_CHARS for c in stripped):
        return True

    # All-caps section headers mistaken for names
    if entity_type == 'PERSON' and stripped.isupper() and len(stripped) > 2:
        return True

    # Known label words mistaken for names (case-insensitive)
    if entity_type == 'PERSON' and stripped.lower() in _NAME_DENYLIST:
        return True

    # Known location false positives
    if entity_type == 'LOCATION' and stripped.lower() in _LOCATION_DENYLIST:
        return True
    # Structural ID patterns — never an entity regardless of type
    for pattern in _STRUCTURAL_PATTERNS:
        if pattern.match(stripped):
            return True

    return False
# ─────────────────────────────────────────────
# Custom regex recognizers for entities
# Presidio doesn't cover out of the box
# ─────────────────────────────────────────────

def _build_iban_recognizer() -> PatternRecognizer:
    iban_pattern = Pattern(
        name="IBAN",
        # Allows optional spaces every 4 chars e.g. AE07 0331 2345 6789 0123 456
        regex=r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){1,7}(?:\s?[A-Z0-9]{1,4})?\b",
        score=0.95,
    )
    return PatternRecognizer(
        supported_entity="IBAN",
        patterns=[iban_pattern],
        context=["iban", "bank", "account", "transfer"],
    )


def _build_credit_card_recognizer() -> PatternRecognizer:
    # Covers Visa, Mastercard, Amex, Discover
    cc_pattern = Pattern(
        name="CREDIT_CARD_EXTENDED",
        regex=(
            r"(?<![A-Z]{2}\d{2}\s)(?<![A-Z]{2}\d{2})"  # negative lookbehind — not IBAN prefix
            r"\b(?:"
            r"4[0-9]{12}(?:[0-9]{3})?"            # Visa
            r"|5[1-5][0-9]{14}"                    # Mastercard
            r"|3[47][0-9]{13}"                     # Amex
            r"|6(?:011|5[0-9]{2})[0-9]{12}"        # Discover
            r"|(?:\d{4}[- ]){3}\d{4}"              # spaced/dashed format — not preceded by IBAN
            r")\b"
        ),
        score=0.85,
    )
    return PatternRecognizer(
        supported_entity="CREDIT_CARD",
        patterns=[cc_pattern],
        context=["card", "credit", "debit", "visa", "mastercard", "payment"],
    )


def _build_passport_recognizer() -> PatternRecognizer:
    patterns = [
        Pattern(name="PASSPORT_US",   regex=r"\b[A-Z]{1}[0-9]{8}\b",   score=0.6),
        Pattern(name="PASSPORT_UK",   regex=r"\b[0-9]{9}\b",            score=0.5),
        Pattern(name="PASSPORT_INTL", regex=r"\b[A-Z]{2}[0-9]{7}\b",   score=0.65),
    ]
    return PatternRecognizer(
        supported_entity="PASSPORT",
        patterns=patterns,
        context=["passport", "travel", "document", "nationality"],
    )


def _build_national_id_recognizer() -> PatternRecognizer:
    patterns = [
        Pattern(name="SSN",        regex=r"\b\d{3}-\d{2}-\d{4}\b",          score=0.85),
        Pattern(name="UAE_ID",     regex=r"\b784-\d{4}-\d{7}-\d{1}\b",      score=0.95),
        Pattern(name="NATIONAL_ID",regex=r"\b[A-Z]{1,2}\d{6,9}[A-Z]?\b",   score=0.6),
    ]
    return PatternRecognizer(
        supported_entity="NATIONAL_ID",
        patterns=patterns,
        context=["id", "national", "identity", "ssn", "emirates", "civil"],
    )


def _build_ip_address_recognizer() -> PatternRecognizer:
    patterns = [
        Pattern(
            name="IPV4",
            regex=r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
            score=0.85,
        ),
        Pattern(
            name="IPV6",
            regex=r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
            score=0.85,
        ),
    ]
    return PatternRecognizer(
        supported_entity="IP_ADDRESS",
        patterns=patterns,
        context=["ip", "address", "server", "host", "network"],
    )

def _build_phone_recognizer() -> PatternRecognizer:
    patterns = [
        Pattern(
            name="PHONE_INTL_PLUS",
            # Must start with + and not be preceded by letters (rules out IBAN prefix like AE07)
            regex=r"(?<![A-Z0-9])\+\d[\d\s\-().]{6,20}\d",
            score=0.75,
        ),
        Pattern(
            name="PHONE_LOCAL",
            # Must not be preceded by alphanumeric (rules out being mid-IBAN)
            regex=r"(?<![A-Z0-9])(?:\(\d{2,4}\)[\s\-]?)?\d{2,4}[\s\-]\d{3,4}[\s\-]\d{3,4}(?!\d)",
            score=0.6,
        ),
    ]
    return PatternRecognizer(
        supported_entity="PHONE_NUMBER",
        patterns=patterns,
        context=["phone", "mobile", "cell", "tel", "contact", "call", "fax", "alt"],
    )

def _build_url_recognizer() -> PatternRecognizer:
    patterns = [
        Pattern(
            name="URL_WITH_SCHEME",
            # Must have explicit scheme, surrounded by whitespace or line boundaries
            # This prevents matching inside email addresses
            regex=r"(?<!\S)https?://[^\s/$.?#][^\s]*(?!\S)",
            score=0.85,
        ),
        Pattern(
            name="URL_WWW",
            # Must start with www. and be surrounded by whitespace
            regex=r"(?<!\S)www\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?(?!\S)",
            score=0.75,
        ),
    ]
    return PatternRecognizer(
        supported_entity="URL",
        patterns=patterns,
    )


def _build_date_recognizer() -> PatternRecognizer:
    _MONTHS = (
        r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?"
        r"|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
    )
    patterns = [
        Pattern(name="DATE_DMY",   regex=r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",              score=0.6),
        Pattern(name="DATE_LONG",  regex=rf"\b\d{{1,2}}\s+{_MONTHS}\s+\d{{4}}\b",            score=0.75),
        Pattern(name="DATE_ISO",   regex=r"\b\d{4}-\d{2}-\d{2}\b",                           score=0.7),
    ]
    return PatternRecognizer(
        supported_entity="DATE",
        patterns=patterns,
        context=["date", "born", "dob", "birthday", "issued", "expiry", "expires"],
    )


def _build_vehicle_recognizer() -> PatternRecognizer:
    patterns = [
        Pattern(name="PLATE_UK",  regex=r"\b[A-Z]{2}\d{2}\s?[A-Z]{3}\b",      score=0.7),
        Pattern(name="PLATE_US",  regex=r"\b[A-Z0-9]{2,3}[- ]?[A-Z0-9]{3,4}\b", score=0.5),
        Pattern(name="VIN",       regex=r"\b[A-HJ-NPR-Z0-9]{17}\b",            score=0.75),
    ]
    return PatternRecognizer(
        supported_entity="VEHICLE",
        patterns=patterns,
        context=["car", "vehicle", "plate", "registration", "vin", "license plate"],
    )


# ─────────────────────────────────────────────
# Presidio entity types to scrub in doc mode
# ─────────────────────────────────────────────

DOC_ENTITIES = [
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "IBAN",
    "CREDIT_CARD",
    "PASSPORT",
    "NATIONAL_ID",
    "IP_ADDRESS",
    "URL",
    "DATE",
    "VEHICLE",
    "LOCATION",
    "ORGANIZATION",
    "MEDICAL_LICENSE",
    "US_BANK_NUMBER",
    "US_DRIVER_LICENSE",
    "NRP",               # Nationality / Religion / Political group
]

# Map Presidio entity type → vault placeholder type label
ENTITY_LABEL_MAP = {
    "PERSON":            "NAME",
    "EMAIL_ADDRESS":     "EMAIL",
    "PHONE_NUMBER":      "PHONE",
    "IBAN":              "IBAN",
    "CREDIT_CARD":       "CREDIT_CARD",
    "PASSPORT":          "PASSPORT",
    "NATIONAL_ID":       "NATIONAL_ID",
    "IP_ADDRESS":        "IP_ADDRESS",
    "URL":               "URL",
    "DATE":              "DATE",
    "VEHICLE":           "VEHICLE",
    "LOCATION":          "LOCATION",
    "ORGANIZATION":      "ORG",
    "MEDICAL_LICENSE":   "MEDICAL_ID",
    "US_BANK_NUMBER":    "BANK_ACCOUNT",
    "US_DRIVER_LICENSE": "DRIVER_LICENSE",
    "NRP":               "NRP",
}


# ─────────────────────────────────────────────
# Analyzer setup
# ─────────────────────────────────────────────

def _build_analyzer() -> AnalyzerEngine:
    """Build and return a Presidio AnalyzerEngine with all custom recognizers."""
    provider = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [
            {"lang_code": "en", "model_name": "en_core_web_lg"}
        ],
    })
    nlp_engine = provider.create_engine()

    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])

    # Remove Presidio's built-in URL recognizer — it's too aggressive
    # and matches bare domains inside email addresses before EMAIL_ADDRESS fires
    try:
        analyzer.registry.remove_recognizer("UrlRecognizer")
    except Exception:
        pass

    # Register custom recognizers
    for recognizer in [
        _build_iban_recognizer(),
        _build_phone_recognizer(),
        _build_credit_card_recognizer(),
        _build_passport_recognizer(),
        _build_national_id_recognizer(),
        _build_ip_address_recognizer(),
        _build_url_recognizer(),
        _build_date_recognizer(),
        # _build_vehicle_recognizer(),
    ]:
        analyzer.registry.add_recognizer(recognizer)

    return analyzer


# Singleton — build once per session
_analyzer: AnalyzerEngine | None = None

def get_analyzer() -> AnalyzerEngine:
    global _analyzer
    if _analyzer is None:
        _analyzer = _build_analyzer()
    return _analyzer


# ─────────────────────────────────────────────
# Main detection function
# ─────────────────────────────────────────────

def detect_and_mask(
    text: str,
    vault: Vault,
    language: str = "en",
    entities: list[str] | None = None,
    score_threshold: float = 0.5,
) -> str:
    """
    Detect PII in text, register each finding in the vault,
    and return the masked text with placeholders.
    """
    if entities is None:
        entities = DOC_ENTITIES
    
    analyzer = get_analyzer()

    results: list[RecognizerResult] = analyzer.analyze(
        text=text,
        entities=entities,
        language=language,
        score_threshold=score_threshold,
    )

    if not results:
        return text

    # Clip any span that crosses a pipe separator (CSV field boundary)
    import re as _re
    clipped = []
    for r in results:
        span = text[r.start:r.end]
        pipe_pos = span.find('|')
        if pipe_pos != -1:
            # Truncate span to just before the pipe
            new_end = r.start + pipe_pos
            new_span = text[r.start:new_end].strip()
            if len(new_span) > 1:
                from presidio_analyzer import RecognizerResult
                clipped.append(RecognizerResult(
                    entity_type=r.entity_type,
                    start=r.start,
                    end=r.start + len(new_span),
                    score=r.score,
                ))
        else:
            clipped.append(r)
    results = clipped

    # Filter structural false positives before anything else
    results = [
        r for r in results
        if not _is_structural_false_positive(text[r.start:r.end], r.entity_type)
    ]

    if not results:
        return text

    # Sort by score descending first — highest confidence wins when spans overlap
    results = sorted(results, key=lambda r: r.score, reverse=True)

    # Deduplicate overlapping spans — highest score always wins
    deduped: list[RecognizerResult] = []
    for result in results:
        overlaps = any(
            r.start < result.end and r.end > result.start
            for r in deduped
        )
        if not overlaps:
            deduped.append(result)

    # Now sort by start position descending for safe replacement
    # (replace from end to start so earlier indices stay valid)
    deduped = sorted(deduped, key=lambda r: r.start, reverse=True)

    masked = text
    for result in deduped:
        real_value = text[result.start:result.end]
        entity_label = ENTITY_LABEL_MAP.get(result.entity_type, result.entity_type)
        placeholder = vault.add(real_value, entity_label)
        masked = masked[:result.start] + placeholder + masked[result.end:]

    return masked


# ─────────────────────────────────────────────
# Utility — scan only (no masking), for previews
# ─────────────────────────────────────────────

def scan_only(
    text: str,
    language: str = "en",
    score_threshold: float = 0.5,
) -> list[dict[str, Any]]:
    """
    Return a list of detected PII findings without modifying the text.
    Useful for previewing what would be masked.
    """
    analyzer = get_analyzer()
    results = analyzer.analyze(
        text=text,
        entities=DOC_ENTITIES,
        language=language,
        score_threshold=score_threshold,
    )
    return [
        {
            "entity_type": r.entity_type,
            "value": text[r.start:r.end],
            "score": round(r.score, 2),
            "start": r.start,
            "end": r.end,
        }
        for r in sorted(results, key=lambda x: x.start)
    ]