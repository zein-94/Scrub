# detectors/secrets.py

import re
from dataclasses import dataclass
from typing import Any
from vault import Vault


# ─────────────────────────────────────────────
# Secret pattern registry
# Each entry defines a credential type,
# its regex, and a confidence score
# ─────────────────────────────────────────────

@dataclass
class SecretPattern:
    name: str           # Vault label e.g. "AWS_KEY"
    regex: str          # Detection pattern
    score: float        # Confidence 0.0 - 1.0
    description: str    # Human-readable label for CLI output
    group: int = 1      # Regex capture group containing the secret value


SECRET_PATTERNS: list[SecretPattern] = [

    # ── Cloud Providers ──────────────────────────────────────────────
    SecretPattern(
        name="AWS_ACCESS_KEY",
        regex=r"(?i)(AKIA[0-9A-Z]{16})",
        score=0.99,
        description="AWS Access Key ID",
        group=1,
    ),
    SecretPattern(
        name="AWS_SECRET_KEY",
        regex=r"(?i)(?:aws_secret_access_key|aws_secret)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        score=0.95,
        description="AWS Secret Access Key",
    ),
    SecretPattern(
        name="GCP_SERVICE_ACCOUNT",
        regex=r'"private_key"\s*:\s*"(-----BEGIN RSA PRIVATE KEY-----[^"]+)"',
        score=0.99,
        description="GCP Service Account Private Key",
    ),
    SecretPattern(
        name="AZURE_CLIENT_SECRET",
        regex=r"(?i)(?:azure|az)_?(?:client)?_?secret\s*[=:]\s*['\"]?([A-Za-z0-9\-._~]{32,})['\"]?",
        score=0.85,
        description="Azure Client Secret",
    ),

    # ── API Keys (generic + specific) ────────────────────────────────
    SecretPattern(
        name="API_KEY",
        regex=r"(?i)(?:api[_-]?key|apikey|api[_-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9\-._~+/]{16,})['\"]?",
        score=0.8,
        description="Generic API Key",
    ),
    SecretPattern(
        name="STRIPE_KEY",
        regex=r"((?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,})",
        score=0.99,
        description="Stripe Secret/Public Key",
        group=1,
    ),
    SecretPattern(
        name="SENDGRID_KEY",
        regex=r"(SG\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,})",
        score=0.99,
        description="SendGrid API Key",
        group=1,
    ),
    SecretPattern(
        name="TWILIO_KEY",
        regex=r"(SK[a-f0-9]{32})",
        score=0.9,
        description="Twilio API Key",
        group=1,
    ),
    SecretPattern(
        name="GITHUB_TOKEN",
        regex=r"(gh[pousr]_[A-Za-z0-9]{20,})",
        score=0.99,
        description="GitHub Personal Access Token",
        group=1,
    ),
    SecretPattern(
        name="GITLAB_TOKEN",
        regex=r"(glpat-[A-Za-z0-9\-_]{20,})",
        score=0.99,
        description="GitLab Personal Access Token",
        group=1,
    ),
    SecretPattern(
        name="SLACK_TOKEN",
        regex=r"(xox[baprs]-[A-Za-z0-9\-]{10,})",
        score=0.99,
        description="Slack Token",
        group=1,
    ),
    SecretPattern(
        name="OPENAI_KEY",
        regex=r"(sk-[A-Za-z0-9]{32,})",
        score=0.9,
        description="OpenAI API Key",
        group=1,
    ),
    SecretPattern(
        name="ANTHROPIC_KEY",
        regex=r"(sk-ant-[A-Za-z0-9\-_]{32,})",
        score=0.99,
        description="Anthropic API Key",
        group=1,
    ),
    SecretPattern(
        name="MAILCHIMP_KEY",
        regex=r"([a-f0-9]{32}-us\d+)",
        score=0.9,
        description="Mailchimp API Key",
        group=1,
    ),
    SecretPattern(
        name="MAPBOX_TOKEN",
        regex=r"(pk\.eyJ1[A-Za-z0-9\-_.]+)",
        score=0.95,
        description="Mapbox Token",
        group=1,
    ),

    # ── Passwords & Secrets ──────────────────────────────────────────
    SecretPattern(
        name="PASSWORD",
        regex=r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{6,})['\"]",
        score=0.8,
        description="Hardcoded Password",
    ),
    SecretPattern(
        name="SECRET",
        # Lowered minimum to 4 chars — catches short secrets like "sess123"
        regex=r"(?i)(?:secret|secret_key|app_secret|session_secret)\s*[=:]\s*['\"]([^'\"]{4,})['\"]",
        score=0.75,
        description="Hardcoded Secret",
    ),
    SecretPattern(
        name="ENCRYPTION_KEY",
        regex=r"(?i)(?:encryption[_-]?key|aes[_-]?key|hmac[_-]?secret)\s*[=:]\s*['\"]?([A-Za-z0-9+/=]{16,})['\"]?",
        score=0.85,
        description="Encryption Key",
    ),

    # ── Tokens ───────────────────────────────────────────────────────
    SecretPattern(
        name="JWT_TOKEN",
        regex=r"(eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+)",
        score=0.95,
        description="JWT Token",
        group=1,
    ),
    SecretPattern(
        name="BEARER_TOKEN",
        regex=r"(?i)bearer\s+([A-Za-z0-9\-_.~+/]{20,})",
        score=0.85,
        description="Bearer Token",
    ),
    SecretPattern(
        name="OAUTH_TOKEN",
        regex=r"(?i)(?:access[_-]?token|oauth[_-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9\-_.~+/]{20,})['\"]?",
        score=0.8,
        description="OAuth Access Token",
    ),
    SecretPattern(
        name="REFRESH_TOKEN",
        regex=r"(?i)refresh[_-]?token\s*[=:]\s*['\"]?([A-Za-z0-9\-_.~+/]{20,})['\"]?",
        score=0.8,
        description="Refresh Token",
    ),

    # ── Database & Connection Strings ─────────────────────────────────
    SecretPattern(
        name="DB_PASSWORD",
        regex=r"(?i)(?:db[_-]?password|database[_-]?password)\s*[=:]\s*['\"]([^'\"]{4,})['\"]",
        score=0.85,
        description="Database Password",
    ),
    SecretPattern(
        name="CONNECTION_STRING",
        # Handles both user:pass@host and :pass@host (empty username like Redis)
        regex=r"(?i)(?:mongodb|postgresql|mysql|redis|amqp|mssql)://[^\s'\"@]*:[^\s'\"@]+@[^\s'\"]+",
        score=0.95,
        description="Database Connection String",
        group=0,
    ),
    SecretPattern(
        name="DSN",
        regex=r"(?i)(?:dsn|data[_-]?source[_-]?name)\s*[=:]\s*['\"]([^'\"]+)['\"]",
        score=0.8,
        description="DSN / Data Source Name",
    ),

    # ── Private Keys & Certificates ──────────────────────────────────
    SecretPattern(
        name="RSA_PRIVATE_KEY",
        regex=r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[^-]+-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)",
        score=0.99,
        description="Private Key (PEM)",
        group=1,
    ),
    SecretPattern(
        name="CERTIFICATE",
        regex=r"(-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----)",
        score=0.9,
        description="Certificate (PEM)",
        group=1,
    ),

    # ── Infrastructure ───────────────────────────────────────────────
    SecretPattern(
        name="SSH_KEY",
        regex=r"(ssh-(?:rsa|dss|ed25519|ecdsa)\s+AAAA[A-Za-z0-9+/]+[=]{0,3}(?:\s+\S+)?)",
        score=0.99,
        description="SSH Public Key",
        group=1,
    ),
    SecretPattern(
        name="WEBHOOK_URL",
        regex=r"(https://(?:hooks\.slack\.com|discord\.com/api/webhooks)/[^\s'\"]+)",
        score=0.95,
        description="Webhook URL (Slack/Discord)",
        group=1,
    ),
    SecretPattern(
        name="IP_ADDRESS",
        # Matches both inline context (host = "x") and variable names (INTERNAL_HOST = "x")
        regex=r"(?i)(?:[A-Z_]*(?:server|host|ip|endpoint|addr)[A-Z_]*)\s*[=:]\s*['\"]?((?:\d{1,3}\.){3}\d{1,3})['\"]?",
        score=0.7,
        description="Hardcoded IP / Server Address",
    ),
]


# ─────────────────────────────────────────────
# Detection result dataclass
# ─────────────────────────────────────────────

@dataclass
class SecretFinding:
    name: str           # e.g. "AWS_ACCESS_KEY"
    description: str    # e.g. "AWS Access Key ID"
    value: str          # actual secret value found
    line_number: int    # line it was found on
    score: float        # confidence score


# ─────────────────────────────────────────────
# Main detection function
# ─────────────────────────────────────────────

def detect_secrets(
    text: str,
    vault: Vault,
    score_threshold: float = 0.7,
) -> tuple[str, list[SecretFinding]]:
    """
    Scan text for credentials and secrets.
    Registers findings in the vault and returns:
      - masked text with placeholders
      - list of SecretFinding for CLI reporting
    """
    findings: list[SecretFinding] = []
    lines = text.split("\n")

    # Build a map of character offset -> line number for reporting
    line_offsets: list[int] = []
    offset = 0
    for line in lines:
        line_offsets.append(offset)
        offset += len(line) + 1  # +1 for newline

    def _get_line_number(pos: int) -> int:
        for i, start in enumerate(reversed(line_offsets)):
            if pos >= start:
                return len(line_offsets) - i
        return 1

    # Track spans already masked to avoid double replacement
    masked_spans: list[tuple[int, int]] = []
    replacements: list[tuple[int, int, str]] = []  # (start, end, placeholder)

    for pattern in SECRET_PATTERNS:
        if pattern.score < score_threshold:
            continue

        flags = re.DOTALL | re.MULTILINE
        for match in re.finditer(pattern.regex, text, flags):
            # Extract the secret value from the right group
            group_idx = pattern.group if pattern.group < len(match.groups()) + 1 else 0
            try:
                secret_value = match.group(group_idx)
                start = match.start(group_idx)
                end = match.end(group_idx)
            except IndexError:
                secret_value = match.group(0)
                start = match.start(0)
                end = match.end(0)

            if not secret_value:
                continue

            # Skip if this span is already handled
            overlaps = any(s < end and e > start for s, e in masked_spans)
            if overlaps:
                continue

            masked_spans.append((start, end))
            line_num = _get_line_number(start)

            findings.append(SecretFinding(
                name=pattern.name,
                description=pattern.description,
                value=secret_value,
                line_number=line_num,
                score=pattern.score,
            ))

            placeholder = vault.add(secret_value, pattern.name)
            replacements.append((start, end, placeholder))

    # Apply replacements from end to start to preserve offsets
    replacements.sort(key=lambda x: x[0], reverse=True)
    masked = text
    for start, end, placeholder in replacements:
        masked = masked[:start] + placeholder + masked[end:]

    return masked, findings


# ─────────────────────────────────────────────
# Utility — scan only (no masking)
# ─────────────────────────────────────────────

def scan_secrets_only(
    text: str,
    score_threshold: float = 0.7,
) -> list[dict[str, Any]]:
    """
    Dry-run scan — returns findings without modifying text or vault.
    """
    from vault import Vault
    dummy_vault = Vault()
    _, findings = detect_secrets(text, dummy_vault, score_threshold)
    return [
        {
            "name": f.name,
            "description": f.description,
            "value": f.value,
            "line_number": f.line_number,
            "score": f.score,
        }
        for f in findings
    ]