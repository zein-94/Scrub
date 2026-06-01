# Scrub CLI — Privacy-first PII masking for AI agents
# Copyright (C) 2024 Scrub Contributors
# Licensed under GNU GPL v3 — see LICENSE for details
# analyzers/security.py

import ast
import re
import json
import tempfile
import textwrap
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from rich.console import Console


# ─────────────────────────────────────────────
# Severity levels
# ─────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


SEVERITY_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "red",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "cyan",
    Severity.INFO:     "dim",
}

SEVERITY_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
    Severity.INFO:     "⚪",
}


# ─────────────────────────────────────────────
# Finding dataclass
# ─────────────────────────────────────────────

@dataclass
class SecurityFinding:
    rule_id:     str
    title:       str
    description: str
    severity:    Severity
    line_number: int
    line_text:   str       = ""
    cwe:         str       = ""    # e.g. "CWE-89: SQL Injection"
    advice:      str       = ""    # what to do instead
    source:      str       = "custom"  # "bandit" or "custom"


# ─────────────────────────────────────────────
# Custom exploit / vulnerability rules
# These are patterns Bandit doesn't cover well
# ─────────────────────────────────────────────

@dataclass
class ExploitRule:
    rule_id:     str
    title:       str
    description: str
    severity:    Severity
    regex:       str
    cwe:         str  = ""
    advice:      str  = ""
    languages:   list[str] = field(default_factory=lambda: ["python", "js", "ts", "any"])


EXPLOIT_RULES: list[ExploitRule] = [

    # ── Injection ────────────────────────────────────────────────────
    ExploitRule(
        rule_id="SCRUB-001",
        title="SQL Injection Risk",
        description="String formatting or concatenation used to build SQL query.",
        severity=Severity.CRITICAL,
        regex=r"(?i)(execute|cursor\.execute|query|raw)\s*\(\s*['\"].*?['\"].*?%|f['\"].*?SELECT|f['\"].*?INSERT|f['\"].*?UPDATE|f['\"].*?DELETE",
        cwe="CWE-89: SQL Injection",
        advice="Use parameterized queries or an ORM instead of string formatting.",
    ),
    ExploitRule(
        rule_id="SCRUB-002",
        title="Command Injection Risk",
        description="User-controlled input may be passed to a shell command.",
        severity=Severity.CRITICAL,
        regex=r"(?:os\.system|subprocess\.call|subprocess\.run|popen)\s*\(\s*(?:f['\"]|['\"].*?\+|.*?format)",
        cwe="CWE-78: OS Command Injection",
        advice="Avoid shell=True. Use subprocess with a list of arguments and validate all input.",
    ),
    ExploitRule(
        rule_id="SCRUB-003",
        title="LDAP Injection Risk",
        description="Unescaped input used in LDAP filter construction.",
        severity=Severity.HIGH,
        regex=r"(?i)ldap.*search.*filter.*[\+%]|ldap.*filter.*format",
        cwe="CWE-90: LDAP Injection",
        advice="Use an LDAP library that supports parameterized filters and escape all user input.",
    ),
    ExploitRule(
        rule_id="SCRUB-004",
        title="XPath Injection Risk",
        description="Unescaped input used in XPath expression.",
        severity=Severity.HIGH,
        regex=r"(?i)xpath.*[\+%].*input|find\(.*f['\"]",
        cwe="CWE-643: XPath Injection",
        advice="Sanitize all user input before including in XPath expressions.",
    ),

    # ── Cryptography ─────────────────────────────────────────────────
    ExploitRule(
        rule_id="SCRUB-005",
        title="Weak Hashing Algorithm",
        description="MD5 or SHA1 used — both are cryptographically broken.",
        severity=Severity.HIGH,
        regex=r"(?i)hashlib\.(md5|sha1)\s*\(|(?:md5|sha1)\s*\(",
        cwe="CWE-327: Use of Broken Cryptographic Algorithm",
        advice="Use SHA-256 or stronger. For passwords, use bcrypt, scrypt, or argon2.",
    ),
    ExploitRule(
        rule_id="SCRUB-006",
        title="Hardcoded Salt or IV",
        description="Static salt or initialization vector detected — weakens encryption.",
        severity=Severity.HIGH,
        regex=r"(?i)(?:salt|iv|nonce)\s*=\s*['\"][^'\"]{4,}['\"]",
        cwe="CWE-760: Predictable Salt",
        advice="Generate cryptographic salt/IV randomly using os.urandom() or secrets module.",
    ),
    ExploitRule(
        rule_id="SCRUB-007",
        title="Insecure Random Number Generator",
        description="random module used for security-sensitive context.",
        severity=Severity.MEDIUM,
        regex=r"(?i)import random|random\.(?:random|randint|choice|seed)\s*\(",
        cwe="CWE-338: Use of Cryptographically Weak PRNG",
        advice="Use the secrets module for security-sensitive random values.",
    ),

    # ── Deserialization ───────────────────────────────────────────────
    ExploitRule(
        rule_id="SCRUB-008",
        title="Unsafe Deserialization (pickle)",
        description="pickle.loads() on untrusted data allows arbitrary code execution.",
        severity=Severity.CRITICAL,
        regex=r"pickle\.loads?\s*\(",
        cwe="CWE-502: Deserialization of Untrusted Data",
        advice="Never unpickle data from untrusted sources. Use JSON or protobuf instead.",
    ),
    ExploitRule(
        rule_id="SCRUB-009",
        title="Unsafe YAML Load",
        description="yaml.load() without Loader can execute arbitrary Python.",
        severity=Severity.CRITICAL,
        regex=r"yaml\.load\s*\(\s*(?!.*Loader=yaml\.SafeLoader)",
        cwe="CWE-502: Deserialization of Untrusted Data",
        advice="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader) instead.",
    ),
    ExploitRule(
        rule_id="SCRUB-010",
        title="Unsafe eval() Usage",
        description="eval() on dynamic or user-controlled input is a code injection vector.",
        severity=Severity.CRITICAL,
        regex=r"\beval\s*\(\s*(?![\'\"])",
        cwe="CWE-95: Improper Neutralization of Directives in Eval",
        advice="Avoid eval() entirely. Use ast.literal_eval() for safe expression parsing.",
    ),

    # ── Network & TLS ─────────────────────────────────────────────────
    ExploitRule(
        rule_id="SCRUB-011",
        title="TLS Certificate Verification Disabled",
        description="SSL/TLS certificate verification is turned off — enables MITM attacks.",
        severity=Severity.CRITICAL,
        regex=r"(?i)verify\s*=\s*False|ssl_verify\s*=\s*False|check_hostname\s*=\s*False",
        cwe="CWE-295: Improper Certificate Validation",
        advice="Never disable certificate verification in production. Fix the certificate instead.",
    ),
    ExploitRule(
        rule_id="SCRUB-012",
        title="Hardcoded HTTP (Non-HTTPS) URL",
        description="Plain HTTP URL detected — traffic is unencrypted.",
        severity=Severity.MEDIUM,
        regex=r"['\"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^'\"]{4,}['\"]",
        cwe="CWE-319: Cleartext Transmission of Sensitive Information",
        advice="Use HTTPS for all external endpoints.",
    ),
    ExploitRule(
        rule_id="SCRUB-013",
        title="Binding to All Interfaces (0.0.0.0)",
        description="Server binding to 0.0.0.0 exposes it on all network interfaces.",
        severity=Severity.MEDIUM,
        regex=r"['\"]0\.0\.0\.0['\"]",
        cwe="CWE-605: Multiple Binds to the Same Port",
        advice="Bind to 127.0.0.1 in development. Use a reverse proxy in production.",
    ),

    # ── Auth & Session ─────────────────────────────────────────────────
    ExploitRule(
        rule_id="SCRUB-014",
        title="Hardcoded JWT Secret",
        description="JWT signing secret is hardcoded in source — can be extracted.",
        severity=Severity.CRITICAL,
        regex=r"(?i)(?:jwt|token).*secret\s*=\s*['\"][^'\"]{4,}['\"]",
        cwe="CWE-321: Use of Hard-coded Cryptographic Key",
        advice="Load JWT secrets from environment variables or a secrets manager.",
    ),
    ExploitRule(
        rule_id="SCRUB-015",
        title="Weak Session Secret",
        description="Session secret key appears short or predictable.",
        severity=Severity.HIGH,
        regex=r"(?i)(?:secret[_-]?key|session[_-]?secret)\s*=\s*['\"][^'\"]{4,20}['\"]",
        cwe="CWE-331: Insufficient Entropy",
        advice="Use a cryptographically random secret of at least 32 bytes via secrets.token_hex(32).",
    ),

    # ── File System ───────────────────────────────────────────────────
    ExploitRule(
        rule_id="SCRUB-016",
        title="Path Traversal Risk",
        description="User input used in file path without sanitization.",
        severity=Severity.HIGH,
        regex=r"(?i)open\s*\(\s*(?:request|input|user|param|data)|os\.path\.join\s*\([^)]*(?:request|input|user)",
        cwe="CWE-22: Path Traversal",
        advice="Validate and sanitize file paths. Use pathlib and ensure the resolved path is within the expected directory.",
    ),
    ExploitRule(
        rule_id="SCRUB-017",
        title="Insecure Temporary File",
        description="tempfile.mktemp() is insecure — race condition between creation and use.",
        severity=Severity.MEDIUM,
        regex=r"tempfile\.mktemp\s*\(",
        cwe="CWE-377: Insecure Temporary File",
        advice="Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead.",
    ),

    # ── Debug & Logging ───────────────────────────────────────────────
    ExploitRule(
        rule_id="SCRUB-018",
        title="Debug Mode Enabled",
        description="Debug mode left on — exposes stack traces and internal info.",
        severity=Severity.HIGH,
        regex=r"(?i)(?:debug\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True)",
        cwe="CWE-94: Improper Control of Generation of Code",
        advice="Disable debug mode in production. Use environment variables to control this.",
    ),
    ExploitRule(
        rule_id="SCRUB-019",
        title="Sensitive Data in Log Statement",
        description="Password, token, or secret may be logged in plaintext.",
        severity=Severity.HIGH,
        regex=r"(?i)(?:log|print|logger)\s*.*(?:password|passwd|secret|token|api_key|credential)",
        cwe="CWE-532: Insertion of Sensitive Information into Log File",
        advice="Never log sensitive values. Mask or omit them from log output.",
    ),

    # ── Dependency & Supply Chain ─────────────────────────────────────
    ExploitRule(
        rule_id="SCRUB-020",
        title="Unpinned Dependency",
        description="Dependency without pinned version — vulnerable to supply chain attacks.",
        severity=Severity.LOW,
        regex=r"^(?!#)[\w\-]+\s*(?:>=|<=|~=|!=|>|<)\s*[\d.]+\s*$|^(?!#)[\w\-]+\s*$",
        cwe="CWE-1357: Reliance on Insufficiently Trustworthy Component",
        advice="Pin all dependencies to exact versions (==) in production.",
    ),
]


# ─────────────────────────────────────────────
# Bandit runner
# ─────────────────────────────────────────────

def _run_bandit(code: str) -> list[SecurityFinding]:
    """
    Run Bandit on code string via temp file.
    Returns findings as SecurityFinding objects.
    """
    findings: list[SecurityFinding] = []

    try:
        import bandit
        from bandit.core import manager as bandit_manager
        from bandit.core import config as bandit_config
    except ImportError:
        return findings

    try:
        with tempfile.NamedTemporaryFile(
            suffix=".py", mode="w", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(code)
            tmp_path = tmp.name

        import subprocess, sys
        result = subprocess.run(
            [
                sys.executable, "-m", "bandit",
                "-f", "json",
                "-q",
                tmp_path,
            ],
            capture_output=True,
            text=True,
        )

        if result.stdout:
            data = json.loads(result.stdout)
            for issue in data.get("results", []):
                sev_str = issue.get("issue_severity", "LOW").upper()
                try:
                    severity = Severity[sev_str]
                except KeyError:
                    severity = Severity.LOW

                findings.append(SecurityFinding(
                    rule_id=issue.get("test_id", "B000"),
                    title=issue.get("test_name", "Bandit Issue").replace("_", " ").title(),
                    description=issue.get("issue_text", ""),
                    severity=severity,
                    line_number=issue.get("line_number", 0),
                    line_text=issue.get("code", "").strip(),
                    cwe=str(issue.get("issue_cwe", {}).get("id", "") or ""),
                    advice="See https://bandit.readthedocs.io for remediation guidance.",
                    source="bandit",
                ))

        Path(tmp_path).unlink(missing_ok=True)

    except Exception:
        pass  # Bandit failures are non-fatal — custom rules still run

    return findings


# ─────────────────────────────────────────────
# Custom rule runner
# ─────────────────────────────────────────────

def _run_custom_rules(
    code: str,
    file_extension: str = "py",
) -> list[SecurityFinding]:
    """Run all custom exploit rules against the code."""
    findings: list[SecurityFinding] = []
    lines = code.splitlines()

    for rule in EXPLOIT_RULES:
        # Skip rules not applicable to this file type
        if "any" not in rule.languages and file_extension not in rule.languages:
            continue

        for match in re.finditer(rule.regex, code, re.MULTILINE | re.DOTALL):
            start = match.start()
            line_number = code[:start].count("\n") + 1
            line_text = lines[line_number - 1].strip() if line_number <= len(lines) else ""

            # Avoid duplicate findings on same rule + line
            already_found = any(
                f.rule_id == rule.rule_id and f.line_number == line_number
                for f in findings
            )
            if already_found:
                continue

            findings.append(SecurityFinding(
                rule_id=rule.rule_id,
                title=rule.title,
                description=rule.description,
                severity=rule.severity,
                line_number=line_number,
                line_text=line_text,
                cwe=rule.cwe,
                advice=rule.advice,
                source="custom",
            ))

    return findings


# ─────────────────────────────────────────────
# Main analysis function
# ─────────────────────────────────────────────

def analyze_code(
    code: str,
    console: Console,
    file_extension: str = "py",
    show_low: bool = True,
) -> list[SecurityFinding]:
    """
    Run full security analysis on code:
      1. Bandit (Python AST-based)
      2. Custom regex exploit rules

    Prints findings to console and returns the full list.
    """
    from rich.table import Table
    from rich.panel import Panel

    all_findings: list[SecurityFinding] = []

    # Run Bandit for Python files
    if file_extension == "py":
        bandit_findings = _run_bandit(code)
        all_findings.extend(bandit_findings)

    # Run custom rules
    custom_findings = _run_custom_rules(code, file_extension)
    all_findings.extend(custom_findings)

    # Deduplicate by title + line (Bandit and custom may overlap)
    seen: set[tuple[str, int]] = set()
    deduped: list[SecurityFinding] = []
    for f in all_findings:
        key = (f.title, f.line_number)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # Sort by severity then line number
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH:     1,
        Severity.MEDIUM:   2,
        Severity.LOW:      3,
        Severity.INFO:     4,
    }
    deduped.sort(key=lambda f: (severity_order[f.severity], f.line_number))

    # Filter low if requested
    if not show_low:
        deduped = [f for f in deduped if f.severity not in (Severity.LOW, Severity.INFO)]

    # ── Print to console ─────────────────────────────────────────────
    if not deduped:
        console.print("\n[green]✓[/green] No security issues detected.")
        return deduped

    critical_count = sum(1 for f in deduped if f.severity == Severity.CRITICAL)
    high_count     = sum(1 for f in deduped if f.severity == Severity.HIGH)
    medium_count   = sum(1 for f in deduped if f.severity == Severity.MEDIUM)
    low_count      = sum(1 for f in deduped if f.severity in (Severity.LOW, Severity.INFO))

    # Summary header
    summary = (
        f"[bold red]{critical_count} CRITICAL[/bold red]  "
        f"[red]{high_count} HIGH[/red]  "
        f"[yellow]{medium_count} MEDIUM[/yellow]  "
        f"[cyan]{low_count} LOW[/cyan]"
    )
    console.print(Panel(summary, title="⚠  Security Analysis", border_style="red"))

    # Detail table
    table = Table(
        show_lines=True,
        border_style="dim",
        show_header=True,
        header_style="bold",
    )
    table.add_column("Sev",        width=10,  no_wrap=True)
    table.add_column("Rule",       width=11,  no_wrap=True, style="dim")
    table.add_column("Title",      width=28)
    table.add_column("Line",       width=6,   justify="right")
    table.add_column("CWE",        width=16,  style="dim")

    for f in deduped:
        color = SEVERITY_COLOR[f.severity]
        icon  = SEVERITY_ICON[f.severity]
        table.add_row(
            f"{icon} [{color}]{f.severity.value}[/{color}]",
            str(f.rule_id),
            str(f.title),
            str(f.line_number),
            str(f.cwe) if f.cwe else "—",
        )

    console.print(table)

    # Print details for CRITICAL and HIGH only
    critical_high = [f for f in deduped if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if critical_high:
        console.print("\n[bold red]⚠  DO NOT share this code with AI agents until these are resolved:[/bold red]\n")
        for f in critical_high:
            color = SEVERITY_COLOR[f.severity]
            console.print(f"  [{color}]{SEVERITY_ICON[f.severity]} {f.rule_id} — {f.title}[/{color}]")
            console.print(f"  [dim]Line {f.line_number}:[/dim] {f.line_text}")
            if f.description:
                console.print(f"  {f.description}")
            if f.advice:
                console.print(f"  [green]→ Fix:[/green] {f.advice}")
            console.print()

    return deduped