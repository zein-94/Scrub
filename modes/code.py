# modes/code.py

from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.syntax import Syntax

from vault import Vault
from detectors.secrets import detect_secrets
from analyzers.security import analyze_code, Severity


# ─────────────────────────────────────────────
# Supported code file types + syntax highlight
# labels for Rich
# ─────────────────────────────────────────────

SUPPORTED_CODE_TYPES = {
    "py":    "Python",
    "js":    "JavaScript",
    "ts":    "TypeScript",
    "jsx":   "React JSX",
    "tsx":   "React TSX",
    "go":    "Go",
    "rb":    "Ruby",
    "rs":    "Rust",
    "java":  "Java",
    "kt":    "Kotlin",
    "swift": "Swift",
    "cs":    "C#",
    "cpp":   "C++",
    "c":     "C",
    "php":   "PHP",
    "sh":    "Shell",
    "bash":  "Bash",
    "zsh":   "Zsh",
    "yaml":  "YAML",
    "yml":   "YAML",
    "toml":  "TOML",
    "env":   "Dotenv",
    "tf":    "Terraform",
    "json":  "JSON",
    "xml":   "XML",
    "sql":   "SQL",
    "dockerfile": "Dockerfile",
}

# Map extension -> Rich/Pygments lexer name
SYNTAX_LEXER = {
    "py":    "python",
    "js":    "javascript",
    "ts":    "typescript",
    "jsx":   "jsx",
    "tsx":   "tsx",
    "go":    "go",
    "rb":    "ruby",
    "rs":    "rust",
    "java":  "java",
    "kt":    "kotlin",
    "swift": "swift",
    "cs":    "csharp",
    "cpp":   "cpp",
    "c":     "c",
    "php":   "php",
    "sh":    "bash",
    "bash":  "bash",
    "zsh":   "bash",
    "yaml":  "yaml",
    "yml":   "yaml",
    "toml":  "toml",
    "env":   "bash",
    "tf":    "hcl",
    "json":  "json",
    "xml":   "xml",
    "sql":   "sql",
    "dockerfile": "dockerfile",
}


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _read_code(path: Path, console: Console) -> str:
    """Read source file as plain text."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to read file: {e}")
        raise SystemExit(1)


def _print_code_snippet(
    code: str,
    line_number: int,
    ext: str,
    console: Console,
    context: int = 2,
):
    """Print a syntax-highlighted snippet around a given line."""
    lines = code.splitlines()
    start = max(0, line_number - context - 1)
    end   = min(len(lines), line_number + context)
    snippet = "\n".join(lines[start:end])
    lexer = SYNTAX_LEXER.get(ext, "text")

    console.print(
        Syntax(
            snippet,
            lexer,
            line_numbers=True,
            start_line=start + 1,
            highlight_lines={line_number},
            theme="monokai",
        )
    )


def _blocker_findings(findings) -> bool:
    """Return True if any CRITICAL or HIGH finding present."""
    return any(
        f.severity in (Severity.CRITICAL, Severity.HIGH)
        for f in findings
    )


# ─────────────────────────────────────────────
# Code mode entry point
# ─────────────────────────────────────────────

def run_code_mode(
    input_path: Optional[Path],
    raw_text: Optional[str],
    console: Console,
) -> tuple[str, Vault]:
    """
    Full code mode pipeline:
      1. Read source file
      2. Static security analysis (Bandit + custom rules)
      3. Credential / secret detection + masking
      4. Return masked code + vault
    """
    vault = Vault()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:

        # ── Step 1: Read ─────────────────────────────────────────────
        task = progress.add_task("Reading source file...", total=None)

        if raw_text is not None:
            code = raw_text
            ext  = "txt"
            file_label = "stdin"
        else:
            ext = input_path.suffix.lstrip(".").lower()
            file_label = SUPPORTED_CODE_TYPES.get(ext, f".{ext} file")
            console.print(
                f"\n[cyan]→[/cyan] Reading [bold]{file_label}[/bold]: "
                f"[dim]{input_path}[/dim]"
            )
            code = _read_code(input_path, console)

        progress.update(task, description="File loaded.")

        if not code.strip():
            console.print("[yellow]⚠[/yellow]  File appears to be empty.")
            return "", vault

        line_count = len(code.splitlines())
        char_count = len(code)
        console.print(
            f"[dim]  {line_count:,} lines · {char_count:,} characters[/dim]"
        )

        # Warn on unsupported types but still proceed
        if ext not in SUPPORTED_CODE_TYPES:
            console.print(
                f"[yellow]⚠[/yellow]  File type [bold].{ext}[/bold] is not in the "
                f"known list — proceeding with generic secret scanning."
            )

        # ── Step 2: Static Security Analysis ─────────────────────────
        progress.update(task, description="Running security analysis...")
        console.print("\n[cyan]→[/cyan] Running static security analysis...")
        progress.stop()

    # Run analysis outside progress (it prints its own output)
    sec_findings = analyze_code(
        code=code,
        console=console,
        file_extension=ext,
    )

    # ── Blocker warning ───────────────────────────────────────────────
    has_blockers = _blocker_findings(sec_findings)
    if has_blockers:
        console.print(Panel(
            "[bold red]CRITICAL or HIGH severity issues were found.\n"
            "Scrub will still mask credentials below,\n"
            "but you should fix these issues BEFORE sharing this code with any AI agent.[/bold red]",
            title="🚨  WARNING",
            border_style="red",
            padding=(1, 2),
        ))

    # ── Step 3: Secret / Credential Detection + Masking ──────────────
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning for credentials...", total=None)

        console.print(
            "\n[cyan]→[/cyan] Scanning for credentials and secrets..."
        )

        masked_code, secret_findings = detect_secrets(
            text=code,
            vault=vault,
        )

        progress.update(task, description="Done.")

    # ── Secret findings summary ───────────────────────────────────────
    if not secret_findings:
        console.print(
            "\n[green]✓[/green] No credentials or secrets detected in code."
        )
    else:
        console.print(
            f"\n[green]✓[/green] Masked [bold]{len(secret_findings)}[/bold] "
            f"credential(s):\n"
        )

        # Group by type
        type_counts: dict[str, int] = {}
        for f in secret_findings:
            type_counts[f.name] = type_counts.get(f.name, 0) + 1

        for secret_type, count in sorted(type_counts.items()):
            console.print(
                f"  [yellow]·[/yellow] {secret_type}: [bold]{count}[/bold]"
            )

        # Show line-level detail with syntax highlight
        console.print()
        for finding in secret_findings:
            console.print(
                f"  [dim]Line {finding.line_number}[/dim] "
                f"[yellow]{finding.description}[/yellow] "
                f"[dim](confidence: {int(finding.score * 100)}%)[/dim]"
            )
            if input_path and ext in SYNTAX_LEXER:
                _print_code_snippet(
                    code=code,
                    line_number=finding.line_number,
                    ext=ext,
                    console=console,
                )

    # ── Final status ──────────────────────────────────────────────────
    console.print()
    if has_blockers and not secret_findings:
        console.print(Panel(
            "[yellow]No credentials were masked, but security issues remain.\n"
            "Review and fix the issues above before sharing.[/yellow]",
            border_style="yellow",
        ))
    elif has_blockers and secret_findings:
        console.print(Panel(
            "[yellow]Credentials have been masked.\n"
            "However, CRITICAL/HIGH security issues remain in the logic itself.\n"
            "Fix those before sharing with any AI agent.[/yellow]",
            border_style="yellow",
        ))
    elif not has_blockers and secret_findings:
        console.print(
            "[green]✓[/green] All credentials masked. "
            "No critical security issues found. Safe to share."
        )
    else:
        console.print(
            "[green]✓[/green] No issues found. Safe to share."
        )

    return masked_code, vault