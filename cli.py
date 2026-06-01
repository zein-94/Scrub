# Scrub CLI — Privacy-first PII masking for AI agents
# Copyright (C) 2024 Scrub Contributors
# Licensed under GNU GPL v3 — see LICENSE for details
# cli.py
import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from typing import Optional
from pathlib import Path
import sys

app = typer.Typer(
    name="scrub",
    help="Scrub — Keep your sensitive data out of AI agents.",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console()


def version_callback(value: bool):
    if value:
        console.print("[bold cyan]Scrub[/bold cyan] v1.0.0")
        raise typer.Exit()


def print_banner():
    banner = Text()
    banner.append("🧹 Scrub", style="bold cyan")
    banner.append(" — Sanitize before you send.", style="dim")
    console.print(Panel(banner, border_style="cyan", padding=(0, 2)))


@app.command("mask")
def mask(
    input_path: Path = typer.Argument(
        ...,
        help="Path to input file. Use '-' to read from stdin.",
        metavar="INPUT",
    ),
    mode: str = typer.Option(
        "doc",
        "--mode", "-m",
        help="[bold]doc[/bold] — emails/docs/sheets  |  [bold]code[/bold] — source code",
        show_default=True,
    ),
    output_path: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Write masked output to file instead of stdout.",
    ),
    vault_path: Optional[Path] = typer.Option(
        None,
        "--vault", "-v",
        help="Save placeholder↔real mapping to an encrypted vault file (for restore later).",
    ),
    language: str = typer.Option(
        "en",
        "--lang", "-l",
        help="Language hint for PII detection (e.g. en, fr, de).",
        show_default=True,
    ),
):
    """
    [bold cyan]Mask[/bold cyan] sensitive data in a file or stdin.

    \b
    Examples:
      scrub mask email.txt
      scrub mask report.docx --mode doc --vault session.vault
      scrub mask main.py --mode code
      cat file.txt | scrub mask -
    """
    print_banner()

    # Validate mode
    if mode not in ("doc", "code"):
        console.print("[red]✗[/red] Invalid mode. Choose [bold]doc[/bold] or [bold]code[/bold].")
        raise typer.Exit(code=1)

    # Read input
    if str(input_path) == "-":
        console.print("[dim]Reading from stdin...[/dim]")
        raw_text = sys.stdin.read()
        file_type = "txt"
    else:
        if not input_path.exists():
            console.print(f"[red]✗[/red] File not found: [bold]{input_path}[/bold]")
            raise typer.Exit(code=1)
        file_type = input_path.suffix.lstrip(".").lower()
        raw_text = None  # parsers will handle file reading

    # Dispatch to mode
    if mode == "doc":
        from modes.document import run_document_mode
        masked_text, vault = run_document_mode(
            input_path=input_path if str(input_path) != "-" else None,
            raw_text=raw_text,
            file_type=file_type,
            language=language,
            console=console,
        )
    else:
        from modes.code import run_code_mode
        masked_text, vault = run_code_mode(
            input_path=input_path if str(input_path) != "-" else None,
            raw_text=raw_text,
            console=console,
        )

    # Output masked text
    if output_path:
        output_path.write_text(masked_text)
        console.print(f"\n[green]✓[/green] Masked output saved to [bold]{output_path}[/bold]")
    else:
        console.rule("[dim]Masked Output[/dim]")
        console.print(masked_text)
        console.rule()

    # Save vault
    if vault_path:
        from vault import save_vault
        save_vault(vault, vault_path, console)
    else:
        console.print(
            "\n[yellow]⚠[/yellow]  No vault path provided. "
            "Placeholder mapping will be [bold]lost[/bold] after this session. "
            "Use [cyan]--vault[/cyan] to save it."
        )

    # Summary table
    _print_summary(vault, mode, console)


@app.command("restore")
def restore(
    input_path: Path = typer.Argument(
        ...,
        help="AI output file containing placeholders. Use '-' for stdin.",
        metavar="INPUT",
    ),
    vault_path: Path = typer.Option(
        ...,
        "--vault", "-v",
        help="Encrypted vault file produced during masking.",
    ),
    output_path: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Write restored output to file instead of stdout.",
    ),
):
    """
    [bold cyan]Restore[/bold cyan] real values into AI output using a saved vault.

    \b
    Examples:
      scrub restore ai_response.txt --vault session.vault
      scrub restore ai_response.txt --vault session.vault --output final.txt
      cat ai_response.txt | scrub restore - --vault session.vault
    """
    print_banner()

    if not vault_path.exists():
        console.print(f"[red]✗[/red] Vault file not found: [bold]{vault_path}[/bold]")
        raise typer.Exit(code=1)

    # Read input
    if str(input_path) == "-":
        text = sys.stdin.read()
    else:
        if not input_path.exists():
            console.print(f"[red]✗[/red] File not found: [bold]{input_path}[/bold]")
            raise typer.Exit(code=1)
        text = input_path.read_text()

    # Load vault and restore
    from vault import load_vault, restore_text
    vault = load_vault(vault_path, console)
    restored_text = restore_text(text, vault, console)

    # Output
    if output_path:
        output_path.write_text(restored_text)
        console.print(f"\n[green]✓[/green] Restored output saved to [bold]{output_path}[/bold]")
    else:
        console.rule("[dim]Restored Output[/dim]")
        console.print(restored_text)
        console.rule()


def _print_summary(vault: dict, mode: str, console: Console):
    """Print a summary table of what was masked."""
    if not vault:
        console.print("\n[dim]No sensitive data detected.[/dim]")
        return

    table = Table(title="Scrub Summary", border_style="cyan", show_lines=True)
    table.add_column("Placeholder", style="bold yellow", no_wrap=True)
    table.add_column("Type", style="cyan")
    table.add_column("Real Value (local only)", style="dim red")

    for placeholder, entry in vault.items():
        table.add_row(
            placeholder,
            entry.get("type", "unknown"),
            entry.get("value", ""),
        )

    console.print()
    console.print(table)
    console.print(f"\n[green]✓[/green] [bold]{len(vault)}[/bold] item(s) masked.")


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(
        None, "--version", callback=version_callback, is_eager=True
    ),
):
    """🧹 [bold cyan]Scrub[/bold cyan] — Sanitize sensitive data before sending to AI agents."""
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


if __name__ == "__main__":
    app()