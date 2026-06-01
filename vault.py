# Scrub CLI — Privacy-first PII masking for AI agents
# Copyright (C) 2024 Scrub Contributors
# Licensed under GNU GPL v3 — see LICENSE for details
# vault.py
import json
import os
import re
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet
from rich.console import Console


# ─────────────────────────────────────────────
# In-memory vault structure:
# {
#   "{{EMAIL_1}}": { "value": "john@example.com", "type": "EMAIL" },
#   "{{NAME_1}}":  { "value": "John Smith",        "type": "NAME"  },
#   ...
# }
# ─────────────────────────────────────────────

class Vault:
    """
    Session-scoped, in-memory store for placeholder <-> real value mappings.
    Never written to disk unless the user explicitly calls save().
    """

    def __init__(self):
        self._store: dict[str, dict] = {}
        self._counters: dict[str, int] = {}

    def add(self, real_value: str, entity_type: str) -> str:
        """
        Register a real value and return its placeholder.
        If the same value was already registered, returns the existing placeholder.
        """
        # Deduplicate — same value always gets same placeholder
        for placeholder, entry in self._store.items():
            if entry["value"] == real_value and entry["type"] == entity_type:
                return placeholder

        # Increment counter per type
        self._counters[entity_type] = self._counters.get(entity_type, 0) + 1
        placeholder = f"{{{{{entity_type}_{self._counters[entity_type]}}}}}"

        self._store[placeholder] = {
            "value": real_value,
            "type": entity_type,
        }
        return placeholder

    def restore(self, text: str) -> str:
        """Replace all placeholders in text with their real values."""
        for placeholder, entry in self._store.items():
            text = text.replace(placeholder, entry["value"])
        return text

    def to_dict(self) -> dict:
        return dict(self._store)

    def load_dict(self, data: dict):
        self._store = data
        # Rebuild counters from loaded keys
        for placeholder in data:
            match = re.match(r"\{\{([A-Z_]+)_(\d+)\}\}", placeholder)
            if match:
                entity_type, count = match.group(1), int(match.group(2))
                self._counters[entity_type] = max(
                    self._counters.get(entity_type, 0), count
                )

    def __len__(self):
        return len(self._store)

    def __iter__(self):
        return iter(self._store.items())

    def items(self):
        return self._store.items()

    def __bool__(self):
        return bool(self._store)


# ─────────────────────────────────────────────
# Encryption helpers
# ─────────────────────────────────────────────

def _derive_key(vault_path: Path) -> bytes:
    """
    Derive a deterministic Fernet key from the vault filename + a machine-local secret.
    No password prompt — key is tied to the local machine's environment.
    
    For stronger security, users can set SCRUB_SECRET env var.
    """
    import hashlib
    secret = os.environ.get("SCRUB_SECRET", "scrub-local-default-secret")
    seed = f"{secret}::{vault_path.name}"
    raw = hashlib.sha256(seed.encode()).digest()
    # Fernet keys must be 32 url-safe base64 bytes
    import base64
    return base64.urlsafe_b64encode(raw)


def save_vault(vault: Vault, vault_path: Path, console: Console):
    """Encrypt and save vault to disk."""
    try:
        key = _derive_key(vault_path)
        f = Fernet(key)
        payload = json.dumps(vault.to_dict(), ensure_ascii=False).encode()
        encrypted = f.encrypt(payload)
        vault_path.write_bytes(encrypted)
        console.print(
            f"\n[green]✓[/green] Vault saved to [bold]{vault_path}[/bold] "
            f"([dim]{len(vault)} entries encrypted[/dim])"
        )
        console.print(
            "[dim]  Tip: Set [cyan]SCRUB_SECRET[/cyan] env var for stronger encryption.[/dim]"
        )
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to save vault: {e}")


def load_vault(vault_path: Path, console: Console) -> Vault:
    """Decrypt and load vault from disk."""
    try:
        key = _derive_key(vault_path)
        f = Fernet(key)
        encrypted = vault_path.read_bytes()
        payload = f.decrypt(encrypted)
        data = json.loads(payload.decode())
        vault = Vault()
        vault.load_dict(data)
        console.print(
            f"[green]✓[/green] Vault loaded from [bold]{vault_path}[/bold] "
            f"([dim]{len(vault)} entries[/dim])"
        )
        return vault
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to load vault: {e}")
        raise typer.Exit(code=1)


def restore_text(text: str, vault: Vault, console: Console) -> str:
    """Restore all placeholders in text back to real values."""
    original = text
    restored = vault.restore(text)

    count = sum(1 for ph, _ in vault.items() if ph in original)
    if count:
        console.print(f"[green]✓[/green] Restored [bold]{count}[/bold] placeholder(s).")
    else:
        console.print("[yellow]⚠[/yellow]  No placeholders found in input text.")

    return restored