"""
CLI command implementations for Secret's Garden.

This module contains the actual implementation of all CLI commands,
providing a clean separation between the command interface and logic.
"""

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

import typer
from rich import print as rprint
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table

from secrets_garden.config.settings import get_config
from secrets_garden.exceptions import (
    InvalidPasswordError,
    SecretNotFoundError,
    VaultAlreadyExistsError,
    VaultNotFoundError,
)
from secrets_garden.security import PasswordValidator
from secrets_garden.vault.manager import VaultManager

console = Console()


def get_vault_manager(vault_name: Optional[str] = None) -> VaultManager:
    """Get a vault manager instance for the specified or default vault."""
    config = get_config()

    if vault_name is None:
        vault_name = config.settings.vault.default_vault_name

    vault_path = config.get_vault_path(vault_name)
    return VaultManager(vault_path)


def prompt_password(prompt_text: str = "Password", confirm: bool = False, validate: bool = False) -> str:
    """Prompt for a password with optional confirmation and validation."""
    max_attempts = 3

    for attempt in range(max_attempts):
        password = Prompt.ask(prompt_text, password=True)

        # Validate password strength if requested
        if validate:
            validator = PasswordValidator()
            strength = validator.validate(password)

            if not strength.is_strong:
                rprint(f"[yellow]Password is {strength.strength_label.lower()}[/yellow]")

                if strength.issues:
                    rprint("[red]Issues:[/red]")
                    for issue in strength.issues:
                        rprint(f"  • {issue}")

                if strength.suggestions:
                    rprint("[yellow]Suggestions:[/yellow]")
                    for suggestion in strength.suggestions:
                        rprint(f"  • {suggestion}")

                if attempt < max_attempts - 1:
                    rprint(f"[dim]Try again ({attempt + 1}/{max_attempts})[/dim]")
                    continue
                else:
                    rprint("[red]Maximum attempts reached. Using current password.[/red]")

        # Confirm password if requested
        if confirm:
            confirm_password = Prompt.ask("Confirm password", password=True)
            if password != confirm_password:
                rprint("[bold red]Passwords do not match![/bold red]")
                if attempt < max_attempts - 1:
                    continue
                else:
                    raise typer.Exit(1)

        return password

    return password


def create_vault_command(
    vault_name: Optional[str],
    description: Optional[str],
    password: Optional[str],
) -> None:
    """Create a new vault."""
    config = get_config()

    if vault_name is None:
        vault_name = config.settings.vault.default_vault_name

    if password is None:
        rprint(f"[bold green]Creating new vault:[/bold green] {vault_name}")
        rprint("[dim]Choose a strong master password to protect your secrets.[/dim]")
        password = prompt_password("Master password", confirm=True, validate=True)

    vault_manager = get_vault_manager(vault_name)

    try:
        vault_manager.create(password, description or "")
        rprint(f"[bold green]✓[/bold green] Vault '{vault_name}' created successfully")

        # Show next steps
        rprint("\n[dim]Next steps:[/dim]")
        rprint("• Add secrets: [cyan]secrets-garden add <name>[/cyan]")
        rprint("• List secrets: [cyan]secrets-garden list[/cyan]")
        rprint("• Get help: [cyan]secrets-garden --help[/cyan]")

    except VaultAlreadyExistsError as e:
        rprint(f"[bold red]Error:[/bold red] {e.message}")
        raise typer.Exit(1)
    except Exception as e:
        rprint(f"[bold red]Failed to create vault:[/bold red] {e}")
        raise typer.Exit(1)


def unlock_vault_command(vault_name: Optional[str], password: Optional[str]) -> None:
    """Unlock a vault."""
    config = get_config()

    if vault_name is None:
        vault_name = config.settings.vault.default_vault_name

    vault_manager = get_vault_manager(vault_name)

    if not vault_manager.exists:
        rprint(f"[bold red]Error:[/bold red] Vault '{vault_name}' not found")
        rprint(f"Create it with: [cyan]secrets-garden init {vault_name}[/cyan]")
        raise typer.Exit(1)

    if password is None:
        password = prompt_password("Master password")

    try:
        vault_manager.unlock(password)
        rprint(f"[bold green]✓[/bold green] Vault '{vault_name}' unlocked")

    except InvalidPasswordError:
        rprint("[bold red]Invalid password[/bold red]")
        raise typer.Exit(1)
    except VaultNotFoundError as e:
        rprint(f"[bold red]Error:[/bold red] {e.message}")
        raise typer.Exit(1)
    except Exception as e:
        rprint(f"[bold red]Failed to unlock vault:[/bold red] {e}")
        raise typer.Exit(1)


def lock_vault_command(vault_name: Optional[str]) -> None:
    """Lock a vault."""
    config = get_config()

    if vault_name is None:
        vault_name = config.settings.vault.default_vault_name

    vault_manager = get_vault_manager(vault_name)

    try:
        vault_manager.lock()
        rprint(f"[bold green]✓[/bold green] Vault '{vault_name}' locked")

    except Exception as e:
        rprint(f"[bold red]Failed to lock vault:[/bold red] {e}")
        raise typer.Exit(1)


def info_command(vault_name: Optional[str]) -> None:
    """Show vault information."""
    config = get_config()

    if vault_name is None:
        vault_name = config.settings.vault.default_vault_name

    vault_manager = get_vault_manager(vault_name)

    try:
        info = vault_manager.get_vault_info()

        # Create info table
        table = Table(title=f"Vault Information: {vault_name}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Path", str(info["path"]))
        table.add_row("Version", info["version"])
        table.add_row("Status", "🔒 Locked" if info["locked"] else "🔓 Unlocked")

        if info.get("created_at"):
            created_time = time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.localtime(info["created_at"])
            )
            table.add_row("Created", created_time)

        if info.get("description"):
            table.add_row("Description", info["description"])

        if info.get("secrets_count") is not None:
            table.add_row("Secrets", str(info["secrets_count"]))

        if info.get("last_key_rotation"):
            rotation_time = time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.localtime(info["last_key_rotation"])
            )
            table.add_row("Last Key Rotation", rotation_time)

        console.print(table)

    except VaultNotFoundError as e:
        rprint(f"[bold red]Error:[/bold red] {e.message}")
        rprint(f"Create it with: [cyan]secrets-garden init {vault_name}[/cyan]")
        raise typer.Exit(1)
    except Exception as e:
        rprint(f"[bold red]Failed to get vault info:[/bold red] {e}")
        raise typer.Exit(1)


def add_secret_command(
    name: str,
    value: Optional[str],
    description: Optional[str],
    tags: Optional[List[str]],
    vault_name: Optional[str],
) -> None:
    """Add a secret to the vault."""
    vault_manager = get_vault_manager(vault_name)

    if not vault_manager.exists:
        rprint("[bold red]Error:[/bold red] Vault not found")
        raise typer.Exit(1)

    if vault_manager.is_locked:
        password = prompt_password("Master password")
        try:
            vault_manager.unlock(password)
        except InvalidPasswordError:
            rprint("[bold red]Invalid password[/bold red]")
            raise typer.Exit(1)

    if value is None:
        value = Prompt.ask("Secret value", password=True)

    try:
        vault_manager.add_secret(name, value, description or "", tags or [])
        rprint(f"[bold green]✓[/bold green] Secret '{name}' added successfully")

    except Exception as e:
        rprint(f"[bold red]Failed to add secret:[/bold red] {e}")
        raise typer.Exit(1)


def get_secret_command(
    name: str,
    vault_name: Optional[str],
    copy: bool,
    show: bool
) -> None:
    """Get a secret from the vault."""
    vault_manager = get_vault_manager(vault_name)

    if not vault_manager.exists:
        rprint("[bold red]Error:[/bold red] Vault not found")
        raise typer.Exit(1)

    if vault_manager.is_locked:
        password = prompt_password("Master password")
        try:
            vault_manager.unlock(password)
        except InvalidPasswordError:
            rprint("[bold red]Invalid password[/bold red]")
            raise typer.Exit(1)

    try:
        value = vault_manager.get_secret(name)

        if copy:
            try:
                import pyperclip
                pyperclip.copy(value)
                rprint(f"[bold green]✓[/bold green] Secret '{name}' copied to clipboard")

                # Clear clipboard after timeout
                config = get_config()
                timeout = config.settings.security.clear_clipboard_timeout
                if timeout > 0:
                    rprint(f"[dim]Clipboard will be cleared in {timeout} seconds[/dim]")

            except ImportError:
                rprint("[yellow]Warning:[/yellow] pyperclip not available, cannot copy to clipboard")
                show = True

        if show:
            rprint(f"[bold green]Secret '{name}':[/bold green] {value}")
        elif not copy:
            rprint(f"[bold green]✓[/bold green] Secret '{name}' retrieved")
            rprint("[dim]Use --show to display or --copy to copy to clipboard[/dim]")

    except SecretNotFoundError:
        rprint(f"[bold red]Error:[/bold red] Secret '{name}' not found")
        raise typer.Exit(1)
    except Exception as e:
        rprint(f"[bold red]Failed to get secret:[/bold red] {e}")
        raise typer.Exit(1)


def list_secrets_command(
    pattern: Optional[str],
    tags: Optional[List[str]],
    vault_name: Optional[str],
    limit: Optional[int],
) -> None:
    """List secrets in the vault."""
    vault_manager = get_vault_manager(vault_name)

    if not vault_manager.exists:
        rprint("[bold red]Error:[/bold red] Vault not found")
        raise typer.Exit(1)

    if vault_manager.is_locked:
        password = prompt_password("Master password")
        try:
            vault_manager.unlock(password)
        except InvalidPasswordError:
            rprint("[bold red]Invalid password[/bold red]")
            raise typer.Exit(1)

    try:
        secrets = vault_manager.list_secrets(pattern, tags, limit)

        if not secrets:
            rprint("[yellow]No secrets found[/yellow]")
            return

        # Create secrets table
        table = Table(title="Secrets")
        table.add_column("Name", style="cyan")
        table.add_column("Description", style="white")
        table.add_column("Tags", style="blue")
        table.add_column("Created", style="dim")

        for secret in secrets:
            created_time = time.strftime(
                "%Y-%m-%d %H:%M",
                time.localtime(secret["created_at"])
            )

            tags_str = ", ".join(secret["tags"]) if secret["tags"] else ""

            table.add_row(
                secret["name"],
                secret["description"] or "[dim]No description[/dim]",
                tags_str or "[dim]No tags[/dim]",
                created_time,
            )

        console.print(table)
        rprint(f"\n[dim]Found {len(secrets)} secret(s)[/dim]")

    except Exception as e:
        rprint(f"[bold red]Failed to list secrets:[/bold red] {e}")
        raise typer.Exit(1)


def update_secret_command(
    name: str,
    value: Optional[str],
    description: Optional[str],
    tags: Optional[List[str]],
    vault_name: Optional[str],
) -> None:
    """Update a secret in the vault."""
    vault_manager = get_vault_manager(vault_name)

    if not vault_manager.exists:
        rprint("[bold red]Error:[/bold red] Vault not found")
        raise typer.Exit(1)

    if vault_manager.is_locked:
        password = prompt_password("Master password")
        try:
            vault_manager.unlock(password)
        except InvalidPasswordError:
            rprint("[bold red]Invalid password[/bold red]")
            raise typer.Exit(1)

    # Check if at least one field is being updated
    if value is None and description is None and tags is None:
        rprint("[yellow]No changes specified. Use --value, --description, or --tag options.[/yellow]")
        raise typer.Exit(0)

    try:
        vault_manager.update_secret(name, value, description, tags)
        rprint(f"[bold green]✓[/bold green] Secret '{name}' updated successfully")

    except SecretNotFoundError:
        rprint(f"[bold red]Error:[/bold red] Secret '{name}' not found")
        raise typer.Exit(1)
    except Exception as e:
        rprint(f"[bold red]Failed to update secret:[/bold red] {e}")
        raise typer.Exit(1)


def delete_secret_command(
    name: str,
    vault_name: Optional[str],
    force: bool
) -> None:
    """Delete a secret from the vault."""
    vault_manager = get_vault_manager(vault_name)

    if not vault_manager.exists:
        rprint("[bold red]Error:[/bold red] Vault not found")
        raise typer.Exit(1)

    if vault_manager.is_locked:
        password = prompt_password("Master password")
        try:
            vault_manager.unlock(password)
        except InvalidPasswordError:
            rprint("[bold red]Invalid password[/bold red]")
            raise typer.Exit(1)

    # Confirm deletion unless forced
    if not force:
        if not Confirm.ask(f"Delete secret '{name}'? This cannot be undone."):
            rprint("[yellow]Operation cancelled[/yellow]")
            raise typer.Exit(0)

    try:
        vault_manager.delete_secret(name)
        rprint(f"[bold green]✓[/bold green] Secret '{name}' deleted successfully")

    except SecretNotFoundError:
        rprint(f"[bold red]Error:[/bold red] Secret '{name}' not found")
        raise typer.Exit(1)
    except Exception as e:
        rprint(f"[bold red]Failed to delete secret:[/bold red] {e}")
        raise typer.Exit(1)


def export_secrets_command(
    output_path: Path,
    format: str,
    include_values: bool,
    vault_name: Optional[str],
) -> None:
    """Export secrets from the vault."""
    vault_manager = get_vault_manager(vault_name)

    if not vault_manager.exists:
        rprint("[bold red]Error:[/bold red] Vault not found")
        raise typer.Exit(1)

    if vault_manager.is_locked:
        password = prompt_password("Master password")
        try:
            vault_manager.unlock(password)
        except InvalidPasswordError:
            rprint("[bold red]Invalid password[/bold red]")
            raise typer.Exit(1)

    # Warn about including values
    if include_values:
        if not Confirm.ask(
            "Export will include secret values in plain text. Continue?",
            default=False
        ):
            rprint("[yellow]Export cancelled[/yellow]")
            raise typer.Exit(0)

    try:
        vault_manager.export_secrets(output_path, format, include_values)

        if include_values:
            rprint(f"[bold yellow]⚠️[/bold yellow] Secrets exported with values to: {output_path}")
            rprint("[yellow]Warning: File contains sensitive data in plain text![/yellow]")
        else:
            rprint(f"[bold green]✓[/bold green] Secret metadata exported to: {output_path}")

    except Exception as e:
        rprint(f"[bold red]Failed to export secrets:[/bold red] {e}")
        raise typer.Exit(1)


def run_command(
    command: List[str],
    vault_name: Optional[str],
    prefix: str
) -> None:
    """Run a command with secrets as environment variables."""
    vault_manager = get_vault_manager(vault_name)

    if not vault_manager.exists:
        rprint("[bold red]Error:[/bold red] Vault not found")
        raise typer.Exit(1)

    if vault_manager.is_locked:
        password = prompt_password("Master password")
        try:
            vault_manager.unlock(password)
        except InvalidPasswordError:
            rprint("[bold red]Invalid password[/bold red]")
            raise typer.Exit(1)

    try:
        # Get all secrets
        secrets_list = vault_manager.list_secrets()

        # Build environment
        env = os.environ.copy()

        for secret_info in secrets_list:
            secret_name = secret_info["name"]
            secret_value = vault_manager.get_secret(secret_name)

            # Create environment variable name
            env_name = f"{prefix}{secret_name}".upper()
            env[env_name] = secret_value

        rprint(f"[dim]Running command with {len(secrets_list)} secrets as environment variables[/dim]")

        # Execute command
        result = subprocess.run(command, env=env)
        sys.exit(result.returncode)

    except Exception as e:
        rprint(f"[bold red]Failed to run command:[/bold red] {e}")
        raise typer.Exit(1)


def backup_vault_command(backup_path: Path, vault_name: Optional[str]) -> None:
    """Create a backup of the vault."""
    vault_manager = get_vault_manager(vault_name)

    if not vault_manager.exists:
        rprint("[bold red]Error:[/bold red] Vault not found")
        raise typer.Exit(1)

    try:
        vault_manager.backup(backup_path)
        rprint(f"[bold green]✓[/bold green] Vault backed up to: {backup_path}")

    except Exception as e:
        rprint(f"[bold red]Failed to backup vault:[/bold red] {e}")
        raise typer.Exit(1)


def rotate_key_command(
    vault_name: Optional[str],
    password: Optional[str],
    backup: bool = True,
) -> None:
    """Rotate the vault's encryption keys."""
    vault_manager = get_vault_manager(vault_name)

    if not vault_manager.exists:
        rprint("[bold red]Error:[/bold red] Vault not found")
        raise typer.Exit(1)

    if password is None:
        password = prompt_password("Master password")

    # Warn about the operation
    rprint("[yellow]⚠️  Key rotation will re-encrypt all secrets with new keys.[/yellow]")
    rprint("[dim]This provides forward secrecy and protects against key compromise.[/dim]")

    if backup:
        rprint("[dim]A backup will be created before rotation.[/dim]")

    if not Confirm.ask("Continue with key rotation?", default=False):
        rprint("[yellow]Key rotation cancelled[/yellow]")
        raise typer.Exit(0)

    rprint("[yellow]Rotating encryption keys... This may take a moment.[/yellow]")

    try:
        vault_manager.rotate_encryption_key(password, backup)
        rprint("[bold green]✓[/bold green] Encryption keys rotated successfully")

        if backup:
            rprint("[dim]Backup created before rotation[/dim]")

    except InvalidPasswordError:
        rprint("[bold red]Invalid password[/bold red]")
        raise typer.Exit(1)
    except Exception as e:
        rprint(f"[bold red]Failed to rotate keys:[/bold red] {e}")
        raise typer.Exit(1)


def change_password_command(
    vault_name: Optional[str],
    old_password: Optional[str],
    new_password: Optional[str],
) -> None:
    """Change the vault master password."""
    vault_manager = get_vault_manager(vault_name)

    if not vault_manager.exists:
        rprint("[bold red]Error:[/bold red] Vault not found")
        raise typer.Exit(1)

    if old_password is None:
        old_password = prompt_password("Current password")

    if new_password is None:
        new_password = prompt_password("New password", confirm=True, validate=True)

    rprint("[yellow]Changing password... This may take a moment.[/yellow]")

    try:
        vault_manager.change_password(old_password, new_password)
        rprint("[bold green]✓[/bold green] Password changed successfully")

    except InvalidPasswordError:
        rprint("[bold red]Invalid current password[/bold red]")
        raise typer.Exit(1)
    except Exception as e:
        rprint(f"[bold red]Failed to change password:[/bold red] {e}")
        raise typer.Exit(1)
