"""
Main CLI interface for Secret's Garden.

This module provides the command-line interface using Typer for
command structure and Rich for beautiful output formatting.
"""

import sys
from pathlib import Path
from typing import List, Optional

import typer
from rich import print as rprint
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from secrets_garden import __version__
from secrets_garden.cli.commands import (
    add_secret_command,
    backup_vault_command,
    change_password_command,
    create_vault_command,
    delete_secret_command,
    export_secrets_command,
    get_secret_command,
    info_command,
    list_secrets_command,
    lock_vault_command,
    run_command,
    unlock_vault_command,
    update_secret_command,
)
from secrets_garden.config.settings import get_config
from secrets_garden.exceptions import SecretsGardenError


# Create Typer app
app = typer.Typer(
    name="secrets-garden",
    help="🌱 A secure, local-first secrets management CLI tool",
    add_completion=False,
    rich_markup_mode="rich",
)

# Create Rich console
console = Console()


def version_callback(value: bool) -> None:
    """Show version information."""
    if value:
        rprint(f"[bold green]Secret's Garden[/bold green] version [bold]{__version__}[/bold]")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, 
        "--version", 
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version information"
    ),
    vault: Optional[str] = typer.Option(
        None,
        "--vault",
        "-V", 
        help="Vault name to use (defaults to 'default')"
    ),
    config_dir: Optional[Path] = typer.Option(
        None,
        "--config-dir",
        help="Custom configuration directory"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Enable verbose output"
    ),
    quiet: bool = typer.Option(
        False, 
        "--quiet",
        "-q",
        help="Suppress non-essential output"
    ),
) -> None:
    """
    🌱 Secret's Garden - Secure local secrets management
    
    A command-line tool for managing secrets with military-grade encryption.
    All data is stored locally with AES-256-GCM encryption.
    """
    
    # Initialize configuration
    config = get_config()
    
    # Update runtime settings
    if config_dir:
        config.config_dir = config_dir
    
    if verbose:
        config.settings.cli.verbose = True
    
    if quiet:
        config.settings.cli.quiet = True
    
    # Set default vault if specified
    if vault:
        config.settings.vault.default_vault_name = vault


# Vault management commands
@app.command("init")
def init_vault(
    vault_name: Optional[str] = typer.Argument(
        None,
        help="Name of the vault to create"
    ),
    description: Optional[str] = typer.Option(
        None,
        "--description",
        "-d",
        help="Vault description"
    ),
    password: Optional[str] = typer.Option(
        None,
        "--password",
        "-p",
        help="Master password (will prompt if not provided)",
        hidden=True,
    ),
) -> None:
    """Initialize a new secrets vault."""
    create_vault_command(vault_name, description, password)


@app.command("unlock")
def unlock_vault(
    vault_name: Optional[str] = typer.Argument(
        None,
        help="Name of the vault to unlock"
    ),
    password: Optional[str] = typer.Option(
        None,
        "--password",
        "-p", 
        help="Master password (will prompt if not provided)",
        hidden=True,
    ),
) -> None:
    """Unlock a vault for use."""
    unlock_vault_command(vault_name, password)


@app.command("lock")
def lock_vault(
    vault_name: Optional[str] = typer.Argument(
        None,
        help="Name of the vault to lock"
    ),
) -> None:
    """Lock a vault to secure it."""
    lock_vault_command(vault_name)


@app.command("info")
def vault_info(
    vault_name: Optional[str] = typer.Argument(
        None,
        help="Name of the vault to show info for"
    ),
) -> None:
    """Show vault information and statistics."""
    info_command(vault_name)


# Secret management commands
@app.command("add")
def add_secret(
    name: str = typer.Argument(..., help="Secret name"),
    value: Optional[str] = typer.Option(
        None,
        "--value",
        "-v",
        help="Secret value (will prompt if not provided)",
        hidden=True,
    ),
    description: Optional[str] = typer.Option(
        None,
        "--description", 
        "-d",
        help="Secret description"
    ),
    tags: Optional[List[str]] = typer.Option(
        None,
        "--tag",
        "-t",
        help="Tags for the secret (can be used multiple times)"
    ),
    vault_name: Optional[str] = typer.Option(
        None,
        "--vault",
        help="Vault name"
    ),
) -> None:
    """Add a new secret to the vault."""
    add_secret_command(name, value, description, tags, vault_name)


@app.command("get")
def get_secret(
    name: str = typer.Argument(..., help="Secret name"),
    vault_name: Optional[str] = typer.Option(
        None,
        "--vault",
        help="Vault name"
    ),
    copy: bool = typer.Option(
        False,
        "--copy",
        "-c",
        help="Copy secret to clipboard"
    ),
    show: bool = typer.Option(
        False,
        "--show",
        "-s",
        help="Show secret value in terminal"
    ),
) -> None:
    """Get a secret value from the vault."""
    get_secret_command(name, vault_name, copy, show)


@app.command("list")
def list_secrets(
    pattern: Optional[str] = typer.Option(
        None,
        "--pattern",
        "-p",
        help="Name pattern to filter secrets"
    ),
    tags: Optional[List[str]] = typer.Option(
        None,
        "--tag",
        "-t",
        help="Filter by tags"
    ),
    vault_name: Optional[str] = typer.Option(
        None,
        "--vault",
        help="Vault name"
    ),
    limit: Optional[int] = typer.Option(
        None,
        "--limit",
        "-l",
        help="Maximum number of results"
    ),
) -> None:
    """List secrets in the vault."""
    list_secrets_command(pattern, tags, vault_name, limit)


@app.command("update")
def update_secret(
    name: str = typer.Argument(..., help="Secret name"),
    value: Optional[str] = typer.Option(
        None,
        "--value",
        "-v",
        help="New secret value",
        hidden=True,
    ),
    description: Optional[str] = typer.Option(
        None,
        "--description",
        "-d", 
        help="New description"
    ),
    tags: Optional[List[str]] = typer.Option(
        None,
        "--tag",
        "-t",
        help="New tags (replaces all existing tags)"
    ),
    vault_name: Optional[str] = typer.Option(
        None,
        "--vault",
        help="Vault name"
    ),
) -> None:
    """Update an existing secret."""
    update_secret_command(name, value, description, tags, vault_name)


@app.command("delete") 
def delete_secret(
    name: str = typer.Argument(..., help="Secret name"),
    vault_name: Optional[str] = typer.Option(
        None,
        "--vault",
        help="Vault name"
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Skip confirmation prompt"
    ),
) -> None:
    """Delete a secret from the vault."""
    delete_secret_command(name, vault_name, force)


# Utility commands
@app.command("export")
def export_secrets(
    output_path: Path = typer.Argument(..., help="Output file path"),
    format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Export format (json, env)"
    ),
    include_values: bool = typer.Option(
        False,
        "--include-values",
        help="Include secret values in export"
    ),
    vault_name: Optional[str] = typer.Option(
        None,
        "--vault", 
        help="Vault name"
    ),
) -> None:
    """Export vault secrets to a file."""
    export_secrets_command(output_path, format, include_values, vault_name)


@app.command("run")
def run_with_secrets(
    command: List[str] = typer.Argument(..., help="Command to run"),
    vault_name: Optional[str] = typer.Option(
        None,
        "--vault",
        help="Vault name"
    ),
    prefix: str = typer.Option(
        "",
        "--prefix",
        help="Environment variable prefix"
    ),
) -> None:
    """Run a command with secrets as environment variables."""
    run_command(command, vault_name, prefix)


@app.command("backup")
def backup_vault(
    backup_path: Path = typer.Argument(..., help="Backup directory path"),
    vault_name: Optional[str] = typer.Option(
        None,
        "--vault",
        help="Vault name"
    ),
) -> None:
    """Create a backup of the vault."""
    backup_vault_command(backup_path, vault_name)


@app.command("change-password")
def change_password(
    vault_name: Optional[str] = typer.Option(
        None,
        "--vault",
        help="Vault name"
    ),
    old_password: Optional[str] = typer.Option(
        None,
        "--old-password",
        help="Current password",
        hidden=True,
    ),
    new_password: Optional[str] = typer.Option(
        None,
        "--new-password",
        help="New password", 
        hidden=True,
    ),
) -> None:
    """Change the vault master password."""
    change_password_command(vault_name, old_password, new_password)


def handle_error(error: Exception) -> None:
    """Handle and display errors appropriately."""
    if isinstance(error, SecretsGardenError):
        console.print(f"[bold red]Error:[/bold red] {error.message}", err=True)
        if error.details and get_config().settings.cli.verbose:
            console.print(f"[dim]Details: {error.details}[/dim]", err=True)
    else:
        console.print(f"[bold red]Unexpected error:[/bold red] {error}", err=True)
        if get_config().settings.cli.verbose:
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]", err=True)


def run() -> None:
    """Main entry point for the CLI application."""
    try:
        app()
    except SecretsGardenError as e:
        handle_error(e)
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]", err=True)
        sys.exit(130)
    except Exception as e:
        handle_error(e)
        sys.exit(1)


if __name__ == "__main__":
    run()