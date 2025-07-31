"""
Tests for CLI interface.

This module tests the command-line interface functionality,
including command parsing, output formatting, and error handling.
"""

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from typer.testing import CliRunner

from secrets_garden.cli.main import app


class TestCLIInterface:
    """Test the CLI interface."""

    @pytest.fixture
    def runner(self):
        """Provide a CLI test runner."""
        return CliRunner()

    @pytest.fixture
    def temp_config(self, temp_dir: Path, monkeypatch):
        """Set up temporary configuration for CLI tests."""
        config_dir = temp_dir / ".secrets-garden"
        config_dir.mkdir(parents=True)

        # Mock the global config manager
        monkeypatch.setenv("SECRETS_GARDEN_VAULT_DIR", str(temp_dir / "vaults"))
        monkeypatch.setenv("SECRETS_GARDEN_CONFIG_DIR", str(config_dir))

        return config_dir

    def test_version_option(self, runner: CliRunner):
        """Test --version option."""
        result = runner.invoke(app, ["--version"])

        assert result.exit_code == 0
        assert "Secret's Garden" in result.stdout
        assert "version" in result.stdout

    def test_help_option(self, runner: CliRunner):
        """Test --help option."""
        result = runner.invoke(app, ["--help"])

        assert result.exit_code == 0
        assert "Secret's Garden" in result.stdout
        assert "secure, local-first secrets management" in result.stdout

    def test_init_vault_command(self, runner: CliRunner, temp_config):
        """Test vault initialization command."""
        with patch('secrets_garden.cli.commands.prompt_password') as mock_prompt:
            mock_prompt.return_value = "test-password"

            result = runner.invoke(app, ["init", "test-vault", "--description", "Test vault"])

            assert result.exit_code == 0
            assert "created successfully" in result.stdout

    def test_init_vault_with_password(self, runner: CliRunner, temp_config):
        """Test vault initialization with password option."""
        result = runner.invoke(app, [
            "init", "test-vault",
            "--password", "test-password",
            "--description", "Test vault"
        ])

        assert result.exit_code == 0
        assert "created successfully" in result.stdout

    def test_init_duplicate_vault(self, runner: CliRunner, temp_config):
        """Test creating duplicate vault."""
        # Create first vault
        with patch('secrets_garden.cli.commands.prompt_password') as mock_prompt:
            mock_prompt.return_value = "test-password"

            result1 = runner.invoke(app, ["init", "test-vault"])
            assert result1.exit_code == 0

            # Try to create duplicate
            result2 = runner.invoke(app, ["init", "test-vault"])
            assert result2.exit_code == 1
            assert "already exists" in result2.stdout

    def test_unlock_vault_command(self, runner: CliRunner, temp_config):
        """Test vault unlock command."""
        # First create vault
        with patch('secrets_garden.cli.commands.prompt_password') as mock_prompt:
            mock_prompt.return_value = "test-password"

            result1 = runner.invoke(app, ["init", "test-vault"])
            assert result1.exit_code == 0

            # Unlock vault
            result2 = runner.invoke(app, ["unlock", "test-vault"])
            assert result2.exit_code == 0
            assert "unlocked" in result2.stdout

    def test_unlock_with_wrong_password(self, runner: CliRunner, temp_config):
        """Test unlocking with wrong password."""
        # Create vault
        with patch('secrets_garden.cli.commands.prompt_password') as mock_create_prompt:
            mock_create_prompt.return_value = "correct-password"
            result1 = runner.invoke(app, ["init", "test-vault"])
            assert result1.exit_code == 0

        # Try to unlock with wrong password
        with patch('secrets_garden.cli.commands.prompt_password') as mock_unlock_prompt:
            mock_unlock_prompt.return_value = "wrong-password"
            result2 = runner.invoke(app, ["unlock", "test-vault"])
            assert result2.exit_code == 1
            assert "Invalid password" in result2.stdout

    def test_unlock_nonexistent_vault(self, runner: CliRunner, temp_config):
        """Test unlocking non-existent vault."""
        with patch('secrets_garden.cli.commands.prompt_password') as mock_prompt:
            mock_prompt.return_value = "any-password"

            result = runner.invoke(app, ["unlock", "nonexistent-vault"])
            assert result.exit_code == 1
            assert "not found" in result.stdout

    def test_lock_vault_command(self, runner: CliRunner, temp_config):
        """Test vault lock command."""
        # Create and unlock vault
        with patch('secrets_garden.cli.commands.prompt_password') as mock_prompt:
            mock_prompt.return_value = "test-password"

            runner.invoke(app, ["init", "test-vault"])
            runner.invoke(app, ["unlock", "test-vault"])

            # Lock vault
            result = runner.invoke(app, ["lock", "test-vault"])
            assert result.exit_code == 0
            assert "locked" in result.stdout

    def test_info_command(self, runner: CliRunner, temp_config):
        """Test vault info command."""
        # Create vault
        with patch('secrets_garden.cli.commands.prompt_password') as mock_prompt:
            mock_prompt.return_value = "test-password"

            runner.invoke(app, ["init", "test-vault", "--description", "Test description"])

            result = runner.invoke(app, ["info", "test-vault"])
            assert result.exit_code == 0
            assert "Vault Information" in result.stdout
            assert "Test description" in result.stdout
            assert "Locked" in result.stdout

    def test_add_secret_command(self, runner: CliRunner, temp_config):
        """Test adding a secret."""
        # Create and unlock vault
        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.return_value = "test-password"

            runner.invoke(app, ["init", "test-vault"])
            runner.invoke(app, ["unlock", "test-vault"])

        # Add secret with prompted value
        with patch('rich.prompt.Prompt.ask') as mock_prompt:
            mock_prompt.return_value = "secret-value"

            result = runner.invoke(app, [
                "add", "test-secret",
                "--description", "Test secret",
                "--tag", "test",
                "--tag", "demo"
            ])

            assert result.exit_code == 0
            assert "added successfully" in result.stdout

    def test_add_secret_with_value(self, runner: CliRunner, temp_config):
        """Test adding secret with value option."""
        # Create and unlock vault
        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.return_value = "test-password"

            runner.invoke(app, ["init", "test-vault"])
            runner.invoke(app, ["unlock", "test-vault"])

        result = runner.invoke(app, [
            "add", "test-secret",
            "--value", "secret-value",
            "--description", "Test secret"
        ])

        assert result.exit_code == 0
        assert "added successfully" in result.stdout

    def test_add_secret_to_locked_vault(self, runner: CliRunner, temp_config):
        """Test adding secret to locked vault."""
        # Create vault but don't unlock
        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.return_value = "test-password"

            runner.invoke(app, ["init", "test-vault"])

            # Try to add secret (should prompt for password to unlock)
            result = runner.invoke(app, [
                "add", "test-secret",
                "--value", "secret-value"
            ])

            assert result.exit_code == 0
            assert "added successfully" in result.stdout

    def test_get_secret_command(self, runner: CliRunner, temp_config):
        """Test getting a secret."""
        # Setup vault with secret
        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.return_value = "test-password"

            runner.invoke(app, ["init", "test-vault"])
            runner.invoke(app, ["unlock", "test-vault"])
            runner.invoke(app, ["add", "test-secret", "--value", "secret-value"])

        # Get secret
        result = runner.invoke(app, ["get", "test-secret"])
        assert result.exit_code == 0
        assert "retrieved" in result.stdout

    def test_get_secret_with_show(self, runner: CliRunner, temp_config):
        """Test getting secret with show option."""
        # Setup vault with secret
        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.return_value = "test-password"

            runner.invoke(app, ["init", "test-vault"])
            runner.invoke(app, ["unlock", "test-vault"])
            runner.invoke(app, ["add", "test-secret", "--value", "secret-value"])

        # Get secret with show
        result = runner.invoke(app, ["get", "test-secret", "--show"])
        assert result.exit_code == 0
        assert "secret-value" in result.stdout

    def test_get_nonexistent_secret(self, runner: CliRunner, temp_config):
        """Test getting non-existent secret."""
        # Setup vault
        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.return_value = "test-password"

            runner.invoke(app, ["init", "test-vault"])
            runner.invoke(app, ["unlock", "test-vault"])

        result = runner.invoke(app, ["get", "nonexistent-secret"])
        assert result.exit_code == 1
        assert "not found" in result.stdout

    def test_list_secrets_command(self, runner: CliRunner, temp_config):
        """Test listing secrets."""
        # Setup vault with multiple secrets
        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.return_value = "test-password"

            runner.invoke(app, ["init", "test-vault"])
            runner.invoke(app, ["unlock", "test-vault"])

            # Add multiple secrets
            runner.invoke(app, ["add", "secret1", "--value", "value1", "--description", "First secret"])
            runner.invoke(app, ["add", "secret2", "--value", "value2", "--description", "Second secret"])

        result = runner.invoke(app, ["list"])
        assert result.exit_code == 0
        assert "Secrets" in result.stdout
        assert "secret1" in result.stdout
        assert "secret2" in result.stdout
        assert "First secret" in result.stdout
        assert "Second secret" in result.stdout

    def test_list_secrets_with_pattern(self, runner: CliRunner, temp_config):
        """Test listing secrets with pattern filter."""
        # Setup vault with secrets
        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.return_value = "test-password"

            runner.invoke(app, ["init", "test-vault"])
            runner.invoke(app, ["unlock", "test-vault"])

            runner.invoke(app, ["add", "api_key", "--value", "key1"])
            runner.invoke(app, ["add", "api_secret", "--value", "secret1"])
            runner.invoke(app, ["add", "db_password", "--value", "pass1"])

        result = runner.invoke(app, ["list", "--pattern", "api%"])
        assert result.exit_code == 0
        assert "api_key" in result.stdout
        assert "api_secret" in result.stdout
        assert "db_password" not in result.stdout

    def test_list_empty_vault(self, runner: CliRunner, temp_config):
        """Test listing secrets in empty vault."""
        # Setup empty vault
        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.return_value = "test-password"

            runner.invoke(app, ["init", "test-vault"])
            runner.invoke(app, ["unlock", "test-vault"])

        result = runner.invoke(app, ["list"])
        assert result.exit_code == 0
        assert "No secrets found" in result.stdout

    def test_update_secret_command(self, runner: CliRunner, temp_config):
        """Test updating a secret."""
        # Setup vault with secret
        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.return_value = "test-password"

            runner.invoke(app, ["init", "test-vault"])
            runner.invoke(app, ["unlock", "test-vault"])
            runner.invoke(app, ["add", "test-secret", "--value", "original-value"])

        # Update secret
        result = runner.invoke(app, [
            "update", "test-secret",
            "--value", "new-value",
            "--description", "Updated description"
        ])

        assert result.exit_code == 0
        assert "updated successfully" in result.stdout

    def test_update_nonexistent_secret(self, runner: CliRunner, temp_config):
        """Test updating non-existent secret."""
        # Setup vault
        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.return_value = "test-password"

            runner.invoke(app, ["init", "test-vault"])
            runner.invoke(app, ["unlock", "test-vault"])

        result = runner.invoke(app, [
            "update", "nonexistent-secret",
            "--value", "new-value"
        ])

        assert result.exit_code == 1
        assert "not found" in result.stdout

    def test_delete_secret_command(self, runner: CliRunner, temp_config):
        """Test deleting a secret."""
        # Setup vault with secret
        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.return_value = "test-password"

            runner.invoke(app, ["init", "test-vault"])
            runner.invoke(app, ["unlock", "test-vault"])
            runner.invoke(app, ["add", "test-secret", "--value", "secret-value"])

        # Delete with force flag
        result = runner.invoke(app, ["delete", "test-secret", "--force"])
        assert result.exit_code == 0
        assert "deleted successfully" in result.stdout

    def test_delete_with_confirmation(self, runner: CliRunner, temp_config):
        """Test deleting secret with confirmation."""
        # Setup vault with secret
        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.return_value = "test-password"

            runner.invoke(app, ["init", "test-vault"])
            runner.invoke(app, ["unlock", "test-vault"])
            runner.invoke(app, ["add", "test-secret", "--value", "secret-value"])

        # Delete with confirmation (mock user confirms)
        with patch('rich.prompt.Confirm.ask') as mock_confirm:
            mock_confirm.return_value = True

            result = runner.invoke(app, ["delete", "test-secret"])
            assert result.exit_code == 0
            assert "deleted successfully" in result.stdout

    def test_delete_cancelled(self, runner: CliRunner, temp_config):
        """Test deleting secret when user cancels."""
        # Setup vault with secret
        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.return_value = "test-password"

            runner.invoke(app, ["init", "test-vault"])
            runner.invoke(app, ["unlock", "test-vault"])
            runner.invoke(app, ["add", "test-secret", "--value", "secret-value"])

        # Delete but user cancels
        with patch('rich.prompt.Confirm.ask') as mock_confirm:
            mock_confirm.return_value = False

            result = runner.invoke(app, ["delete", "test-secret"])
            assert result.exit_code == 0
            assert "cancelled" in result.stdout

    def test_export_secrets_json(self, runner: CliRunner, temp_config, temp_dir: Path):
        """Test exporting secrets to JSON."""
        # Setup vault with secrets
        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.return_value = "test-password"

            runner.invoke(app, ["init", "test-vault"])
            runner.invoke(app, ["unlock", "test-vault"])
            runner.invoke(app, ["add", "secret1", "--value", "value1"])
            runner.invoke(app, ["add", "secret2", "--value", "value2"])

        export_path = temp_dir / "export.json"
        result = runner.invoke(app, ["export", str(export_path), "--format", "json"])

        assert result.exit_code == 0
        assert "exported" in result.stdout
        assert export_path.exists()

        # Verify export content
        with open(export_path) as f:
            export_data = json.load(f)

        assert "vault" in export_data
        assert "secrets" in export_data
        assert len(export_data["secrets"]) == 2

    def test_export_with_values_confirmation(self, runner: CliRunner, temp_config, temp_dir: Path):
        """Test exporting with values requires confirmation."""
        # Setup vault with secret
        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.return_value = "test-password"

            runner.invoke(app, ["init", "test-vault"])
            runner.invoke(app, ["unlock", "test-vault"])
            runner.invoke(app, ["add", "secret1", "--value", "value1"])

        export_path = temp_dir / "export.json"

        # User confirms export with values
        with patch('rich.prompt.Confirm.ask') as mock_confirm:
            mock_confirm.return_value = True

            result = runner.invoke(app, [
                "export", str(export_path),
                "--format", "json",
                "--include-values"
            ])

            assert result.exit_code == 0
            assert "sensitive data" in result.stdout

    def test_backup_vault_command(self, runner: CliRunner, temp_config, temp_dir: Path):
        """Test vault backup command."""
        # Setup vault with secret
        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.return_value = "test-password"

            runner.invoke(app, ["init", "test-vault"])
            runner.invoke(app, ["unlock", "test-vault"])
            runner.invoke(app, ["add", "test-secret", "--value", "secret-value"])

        backup_path = temp_dir / "backup"
        result = runner.invoke(app, ["backup", str(backup_path)])

        assert result.exit_code == 0
        assert "backed up" in result.stdout
        assert backup_path.exists()
        assert (backup_path / "vault.json").exists()
        assert (backup_path / "secrets.db").exists()

    def test_change_password_command(self, runner: CliRunner, temp_config):
        """Test changing vault password."""
        # Setup vault
        with patch('secrets_garden.cli.commands.prompt_password') as mock_create_password:
            mock_create_password.return_value = "old-password"

            runner.invoke(app, ["init", "test-vault"])
            runner.invoke(app, ["unlock", "test-vault"])
            runner.invoke(app, ["add", "test-secret", "--value", "secret-value"])

        # Change password with prompts
        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.side_effect = ["old-password", "new-password", "new-password"]

            result = runner.invoke(app, ["change-password"])
            assert result.exit_code == 0
            assert "changed successfully" in result.stdout

    def test_change_password_wrong_old(self, runner: CliRunner, temp_config):
        """Test changing password with wrong old password."""
        # Setup vault
        with patch('secrets_garden.cli.commands.prompt_password') as mock_create_password:
            mock_create_password.return_value = "correct-password"

            runner.invoke(app, ["init", "test-vault"])

        # Try to change with wrong old password
        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.side_effect = ["wrong-password", "new-password", "new-password"]

            result = runner.invoke(app, ["change-password"])
            assert result.exit_code == 1
            assert "Invalid current password" in result.stdout

    def test_global_vault_option(self, runner: CliRunner, temp_config):
        """Test global --vault option."""
        # Create vault with specific name
        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.return_value = "test-password"

            result = runner.invoke(app, [
                "--vault", "custom-vault",
                "init",
                "--description", "Custom vault"
            ])

            assert result.exit_code == 0
            assert "created successfully" in result.stdout

    def test_verbose_option(self, runner: CliRunner, temp_config):
        """Test --verbose option."""
        result = runner.invoke(app, ["--verbose", "info", "nonexistent-vault"])

        # Should include more detailed error information in verbose mode
        assert result.exit_code == 1
        assert "not found" in result.stdout

    def test_quiet_option(self, runner: CliRunner, temp_config):
        """Test --quiet option."""
        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.return_value = "test-password"

            result = runner.invoke(app, ["--quiet", "init", "quiet-vault"])

            # Should have minimal output in quiet mode
            assert result.exit_code == 0

    def test_run_command_basic(self, runner: CliRunner, temp_config):
        """Test run command with secrets as environment variables."""
        # Setup vault with secrets
        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.return_value = "test-password"

            runner.invoke(app, ["init", "test-vault"])
            runner.invoke(app, ["unlock", "test-vault"])
            runner.invoke(app, ["add", "API_KEY", "--value", "secret-key"])
            runner.invoke(app, ["add", "DB_PASSWORD", "--value", "secret-pass"])

        # Mock subprocess.run
        with patch('subprocess.run') as mock_run:
            mock_process = Mock()
            mock_process.returncode = 0
            mock_run.return_value = mock_process

            result = runner.invoke(app, ["run", "echo", "test"])

            # Verify subprocess was called with secrets in environment
            assert mock_run.called
            args, kwargs = mock_run.call_args
            assert args[0] == ["echo", "test"]

            env = kwargs["env"]
            assert "API_KEY" in env
            assert env["API_KEY"] == "secret-key"
            assert "DB_PASSWORD" in env
            assert env["DB_PASSWORD"] == "secret-pass"

    @pytest.mark.integration
    def test_cli_error_handling(self, runner: CliRunner, temp_config):
        """Test CLI error handling."""
        # Test various error conditions

        # Non-existent vault
        result = runner.invoke(app, ["info", "nonexistent"])
        assert result.exit_code == 1
        assert "Error:" in result.stdout

        # Invalid command
        result = runner.invoke(app, ["invalid-command"])
        assert result.exit_code != 0

    @pytest.mark.integration
    def test_complete_cli_workflow(self, runner: CliRunner, temp_config):
        """Test complete CLI workflow."""
        vault_name = "workflow-vault"
        password = "workflow-password"

        with patch('secrets_garden.cli.commands.prompt_password') as mock_password:
            mock_password.return_value = password

            # Create vault
            result = runner.invoke(app, ["init", vault_name, "--description", "Workflow test"])
            assert result.exit_code == 0

            # Add secrets
            result = runner.invoke(app, ["add", "secret1", "--value", "value1", "--vault", vault_name])
            assert result.exit_code == 0

            result = runner.invoke(app, ["add", "secret2", "--value", "value2", "--vault", vault_name])
            assert result.exit_code == 0

            # List secrets
            result = runner.invoke(app, ["list", "--vault", vault_name])
            assert result.exit_code == 0
            assert "secret1" in result.stdout
            assert "secret2" in result.stdout

            # Get secret
            result = runner.invoke(app, ["get", "secret1", "--show", "--vault", vault_name])
            assert result.exit_code == 0
            assert "value1" in result.stdout

            # Update secret
            result = runner.invoke(app, [
                "update", "secret1",
                "--value", "updated-value1",
                "--description", "Updated description",
                "--vault", vault_name
            ])
            assert result.exit_code == 0

            # Verify update
            result = runner.invoke(app, ["get", "secret1", "--show", "--vault", vault_name])
            assert result.exit_code == 0
            assert "updated-value1" in result.stdout

            # Delete secret
            result = runner.invoke(app, ["delete", "secret2", "--force", "--vault", vault_name])
            assert result.exit_code == 0

            # Verify deletion
            result = runner.invoke(app, ["list", "--vault", vault_name])
            assert result.exit_code == 0
            assert "secret1" in result.stdout
            assert "secret2" not in result.stdout

            # Lock vault
            result = runner.invoke(app, ["lock", vault_name])
            assert result.exit_code == 0

            # Verify locked
            result = runner.invoke(app, ["info", vault_name])
            assert result.exit_code == 0
            assert "Locked" in result.stdout
