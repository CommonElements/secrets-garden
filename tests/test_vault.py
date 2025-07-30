"""
Tests for vault management operations.

This module tests the VaultManager class which orchestrates
cryptographic and database operations for complete vault functionality.
"""

import json
import time
from pathlib import Path

import pytest

from secrets_garden.exceptions import (
    InvalidPasswordError,
    SecretAlreadyExistsError,
    SecretNotFoundError,
    VaultAlreadyExistsError,
    VaultError,
    VaultLockedError,
    VaultNotFoundError,
)
from secrets_garden.vault.manager import VaultManager, VaultSession


class TestVaultSession:
    """Test the VaultSession class."""
    
    def test_init(self, temp_dir: Path):
        """Test session initialization."""
        vault_path = temp_dir / "test-vault"
        password = "test-password"
        
        session = VaultSession(vault_path, password)
        
        assert session.vault_path == vault_path
        assert session.get_password() == password
        assert isinstance(session.created_at, float)
        assert isinstance(session.last_accessed, float)
    
    def test_is_expired(self, temp_dir: Path):
        """Test session expiration check."""
        vault_path = temp_dir / "test-vault"
        session = VaultSession(vault_path, "test-password")
        
        # Fresh session should not be expired
        assert session.is_expired(timeout_seconds=3600) is False
        
        # Set old last_accessed time
        session.last_accessed = time.time() - 7200  # 2 hours ago
        
        # Should be expired with 1 hour timeout
        assert session.is_expired(timeout_seconds=3600) is True
    
    def test_touch(self, temp_dir: Path):
        """Test session touch (update last accessed)."""
        vault_path = temp_dir / "test-vault"
        session = VaultSession(vault_path, "test-password")
        
        old_time = session.last_accessed
        time.sleep(0.01)  # Small delay
        session.touch()
        
        assert session.last_accessed > old_time
    
    def test_clear(self, temp_dir: Path):
        """Test session clearing."""
        vault_path = temp_dir / "test-vault"
        session = VaultSession(vault_path, "test-password")
        
        session.clear()
        assert session._password == ""


class TestVaultManager:
    """Test the VaultManager class."""
    
    def test_init(self, vault_path: Path):
        """Test vault manager initialization."""
        vault_manager = VaultManager(vault_path)
        
        assert vault_manager.vault_path == vault_path
        assert vault_manager.db_path == vault_path / "secrets.db"
        assert vault_manager.config_path == vault_path / "vault.json"
        assert vault_manager._session is None
    
    def test_is_locked_property(self, vault_manager: VaultManager):
        """Test is_locked property."""
        # Initially locked (no session)
        assert vault_manager.is_locked is True
        
        # Create vault and unlock
        vault_manager.create("test-password", "Test vault")
        vault_manager.unlock("test-password")
        
        # Should be unlocked
        assert vault_manager.is_locked is False
        
        # Lock vault
        vault_manager.lock()
        
        # Should be locked again
        assert vault_manager.is_locked is True
    
    def test_exists_property(self, vault_manager: VaultManager):
        """Test exists property."""
        # Initially doesn't exist
        assert vault_manager.exists is False
        
        # Create vault
        vault_manager.create("test-password", "Test vault")
        
        # Should exist
        assert vault_manager.exists is True
    
    def test_create_vault(self, vault_manager: VaultManager):
        """Test vault creation."""
        password = "test-password-123"
        description = "Test vault description"
        
        vault_manager.create(password, description)
        
        # Check vault exists
        assert vault_manager.exists is True
        assert vault_manager.vault_path.exists()
        assert vault_manager.config_path.exists()
        assert vault_manager.db_path.exists()
        
        # Check config file content
        with open(vault_manager.config_path, 'r') as f:
            config = json.load(f)
        
        assert config["version"] == "1.0"
        assert config["description"] == description
        assert "password_salt" in config
        assert "password_hash" in config
        assert "encryption" in config
    
    def test_create_vault_already_exists(self, vault_manager: VaultManager):
        """Test creating vault that already exists."""
        vault_manager.create("test-password", "Test vault")
        
        with pytest.raises(VaultAlreadyExistsError):
            vault_manager.create("another-password", "Another vault")
    
    def test_unlock_vault(self, vault_manager: VaultManager):
        """Test vault unlocking."""
        password = "test-password-123"
        vault_manager.create(password, "Test vault")
        
        # Should be locked initially
        assert vault_manager.is_locked is True
        
        # Unlock with correct password
        vault_manager.unlock(password)
        
        # Should be unlocked
        assert vault_manager.is_locked is False
        assert vault_manager._session is not None
    
    def test_unlock_vault_wrong_password(self, vault_manager: VaultManager):
        """Test unlocking with wrong password."""
        vault_manager.create("correct-password", "Test vault")
        
        with pytest.raises(InvalidPasswordError):
            vault_manager.unlock("wrong-password")
    
    def test_unlock_nonexistent_vault(self, vault_manager: VaultManager):
        """Test unlocking non-existent vault."""
        with pytest.raises(VaultNotFoundError):
            vault_manager.unlock("any-password")
    
    def test_lock_vault(self, vault_manager: VaultManager):
        """Test vault locking."""
        password = "test-password"
        vault_manager.create(password, "Test vault")
        vault_manager.unlock(password)
        
        # Should be unlocked
        assert vault_manager.is_locked is False
        
        # Lock vault
        vault_manager.lock()
        
        # Should be locked
        assert vault_manager.is_locked is True
        assert vault_manager._session is None
    
    def test_add_secret(self, vault_manager: VaultManager):
        """Test adding a secret."""
        password = "test-password"
        vault_manager.create(password, "Test vault")
        vault_manager.unlock(password)
        
        vault_manager.add_secret(
            "test_secret",
            "secret_value",
            "Test description",
            ["tag1", "tag2"]
        )
        
        # Verify secret was added
        value = vault_manager.get_secret("test_secret")
        assert value == "secret_value"
    
    def test_add_secret_locked_vault(self, vault_manager: VaultManager):
        """Test adding secret to locked vault."""
        password = "test-password"
        vault_manager.create(password, "Test vault")
        # Don't unlock
        
        with pytest.raises(VaultLockedError):
            vault_manager.add_secret("test_secret", "value")
    
    def test_add_duplicate_secret(self, vault_manager: VaultManager):
        """Test adding duplicate secret."""
        password = "test-password"
        vault_manager.create(password, "Test vault")
        vault_manager.unlock(password)
        
        vault_manager.add_secret("test_secret", "value1")
        
        with pytest.raises(SecretAlreadyExistsError):
            vault_manager.add_secret("test_secret", "value2")
    
    def test_get_secret(self, vault_manager: VaultManager):
        """Test retrieving a secret."""
        password = "test-password"
        vault_manager.create(password, "Test vault")
        vault_manager.unlock(password)
        
        original_value = "secret_value_123"
        vault_manager.add_secret("test_secret", original_value)
        
        retrieved_value = vault_manager.get_secret("test_secret")
        assert retrieved_value == original_value
    
    def test_get_nonexistent_secret(self, vault_manager: VaultManager):
        """Test retrieving non-existent secret."""
        password = "test-password"
        vault_manager.create(password, "Test vault")
        vault_manager.unlock(password)
        
        with pytest.raises(SecretNotFoundError):
            vault_manager.get_secret("nonexistent_secret")
    
    def test_get_secret_locked_vault(self, vault_manager: VaultManager):
        """Test retrieving secret from locked vault."""
        password = "test-password"
        vault_manager.create(password, "Test vault")
        vault_manager.unlock(password)
        vault_manager.add_secret("test_secret", "value")
        vault_manager.lock()
        
        with pytest.raises(VaultLockedError):
            vault_manager.get_secret("test_secret")
    
    def test_update_secret(self, vault_manager: VaultManager):
        """Test updating a secret."""
        password = "test-password"
        vault_manager.create(password, "Test vault")
        vault_manager.unlock(password)
        
        # Add original secret
        vault_manager.add_secret("test_secret", "original_value", "Original desc", ["tag1"])
        
        # Update secret
        vault_manager.update_secret(
            "test_secret",
            value="new_value",
            description="New description",
            tags=["tag2", "tag3"]
        )
        
        # Verify update
        updated_value = vault_manager.get_secret("test_secret")
        assert updated_value == "new_value"
    
    def test_update_secret_partial(self, vault_manager: VaultManager):
        """Test partial secret update."""
        password = "test-password"
        vault_manager.create(password, "Test vault")
        vault_manager.unlock(password)
        
        # Add original secret
        vault_manager.add_secret("test_secret", "original_value", "Original desc")
        
        # Update only description
        vault_manager.update_secret("test_secret", description="New description")
        
        # Value should be unchanged
        value = vault_manager.get_secret("test_secret")
        assert value == "original_value"
    
    def test_update_nonexistent_secret(self, vault_manager: VaultManager):
        """Test updating non-existent secret."""
        password = "test-password"
        vault_manager.create(password, "Test vault")
        vault_manager.unlock(password)
        
        with pytest.raises(SecretNotFoundError):
            vault_manager.update_secret("nonexistent_secret", value="new_value")
    
    def test_delete_secret(self, vault_manager: VaultManager):
        """Test deleting a secret."""
        password = "test-password"
        vault_manager.create(password, "Test vault")
        vault_manager.unlock(password)
        
        # Add secret
        vault_manager.add_secret("test_secret", "value")
        
        # Verify it exists
        vault_manager.get_secret("test_secret")
        
        # Delete secret
        vault_manager.delete_secret("test_secret")
        
        # Verify it's gone
        with pytest.raises(SecretNotFoundError):
            vault_manager.get_secret("test_secret")
    
    def test_delete_nonexistent_secret(self, vault_manager: VaultManager):
        """Test deleting non-existent secret."""
        password = "test-password"
        vault_manager.create(password, "Test vault")
        vault_manager.unlock(password)
        
        with pytest.raises(SecretNotFoundError):
            vault_manager.delete_secret("nonexistent_secret")
    
    def test_list_secrets(self, vault_manager: VaultManager):
        """Test listing secrets."""
        password = "test-password"
        vault_manager.create(password, "Test vault")
        vault_manager.unlock(password)
        
        # Add multiple secrets
        secrets_data = [
            ("secret1", "value1", "Description 1", ["tag1", "tag2"]),
            ("secret2", "value2", "Description 2", ["tag2", "tag3"]),
            ("secret3", "value3", "Description 3", ["tag1"]),
        ]
        
        for name, value, desc, tags in secrets_data:
            vault_manager.add_secret(name, value, desc, tags)
        
        # List all secrets
        secrets = vault_manager.list_secrets()
        assert len(secrets) == 3
        
        # Check structure
        for secret in secrets:
            assert "name" in secret
            assert "description" in secret
            assert "tags" in secret
            assert "created_at" in secret
            assert "updated_at" in secret
    
    def test_list_secrets_with_filters(self, vault_manager: VaultManager):
        """Test listing secrets with filters."""
        password = "test-password"
        vault_manager.create(password, "Test vault")
        vault_manager.unlock(password)
        
        # Add secrets
        vault_manager.add_secret("api_key", "value1", tags=["api"])
        vault_manager.add_secret("api_secret", "value2", tags=["api"])
        vault_manager.add_secret("db_password", "value3", tags=["database"])
        
        # Filter by pattern
        api_secrets = vault_manager.list_secrets(pattern="api%")
        assert len(api_secrets) == 2
        
        # Filter by tags
        api_tagged = vault_manager.list_secrets(tags=["api"])
        assert len(api_tagged) == 2
    
    def test_export_secrets_json(self, vault_manager: VaultManager, temp_dir: Path):
        """Test exporting secrets to JSON."""
        password = "test-password"
        vault_manager.create(password, "Test vault")
        vault_manager.unlock(password)
        
        # Add secrets
        vault_manager.add_secret("secret1", "value1", "Description 1")
        vault_manager.add_secret("secret2", "value2", "Description 2")
        
        # Export without values
        export_path = temp_dir / "export.json"
        vault_manager.export_secrets(export_path, format="json", include_values=False)
        
        # Verify export
        assert export_path.exists()
        
        with open(export_path, 'r') as f:
            export_data = json.load(f)
        
        assert "vault" in export_data
        assert "secrets" in export_data
        assert len(export_data["secrets"]) == 2
        assert "secret1" in export_data["secrets"]
        assert "value" not in export_data["secrets"]["secret1"]
    
    def test_export_secrets_json_with_values(self, vault_manager: VaultManager, temp_dir: Path):
        """Test exporting secrets to JSON with values."""
        password = "test-password"
        vault_manager.create(password, "Test vault")
        vault_manager.unlock(password)
        
        # Add secret
        vault_manager.add_secret("secret1", "value1", "Description 1")
        
        # Export with values
        export_path = temp_dir / "export_with_values.json"
        vault_manager.export_secrets(export_path, format="json", include_values=True)
        
        # Verify export
        with open(export_path, 'r') as f:
            export_data = json.load(f)
        
        assert export_data["secrets"]["secret1"]["value"] == "value1"
    
    def test_export_secrets_env(self, vault_manager: VaultManager, temp_dir: Path):
        """Test exporting secrets to environment file."""
        password = "test-password"
        vault_manager.create(password, "Test vault")
        vault_manager.unlock(password)
        
        # Add secrets
        vault_manager.add_secret("API_KEY", "key123")
        vault_manager.add_secret("DB_PASSWORD", "pass456")
        
        # Export with values
        export_path = temp_dir / "secrets.env"
        vault_manager.export_secrets(export_path, format="env", include_values=True)
        
        # Verify export
        assert export_path.exists()
        
        with open(export_path, 'r') as f:
            content = f.read()
        
        assert "API_KEY=key123" in content
        assert "DB_PASSWORD=pass456" in content
    
    def test_get_vault_info(self, vault_manager: VaultManager):
        """Test getting vault information."""
        password = "test-password"
        description = "Test vault description"
        vault_manager.create(password, description)
        
        # Get info while locked
        info = vault_manager.get_vault_info()
        
        assert info["version"] == "1.0"
        assert info["description"] == description
        assert info["locked"] is True
        assert "secrets_count" not in info
        
        # Unlock and get info
        vault_manager.unlock(password)
        vault_manager.add_secret("test_secret", "value")
        
        info = vault_manager.get_vault_info()
        assert info["locked"] is False
        assert info["secrets_count"] == 1
    
    def test_get_vault_info_nonexistent(self, vault_manager: VaultManager):
        """Test getting info for non-existent vault."""
        with pytest.raises(VaultNotFoundError):
            vault_manager.get_vault_info()
    
    def test_change_password(self, vault_manager: VaultManager):
        """Test changing vault password."""
        old_password = "old-password-123"
        new_password = "new-password-456"
        
        vault_manager.create(old_password, "Test vault")
        vault_manager.unlock(old_password)
        
        # Add secret
        vault_manager.add_secret("test_secret", "secret_value")
        
        # Change password
        vault_manager.change_password(old_password, new_password)
        
        # Lock and try to unlock with old password
        vault_manager.lock()
        
        with pytest.raises(InvalidPasswordError):
            vault_manager.unlock(old_password)
        
        # Should work with new password
        vault_manager.unlock(new_password)
        
        # Secret should still be accessible
        value = vault_manager.get_secret("test_secret")
        assert value == "secret_value"
    
    def test_change_password_wrong_old_password(self, vault_manager: VaultManager):
        """Test changing password with wrong old password."""
        password = "correct-password"
        vault_manager.create(password, "Test vault")
        
        with pytest.raises(InvalidPasswordError):
            vault_manager.change_password("wrong-password", "new-password")
    
    def test_backup_vault(self, vault_manager: VaultManager, temp_dir: Path):
        """Test vault backup."""
        password = "test-password"
        vault_manager.create(password, "Test vault")
        vault_manager.unlock(password)
        
        # Add secret
        vault_manager.add_secret("test_secret", "secret_value")
        
        # Create backup
        backup_path = temp_dir / "backup"
        vault_manager.backup(backup_path)
        
        # Verify backup
        assert backup_path.exists()
        assert (backup_path / "vault.json").exists()
        assert (backup_path / "secrets.db").exists()
        
        # Verify backup can be used
        backup_manager = VaultManager(backup_path)
        backup_manager.unlock(password)
        
        value = backup_manager.get_secret("test_secret")
        assert value == "secret_value"
    
    @pytest.mark.integration
    def test_full_workflow(self, vault_manager: VaultManager, sample_secrets: dict):
        """Test complete vault workflow."""
        password = "workflow-test-password"
        
        # Create vault
        vault_manager.create(password, "Workflow test vault")
        
        # Unlock vault
        vault_manager.unlock(password)
        
        # Add all sample secrets
        for name, data in sample_secrets.items():
            vault_manager.add_secret(
                name,
                data["value"],
                data["description"],
                data["tags"]
            )
        
        # Verify all secrets
        for name, data in sample_secrets.items():
            retrieved_value = vault_manager.get_secret(name)
            assert retrieved_value == data["value"]
        
        # List secrets
        secrets_list = vault_manager.list_secrets()
        assert len(secrets_list) == len(sample_secrets)
        
        # Update a secret
        vault_manager.update_secret("api_key", value="updated-api-key")
        updated_value = vault_manager.get_secret("api_key")
        assert updated_value == "updated-api-key"
        
        # Delete a secret
        vault_manager.delete_secret("smtp_password")
        
        with pytest.raises(SecretNotFoundError):
            vault_manager.get_secret("smtp_password")
        
        # Change password
        new_password = "new-workflow-password"
        vault_manager.change_password(password, new_password)
        
        # Lock and unlock with new password
        vault_manager.lock()
        vault_manager.unlock(new_password)
        
        # Verify secrets still work
        value = vault_manager.get_secret("api_key")
        assert value == "updated-api-key"
    
    @pytest.mark.security
    def test_session_timeout_security(self, vault_manager: VaultManager):
        """Test that sessions properly timeout for security."""
        password = "test-password"
        vault_manager.create(password, "Test vault")
        vault_manager.unlock(password)
        
        # Should be unlocked
        assert vault_manager.is_locked is False
        
        # Manually expire session
        vault_manager._session.last_accessed = time.time() - 7200  # 2 hours ago
        
        # Should now be considered locked
        assert vault_manager.is_locked is True
        
        # Operations should fail
        with pytest.raises(VaultLockedError):
            vault_manager.add_secret("test", "value")
    
    @pytest.mark.security
    def test_password_verification_security(self, vault_manager: VaultManager):
        """Test password verification security properties."""
        password = "secure-password-123"
        vault_manager.create(password, "Security test vault")
        
        # Should not be able to unlock with similar passwords
        similar_passwords = [
            "secure-password-124",  # Off by one
            "secure-password-12",   # Missing digit
            "Secure-password-123",  # Different case
            "secure-password-123 ", # Extra space
            "",                     # Empty
        ]
        
        for bad_password in similar_passwords:
            with pytest.raises(InvalidPasswordError):
                vault_manager.unlock(bad_password)