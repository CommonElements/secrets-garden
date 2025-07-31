"""
Vault manager for Secret's Garden.

This module provides the main interface for vault operations,
orchestrating the cryptographic and database layers to provide
a secure secrets management system.

Features:
- Vault creation and initialization
- Secure unlocking with master password verification
- Secret CRUD operations with encryption
- Vault locking and session management
- Import/export functionality
- Backup and restore operations
"""

import json
import os
import time
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from secrets_garden.exceptions import (
    InvalidPasswordError,
    VaultAlreadyExistsError,
    VaultCorruptedError,
    VaultError,
    VaultLockedError,
    VaultNotFoundError,
)
from secrets_garden.security import BruteForceProtector, PasswordValidator
from secrets_garden.vault.crypto import CryptoManager
from secrets_garden.vault.database import DatabaseManager, SecretRecord


class VaultSession:
    """Represents an active vault session with decryption capabilities."""

    def __init__(self, vault_path: Path, password: str) -> None:
        self.vault_path = vault_path
        self._password = password
        self.created_at = time.time()
        self.last_accessed = time.time()

    def is_expired(self, timeout_seconds: int = 3600) -> bool:
        """Check if session has expired."""
        return (time.time() - self.last_accessed) > timeout_seconds

    def touch(self) -> None:
        """Update last accessed time."""
        self.last_accessed = time.time()

    def get_password(self) -> str:
        """Get the password for this session."""
        self.touch()
        return self._password

    def clear(self) -> None:
        """Clear sensitive session data."""
        self._password = ""


class VaultManager:
    """
    Main interface for vault operations.
    
    This class orchestrates the cryptographic and database layers
    to provide a complete secrets management system with proper
    security controls and session management.
    """

    def __init__(self, vault_path: Path) -> None:
        """
        Initialize the vault manager.
        
        Args:
            vault_path: Path to the vault directory
        """
        self.vault_path = vault_path
        self.db_path = vault_path / "secrets.db"
        self.config_path = vault_path / "vault.json"

        self.crypto = CryptoManager()
        self.database = DatabaseManager(self.db_path)
        self._session: Optional[VaultSession] = None

        # Initialize security components
        self.password_validator = PasswordValidator(min_length=12, min_entropy=50)
        brute_force_storage = vault_path / ".auth_attempts.json"
        self.brute_force_protector = BruteForceProtector(
            max_attempts=5,
            lockout_duration=300,  # 5 minutes
            storage_path=brute_force_storage
        )

    @property
    def is_locked(self) -> bool:
        """Check if the vault is currently locked."""
        return self._session is None or self._session.is_expired()

    @property
    def exists(self) -> bool:
        """Check if the vault exists."""
        return self.vault_path.exists() and self.config_path.exists()

    def create(self, password: str, description: str = "", validate_password: bool = True) -> None:
        """
        Create a new vault.
        
        Args:
            password: Master password for the vault
            description: Optional vault description
            validate_password: Whether to validate password strength
            
        Raises:
            VaultAlreadyExistsError: If vault already exists
            InvalidPasswordError: If password validation fails
            VaultError: If creation fails
        """
        if self.exists:
            raise VaultAlreadyExistsError(f"Vault already exists at {self.vault_path}")

        # Validate password strength
        if validate_password:
            strength = self.password_validator.validate(password)
            if not strength.is_strong:
                error_msg = f"Password is {strength.strength_label.lower()}"
                if strength.issues:
                    error_msg += f": {'; '.join(strength.issues)}"
                if strength.suggestions:
                    error_msg += f". Suggestions: {'; '.join(strength.suggestions)}"
                raise InvalidPasswordError(error_msg)

        try:
            # Create vault directory
            self.vault_path.mkdir(parents=True, exist_ok=True)

            # Generate salt and hash the master password
            password_hash, salt = self.crypto.hash_password(password)

            # Create vault configuration
            config = {
                "version": "1.0",
                "created_at": time.time(),
                "description": description,
                "password_salt": salt.hex(),
                "password_hash": password_hash.hex(),
                "encryption": {
                    "algorithm": "AES-256-GCM",
                    "kdf": "PBKDF2-HMAC-SHA256",
                    "iterations": CryptoManager.PBKDF2_ITERATIONS,
                },
            }

            # Write configuration file
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)

            # Set restrictive permissions on config file
            os.chmod(self.config_path, 0o600)

            # Initialize database
            self.database.connect()
            self.database.initialize_schema()
            self.database.disconnect()

            # Set restrictive permissions on database
            os.chmod(self.db_path, 0o600)

        except Exception as e:
            # Clean up on failure
            if self.vault_path.exists():
                import shutil
                shutil.rmtree(self.vault_path, ignore_errors=True)
            raise VaultError(f"Failed to create vault: {e}") from e

    def unlock(self, password: str) -> None:
        """
        Unlock the vault with the master password.
        
        Args:
            password: Master password
            
        Raises:
            VaultNotFoundError: If vault doesn't exist
            InvalidPasswordError: If password is incorrect
            VaultCorruptedError: If vault is corrupted
            VaultError: If unlock fails or brute force protection active
        """
        if not self.exists:
            raise VaultNotFoundError(f"Vault not found at {self.vault_path}")

        # Check brute force protection
        vault_id = str(self.vault_path)
        if not self.brute_force_protector.check_attempt_allowed(vault_id):
            remaining = self.brute_force_protector.get_lockout_remaining(vault_id)
            if remaining:
                raise VaultError(f"Too many failed attempts. Vault locked for {remaining} seconds.")
            else:
                raise VaultError("Too many failed attempts. Vault temporarily locked.")

        success = False
        try:
            # Load vault configuration
            with open(self.config_path) as f:
                config = json.load(f)

            # Extract stored password data
            stored_salt = bytes.fromhex(config["password_salt"])
            stored_hash = bytes.fromhex(config["password_hash"])

            # Verify password
            if not self.crypto.verify_password(password, stored_salt, stored_hash):
                raise InvalidPasswordError("Invalid master password")

            success = True

            # Connect to database and verify integrity
            self.database.connect()

            if not self.database.verify_integrity():
                self.database.disconnect()
                raise VaultCorruptedError("Vault database is corrupted")

            # Create session
            self._session = VaultSession(self.vault_path, password)

        except (KeyError, ValueError, json.JSONDecodeError) as e:
            raise VaultCorruptedError(f"Vault configuration is corrupted: {e}") from e
        except Exception as e:
            if self.database._connection:
                self.database.disconnect()
            raise VaultError(f"Failed to unlock vault: {e}") from e
        finally:
            # Record the attempt result for brute force protection
            self.brute_force_protector.record_attempt(vault_id, success)

    def lock(self) -> None:
        """Lock the vault and clear session data."""
        if self._session:
            self._session.clear()
            self._session = None

        if self.database._connection:
            self.database.disconnect()

    @contextmanager
    def _ensure_unlocked(self) -> Generator[str, None, None]:
        """Context manager to ensure vault is unlocked."""
        if self.is_locked:
            raise VaultLockedError("Vault is locked")

        password = self._session.get_password()
        yield password

    def add_secret(
        self,
        name: str,
        value: str,
        description: str = "",
        tags: Union[List[str], None] = None,
    ) -> None:
        """
        Add a new secret to the vault.
        
        Args:
            name: Secret name (must be unique)
            value: Secret value to encrypt
            description: Optional description
            tags: Optional list of tags
            
        Raises:
            VaultLockedError: If vault is locked
            SecretAlreadyExistsError: If secret already exists
            VaultError: If operation fails
        """
        with self._ensure_unlocked() as password:
            try:
                # Encrypt the secret value
                encrypted_data = self.crypto.encrypt(value, password)

                # Create secret record
                record = SecretRecord(
                    name=name,
                    encrypted_value=encrypted_data,
                    description=description,
                    tags=",".join(tags) if tags else "",
                )

                # Store in database
                self.database.create_secret(record)

            except Exception as e:
                raise VaultError(f"Failed to add secret: {e}") from e

    def get_secret(self, name: str) -> str:
        """
        Retrieve and decrypt a secret value.
        
        Args:
            name: Secret name
            
        Returns:
            Decrypted secret value
            
        Raises:
            VaultLockedError: If vault is locked
            SecretNotFoundError: If secret doesn't exist
            VaultError: If operation fails
        """
        with self._ensure_unlocked() as password:
            try:
                # Get encrypted record from database
                record = self.database.get_secret(name)

                # Decrypt the value
                decrypted_value = self.crypto.decrypt(record.encrypted_value, password)

                return decrypted_value

            except Exception as e:
                raise VaultError(f"Failed to get secret: {e}") from e

    def update_secret(
        self,
        name: str,
        value: Union[str, None] = None,
        description: Union[str, None] = None,
        tags: Union[List[str], None] = None,
    ) -> None:
        """
        Update an existing secret.
        
        Args:
            name: Secret name
            value: New secret value (if provided)
            description: New description (if provided)
            tags: New tags (if provided)
            
        Raises:
            VaultLockedError: If vault is locked
            SecretNotFoundError: If secret doesn't exist
            VaultError: If operation fails
        """
        with self._ensure_unlocked() as password:
            try:
                # Get existing record
                record = self.database.get_secret(name)

                # Update fields as needed
                if value is not None:
                    record.encrypted_value = self.crypto.encrypt(value, password)

                if description is not None:
                    record.description = description

                if tags is not None:
                    record.tags = ",".join(tags)

                record.updated_at = time.time()

                # Save updated record
                self.database.update_secret(record)

            except Exception as e:
                raise VaultError(f"Failed to update secret: {e}") from e

    def delete_secret(self, name: str) -> None:
        """
        Delete a secret from the vault.
        
        Args:
            name: Secret name
            
        Raises:
            VaultLockedError: If vault is locked
            SecretNotFoundError: If secret doesn't exist
            VaultError: If operation fails
        """
        with self._ensure_unlocked():
            try:
                self.database.delete_secret(name)

            except Exception as e:
                raise VaultError(f"Failed to delete secret: {e}") from e

    def list_secrets(
        self,
        pattern: Union[str, None] = None,
        tags: Union[List[str], None] = None,
        limit: Union[int, None] = None,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        List secrets in the vault.
        
        Args:
            pattern: Optional name pattern for filtering
            tags: Optional tags for filtering
            limit: Maximum number of results
            offset: Number of results to skip
            
        Returns:
            List of secret metadata (no values)
            
        Raises:
            VaultLockedError: If vault is locked
            VaultError: If operation fails
        """
        with self._ensure_unlocked():
            try:
                return self.database.list_secrets(pattern, tags, limit, offset)

            except Exception as e:
                raise VaultError(f"Failed to list secrets: {e}") from e

    def export_secrets(
        self,
        output_path: Path,
        format: str = "json",
        include_values: bool = False,
    ) -> None:
        """
        Export vault secrets to a file.
        
        Args:
            output_path: Path for export file
            format: Export format ("json" or "env")
            include_values: Whether to include decrypted values
            
        Raises:
            VaultLockedError: If vault is locked
            VaultError: If export fails
        """
        with self._ensure_unlocked() as password:
            try:
                secrets = self.database.list_secrets()

                if format == "json":
                    export_data = {
                        "vault": {
                            "exported_at": time.time(),
                            "secrets_count": len(secrets),
                        },
                        "secrets": {},
                    }

                    for secret_info in secrets:
                        secret_data = {
                            "description": secret_info["description"],
                            "tags": secret_info["tags"],
                            "created_at": secret_info["created_at"],
                            "updated_at": secret_info["updated_at"],
                        }

                        if include_values:
                            secret_data["value"] = self.get_secret(secret_info["name"])

                        export_data["secrets"][secret_info["name"]] = secret_data

                    with open(output_path, 'w') as f:
                        json.dump(export_data, f, indent=2)

                elif format == "env":
                    with open(output_path, 'w') as f:
                        for secret_info in secrets:
                            if include_values:
                                value = self.get_secret(secret_info["name"])
                                f.write(f"{secret_info['name']}={value}\n")
                            else:
                                f.write(f"# {secret_info['name']}=<value>\n")

                else:
                    raise VaultError(f"Unsupported export format: {format}")

            except Exception as e:
                raise VaultError(f"Failed to export secrets: {e}") from e

    def get_vault_info(self) -> Dict[str, Any]:
        """
        Get vault information and statistics.
        
        Returns:
            Dictionary with vault metadata
            
        Raises:
            VaultNotFoundError: If vault doesn't exist
            VaultError: If operation fails
        """
        if not self.exists:
            raise VaultNotFoundError(f"Vault not found at {self.vault_path}")

        try:
            # Load configuration
            with open(self.config_path) as f:
                config = json.load(f)

            info = {
                "path": str(self.vault_path),
                "version": config.get("version", "unknown"),
                "created_at": config.get("created_at"),
                "description": config.get("description", ""),
                "locked": self.is_locked,
                "last_key_rotation": config.get("last_key_rotation"),
            }

            # Add statistics if unlocked
            if not self.is_locked:
                info["secrets_count"] = self.database.count_secrets()

            return info

        except Exception as e:
            raise VaultError(f"Failed to get vault info: {e}") from e

    def change_password(self, old_password: str, new_password: str, validate_password: bool = True) -> None:
        """
        Change the vault master password.
        
        This operation re-encrypts all secrets with the new password.
        
        Args:
            old_password: Current master password
            new_password: New master password
            validate_password: Whether to validate new password strength
            
        Raises:
            VaultLockedError: If vault is locked
            InvalidPasswordError: If old password is incorrect or new password validation fails
            VaultError: If operation fails
        """
        # Verify old password by attempting to unlock
        if self.is_locked:
            self.unlock(old_password)

        # Validate new password strength
        if validate_password:
            strength = self.password_validator.validate(new_password)
            if not strength.is_strong:
                error_msg = f"New password is {strength.strength_label.lower()}"
                if strength.issues:
                    error_msg += f": {'; '.join(strength.issues)}"
                if strength.suggestions:
                    error_msg += f". Suggestions: {'; '.join(strength.suggestions)}"
                raise InvalidPasswordError(error_msg)

        try:
            # Get all secrets with current password
            secrets_data = []
            secret_list = self.database.list_secrets()

            for secret_info in secret_list:
                record = self.database.get_secret(secret_info["name"])
                decrypted_value = self.crypto.decrypt(record.encrypted_value, old_password)
                secrets_data.append((record, decrypted_value))

            # Generate new password hash
            new_hash, new_salt = self.crypto.hash_password(new_password)

            # Update configuration
            with open(self.config_path) as f:
                config = json.load(f)

            config["password_salt"] = new_salt.hex()
            config["password_hash"] = new_hash.hex()

            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)

            # Re-encrypt all secrets with new password
            for record, decrypted_value in secrets_data:
                new_encrypted_data = self.crypto.encrypt(decrypted_value, new_password)
                record.encrypted_value = new_encrypted_data
                record.updated_at = time.time()
                self.database.update_secret(record)

            # Update session
            if self._session:
                self._session._password = new_password

        except Exception as e:
            raise VaultError(f"Failed to change password: {e}") from e

    def rotate_encryption_key(self, password: str, backup_before_rotation: bool = True) -> None:
        """
        Rotate the vault's encryption keys while keeping the same password.
        
        This operation re-encrypts all secrets with a new salt, providing
        forward secrecy and protection against cryptographic key compromise.
        
        Args:
            password: Current master password
            backup_before_rotation: Whether to create a backup before rotation
            
        Raises:
            VaultLockedError: If vault is locked
            InvalidPasswordError: If password is incorrect
            VaultError: If rotation fails
        """
        if not self.exists:
            raise VaultNotFoundError(f"Vault not found at {self.vault_path}")

        # Ensure vault is unlocked
        if self.is_locked:
            self.unlock(password)

        try:
            # Create backup if requested
            if backup_before_rotation:
                backup_dir = self.vault_path.parent / f"{self.vault_path.name}_backup_{int(time.time())}"
                self.backup(backup_dir)

            # Get all secrets with current password
            secrets_data = []
            secret_list = self.database.list_secrets()

            for secret_info in secret_list:
                record = self.database.get_secret(secret_info["name"])
                decrypted_value = self.crypto.decrypt(record.encrypted_value, password)
                secrets_data.append((record, decrypted_value))

            # Generate new salt for the same password (key rotation)
            new_hash, new_salt = self.crypto.hash_password(password)

            # Update configuration with new salt
            with open(self.config_path) as f:
                config = json.load(f)

            # Store old salt for rollback if needed
            old_salt = config["password_salt"]
            old_hash = config["password_hash"]

            config["password_salt"] = new_salt.hex()
            config["password_hash"] = new_hash.hex()
            config["last_key_rotation"] = time.time()

            # Write updated configuration
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)

            try:
                # Re-encrypt all secrets with new salt-derived key
                for record, decrypted_value in secrets_data:
                    new_encrypted_data = self.crypto.encrypt(decrypted_value, password)
                    record.encrypted_value = new_encrypted_data
                    record.updated_at = time.time()
                    self.database.update_secret(record)

                # Update session with new key derivation
                if self._session:
                    self._session._password = password  # Refresh session

            except Exception as e:
                # Rollback configuration on failure
                config["password_salt"] = old_salt
                config["password_hash"] = old_hash
                if "last_key_rotation" in config:
                    del config["last_key_rotation"]

                with open(self.config_path, 'w') as f:
                    json.dump(config, f, indent=2)

                raise VaultError(f"Key rotation failed, configuration rolled back: {e}") from e

        except Exception as e:
            raise VaultError(f"Failed to rotate encryption key: {e}") from e

    def backup(self, backup_path: Path) -> None:
        """
        Create a backup of the vault.
        
        Args:
            backup_path: Path for backup directory
            
        Raises:
            VaultError: If backup fails
        """
        try:
            import shutil

            backup_path.mkdir(parents=True, exist_ok=True)

            # Copy vault configuration
            shutil.copy2(self.config_path, backup_path / "vault.json")

            # Backup database if connected
            if not self.is_locked:
                self.database.backup_database(backup_path / "secrets.db")
            else:
                shutil.copy2(self.db_path, backup_path / "secrets.db")

        except Exception as e:
            raise VaultError(f"Failed to backup vault: {e}") from e
