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
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Union

from secrets_garden.exceptions import (
    InvalidPasswordError,
    VaultAlreadyExistsError,
    VaultCorruptedError,
    VaultError,
    VaultLockedError,
    VaultNotFoundError,
)
from secrets_garden.vault.crypto import CryptoManager, EncryptedData
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
    
    @property
    def is_locked(self) -> bool:
        """Check if the vault is currently locked."""
        return self._session is None or self._session.is_expired()
    
    @property 
    def exists(self) -> bool:
        """Check if the vault exists."""
        return self.vault_path.exists() and self.config_path.exists()
    
    def create(self, password: str, description: str = "") -> None:
        """
        Create a new vault.
        
        Args:
            password: Master password for the vault
            description: Optional vault description
            
        Raises:
            VaultAlreadyExistsError: If vault already exists
            VaultError: If creation fails
        """
        if self.exists:
            raise VaultAlreadyExistsError(f"Vault already exists at {self.vault_path}")
        
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
            VaultError: If unlock fails
        """
        if not self.exists:
            raise VaultNotFoundError(f"Vault not found at {self.vault_path}")
        
        try:
            # Load vault configuration
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            
            # Extract stored password data
            stored_salt = bytes.fromhex(config["password_salt"])
            stored_hash = bytes.fromhex(config["password_hash"])
            
            # Verify password
            if not self.crypto.verify_password(password, stored_salt, stored_hash):
                raise InvalidPasswordError("Invalid master password")
            
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
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            
            info = {
                "path": str(self.vault_path),
                "version": config.get("version", "unknown"),
                "created_at": config.get("created_at"),
                "description": config.get("description", ""),
                "locked": self.is_locked,
            }
            
            # Add statistics if unlocked
            if not self.is_locked:
                info["secrets_count"] = self.database.count_secrets()
            
            return info
            
        except Exception as e:
            raise VaultError(f"Failed to get vault info: {e}") from e
    
    def change_password(self, old_password: str, new_password: str) -> None:
        """
        Change the vault master password.
        
        This operation re-encrypts all secrets with the new password.
        
        Args:
            old_password: Current master password
            new_password: New master password
            
        Raises:
            VaultLockedError: If vault is locked
            InvalidPasswordError: If old password is incorrect
            VaultError: If operation fails
        """
        # Verify old password by attempting to unlock
        if self.is_locked:
            self.unlock(old_password)
        
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
            with open(self.config_path, 'r') as f:
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