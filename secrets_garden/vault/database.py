"""
Database operations for Secret's Garden.

This module handles all SQLite database operations for storing encrypted
secrets. The database schema is designed for security and efficiency,
with proper indexing and constraints.

Security Features:
- All secret values are stored as encrypted blobs
- Parameterized queries prevent SQL injection
- Database integrity checks
- Atomic transactions for consistency
- Secure deletion with overwriting
"""

import sqlite3
import time
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from secrets_garden.exceptions import (
    DatabaseError,
    SecretAlreadyExistsError,
    SecretNotFoundError,
    VaultCorruptedError,
)
from secrets_garden.vault.crypto import EncryptedData


class SecretRecord:
    """Represents a secret stored in the database."""

    def __init__(
        self,
        name: str,
        encrypted_value: EncryptedData,
        description: str = "",
        tags: str = "",
        created_at: Union[float, None] = None,
        updated_at: Union[float, None] = None,
    ) -> None:
        self.name = name
        self.encrypted_value = encrypted_value
        self.description = description
        self.tags = tags
        self.created_at = created_at or time.time()
        self.updated_at = updated_at or time.time()

    def to_dict(self) -> Dict[str, Any]:
        """Convert the record to a dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "tags": self.tags,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class DatabaseManager:
    """
    Manages SQLite database operations for Secret's Garden.
    
    This class provides a secure abstraction layer over SQLite,
    handling schema creation, migrations, and CRUD operations
    for encrypted secrets.
    """

    # Database schema version for migrations
    SCHEMA_VERSION = 1

    def __init__(self, db_path: Path) -> None:
        """
        Initialize the database manager.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self._connection: Optional[sqlite3.Connection] = None

    def connect(self) -> None:
        """
        Connect to the SQLite database.
        
        Raises:
            DatabaseError: If connection fails
        """
        try:
            self._connection = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
                timeout=30.0,
            )

            # Configure SQLite for security and performance
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA secure_delete=ON")

            # Set row factory for easier data access
            self._connection.row_factory = sqlite3.Row

        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to connect to database: {e}") from e

    def disconnect(self) -> None:
        """Close the database connection."""
        if self._connection:
            self._connection.close()
            self._connection = None

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Connection, None, None]:
        """
        Context manager for database transactions.
        
        Ensures proper transaction handling with automatic
        rollback on exceptions.
        
        Yields:
            The database connection
            
        Raises:
            DatabaseError: If transaction fails
        """
        if not self._connection:
            raise DatabaseError("Database not connected")

        try:
            self._connection.execute("BEGIN")
            yield self._connection
            self._connection.commit()
        except Exception as e:
            self._connection.rollback()
            raise DatabaseError(f"Transaction failed: {e}") from e

    def initialize_schema(self) -> None:
        """
        Initialize the database schema.
        
        Creates all necessary tables and indexes if they don't exist.
        
        Raises:
            DatabaseError: If schema creation fails
        """
        if not self._connection:
            raise DatabaseError("Database not connected")

        try:
            with self.transaction() as conn:
                # Create metadata table for schema versioning
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        created_at REAL NOT NULL DEFAULT (julianday('now')),
                        updated_at REAL NOT NULL DEFAULT (julianday('now'))
                    )
                """)

                # Create secrets table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS secrets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL UNIQUE,
                        description TEXT NOT NULL DEFAULT '',
                        tags TEXT NOT NULL DEFAULT '',
                        ciphertext BLOB NOT NULL,
                        nonce BLOB NOT NULL,
                        tag BLOB NOT NULL,
                        salt BLOB NOT NULL,
                        created_at REAL NOT NULL DEFAULT (julianday('now')),
                        updated_at REAL NOT NULL DEFAULT (julianday('now'))
                    )
                """)

                # Create indexes for performance
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_secrets_name 
                    ON secrets(name)
                """)

                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_secrets_tags 
                    ON secrets(tags)
                """)

                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_secrets_created 
                    ON secrets(created_at)
                """)

                # Store schema version
                conn.execute("""
                    INSERT OR REPLACE INTO metadata (key, value, updated_at)
                    VALUES ('schema_version', ?, julianday('now'))
                """, (str(self.SCHEMA_VERSION),))

        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to initialize schema: {e}") from e

    def verify_integrity(self) -> bool:
        """
        Verify database integrity.
        
        Returns:
            True if database is intact, False otherwise
            
        Raises:
            DatabaseError: If integrity check fails
        """
        if not self._connection:
            raise DatabaseError("Database not connected")

        try:
            cursor = self._connection.execute("PRAGMA integrity_check")
            result = cursor.fetchone()
            return result and result[0] == "ok"

        except sqlite3.Error as e:
            raise DatabaseError(f"Integrity check failed: {e}") from e

    def get_schema_version(self) -> int:
        """
        Get the current schema version.
        
        Returns:
            Schema version number
            
        Raises:
            VaultCorruptedError: If schema version cannot be determined
        """
        if not self._connection:
            raise DatabaseError("Database not connected")

        try:
            cursor = self._connection.execute("""
                SELECT value FROM metadata WHERE key = 'schema_version'
            """)
            result = cursor.fetchone()

            if not result:
                raise VaultCorruptedError("Schema version not found")

            return int(result[0])

        except (sqlite3.Error, ValueError) as e:
            raise VaultCorruptedError(f"Invalid schema version: {e}") from e

    def create_secret(self, record: SecretRecord) -> None:
        """
        Create a new secret in the database.
        
        Args:
            record: The secret record to create
            
        Raises:
            SecretAlreadyExistsError: If secret already exists
            DatabaseError: If creation fails
        """
        if not self._connection:
            raise DatabaseError("Database not connected")

        try:
            with self.transaction() as conn:
                conn.execute("""
                    INSERT INTO secrets (
                        name, description, tags, ciphertext, nonce, tag, salt,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    record.name,
                    record.description,
                    record.tags,
                    record.encrypted_value.ciphertext,
                    record.encrypted_value.nonce,
                    record.encrypted_value.tag,
                    record.encrypted_value.salt,
                    record.created_at,
                    record.updated_at,
                ))

        except sqlite3.IntegrityError as e:
            if "UNIQUE constraint failed" in str(e):
                raise SecretAlreadyExistsError(f"Secret '{record.name}' already exists")
            raise DatabaseError(f"Failed to create secret: {e}") from e
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to create secret: {e}") from e

    def get_secret(self, name: str) -> SecretRecord:
        """
        Retrieve a secret by name.
        
        Args:
            name: The secret name
            
        Returns:
            The secret record
            
        Raises:
            SecretNotFoundError: If secret doesn't exist
            DatabaseError: If retrieval fails
        """
        if not self._connection:
            raise DatabaseError("Database not connected")

        try:
            cursor = self._connection.execute("""
                SELECT name, description, tags, ciphertext, nonce, tag, salt,
                       created_at, updated_at
                FROM secrets WHERE name = ?
            """, (name,))

            row = cursor.fetchone()
            if not row:
                raise SecretNotFoundError(f"Secret '{name}' not found")

            encrypted_data = EncryptedData(
                ciphertext=row["ciphertext"],
                nonce=row["nonce"],
                tag=row["tag"],
                salt=row["salt"],
            )

            return SecretRecord(
                name=row["name"],
                encrypted_value=encrypted_data,
                description=row["description"],
                tags=row["tags"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )

        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to get secret: {e}") from e

    def update_secret(self, record: SecretRecord) -> None:
        """
        Update an existing secret.
        
        Args:
            record: The updated secret record
            
        Raises:
            SecretNotFoundError: If secret doesn't exist
            DatabaseError: If update fails
        """
        if not self._connection:
            raise DatabaseError("Database not connected")

        try:
            with self.transaction() as conn:
                cursor = conn.execute("""
                    UPDATE secrets SET
                        description = ?, tags = ?, ciphertext = ?, nonce = ?,
                        tag = ?, salt = ?, updated_at = ?
                    WHERE name = ?
                """, (
                    record.description,
                    record.tags,
                    record.encrypted_value.ciphertext,
                    record.encrypted_value.nonce,
                    record.encrypted_value.tag,
                    record.encrypted_value.salt,
                    record.updated_at,
                    record.name,
                ))

                if cursor.rowcount == 0:
                    raise SecretNotFoundError(f"Secret '{record.name}' not found")

        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to update secret: {e}") from e

    def delete_secret(self, name: str) -> None:
        """
        Delete a secret by name.
        
        Args:
            name: The secret name
            
        Raises:
            SecretNotFoundError: If secret doesn't exist
            DatabaseError: If deletion fails
        """
        if not self._connection:
            raise DatabaseError("Database not connected")

        try:
            with self.transaction() as conn:
                cursor = conn.execute("DELETE FROM secrets WHERE name = ?", (name,))

                if cursor.rowcount == 0:
                    raise SecretNotFoundError(f"Secret '{name}' not found")

        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to delete secret: {e}") from e

    def list_secrets(
        self,
        pattern: Union[str, None] = None,
        tags: Union[List[str], None] = None,
        limit: Union[int, None] = None,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        List secrets with optional filtering.
        
        Args:
            pattern: Optional name pattern (SQL LIKE syntax)
            tags: Optional list of tags to filter by
            limit: Maximum number of results
            offset: Number of results to skip
            
        Returns:
            List of secret metadata (no encrypted values)
            
        Raises:
            DatabaseError: If listing fails
        """
        if not self._connection:
            raise DatabaseError("Database not connected")

        try:
            query = """
                SELECT name, description, tags, created_at, updated_at
                FROM secrets
                WHERE 1=1
            """
            params = []

            if pattern:
                query += " AND name LIKE ?"
                params.append(pattern)

            if tags:
                for tag in tags:
                    query += " AND tags LIKE ?"
                    params.append(f"%{tag}%")

            query += " ORDER BY name"

            if limit:
                query += " LIMIT ?"
                params.append(limit)

            if offset:
                query += " OFFSET ?"
                params.append(offset)

            cursor = self._connection.execute(query, params)

            return [
                {
                    "name": row["name"],
                    "description": row["description"],
                    "tags": row["tags"].split(",") if row["tags"] else [],
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                }
                for row in cursor.fetchall()
            ]

        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to list secrets: {e}") from e

    def count_secrets(self) -> int:
        """
        Get the total number of secrets.
        
        Returns:
            Number of secrets in the vault
            
        Raises:
            DatabaseError: If count fails
        """
        if not self._connection:
            raise DatabaseError("Database not connected")

        try:
            cursor = self._connection.execute("SELECT COUNT(*) FROM secrets")
            result = cursor.fetchone()
            return result[0] if result else 0

        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to count secrets: {e}") from e

    def backup_database(self, backup_path: Path) -> None:
        """
        Create a backup of the database.
        
        Args:
            backup_path: Path for the backup file
            
        Raises:
            DatabaseError: If backup fails
        """
        if not self._connection:
            raise DatabaseError("Database not connected")

        try:
            backup_conn = sqlite3.connect(str(backup_path))
            self._connection.backup(backup_conn)
            backup_conn.close()

        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to backup database: {e}") from e
