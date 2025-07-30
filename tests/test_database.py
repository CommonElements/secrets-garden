"""
Tests for database operations.

This module tests all database functionality including schema creation,
CRUD operations, and data integrity checks.
"""

import sqlite3
import time
from pathlib import Path

import pytest

from secrets_garden.exceptions import (
    DatabaseError,
    SecretAlreadyExistsError,
    SecretNotFoundError,
    VaultCorruptedError,
)
from secrets_garden.vault.crypto import CryptoManager, EncryptedData
from secrets_garden.vault.database import DatabaseManager, SecretRecord


class TestSecretRecord:
    """Test the SecretRecord class."""
    
    def test_init_minimal(self):
        """Test SecretRecord initialization with minimal data."""
        encrypted_data = EncryptedData(
            ciphertext=b"encrypted",
            nonce=b"nonce123456",
            tag=b"tag1234567890123",
            salt=b"salt" * 8,
        )
        
        record = SecretRecord("test_secret", encrypted_data)
        
        assert record.name == "test_secret"
        assert record.encrypted_value == encrypted_data
        assert record.description == ""
        assert record.tags == ""
        assert isinstance(record.created_at, float)
        assert isinstance(record.updated_at, float)
    
    def test_init_full(self):
        """Test SecretRecord initialization with all data."""
        encrypted_data = EncryptedData(
            ciphertext=b"encrypted",
            nonce=b"nonce123456",
            tag=b"tag1234567890123",
            salt=b"salt" * 8,
        )
        
        created_time = time.time() - 1000
        updated_time = time.time()
        
        record = SecretRecord(
            name="test_secret",
            encrypted_value=encrypted_data,
            description="Test description",
            tags="tag1,tag2,tag3",
            created_at=created_time,
            updated_at=updated_time,
        )
        
        assert record.name == "test_secret"
        assert record.encrypted_value == encrypted_data
        assert record.description == "Test description"
        assert record.tags == "tag1,tag2,tag3"
        assert record.created_at == created_time
        assert record.updated_at == updated_time
    
    def test_to_dict(self):
        """Test conversion to dictionary."""
        encrypted_data = EncryptedData(
            ciphertext=b"encrypted",
            nonce=b"nonce123456",
            tag=b"tag1234567890123",
            salt=b"salt" * 8,
        )
        
        record = SecretRecord(
            name="test_secret",
            encrypted_value=encrypted_data,
            description="Test description",
            tags="tag1,tag2",
        )
        
        result = record.to_dict()
        
        expected_keys = {"name", "description", "tags", "created_at", "updated_at"}
        assert set(result.keys()) == expected_keys
        assert result["name"] == "test_secret"
        assert result["description"] == "Test description"
        assert result["tags"] == "tag1,tag2"


class TestDatabaseManager:
    """Test the DatabaseManager class."""
    
    def test_init(self, temp_dir: Path):
        """Test database manager initialization."""
        db_path = temp_dir / "test.db"
        db_manager = DatabaseManager(db_path)
        
        assert db_manager.db_path == db_path
        assert db_manager._connection is None
    
    def test_connect_disconnect(self, temp_dir: Path):
        """Test database connection and disconnection."""
        db_path = temp_dir / "test.db"
        db_manager = DatabaseManager(db_path)
        
        # Test connection
        db_manager.connect()
        assert db_manager._connection is not None
        assert isinstance(db_manager._connection, sqlite3.Connection)
        
        # Test disconnection
        db_manager.disconnect()
        assert db_manager._connection is None
    
    def test_initialize_schema(self, temp_dir: Path):
        """Test database schema initialization."""
        db_path = temp_dir / "test.db"
        db_manager = DatabaseManager(db_path)
        
        db_manager.connect()
        db_manager.initialize_schema()
        
        # Check that tables exist
        cursor = db_manager._connection.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name IN ('metadata', 'secrets')
        """)
        tables = [row[0] for row in cursor.fetchall()]
        
        assert "metadata" in tables
        assert "secrets" in tables
        
        # Check schema version
        version = db_manager.get_schema_version()
        assert version == db_manager.SCHEMA_VERSION
        
        db_manager.disconnect()
    
    def test_verify_integrity(self, temp_dir: Path):
        """Test database integrity check."""
        db_path = temp_dir / "test.db"
        db_manager = DatabaseManager(db_path)
        
        db_manager.connect()
        db_manager.initialize_schema()
        
        # Fresh database should pass integrity check
        assert db_manager.verify_integrity() is True
        
        db_manager.disconnect()
    
    def test_transaction_success(self, temp_dir: Path):
        """Test successful transaction."""
        db_path = temp_dir / "test.db"
        db_manager = DatabaseManager(db_path)
        
        db_manager.connect()
        db_manager.initialize_schema()
        
        with db_manager.transaction() as conn:
            conn.execute("INSERT INTO metadata (key, value) VALUES (?, ?)", ("test", "value"))
        
        # Check that data was committed
        cursor = db_manager._connection.execute("SELECT value FROM metadata WHERE key = ?", ("test",))
        result = cursor.fetchone()
        assert result[0] == "value"
        
        db_manager.disconnect()
    
    def test_transaction_rollback(self, temp_dir: Path):
        """Test transaction rollback on error."""
        db_path = temp_dir / "test.db"
        db_manager = DatabaseManager(db_path)
        
        db_manager.connect()
        db_manager.initialize_schema()
        
        # Transaction that should fail and rollback
        with pytest.raises(DatabaseError):
            with db_manager.transaction() as conn:
                conn.execute("INSERT INTO metadata (key, value) VALUES (?, ?)", ("test", "value"))
                # Simulate an error
                raise Exception("Simulated error")
        
        # Check that data was not committed
        cursor = db_manager._connection.execute("SELECT COUNT(*) FROM metadata WHERE key = ?", ("test",))
        result = cursor.fetchone()
        assert result[0] == 0
        
        db_manager.disconnect()
    
    def test_create_secret(self, temp_dir: Path, crypto_manager: CryptoManager):
        """Test creating a secret."""
        db_path = temp_dir / "test.db"
        db_manager = DatabaseManager(db_path)
        
        db_manager.connect()
        db_manager.initialize_schema()
        
        # Create test secret
        encrypted_data = crypto_manager.encrypt("test-value", "test-password")
        record = SecretRecord(
            name="test_secret",
            encrypted_value=encrypted_data,
            description="Test description",
            tags="tag1,tag2",
        )
        
        db_manager.create_secret(record)
        
        # Verify secret was created
        cursor = db_manager._connection.execute("SELECT COUNT(*) FROM secrets WHERE name = ?", ("test_secret",))
        result = cursor.fetchone()
        assert result[0] == 1
        
        db_manager.disconnect()
    
    def test_create_duplicate_secret(self, temp_dir: Path, crypto_manager: CryptoManager):
        """Test creating a duplicate secret."""
        db_path = temp_dir / "test.db"
        db_manager = DatabaseManager(db_path)
        
        db_manager.connect()
        db_manager.initialize_schema()
        
        # Create first secret
        encrypted_data = crypto_manager.encrypt("test-value", "test-password")
        record = SecretRecord("test_secret", encrypted_data)
        
        db_manager.create_secret(record)
        
        # Try to create duplicate
        with pytest.raises(SecretAlreadyExistsError):
            db_manager.create_secret(record)
        
        db_manager.disconnect()
    
    def test_get_secret(self, temp_dir: Path, crypto_manager: CryptoManager):
        """Test retrieving a secret."""
        db_path = temp_dir / "test.db"
        db_manager = DatabaseManager(db_path)
        
        db_manager.connect()
        db_manager.initialize_schema()
        
        # Create test secret
        encrypted_data = crypto_manager.encrypt("test-value", "test-password")
        original_record = SecretRecord(
            name="test_secret",
            encrypted_value=encrypted_data,
            description="Test description",
            tags="tag1,tag2",
        )
        
        db_manager.create_secret(original_record)
        
        # Retrieve secret
        retrieved_record = db_manager.get_secret("test_secret")
        
        assert retrieved_record.name == original_record.name
        assert retrieved_record.description == original_record.description
        assert retrieved_record.tags == original_record.tags
        assert retrieved_record.encrypted_value.ciphertext == original_record.encrypted_value.ciphertext
        
        db_manager.disconnect()
    
    def test_get_nonexistent_secret(self, temp_dir: Path):
        """Test retrieving a non-existent secret."""
        db_path = temp_dir / "test.db"
        db_manager = DatabaseManager(db_path)
        
        db_manager.connect()
        db_manager.initialize_schema()
        
        with pytest.raises(SecretNotFoundError):
            db_manager.get_secret("nonexistent_secret")
        
        db_manager.disconnect()
    
    def test_update_secret(self, temp_dir: Path, crypto_manager: CryptoManager):
        """Test updating a secret."""
        db_path = temp_dir / "test.db"
        db_manager = DatabaseManager(db_path)
        
        db_manager.connect()
        db_manager.initialize_schema()
        
        # Create original secret
        encrypted_data = crypto_manager.encrypt("original-value", "test-password")
        original_record = SecretRecord("test_secret", encrypted_data, "Original description")
        
        db_manager.create_secret(original_record)
        
        # Update secret
        new_encrypted_data = crypto_manager.encrypt("new-value", "test-password")
        updated_record = SecretRecord(
            name="test_secret",
            encrypted_value=new_encrypted_data,
            description="Updated description",
            tags="new,tags",
            created_at=original_record.created_at,
            updated_at=time.time(),
        )
        
        db_manager.update_secret(updated_record)
        
        # Verify update
        retrieved_record = db_manager.get_secret("test_secret")
        assert retrieved_record.description == "Updated description"
        assert retrieved_record.tags == "new,tags"
        assert retrieved_record.updated_at > original_record.updated_at
        
        db_manager.disconnect()
    
    def test_update_nonexistent_secret(self, temp_dir: Path, crypto_manager: CryptoManager):
        """Test updating a non-existent secret."""
        db_path = temp_dir / "test.db"
        db_manager = DatabaseManager(db_path)
        
        db_manager.connect()
        db_manager.initialize_schema()
        
        encrypted_data = crypto_manager.encrypt("test-value", "test-password")
        record = SecretRecord("nonexistent_secret", encrypted_data)
        
        with pytest.raises(SecretNotFoundError):
            db_manager.update_secret(record)
        
        db_manager.disconnect()
    
    def test_delete_secret(self, temp_dir: Path, crypto_manager: CryptoManager):
        """Test deleting a secret."""
        db_path = temp_dir / "test.db"
        db_manager = DatabaseManager(db_path)
        
        db_manager.connect()
        db_manager.initialize_schema()
        
        # Create secret
        encrypted_data = crypto_manager.encrypt("test-value", "test-password")
        record = SecretRecord("test_secret", encrypted_data)
        
        db_manager.create_secret(record)
        
        # Verify it exists
        db_manager.get_secret("test_secret")
        
        # Delete secret
        db_manager.delete_secret("test_secret")
        
        # Verify it's gone
        with pytest.raises(SecretNotFoundError):
            db_manager.get_secret("test_secret")
        
        db_manager.disconnect()
    
    def test_delete_nonexistent_secret(self, temp_dir: Path):
        """Test deleting a non-existent secret."""
        db_path = temp_dir / "test.db"
        db_manager = DatabaseManager(db_path)
        
        db_manager.connect()
        db_manager.initialize_schema()
        
        with pytest.raises(SecretNotFoundError):
            db_manager.delete_secret("nonexistent_secret")
        
        db_manager.disconnect()
    
    def test_list_secrets_empty(self, temp_dir: Path):
        """Test listing secrets in empty database."""
        db_path = temp_dir / "test.db"
        db_manager = DatabaseManager(db_path)
        
        db_manager.connect()
        db_manager.initialize_schema()
        
        secrets = db_manager.list_secrets()
        assert secrets == []
        
        db_manager.disconnect()
    
    def test_list_secrets_with_data(self, temp_dir: Path, crypto_manager: CryptoManager):
        """Test listing secrets with data."""
        db_path = temp_dir / "test.db"
        db_manager = DatabaseManager(db_path)
        
        db_manager.connect()
        db_manager.initialize_schema()
        
        # Create multiple secrets
        secrets_data = [
            ("secret1", "value1", "Description 1", "tag1,tag2"),
            ("secret2", "value2", "Description 2", "tag2,tag3"),
            ("secret3", "value3", "Description 3", "tag1"),
        ]
        
        for name, value, desc, tags in secrets_data:
            encrypted_data = crypto_manager.encrypt(value, "test-password")
            record = SecretRecord(name, encrypted_data, desc, tags)
            db_manager.create_secret(record)
        
        # List all secrets
        secrets = db_manager.list_secrets()
        assert len(secrets) == 3
        
        # Check that secrets are sorted by name
        names = [s["name"] for s in secrets]
        assert names == ["secret1", "secret2", "secret3"]
        
        # Check structure
        for secret in secrets:
            assert "name" in secret
            assert "description" in secret
            assert "tags" in secret
            assert "created_at" in secret
            assert "updated_at" in secret
            assert isinstance(secret["tags"], list)
        
        db_manager.disconnect()
    
    def test_list_secrets_with_pattern(self, temp_dir: Path, crypto_manager: CryptoManager):
        """Test listing secrets with name pattern."""
        db_path = temp_dir / "test.db"
        db_manager = DatabaseManager(db_path)
        
        db_manager.connect()
        db_manager.initialize_schema()
        
        # Create secrets
        secrets_data = [
            ("api_key", "value1"),
            ("api_secret", "value2"),
            ("db_password", "value3"),
        ]
        
        for name, value in secrets_data:
            encrypted_data = crypto_manager.encrypt(value, "test-password")
            record = SecretRecord(name, encrypted_data)
            db_manager.create_secret(record)
        
        # List with pattern
        secrets = db_manager.list_secrets(pattern="api%")
        assert len(secrets) == 2
        names = [s["name"] for s in secrets]
        assert "api_key" in names
        assert "api_secret" in names
        
        db_manager.disconnect()
    
    def test_list_secrets_with_tags(self, temp_dir: Path, crypto_manager: CryptoManager):
        """Test listing secrets with tag filter."""
        db_path = temp_dir / "test.db"
        db_manager = DatabaseManager(db_path)
        
        db_manager.connect()
        db_manager.initialize_schema()
        
        # Create secrets with different tags
        secrets_data = [
            ("secret1", "value1", "tag1,tag2"),
            ("secret2", "value2", "tag2,tag3"),
            ("secret3", "value3", "tag4"),
        ]
        
        for name, value, tags in secrets_data:
            encrypted_data = crypto_manager.encrypt(value, "test-password")
            record = SecretRecord(name, encrypted_data, tags=tags)
            db_manager.create_secret(record)
        
        # List with tag filter
        secrets = db_manager.list_secrets(tags=["tag2"])
        assert len(secrets) == 2
        names = [s["name"] for s in secrets]
        assert "secret1" in names
        assert "secret2" in names
        
        db_manager.disconnect()
    
    def test_list_secrets_with_limit(self, temp_dir: Path, crypto_manager: CryptoManager):
        """Test listing secrets with limit."""
        db_path = temp_dir / "test.db"
        db_manager = DatabaseManager(db_path)
        
        db_manager.connect()
        db_manager.initialize_schema()
        
        # Create multiple secrets
        for i in range(5):
            encrypted_data = crypto_manager.encrypt(f"value{i}", "test-password")
            record = SecretRecord(f"secret{i}", encrypted_data)
            db_manager.create_secret(record)
        
        # List with limit
        secrets = db_manager.list_secrets(limit=3)
        assert len(secrets) == 3
        
        db_manager.disconnect()
    
    def test_count_secrets(self, temp_dir: Path, crypto_manager: CryptoManager):
        """Test counting secrets."""
        db_path = temp_dir / "test.db"
        db_manager = DatabaseManager(db_path)
        
        db_manager.connect()
        db_manager.initialize_schema()
        
        # Initially empty
        assert db_manager.count_secrets() == 0
        
        # Add secrets and count
        for i in range(3):
            encrypted_data = crypto_manager.encrypt(f"value{i}", "test-password")
            record = SecretRecord(f"secret{i}", encrypted_data)
            db_manager.create_secret(record)
        
        assert db_manager.count_secrets() == 3
        
        db_manager.disconnect()
    
    def test_backup_database(self, temp_dir: Path, crypto_manager: CryptoManager):
        """Test database backup."""
        db_path = temp_dir / "test.db"
        backup_path = temp_dir / "backup.db"
        
        db_manager = DatabaseManager(db_path)
        
        db_manager.connect()
        db_manager.initialize_schema()
        
        # Add some data
        encrypted_data = crypto_manager.encrypt("test-value", "test-password")
        record = SecretRecord("test_secret", encrypted_data)
        db_manager.create_secret(record)
        
        # Create backup
        db_manager.backup_database(backup_path)
        
        db_manager.disconnect()
        
        # Verify backup exists and has data
        assert backup_path.exists()
        
        backup_manager = DatabaseManager(backup_path)
        backup_manager.connect()
        
        count = backup_manager.count_secrets()
        assert count == 1
        
        retrieved_record = backup_manager.get_secret("test_secret")
        assert retrieved_record.name == "test_secret"
        
        backup_manager.disconnect()
    
    def test_connection_error(self, temp_dir: Path):
        """Test database operations without connection."""
        db_path = temp_dir / "test.db"
        db_manager = DatabaseManager(db_path)
        
        # Try operations without connecting
        with pytest.raises(DatabaseError):
            db_manager.initialize_schema()
        
        with pytest.raises(DatabaseError):
            with db_manager.transaction():
                pass
    
    @pytest.mark.integration
    def test_concurrent_access(self, temp_dir: Path, crypto_manager: CryptoManager):
        """Test concurrent database access."""
        db_path = temp_dir / "test.db"
        
        # Create and initialize database
        db_manager1 = DatabaseManager(db_path)
        db_manager1.connect()
        db_manager1.initialize_schema()
        
        # Create second connection
        db_manager2 = DatabaseManager(db_path)
        db_manager2.connect()
        
        # Add secret from first connection
        encrypted_data = crypto_manager.encrypt("value1", "test-password")
        record1 = SecretRecord("secret1", encrypted_data)
        db_manager1.create_secret(record1)
        
        # Read from second connection
        retrieved_record = db_manager2.get_secret("secret1")
        assert retrieved_record.name == "secret1"
        
        db_manager1.disconnect()
        db_manager2.disconnect()