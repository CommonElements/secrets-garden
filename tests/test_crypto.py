"""
Tests for cryptographic operations.

This module tests all cryptographic functionality including encryption,
decryption, key derivation, and security properties.
"""

import secrets
from typing import Dict

import pytest

from secrets_garden.exceptions import (
    CryptoError,
    DecryptionError,
    EncryptionError,
    InvalidPasswordError,
)
from secrets_garden.vault.crypto import CryptoManager, EncryptedData


class TestCryptoManager:
    """Test the CryptoManager class."""
    
    def test_init(self, crypto_manager: CryptoManager):
        """Test crypto manager initialization."""
        assert isinstance(crypto_manager, CryptoManager)
        assert crypto_manager.KEY_SIZE == 32
        assert crypto_manager.NONCE_SIZE == 12
        assert crypto_manager.TAG_SIZE == 16
        assert crypto_manager.SALT_SIZE == 32
        assert crypto_manager.PBKDF2_ITERATIONS == 600_000
    
    def test_generate_salt(self, crypto_manager: CryptoManager):
        """Test salt generation."""
        salt1 = crypto_manager.generate_salt()
        salt2 = crypto_manager.generate_salt()
        
        # Check salt properties
        assert len(salt1) == crypto_manager.SALT_SIZE
        assert len(salt2) == crypto_manager.SALT_SIZE
        assert isinstance(salt1, bytes)
        assert isinstance(salt2, bytes)
        
        # Salts should be unique
        assert salt1 != salt2
    
    def test_derive_key(self, crypto_manager: CryptoManager):
        """Test key derivation from password."""
        password = "test-password-123"
        salt = crypto_manager.generate_salt()
        
        key1 = crypto_manager.derive_key(password, salt)
        key2 = crypto_manager.derive_key(password, salt)
        
        # Keys should be identical for same input
        assert key1 == key2
        assert len(key1) == crypto_manager.KEY_SIZE
        assert isinstance(key1, bytes)
    
    def test_derive_key_different_passwords(self, crypto_manager: CryptoManager):
        """Test key derivation with different passwords."""
        salt = crypto_manager.generate_salt()
        
        key1 = crypto_manager.derive_key("password1", salt)
        key2 = crypto_manager.derive_key("password2", salt)
        
        # Different passwords should produce different keys
        assert key1 != key2
    
    def test_derive_key_different_salts(self, crypto_manager: CryptoManager):
        """Test key derivation with different salts."""
        password = "same-password"
        
        salt1 = crypto_manager.generate_salt()
        salt2 = crypto_manager.generate_salt()
        
        key1 = crypto_manager.derive_key(password, salt1)
        key2 = crypto_manager.derive_key(password, salt2)
        
        # Different salts should produce different keys
        assert key1 != key2
    
    @pytest.mark.security
    def test_encrypt_decrypt_roundtrip(self, crypto_manager: CryptoManager):
        """Test encryption and decryption roundtrip."""
        password = "test-password-123"
        plaintext = "This is a secret message!"
        
        # Encrypt
        encrypted_data = crypto_manager.encrypt(plaintext, password)
        
        # Verify encrypted data structure
        assert isinstance(encrypted_data, EncryptedData)
        assert len(encrypted_data.ciphertext) > 0
        assert len(encrypted_data.nonce) == crypto_manager.NONCE_SIZE
        assert len(encrypted_data.tag) == crypto_manager.TAG_SIZE
        assert len(encrypted_data.salt) == crypto_manager.SALT_SIZE
        
        # Decrypt
        decrypted = crypto_manager.decrypt(encrypted_data, password)
        
        # Verify roundtrip
        assert decrypted == plaintext
    
    def test_encrypt_different_results(self, crypto_manager: CryptoManager):
        """Test that encryption produces different results each time."""
        password = "test-password"
        plaintext = "same message"
        
        encrypted1 = crypto_manager.encrypt(plaintext, password)
        encrypted2 = crypto_manager.encrypt(plaintext, password)
        
        # Results should be different due to random nonce and salt
        assert encrypted1.ciphertext != encrypted2.ciphertext
        assert encrypted1.nonce != encrypted2.nonce
        assert encrypted1.salt != encrypted2.salt
        assert encrypted1.tag != encrypted2.tag
        
        # But both should decrypt to the same plaintext
        decrypted1 = crypto_manager.decrypt(encrypted1, password)
        decrypted2 = crypto_manager.decrypt(encrypted2, password)
        
        assert decrypted1 == plaintext
        assert decrypted2 == plaintext
    
    def test_decrypt_wrong_password(self, crypto_manager: CryptoManager):
        """Test decryption with wrong password."""
        correct_password = "correct-password"
        wrong_password = "wrong-password"
        plaintext = "secret message"
        
        encrypted_data = crypto_manager.encrypt(plaintext, correct_password)
        
        with pytest.raises(InvalidPasswordError):
            crypto_manager.decrypt(encrypted_data, wrong_password)
    
    @pytest.mark.security
    def test_encryption_with_various_data_types(self, crypto_manager: CryptoManager, encrypted_data_samples: Dict):
        """Test encryption/decryption with various data types."""
        password = "test-password"
        
        for sample_name, sample_data in encrypted_data_samples.items():
            plaintext = sample_data["plaintext"]
            
            # Encrypt
            encrypted = crypto_manager.encrypt(plaintext, password)
            
            # Decrypt and verify
            decrypted = crypto_manager.decrypt(encrypted, password)
            assert decrypted == plaintext, f"Failed for sample: {sample_name}"
    
    def test_hash_password(self, crypto_manager: CryptoManager):
        """Test password hashing."""
        password = "test-password-123"
        
        # Hash with generated salt
        hash1, salt1 = crypto_manager.hash_password(password)
        hash2, salt2 = crypto_manager.hash_password(password)
        
        # Different salts should produce different hashes
        assert hash1 != hash2
        assert salt1 != salt2
        assert len(hash1) == crypto_manager.KEY_SIZE
        assert len(salt1) == crypto_manager.SALT_SIZE
        
        # Hash with provided salt
        provided_salt = crypto_manager.generate_salt()
        hash3, salt3 = crypto_manager.hash_password(password, provided_salt)
        
        assert salt3 == provided_salt
        assert len(hash3) == crypto_manager.KEY_SIZE
    
    def test_verify_password(self, crypto_manager: CryptoManager):
        """Test password verification."""
        password = "test-password-123"
        wrong_password = "wrong-password"
        
        key_hash, salt = crypto_manager.hash_password(password)
        
        # Correct password should verify
        assert crypto_manager.verify_password(password, salt, key_hash) is True
        
        # Wrong password should not verify
        assert crypto_manager.verify_password(wrong_password, salt, key_hash) is False
    
    def test_secure_compare(self, crypto_manager: CryptoManager):
        """Test secure comparison function."""
        data1 = b"same data"
        data2 = b"same data"
        data3 = b"different data"
        
        # Same data should compare equal
        assert crypto_manager.secure_compare(data1, data2) is True
        
        # Different data should not compare equal
        assert crypto_manager.secure_compare(data1, data3) is False
        
        # Different lengths should not compare equal
        assert crypto_manager.secure_compare(b"short", b"longer data") is False
    
    @pytest.mark.security
    def test_memory_clearing(self, crypto_manager: CryptoManager):
        """Test that sensitive data clearing doesn't raise exceptions."""
        # This test mainly ensures the memory clearing function
        # doesn't raise exceptions, as we can't easily verify
        # that memory is actually cleared in Python
        test_data = b"sensitive data that should be cleared"
        
        # Should not raise any exceptions
        crypto_manager._clear_bytes(test_data)
    
    @pytest.mark.security
    def test_encrypted_data_immutability(self, crypto_manager: CryptoManager):
        """Test that EncryptedData is immutable."""
        password = "test-password"
        plaintext = "test message"
        
        encrypted_data = crypto_manager.encrypt(plaintext, password)
        
        # EncryptedData should be a NamedTuple (immutable)
        with pytest.raises(AttributeError):
            encrypted_data.ciphertext = b"modified"
    
    def test_encryption_error_handling(self, crypto_manager: CryptoManager, monkeypatch):
        """Test encryption error handling."""
        # Mock the encryption to raise an exception
        def mock_encrypt_failure(*args, **kwargs):
            raise Exception("Simulated encryption failure")
        
        monkeypatch.setattr(crypto_manager, "derive_key", mock_encrypt_failure)
        
        with pytest.raises(EncryptionError):
            crypto_manager.encrypt("test", "password")
    
    def test_decryption_error_handling(self, crypto_manager: CryptoManager):
        """Test decryption error handling."""
        # Create corrupted encrypted data
        password = "test-password"
        plaintext = "test message"
        
        encrypted_data = crypto_manager.encrypt(plaintext, password)
        
        # Corrupt the ciphertext
        corrupted_data = EncryptedData(
            ciphertext=b"corrupted",
            nonce=encrypted_data.nonce,
            tag=encrypted_data.tag,
            salt=encrypted_data.salt,
        )
        
        with pytest.raises(DecryptionError):
            crypto_manager.decrypt(corrupted_data, password)
    
    @pytest.mark.slow
    def test_pbkdf2_iterations_performance(self, crypto_manager: CryptoManager):
        """Test that PBKDF2 iterations are sufficiently high for security."""
        import time
        
        password = "test-password"
        salt = crypto_manager.generate_salt()
        
        start_time = time.time()
        crypto_manager.derive_key(password, salt)
        end_time = time.time()
        
        # Key derivation should take some time (at least 100ms for 600k iterations)
        duration = end_time - start_time
        assert duration > 0.1, "Key derivation is too fast, may not be secure"
    
    @pytest.mark.security
    def test_nonce_uniqueness(self, crypto_manager: CryptoManager):
        """Test that nonces are unique across encryptions."""
        password = "test-password"
        plaintext = "test message"
        
        nonces = set()
        
        # Generate multiple encryptions
        for _ in range(100):
            encrypted_data = crypto_manager.encrypt(plaintext, password)
            assert encrypted_data.nonce not in nonces, "Nonce collision detected"
            nonces.add(encrypted_data.nonce)
    
    @pytest.mark.security 
    def test_salt_uniqueness(self, crypto_manager: CryptoManager):
        """Test that salts are unique."""
        salts = set()
        
        # Generate multiple salts
        for _ in range(100):
            salt = crypto_manager.generate_salt()
            assert salt not in salts, "Salt collision detected"
            salts.add(salt)
    
    def test_unicode_handling(self, crypto_manager: CryptoManager):
        """Test encryption/decryption of Unicode text."""
        password = "тест-пароль-123"  # Cyrillic password
        plaintext = "Hello 世界! 🌍 café naïve résumé"  # Mixed Unicode
        
        encrypted_data = crypto_manager.encrypt(plaintext, password)
        decrypted = crypto_manager.decrypt(encrypted_data, password)
        
        assert decrypted == plaintext
    
    def test_empty_string_handling(self, crypto_manager: CryptoManager):
        """Test encryption/decryption of empty strings."""
        password = "test-password"
        plaintext = ""
        
        encrypted_data = crypto_manager.encrypt(plaintext, password)
        decrypted = crypto_manager.decrypt(encrypted_data, password)
        
        assert decrypted == plaintext
    
    def test_large_data_handling(self, crypto_manager: CryptoManager):
        """Test encryption/decryption of large data."""
        password = "test-password"
        plaintext = "A" * 10000  # 10KB of data
        
        encrypted_data = crypto_manager.encrypt(plaintext, password)
        decrypted = crypto_manager.decrypt(encrypted_data, password)
        
        assert decrypted == plaintext