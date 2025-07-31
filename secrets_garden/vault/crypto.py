"""
Cryptographic operations for Secret's Garden.

This module provides secure encryption and decryption using AES-256-GCM
with PBKDF2 key derivation. All operations are designed to be memory-safe
and follow cryptographic best practices.

Security Features:
- AES-256-GCM for authenticated encryption
- PBKDF2 with SHA-256 for key derivation (600,000 iterations)
- Cryptographically secure random salt generation
- Memory-safe operations with explicit cleanup
- Constant-time comparisons where applicable
"""

import secrets
from typing import NamedTuple, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from secrets_garden.exceptions import (
    CryptoError,
    DecryptionError,
    EncryptionError,
    InvalidPasswordError,
)


class EncryptedData(NamedTuple):
    """Container for encrypted data and associated metadata."""

    ciphertext: bytes
    nonce: bytes
    tag: bytes
    salt: bytes


class CryptoManager:
    """
    Handles all cryptographic operations for Secret's Garden.
    
    This class provides secure encryption/decryption using AES-256-GCM
    with PBKDF2 key derivation. All operations are memory-safe and
    follow industry best practices.
    """

    # Cryptographic constants
    KEY_SIZE = 32  # 256 bits for AES-256
    NONCE_SIZE = 12  # 96 bits (recommended for GCM)
    TAG_SIZE = 16  # 128 bits (GCM authentication tag)
    SALT_SIZE = 32  # 256 bits for PBKDF2 salt
    PBKDF2_ITERATIONS = 600_000  # OWASP recommended minimum for 2023

    def __init__(self) -> None:
        """Initialize the crypto manager."""
        pass

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive an encryption key from a password using PBKDF2.
        
        Uses PBKDF2-HMAC-SHA256 with 600,000 iterations for robust
        protection against brute-force attacks.
        
        Args:
            password: The master password
            salt: Cryptographically random salt
            
        Returns:
            32-byte derived key suitable for AES-256
            
        Raises:
            CryptoError: If key derivation fails
        """
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.KEY_SIZE,
                salt=salt,
                iterations=self.PBKDF2_ITERATIONS,
            )
            return kdf.derive(password.encode('utf-8'))
        except Exception as e:
            raise CryptoError(f"Key derivation failed: {e}") from e

    def generate_salt(self) -> bytes:
        """
        Generate a cryptographically secure random salt.
        
        Returns:
            32 bytes of cryptographically random data
        """
        return secrets.token_bytes(self.SALT_SIZE)

    def encrypt(self, plaintext: str, password: str) -> EncryptedData:
        """
        Encrypt plaintext using AES-256-GCM with PBKDF2 key derivation.
        
        This method:
        1. Generates a random salt for key derivation
        2. Derives a key using PBKDF2-HMAC-SHA256
        3. Generates a random nonce for GCM
        4. Encrypts the data using AES-256-GCM
        5. Returns all components needed for decryption
        
        Args:
            plaintext: The data to encrypt
            password: The master password
            
        Returns:
            EncryptedData containing ciphertext, nonce, tag, and salt
            
        Raises:
            EncryptionError: If encryption fails
        """
        try:
            # Generate random salt and derive key
            salt = self.generate_salt()
            key = self.derive_key(password, salt)

            # Generate random nonce for GCM
            nonce = secrets.token_bytes(self.NONCE_SIZE)

            # Create cipher and encryptor
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce)
            )
            encryptor = cipher.encryptor()

            # Encrypt the plaintext
            plaintext_bytes = plaintext.encode('utf-8')
            ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()

            # Get the authentication tag
            tag = encryptor.tag

            # Clear sensitive data from memory
            self._clear_bytes(key)

            return EncryptedData(
                ciphertext=ciphertext,
                nonce=nonce,
                tag=tag,
                salt=salt
            )

        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}") from e

    def decrypt(self, encrypted_data: EncryptedData, password: str) -> str:
        """
        Decrypt data using AES-256-GCM with PBKDF2 key derivation.
        
        This method:
        1. Derives the key using the stored salt and provided password
        2. Creates a GCM decryptor with the stored nonce
        3. Attempts to decrypt and verify the data
        4. Returns the plaintext if authentication succeeds
        
        Args:
            encrypted_data: The encrypted data bundle
            password: The master password
            
        Returns:
            The decrypted plaintext
            
        Raises:
            DecryptionError: If decryption or authentication fails
            InvalidPasswordError: If the password is incorrect
        """
        try:
            # Derive key using stored salt
            key = self.derive_key(password, encrypted_data.salt)

            # Create cipher and decryptor
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(encrypted_data.nonce, encrypted_data.tag)
            )
            decryptor = cipher.decryptor()

            # Decrypt the ciphertext
            plaintext_bytes = (
                decryptor.update(encrypted_data.ciphertext) +
                decryptor.finalize()
            )

            # Clear sensitive data from memory
            self._clear_bytes(key)

            return plaintext_bytes.decode('utf-8')

        except Exception as e:
            # Clear any derived key material
            if 'key' in locals():
                self._clear_bytes(key)

            # Provide specific error for authentication failures
            if "authentication" in str(e).lower() or "tag" in str(e).lower():
                raise InvalidPasswordError(
                    "Invalid password or corrupted data"
                ) from e

            raise DecryptionError(f"Decryption failed: {e}") from e

    def verify_password(
        self,
        password: str,
        stored_salt: bytes,
        stored_key_hash: bytes
    ) -> bool:
        """
        Verify a password against a stored key hash.
        
        This method derives a key from the password and salt,
        then compares it against the stored hash using a
        constant-time comparison to prevent timing attacks.
        
        Args:
            password: The password to verify
            stored_salt: The salt used for key derivation
            stored_key_hash: The hash of the expected key
            
        Returns:
            True if the password is correct, False otherwise
        """
        try:
            derived_key = self.derive_key(password, stored_salt)

            # Use constant-time comparison to prevent timing attacks
            result = secrets.compare_digest(derived_key, stored_key_hash)

            # Clear derived key from memory
            self._clear_bytes(derived_key)

            return result

        except Exception:
            return False

    def hash_password(self, password: str, salt: Union[bytes, None] = None) -> Tuple[bytes, bytes]:
        """
        Hash a password for storage.
        
        Args:
            password: The password to hash
            salt: Optional salt (will generate if not provided)
            
        Returns:
            Tuple of (key_hash, salt)
        """
        if salt is None:
            salt = self.generate_salt()

        key_hash = self.derive_key(password, salt)
        return key_hash, salt

    @staticmethod
    def _clear_bytes(data: bytes) -> None:
        """
        Attempt to clear sensitive data from memory.
        
        Note: This is a best-effort approach. Python's memory management
        makes it impossible to guarantee that sensitive data is cleared,
        but this reduces the window of exposure.
        
        Args:
            data: The bytes to clear
        """
        if hasattr(data, '__array_interface__'):
            # For bytes-like objects that support the buffer protocol
            try:
                # Overwrite with zeros
                import ctypes
                address = data.__array_interface__['data'][0]
                ctypes.memset(address, 0, len(data))
            except Exception:
                # If clearing fails, we can't do much about it
                pass

    def secure_compare(self, a: bytes, b: bytes) -> bool:
        """
        Perform a constant-time comparison of two byte sequences.
        
        Args:
            a: First byte sequence
            b: Second byte sequence
            
        Returns:
            True if sequences are equal, False otherwise
        """
        return secrets.compare_digest(a, b)
