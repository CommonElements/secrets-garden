"""Custom exceptions for Secret's Garden."""

from typing import Union


class SecretsGardenError(Exception):
    """Base exception class for all Secret's Garden errors."""

    def __init__(self, message: str, details: Union[str, None] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


class VaultError(SecretsGardenError):
    """Raised when vault operations fail."""
    pass


class VaultNotFoundError(VaultError):
    """Raised when a vault cannot be found."""
    pass


class VaultAlreadyExistsError(VaultError):
    """Raised when trying to create a vault that already exists."""
    pass


class VaultLockedError(VaultError):
    """Raised when trying to access a locked vault."""
    pass


class VaultCorruptedError(VaultError):
    """Raised when a vault appears to be corrupted."""
    pass


class CryptoError(SecretsGardenError):
    """Raised when cryptographic operations fail."""
    pass


class InvalidPasswordError(CryptoError):
    """Raised when an invalid password is provided."""
    pass


class EncryptionError(CryptoError):
    """Raised when encryption fails."""
    pass


class DecryptionError(CryptoError):
    """Raised when decryption fails."""
    pass


class DatabaseError(SecretsGardenError):
    """Raised when database operations fail."""
    pass


class SecretNotFoundError(DatabaseError):
    """Raised when a secret cannot be found."""
    pass


class SecretAlreadyExistsError(DatabaseError):
    """Raised when trying to create a secret that already exists."""
    pass


class ConfigError(SecretsGardenError):
    """Raised when configuration is invalid or missing."""
    pass
