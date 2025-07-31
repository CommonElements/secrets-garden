"""
Secret's Garden - A secure, local-first secrets management CLI tool.

A command-line secrets manager that uses military-grade encryption to store
your sensitive data locally. No cloud, no network calls, just secure local storage.
"""

__version__ = "0.1.0"
__author__ = "Harry Schoeller"
__email__ = "harry@example.com"

from secrets_garden.exceptions import (
    CryptoError,
    DatabaseError,
    SecretsGardenError,
    VaultError,
)

__all__ = [
    "__version__",
    "__author__",
    "__email__",
    "SecretsGardenError",
    "VaultError",
    "CryptoError",
    "DatabaseError",
]
