"""
Pytest configuration and fixtures for Secret's Garden tests.

This module provides shared fixtures and configuration for the test suite,
including temporary vaults, mock data, and test utilities.
"""

import os
import tempfile
from pathlib import Path
from typing import Generator

import pytest

from secrets_garden.config.settings import ConfigManager
from secrets_garden.vault.crypto import CryptoManager
from secrets_garden.vault.manager import VaultManager


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provide a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def config_manager(temp_dir: Path) -> ConfigManager:
    """Provide a configuration manager with temporary config directory."""
    return ConfigManager(config_dir=temp_dir / ".secrets-garden")


@pytest.fixture
def crypto_manager() -> CryptoManager:
    """Provide a crypto manager instance."""
    return CryptoManager()


@pytest.fixture
def vault_path(temp_dir: Path) -> Path:
    """Provide a temporary vault path."""
    return temp_dir / "test-vault"


@pytest.fixture
def vault_manager(vault_path: Path) -> VaultManager:
    """Provide a vault manager instance."""
    return VaultManager(vault_path)


@pytest.fixture
def unlocked_vault(vault_manager: VaultManager) -> VaultManager:
    """Provide an unlocked vault with test data."""
    test_password = "test-password-123"
    vault_manager.create(test_password, "Test vault")
    vault_manager.unlock(test_password)
    
    # Add some test secrets
    vault_manager.add_secret("api_key", "sk-1234567890", "API key for service", ["api", "prod"])
    vault_manager.add_secret("db_password", "super-secret-password", "Database password", ["db"])
    vault_manager.add_secret("simple_secret", "simple-value", "Simple test secret")
    
    return vault_manager


@pytest.fixture
def sample_secrets() -> dict:
    """Provide sample secret data for tests."""
    return {
        "api_key": {
            "value": "sk-1234567890abcdef",
            "description": "Production API key",
            "tags": ["api", "production", "critical"]
        },
        "database_url": {
            "value": "postgresql://user:pass@localhost/db",
            "description": "Main database connection",
            "tags": ["database", "connection"]
        },
        "jwt_secret": {
            "value": "my-super-secret-jwt-key-2023",
            "description": "JWT signing secret",
            "tags": ["auth", "jwt"]
        },
        "redis_password": {
            "value": "redis-secret-password",
            "description": "Redis instance password",
            "tags": ["cache", "redis"]
        },
        "smtp_password": {
            "value": "email-service-password",
            "description": "SMTP server password",
            "tags": ["email", "smtp"]
        }
    }


@pytest.fixture
def encrypted_data_samples(crypto_manager: CryptoManager) -> dict:
    """Provide encrypted data samples for testing."""
    password = "test-password"
    
    samples = {
        "simple": "simple value",
        "multiline": "line 1\nline 2\nline 3",
        "special_chars": "!@#$%^&*()_+-=[]{}|;:,.<>?",
        "unicode": "Hello 世界 🌍 ñoël",
        "long_text": "A" * 1000,
        "json_like": '{"key": "value", "number": 123}',
    }
    
    encrypted_samples = {}
    for key, plaintext in samples.items():
        encrypted_samples[key] = {
            "plaintext": plaintext,
            "encrypted": crypto_manager.encrypt(plaintext, password)
        }
    
    return encrypted_samples


@pytest.fixture(autouse=True)
def clean_environment():
    """Clean environment variables before each test."""
    # Store original environment
    original_env = os.environ.copy()
    
    # Remove any Secret's Garden environment variables
    for key in list(os.environ.keys()):
        if key.startswith("SECRETS_GARDEN_"):
            del os.environ[key]
    
    yield
    
    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def mock_keyring(monkeypatch):
    """Mock keyring operations for testing."""
    stored_passwords = {}
    
    def mock_get_password(service: str, username: str) -> str | None:
        return stored_passwords.get(f"{service}:{username}")
    
    def mock_set_password(service: str, username: str, password: str) -> None:
        stored_passwords[f"{service}:{username}"] = password
    
    def mock_delete_password(service: str, username: str) -> None:
        key = f"{service}:{username}"
        if key in stored_passwords:
            del stored_passwords[key]
    
    try:
        import keyring
        monkeypatch.setattr(keyring, "get_password", mock_get_password)
        monkeypatch.setattr(keyring, "set_password", mock_set_password)
        monkeypatch.setattr(keyring, "delete_password", mock_delete_password)
    except ImportError:
        # keyring not available, skip mocking
        pass
    
    return stored_passwords


# Test markers
pytest.mark.unit = pytest.mark.unit
pytest.mark.integration = pytest.mark.integration
pytest.mark.security = pytest.mark.security
pytest.mark.slow = pytest.mark.slow


# Test configuration
def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line("markers", "unit: unit tests")
    config.addinivalue_line("markers", "integration: integration tests")
    config.addinivalue_line("markers", "security: security-focused tests")
    config.addinivalue_line("markers", "slow: slow tests")


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add default markers."""
    for item in items:
        # Add unit marker to tests without specific markers
        if not any(mark.name in ["integration", "security", "slow"] for mark in item.iter_markers()):
            item.add_marker(pytest.mark.unit)