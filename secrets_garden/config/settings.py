"""
Configuration management for Secret's Garden.

This module handles application settings, configuration files,
and environment variables with proper validation and defaults.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator
from pydantic_settings import BaseSettings

from secrets_garden.exceptions import ConfigError


class VaultConfig(BaseModel):
    """Configuration for vault-specific settings."""
    
    default_vault_name: str = Field(default="default", description="Default vault name")
    session_timeout: int = Field(default=3600, ge=300, description="Session timeout in seconds")  
    auto_lock: bool = Field(default=True, description="Automatically lock vault after timeout")
    backup_on_change: bool = Field(default=False, description="Create backup before changes")
    
    @validator('session_timeout')
    def validate_timeout(cls, v: int) -> int:
        if v < 300:  # Minimum 5 minutes
            raise ValueError("Session timeout must be at least 300 seconds")
        return v


class SecurityConfig(BaseModel):
    """Security-related configuration."""
    
    clear_clipboard_timeout: int = Field(default=30, ge=5, description="Clipboard clear timeout")
    max_password_attempts: int = Field(default=3, ge=1, description="Maximum password attempts")
    require_confirmation: bool = Field(default=True, description="Require confirmation for destructive operations")
    export_include_values: bool = Field(default=False, description="Include values in exports by default")
    
    @validator('clear_clipboard_timeout')
    def validate_clipboard_timeout(cls, v: int) -> int:
        if v < 5:
            raise ValueError("Clipboard timeout must be at least 5 seconds")
        return v


class CLIConfig(BaseModel):
    """CLI interface configuration."""
    
    color_output: bool = Field(default=True, description="Enable colored output")
    verbose: bool = Field(default=False, description="Enable verbose output")
    quiet: bool = Field(default=False, description="Enable quiet mode")
    progress_bars: bool = Field(default=True, description="Show progress bars")
    table_style: str = Field(default="rounded", description="Table style for output")
    
    @validator('table_style')
    def validate_table_style(cls, v: str) -> str:
        valid_styles = ["ascii", "rounded", "simple", "grid", "fancy_grid"]
        if v not in valid_styles:
            raise ValueError(f"Table style must be one of: {', '.join(valid_styles)}")
        return v


class AppSettings(BaseSettings):
    """Main application settings."""
    
    # Application info
    app_name: str = Field(default="secrets-garden", description="Application name")
    version: str = Field(default="0.1.0", description="Application version")
    
    # Paths
    vault_dir: Path = Field(
        default_factory=lambda: Path.home() / ".secrets-garden" / "vaults",
        description="Default vault directory"
    )
    config_dir: Path = Field(
        default_factory=lambda: Path.home() / ".secrets-garden",
        description="Configuration directory"
    )
    
    # Component configs
    vault: VaultConfig = Field(default_factory=VaultConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    cli: CLIConfig = Field(default_factory=CLIConfig)
    
    class Config:
        env_prefix = "SECRETS_GARDEN_"
        env_nested_delimiter = "__"
        case_sensitive = False
        
    @validator('vault_dir', 'config_dir')
    def ensure_path_exists(cls, v: Path) -> Path:
        v.mkdir(parents=True, exist_ok=True)
        return v


class ConfigManager:
    """Manages application configuration."""
    
    def __init__(self, config_dir: Optional[Path] = None) -> None:
        """
        Initialize configuration manager.
        
        Args:
            config_dir: Optional custom config directory
        """
        self.config_dir = config_dir or Path.home() / ".secrets-garden"
        self.config_file = self.config_dir / "config.json"
        self._settings: Optional[AppSettings] = None
    
    @property
    def settings(self) -> AppSettings:
        """Get current application settings."""
        if self._settings is None:
            self._settings = self.load_settings()
        return self._settings
    
    def load_settings(self) -> AppSettings:
        """
        Load settings from file and environment.
        
        Returns:
            Loaded application settings
            
        Raises:
            ConfigError: If configuration is invalid
        """
        try:
            # Create config directory if it doesn't exist
            self.config_dir.mkdir(parents=True, exist_ok=True)
            
            # Load from environment variables first
            settings = AppSettings()
            
            # Override with config file if it exists
            if self.config_file.exists():
                import json
                
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                
                # Update settings with file data
                settings = AppSettings(**config_data)
            
            return settings
            
        except Exception as e:
            raise ConfigError(f"Failed to load configuration: {e}") from e
    
    def save_settings(self, settings: AppSettings) -> None:
        """
        Save settings to configuration file.
        
        Args:
            settings: Settings to save
            
        Raises:
            ConfigError: If saving fails
        """
        try:
            import json
            
            # Ensure directory exists
            self.config_dir.mkdir(parents=True, exist_ok=True)
            
            # Convert to dict for JSON serialization
            config_data = settings.dict()
            
            # Convert Path objects to strings
            def path_to_str(obj: Any) -> Any:
                if isinstance(obj, Path):
                    return str(obj)
                elif isinstance(obj, dict):
                    return {k: path_to_str(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [path_to_str(item) for item in obj]
                return obj
            
            config_data = path_to_str(config_data)
            
            # Write configuration file
            with open(self.config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            # Set restrictive permissions
            os.chmod(self.config_file, 0o600)
            
            # Update cached settings
            self._settings = settings
            
        except Exception as e:
            raise ConfigError(f"Failed to save configuration: {e}") from e
    
    def get_vault_path(self, vault_name: str) -> Path:
        """
        Get the path for a named vault.
        
        Args:
            vault_name: Name of the vault
            
        Returns:
            Path to the vault directory
        """
        return self.settings.vault_dir / vault_name
    
    def list_vaults(self) -> List[str]:
        """
        List available vault names.
        
        Returns:
            List of vault names
        """
        if not self.settings.vault_dir.exists():
            return []
        
        vaults = []
        for item in self.settings.vault_dir.iterdir():
            if item.is_dir() and (item / "vault.json").exists():
                vaults.append(item.name)
        
        return sorted(vaults)
    
    def get_default_vault_path(self) -> Path:
        """Get path to the default vault."""
        return self.get_vault_path(self.settings.vault.default_vault_name)
    
    def update_setting(self, key: str, value: Any) -> None:
        """
        Update a specific setting.
        
        Args:
            key: Setting key (dot notation supported, e.g., "vault.session_timeout")
            value: New value
            
        Raises:
            ConfigError: If update fails
        """
        try:
            settings = self.settings.copy(deep=True)
            
            # Handle nested keys
            keys = key.split('.')
            obj = settings
            
            for k in keys[:-1]:
                if not hasattr(obj, k):
                    raise ConfigError(f"Invalid setting key: {key}")
                obj = getattr(obj, k)
            
            if not hasattr(obj, keys[-1]):
                raise ConfigError(f"Invalid setting key: {key}")
            
            setattr(obj, keys[-1], value)
            
            # Validate the updated settings
            settings = AppSettings(**settings.dict())
            
            # Save the updated settings
            self.save_settings(settings)
            
        except Exception as e:
            raise ConfigError(f"Failed to update setting '{key}': {e}") from e
    
    def reset_to_defaults(self) -> None:
        """Reset configuration to default values."""
        try:
            default_settings = AppSettings()
            self.save_settings(default_settings)
            
        except Exception as e:
            raise ConfigError(f"Failed to reset configuration: {e}") from e
    
    def validate_config(self) -> List[str]:
        """
        Validate current configuration.
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        try:
            settings = self.load_settings()
            
            # Check vault directory permissions
            if not os.access(settings.vault_dir, os.R_OK | os.W_OK):
                errors.append(f"Vault directory not accessible: {settings.vault_dir}")
            
            # Check config directory permissions
            if not os.access(settings.config_dir, os.R_OK | os.W_OK):
                errors.append(f"Config directory not accessible: {settings.config_dir}")
            
            # Validate timeout values
            if settings.vault.session_timeout < 300:
                errors.append("Session timeout must be at least 300 seconds")
            
            if settings.security.clear_clipboard_timeout < 5:
                errors.append("Clipboard timeout must be at least 5 seconds")
            
        except Exception as e:
            errors.append(f"Configuration validation failed: {e}")
        
        return errors


# Global configuration manager instance
_config_manager: Optional[ConfigManager] = None


def get_config() -> ConfigManager:
    """Get the global configuration manager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager


def get_settings() -> AppSettings:
    """Get the current application settings."""
    return get_config().settings