"""
Security utilities and validation for Secret's Garden.

This module provides security-focused utilities including password
strength validation, entropy calculation, and brute force protection.
"""

import math
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Union


@dataclass
class PasswordStrength:
    """Results of password strength analysis."""

    score: int  # 0-100
    entropy: float
    length: int
    has_upper: bool
    has_lower: bool
    has_digits: bool
    has_symbols: bool
    has_unicode: bool
    is_common: bool
    issues: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)

    @property
    def is_strong(self) -> bool:
        """Check if password meets minimum strength requirements."""
        return self.score >= 70 and self.entropy >= 50 and len(self.issues) == 0

    @property
    def strength_label(self) -> str:
        """Get human-readable strength label."""
        if self.score >= 90:
            return "Very Strong"
        elif self.score >= 70:
            return "Strong"
        elif self.score >= 50:
            return "Moderate"
        elif self.score >= 30:
            return "Weak"
        else:
            return "Very Weak"


class PasswordValidator:
    """Validates password strength and provides security recommendations."""

    # Common passwords to check against (top 1000 most common)
    COMMON_PASSWORDS = {
        "password", "123456", "password123", "admin", "qwerty", "letmein",
        "welcome", "monkey", "dragon", "master", "shadow", "abc123",
        "football", "baseball", "superman", "princess", "sunshine",
        "iloveyou", "trustno1", "starwars", "computer", "michelle",
        "jessica", "amanda", "jordan", "hunter", "daniel", "michael",
        "matthew", "ashley", "andrew", "joshua", "jennifer", "nicole",
        "charlie", "secret", "summer", "internet", "service", "canada",
        "hello", "ranger", "donald", "harley",
        "hockey", "maggie", "mike", "mustang", "snoopy",
        "buster", "mindy",
        "patrick", "123abc", "bear", "calvin", "changeme",
        "diamond", "fuckme", "fuckyou", "miller", "tiger",
        "alex", "apple", "avalon", "brandy", "chelsea",
        "coffee", "falcon", "freedom", "gandalf", "green", "helpme",
        "linda", "magic", "newyork", "soccer", "thomas", "wizard"
    }

    # Character sets for entropy calculation
    CHARSET_LOWER = set("abcdefghijklmnopqrstuvwxyz")
    CHARSET_UPPER = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    CHARSET_DIGITS = set("0123456789")
    CHARSET_SYMBOLS = set("!@#$%^&*()_+-=[]{}|;:,.<>?")
    CHARSET_SPACE = set(" ")

    def __init__(self, min_length: int = 12, min_entropy: int = 50):
        """
        Initialize password validator.
        
        Args:
            min_length: Minimum password length
            min_entropy: Minimum entropy bits required
        """
        self.min_length = min_length
        self.min_entropy = min_entropy

    def validate(self, password: str) -> PasswordStrength:
        """
        Validate password strength and security.
        
        Args:
            password: Password to validate
            
        Returns:
            PasswordStrength analysis results
        """
        if not password:
            return PasswordStrength(
                score=0, entropy=0, length=0,
                has_upper=False, has_lower=False, has_digits=False,
                has_symbols=False, has_unicode=False, is_common=False,
                issues=["Password cannot be empty"],
                suggestions=["Use a password with at least 12 characters"]
            )

        # Character analysis
        has_lower = bool(set(password) & self.CHARSET_LOWER)
        has_upper = bool(set(password) & self.CHARSET_UPPER)
        has_digits = bool(set(password) & self.CHARSET_DIGITS)
        has_symbols = bool(set(password) & self.CHARSET_SYMBOLS)
        has_unicode = any(ord(c) > 127 for c in password)

        # Calculate entropy
        entropy = self._calculate_entropy(password)

        # Check against common passwords
        is_common = password.lower() in self.COMMON_PASSWORDS

        # Analyze issues and generate suggestions
        issues = []
        suggestions = []

        if len(password) < self.min_length:
            issues.append(f"Password too short (minimum {self.min_length} characters)")
            suggestions.append(f"Use at least {self.min_length} characters")

        if entropy < self.min_entropy:
            issues.append(f"Password entropy too low ({entropy:.1f} bits, minimum {self.min_entropy})")
            suggestions.append("Use a mix of letters, numbers, and symbols")

        if is_common:
            issues.append("Password is commonly used")
            suggestions.append("Avoid common passwords and dictionary words")

        if not has_lower:
            suggestions.append("Add lowercase letters")
        if not has_upper:
            suggestions.append("Add uppercase letters")
        if not has_digits:
            suggestions.append("Add numbers")
        if not has_symbols:
            suggestions.append("Add special characters (!@#$%^&*)")

        # Check for patterns
        if self._has_sequential_chars(password):
            issues.append("Contains sequential characters (123, abc)")
            suggestions.append("Avoid sequential characters and patterns")

        if self._has_repeated_chars(password):
            issues.append("Contains repeated characters (aaa, 111)")
            suggestions.append("Avoid repeated characters")

        # Calculate score
        score = self._calculate_score(
            password, entropy, has_lower, has_upper,
            has_digits, has_symbols, has_unicode, is_common, issues
        )

        return PasswordStrength(
            score=score,
            entropy=entropy,
            length=len(password),
            has_upper=has_upper,
            has_lower=has_lower,
            has_digits=has_digits,
            has_symbols=has_symbols,
            has_unicode=has_unicode,
            is_common=is_common,
            issues=issues,
            suggestions=suggestions
        )

    def _calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits."""
        if not password:
            return 0.0

        # Determine character set size
        charset_size = 0

        if set(password) & self.CHARSET_LOWER:
            charset_size += len(self.CHARSET_LOWER)
        if set(password) & self.CHARSET_UPPER:
            charset_size += len(self.CHARSET_UPPER)
        if set(password) & self.CHARSET_DIGITS:
            charset_size += len(self.CHARSET_DIGITS)
        if set(password) & self.CHARSET_SYMBOLS:
            charset_size += len(self.CHARSET_SYMBOLS)
        if set(password) & self.CHARSET_SPACE:
            charset_size += len(self.CHARSET_SPACE)

        # Add Unicode characters
        unicode_chars = set(c for c in password if ord(c) > 127)
        charset_size += len(unicode_chars)

        if charset_size == 0:
            return 0.0

        # Calculate entropy: log2(charset_size^length)
        entropy = len(password) * math.log2(charset_size)

        # Apply penalties for patterns
        if self._has_repeated_chars(password):
            entropy *= 0.8
        if self._has_sequential_chars(password):
            entropy *= 0.8
        if self._has_keyboard_patterns(password):
            entropy *= 0.7

        return entropy

    def _calculate_score(
        self,
        password: str,
        entropy: float,
        has_lower: bool,
        has_upper: bool,
        has_digits: bool,
        has_symbols: bool,
        has_unicode: bool,
        is_common: bool,
        issues: List[str]
    ) -> int:
        """Calculate overall password score (0-100)."""
        score = 0

        # Base score from entropy
        score += min(50, entropy)

        # Character diversity bonuses
        if has_lower:
            score += 5
        if has_upper:
            score += 5
        if has_digits:
            score += 5
        if has_symbols:
            score += 10
        if has_unicode:
            score += 5

        # Length bonuses
        if len(password) >= 12:
            score += 10
        if len(password) >= 16:
            score += 5
        if len(password) >= 20:
            score += 5

        # Penalties
        if is_common:
            score -= 30
        if len(issues) > 0:
            score -= len(issues) * 5

        return max(0, min(100, int(score)))

    def _has_repeated_chars(self, password: str) -> bool:
        """Check for repeated characters (aaa, 111)."""
        return bool(re.search(r'(.)\1{2,}', password))

    def _has_sequential_chars(self, password: str) -> bool:
        """Check for sequential characters (123, abc)."""
        sequences = [
            "0123456789",
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        ]

        for seq in sequences:
            for i in range(len(seq) - 2):
                if seq[i:i+3] in password or seq[i:i+3][::-1] in password:
                    return True

        return False

    def _has_keyboard_patterns(self, password: str) -> bool:
        """Check for keyboard patterns (qwerty, asdf)."""
        keyboard_patterns = [
            "qwerty", "qwertz", "azerty", "asdf", "asdfgh",
            "zxcv", "zxcvbn", "123456", "1234567890"
        ]

        password_lower = password.lower()
        for pattern in keyboard_patterns:
            if pattern in password_lower or pattern[::-1] in password_lower:
                return True

        return False


@dataclass
class BruteForceAttempt:
    """Record of a brute force attempt."""

    timestamp: float
    success: bool
    ip_address: str = "local"


class BruteForceProtector:
    """Protects against brute force attacks on vault passwords."""

    def __init__(
        self,
        max_attempts: int = 5,
        lockout_duration: int = 300,  # 5 minutes
        max_lockout_duration: int = 3600,  # 1 hour
        storage_path: Union[Path, None] = None
    ):
        """
        Initialize brute force protector.
        
        Args:
            max_attempts: Maximum failed attempts before lockout
            lockout_duration: Initial lockout duration in seconds
            max_lockout_duration: Maximum lockout duration in seconds
            storage_path: Path to store attempt records
        """
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration
        self.max_lockout_duration = max_lockout_duration
        self.storage_path = storage_path

        # In-memory storage for attempts
        self.attempts: Dict[str, List[BruteForceAttempt]] = {}
        self.lockout_times: Dict[str, float] = {}

        if storage_path:
            self._load_attempts()

    def check_attempt_allowed(self, identifier: str = "default") -> bool:
        """
        Check if an authentication attempt is allowed.
        
        Args:
            identifier: Unique identifier for the source (e.g., IP, user)
            
        Returns:
            True if attempt is allowed, False if locked out
        """
        current_time = time.time()

        # Check if currently locked out
        if identifier in self.lockout_times:
            lockout_end = self.lockout_times[identifier]
            if current_time < lockout_end:
                return False
            else:
                # Lockout expired, remove it
                del self.lockout_times[identifier]

        # Check recent failed attempts
        if identifier in self.attempts:
            recent_attempts = [
                attempt for attempt in self.attempts[identifier]
                if current_time - attempt.timestamp < 3600  # 1 hour window
                and not attempt.success
            ]

            if len(recent_attempts) >= self.max_attempts:
                # Calculate exponential backoff
                attempt_count = len(recent_attempts)
                lockout_time = min(
                    self.lockout_duration * (2 ** (attempt_count - self.max_attempts)),
                    self.max_lockout_duration
                )

                self.lockout_times[identifier] = current_time + lockout_time
                self._save_attempts()
                return False

        return True

    def record_attempt(self, identifier: str, success: bool) -> None:
        """
        Record an authentication attempt.
        
        Args:
            identifier: Unique identifier for the source
            success: Whether the attempt was successful
        """
        if identifier not in self.attempts:
            self.attempts[identifier] = []

        attempt = BruteForceAttempt(
            timestamp=time.time(),
            success=success
        )

        self.attempts[identifier].append(attempt)

        # If successful, clear lockout
        if success and identifier in self.lockout_times:
            del self.lockout_times[identifier]

        # Clean old attempts (keep only last 24 hours)
        cutoff_time = time.time() - 86400  # 24 hours
        self.attempts[identifier] = [
            a for a in self.attempts[identifier]
            if a.timestamp > cutoff_time
        ]

        self._save_attempts()

    def get_lockout_remaining(self, identifier: str = "default") -> Union[int, None]:
        """
        Get remaining lockout time in seconds.
        
        Args:
            identifier: Unique identifier for the source
            
        Returns:
            Remaining lockout time in seconds, or None if not locked out
        """
        if identifier not in self.lockout_times:
            return None

        remaining = self.lockout_times[identifier] - time.time()
        return max(0, int(remaining)) if remaining > 0 else None

    def reset_attempts(self, identifier: str = "default") -> None:
        """
        Reset all attempts for an identifier.
        
        Args:
            identifier: Unique identifier to reset
        """
        if identifier in self.attempts:
            del self.attempts[identifier]
        if identifier in self.lockout_times:
            del self.lockout_times[identifier]

        self._save_attempts()

    def _load_attempts(self) -> None:
        """Load attempt records from storage."""
        if not self.storage_path or not self.storage_path.exists():
            return

        try:
            import json
            with open(self.storage_path) as f:
                data = json.load(f)

            # Reconstruct attempts
            for identifier, attempts_data in data.get('attempts', {}).items():
                self.attempts[identifier] = [
                    BruteForceAttempt(
                        timestamp=a['timestamp'],
                        success=a['success'],
                        ip_address=a.get('ip_address', 'local')
                    )
                    for a in attempts_data
                ]

            # Reconstruct lockout times
            self.lockout_times = data.get('lockout_times', {})

        except Exception:
            # If loading fails, start fresh
            self.attempts = {}
            self.lockout_times = {}

    def _save_attempts(self) -> None:
        """Save attempt records to storage."""
        if not self.storage_path:
            return

        try:
            import json

            # Prepare data for serialization
            data = {
                'attempts': {
                    identifier: [
                        {
                            'timestamp': a.timestamp,
                            'success': a.success,
                            'ip_address': a.ip_address
                        }
                        for a in attempts
                    ]
                    for identifier, attempts in self.attempts.items()
                },
                'lockout_times': self.lockout_times
            }

            # Ensure directory exists
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)

            # Write atomically
            temp_path = self.storage_path.with_suffix('.tmp')
            with open(temp_path, 'w') as f:
                json.dump(data, f, indent=2)

            temp_path.replace(self.storage_path)

            # Set restrictive permissions
            import os
            os.chmod(self.storage_path, 0o600)

        except Exception:
            # If saving fails, continue silently
            pass
