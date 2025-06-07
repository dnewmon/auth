"""
Password Policy Enforcement Module

This module provides comprehensive password policy validation and enforcement
capabilities for credential management.
"""

import re
from typing import List, Dict, Any, Tuple
from ..models.config import get_config_value, DEFAULT_CONFIG


class PasswordPolicyValidator:
    """Validates passwords against configurable policy rules."""
    
    def __init__(self):
        """Initialize the validator with current configuration."""
        self.enabled = get_config_value("PASSWORD_POLICY_ENABLED", DEFAULT_CONFIG["PASSWORD_POLICY_ENABLED"])
        self.min_length = get_config_value("PASSWORD_POLICY_MIN_LENGTH", DEFAULT_CONFIG["PASSWORD_POLICY_MIN_LENGTH"])
        self.max_length = get_config_value("PASSWORD_POLICY_MAX_LENGTH", DEFAULT_CONFIG["PASSWORD_POLICY_MAX_LENGTH"])
        
        # Character requirements
        self.require_uppercase = get_config_value("PASSWORD_POLICY_REQUIRE_UPPERCASE", DEFAULT_CONFIG["PASSWORD_POLICY_REQUIRE_UPPERCASE"])
        self.require_lowercase = get_config_value("PASSWORD_POLICY_REQUIRE_LOWERCASE", DEFAULT_CONFIG["PASSWORD_POLICY_REQUIRE_LOWERCASE"])
        self.require_digits = get_config_value("PASSWORD_POLICY_REQUIRE_DIGITS", DEFAULT_CONFIG["PASSWORD_POLICY_REQUIRE_DIGITS"])
        self.require_symbols = get_config_value("PASSWORD_POLICY_REQUIRE_SYMBOLS", DEFAULT_CONFIG["PASSWORD_POLICY_REQUIRE_SYMBOLS"])
        
        # Minimum character counts
        self.min_uppercase = get_config_value("PASSWORD_POLICY_MIN_UPPERCASE", DEFAULT_CONFIG["PASSWORD_POLICY_MIN_UPPERCASE"])
        self.min_lowercase = get_config_value("PASSWORD_POLICY_MIN_LOWERCASE", DEFAULT_CONFIG["PASSWORD_POLICY_MIN_LOWERCASE"])
        self.min_digits = get_config_value("PASSWORD_POLICY_MIN_DIGITS", DEFAULT_CONFIG["PASSWORD_POLICY_MIN_DIGITS"])
        self.min_symbols = get_config_value("PASSWORD_POLICY_MIN_SYMBOLS", DEFAULT_CONFIG["PASSWORD_POLICY_MIN_SYMBOLS"])
        
        # Forbidden passwords and patterns
        # Don't use cached config for complex types like lists
        try:
            from flask import current_app
            self.forbidden_passwords = current_app.config.get("PASSWORD_POLICY_FORBIDDEN_PASSWORDS", DEFAULT_CONFIG["PASSWORD_POLICY_FORBIDDEN_PASSWORDS"])
        except RuntimeError:
            self.forbidden_passwords = DEFAULT_CONFIG["PASSWORD_POLICY_FORBIDDEN_PASSWORDS"]
        
        self.forbid_common_patterns = get_config_value("PASSWORD_POLICY_FORBID_COMMON_PATTERNS", DEFAULT_CONFIG["PASSWORD_POLICY_FORBID_COMMON_PATTERNS"])
        self.forbid_personal_info = get_config_value("PASSWORD_POLICY_FORBID_PERSONAL_INFO", DEFAULT_CONFIG["PASSWORD_POLICY_FORBID_PERSONAL_INFO"])
        
        # Enforcement settings
        self.enforce_on_creation = get_config_value("PASSWORD_POLICY_ENFORCE_ON_CREATION", DEFAULT_CONFIG["PASSWORD_POLICY_ENFORCE_ON_CREATION"])
        self.enforce_on_update = get_config_value("PASSWORD_POLICY_ENFORCE_ON_UPDATE", DEFAULT_CONFIG["PASSWORD_POLICY_ENFORCE_ON_UPDATE"])
        self.warn_only = get_config_value("PASSWORD_POLICY_WARN_ONLY", DEFAULT_CONFIG["PASSWORD_POLICY_WARN_ONLY"])
    
    def validate_password(self, password: str, user_info: Dict[str, Any] = None, operation: str = "create") -> Tuple[bool, List[str], List[str]]:
        """
        Validate a password against the configured policy.
        
        Args:
            password: The password to validate
            user_info: Optional user information for personal info checks
            operation: The operation type ("create" or "update")
            
        Returns:
            Tuple of (is_valid, errors, warnings)
        """
        if not self.enabled:
            return True, [], []
        
        # Check if enforcement applies to this operation
        should_enforce = (
            (operation == "create" and self.enforce_on_creation) or
            (operation == "update" and self.enforce_on_update)
        )
        
        if not should_enforce:
            return True, [], []
        
        errors = []
        warnings = []
        
        # Length validation
        length_errors = self._validate_length(password)
        errors.extend(length_errors)
        
        # Character requirements
        char_errors = self._validate_character_requirements(password)
        errors.extend(char_errors)
        
        # Forbidden passwords
        forbidden_errors = self._validate_forbidden_passwords(password)
        errors.extend(forbidden_errors)
        
        # Common patterns
        if self.forbid_common_patterns:
            pattern_errors = self._validate_common_patterns(password)
            errors.extend(pattern_errors)
        
        # Personal information
        if self.forbid_personal_info and user_info:
            personal_errors = self._validate_personal_info(password, user_info)
            errors.extend(personal_errors)
        
        # If warn_only mode, convert errors to warnings
        if self.warn_only:
            warnings.extend(errors)
            errors = []
        
        is_valid = len(errors) == 0
        return is_valid, errors, warnings
    
    def _validate_length(self, password: str) -> List[str]:
        """Validate password length requirements."""
        errors = []
        
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters long")
        
        if len(password) > self.max_length:
            errors.append(f"Password must be no more than {self.max_length} characters long")
        
        return errors
    
    def _validate_character_requirements(self, password: str) -> List[str]:
        """Validate character type requirements."""
        errors = []
        
        # Count character types
        uppercase_count = sum(1 for c in password if c.isupper())
        lowercase_count = sum(1 for c in password if c.islower())
        digit_count = sum(1 for c in password if c.isdigit())
        symbol_count = sum(1 for c in password if not c.isalnum())
        
        # Check requirements
        if self.require_uppercase and uppercase_count < self.min_uppercase:
            if self.min_uppercase == 1:
                errors.append("Password must contain at least one uppercase letter")
            else:
                errors.append(f"Password must contain at least {self.min_uppercase} uppercase letters")
        
        if self.require_lowercase and lowercase_count < self.min_lowercase:
            if self.min_lowercase == 1:
                errors.append("Password must contain at least one lowercase letter")
            else:
                errors.append(f"Password must contain at least {self.min_lowercase} lowercase letters")
        
        if self.require_digits and digit_count < self.min_digits:
            if self.min_digits == 1:
                errors.append("Password must contain at least one digit")
            else:
                errors.append(f"Password must contain at least {self.min_digits} digits")
        
        if self.require_symbols and symbol_count < self.min_symbols:
            if self.min_symbols == 1:
                errors.append("Password must contain at least one special character")
            else:
                errors.append(f"Password must contain at least {self.min_symbols} special characters")
        
        return errors
    
    def _validate_forbidden_passwords(self, password: str) -> List[str]:
        """Check against forbidden password list."""
        errors = []
        
        # Case-insensitive check
        password_lower = password.lower()
        for forbidden in self.forbidden_passwords:
            if password_lower == forbidden.lower():
                errors.append("This password is commonly used and not allowed")
                break
        
        return errors
    
    def _validate_common_patterns(self, password: str) -> List[str]:
        """Check for common weak patterns."""
        errors = []
        
        # Sequential characters (abc, 123, etc.)
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
            errors.append("Password contains sequential alphabetic characters")
        
        if re.search(r'(123|234|345|456|567|678|789|890)', password):
            errors.append("Password contains sequential numeric characters")
        
        # Repeated characters
        if re.search(r'(.)\1{2,}', password):
            errors.append("Password contains too many repeated characters")
        
        # Keyboard patterns
        keyboard_patterns = [
            r'qwerty|qwertz|asdfgh|zxcvbn',
            r'123456|654321',
            r'!@#\$%\^|!@#\$%|!@#\$'
        ]
        
        for pattern in keyboard_patterns:
            if re.search(pattern, password.lower()):
                errors.append("Password contains keyboard patterns")
                break
        
        return errors
    
    def _validate_personal_info(self, password: str, user_info: Dict[str, Any]) -> List[str]:
        """Check if password contains personal information."""
        errors = []
        
        password_lower = password.lower()
        
        # Check username
        username = user_info.get('username', '')
        if username and len(username) >= 3 and username.lower() in password_lower:
            errors.append("Password should not contain your username")
        
        # Check email parts
        email = user_info.get('email', '')
        if email and '@' in email:
            email_parts = email.split('@')
            if len(email_parts[0]) >= 3 and email_parts[0].lower() in password_lower:
                errors.append("Password should not contain parts of your email address")
        
        # Check first/last name if provided
        first_name = user_info.get('first_name', '')
        if first_name and len(first_name) >= 3 and first_name.lower() in password_lower:
            errors.append("Password should not contain your first name")
        
        last_name = user_info.get('last_name', '')
        if last_name and len(last_name) >= 3 and last_name.lower() in password_lower:
            errors.append("Password should not contain your last name")
        
        return errors
    
    def get_policy_info(self) -> Dict[str, Any]:
        """Get current policy configuration for display."""
        if not self.enabled:
            return {"enabled": False}
        
        return {
            "enabled": True,
            "min_length": self.min_length,
            "max_length": self.max_length,
            "require_uppercase": self.require_uppercase,
            "require_lowercase": self.require_lowercase,
            "require_digits": self.require_digits,
            "require_symbols": self.require_symbols,
            "min_uppercase": self.min_uppercase,
            "min_lowercase": self.min_lowercase,
            "min_digits": self.min_digits,
            "min_symbols": self.min_symbols,
            "forbid_common_patterns": self.forbid_common_patterns,
            "forbid_personal_info": self.forbid_personal_info,
            "enforce_on_creation": self.enforce_on_creation,
            "enforce_on_update": self.enforce_on_update,
            "warn_only": self.warn_only
        }


def validate_credential_password(password: str, user_info: Dict[str, Any] = None, operation: str = "create") -> Tuple[bool, List[str], List[str]]:
    """
    Convenience function to validate a credential password.
    
    Args:
        password: The password to validate
        user_info: Optional user information
        operation: The operation type ("create" or "update")
        
    Returns:
        Tuple of (is_valid, errors, warnings)
    """
    validator = PasswordPolicyValidator()
    return validator.validate_password(password, user_info, operation)


def get_password_policy() -> Dict[str, Any]:
    """Get the current password policy configuration."""
    validator = PasswordPolicyValidator()
    return validator.get_policy_info()