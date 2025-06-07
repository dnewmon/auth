from flask import current_app
from functools import lru_cache

@lru_cache(maxsize=32)
def get_config_value(key, default=None):
    """Get a configuration value, with caching for performance."""
    try:
        return current_app.config[key]
    except (RuntimeError, KeyError):
        return default

# Default configuration values
DEFAULT_CONFIG = {
    "MODEL_ENCRYPTION_SALT_LENGTH": 32,
    "MODEL_OTP_SECRET_LENGTH": 32,
    
    # Password Policy Configuration
    "PASSWORD_POLICY_ENABLED": True,
    "PASSWORD_POLICY_MIN_LENGTH": 8,
    "PASSWORD_POLICY_MAX_LENGTH": 128,
    "PASSWORD_POLICY_REQUIRE_UPPERCASE": True,
    "PASSWORD_POLICY_REQUIRE_LOWERCASE": True,
    "PASSWORD_POLICY_REQUIRE_DIGITS": True,
    "PASSWORD_POLICY_REQUIRE_SYMBOLS": True,
    "PASSWORD_POLICY_MIN_UPPERCASE": 1,
    "PASSWORD_POLICY_MIN_LOWERCASE": 1,
    "PASSWORD_POLICY_MIN_DIGITS": 1,
    "PASSWORD_POLICY_MIN_SYMBOLS": 1,
    "PASSWORD_POLICY_FORBIDDEN_PASSWORDS": ["password", "123456", "qwerty", "abc123", "password123"],
    "PASSWORD_POLICY_FORBID_COMMON_PATTERNS": True,
    "PASSWORD_POLICY_FORBID_PERSONAL_INFO": True,
    "PASSWORD_POLICY_ENFORCE_ON_CREATION": True,
    "PASSWORD_POLICY_ENFORCE_ON_UPDATE": True,
    "PASSWORD_POLICY_WARN_ONLY": False,  # If True, show warnings but allow saving
} 