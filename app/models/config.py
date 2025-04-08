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
} 