"""
Secure password generator utility.

Provides cryptographically secure password generation with customizable options
for length, character sets, and complexity requirements.
"""

import secrets
import string
from typing import List, Set


class PasswordGenerator:
    """Secure password generator with customizable options."""
    
    # Character sets
    LOWERCASE = string.ascii_lowercase
    UPPERCASE = string.ascii_uppercase
    DIGITS = string.digits
    SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    SAFE_SYMBOLS = "!@#$%^&*_+-="  # Symbols safe for most systems
    
    # Ambiguous characters that can be confused
    AMBIGUOUS = "0O1lI|"
    
    def __init__(self):
        """Initialize the password generator."""
        self.reset_to_defaults()
    
    def reset_to_defaults(self):
        """Reset all options to secure defaults."""
        self.length = 16
        self.use_lowercase = True
        self.use_uppercase = True
        self.use_digits = True
        self.use_symbols = True
        self.use_safe_symbols_only = False
        self.exclude_ambiguous = True
        self.min_lowercase = 1
        self.min_uppercase = 1
        self.min_digits = 1
        self.min_symbols = 1
        self.exclude_chars = set()
        self.require_chars = set()
    
    def set_length(self, length: int) -> 'PasswordGenerator':
        """Set password length."""
        if length < 4:
            raise ValueError("Password length must be at least 4 characters")
        if length > 128:
            raise ValueError("Password length cannot exceed 128 characters")
        self.length = length
        return self
    
    def set_character_sets(self, lowercase: bool = True, uppercase: bool = True, 
                          digits: bool = True, symbols: bool = True) -> 'PasswordGenerator':
        """Configure which character sets to use."""
        self.use_lowercase = lowercase
        self.use_uppercase = uppercase
        self.use_digits = digits
        self.use_symbols = symbols
        return self
    
    def set_safe_symbols_only(self, safe_only: bool = True) -> 'PasswordGenerator':
        """Use only safe symbols that work in most systems."""
        self.use_safe_symbols_only = safe_only
        return self
    
    def set_exclude_ambiguous(self, exclude: bool = True) -> 'PasswordGenerator':
        """Exclude ambiguous characters like 0, O, 1, l, I."""
        self.exclude_ambiguous = exclude
        return self
    
    def set_minimum_requirements(self, lowercase: int = 0, uppercase: int = 0,
                               digits: int = 0, symbols: int = 0) -> 'PasswordGenerator':
        """Set minimum character requirements for each type."""
        self.min_lowercase = max(0, lowercase)
        self.min_uppercase = max(0, uppercase)
        self.min_digits = max(0, digits)
        self.min_symbols = max(0, symbols)
        return self
    
    def exclude_characters(self, chars: str) -> 'PasswordGenerator':
        """Exclude specific characters from generation."""
        self.exclude_chars.update(chars)
        return self
    
    def require_characters(self, chars: str) -> 'PasswordGenerator':
        """Require specific characters to be included."""
        self.require_chars.update(chars)
        return self
    
    def _build_character_set(self) -> str:
        """Build the character set based on current configuration."""
        charset = ""
        
        if self.use_lowercase:
            charset += self.LOWERCASE
        if self.use_uppercase:
            charset += self.UPPERCASE
        if self.use_digits:
            charset += self.DIGITS
        if self.use_symbols:
            if self.use_safe_symbols_only:
                charset += self.SAFE_SYMBOLS
            else:
                charset += self.SYMBOLS
        
        # Remove ambiguous characters if requested
        if self.exclude_ambiguous:
            charset = ''.join(c for c in charset if c not in self.AMBIGUOUS)
        
        # Remove excluded characters
        charset = ''.join(c for c in charset if c not in self.exclude_chars)
        
        # Ensure we have characters left
        if not charset:
            raise ValueError("No characters available with current configuration")
        
        return charset
    
    def _validate_requirements(self) -> None:
        """Validate that requirements can be met with current settings."""
        min_total = (self.min_lowercase + self.min_uppercase + 
                    self.min_digits + self.min_symbols + len(self.require_chars))
        
        if min_total > self.length:
            raise ValueError(f"Minimum requirements ({min_total}) exceed password length ({self.length})")
        
        # Check if character sets are available for requirements
        if self.min_lowercase > 0 and not self.use_lowercase:
            raise ValueError("Lowercase characters required but not enabled")
        if self.min_uppercase > 0 and not self.use_uppercase:
            raise ValueError("Uppercase characters required but not enabled")
        if self.min_digits > 0 and not self.use_digits:
            raise ValueError("Digits required but not enabled")
        if self.min_symbols > 0 and not self.use_symbols:
            raise ValueError("Symbols required but not enabled")
    
    def _get_required_characters(self) -> List[str]:
        """Get characters that must be included to meet requirements."""
        required = []
        
        # Add minimum required characters from each set
        if self.min_lowercase > 0 and self.use_lowercase:
            available = [c for c in self.LOWERCASE if c not in self.exclude_chars]
            if self.exclude_ambiguous:
                available = [c for c in available if c not in self.AMBIGUOUS]
            required.extend(secrets.choice(available) for _ in range(self.min_lowercase))
        
        if self.min_uppercase > 0 and self.use_uppercase:
            available = [c for c in self.UPPERCASE if c not in self.exclude_chars]
            if self.exclude_ambiguous:
                available = [c for c in available if c not in self.AMBIGUOUS]
            required.extend(secrets.choice(available) for _ in range(self.min_uppercase))
        
        if self.min_digits > 0 and self.use_digits:
            available = [c for c in self.DIGITS if c not in self.exclude_chars]
            if self.exclude_ambiguous:
                available = [c for c in available if c not in self.AMBIGUOUS]
            required.extend(secrets.choice(available) for _ in range(self.min_digits))
        
        if self.min_symbols > 0 and self.use_symbols:
            symbol_set = self.SAFE_SYMBOLS if self.use_safe_symbols_only else self.SYMBOLS
            available = [c for c in symbol_set if c not in self.exclude_chars]
            required.extend(secrets.choice(available) for _ in range(self.min_symbols))
        
        # Add explicitly required characters
        required.extend(self.require_chars)
        
        return required
    
    def generate(self) -> str:
        """Generate a secure password with current configuration."""
        self._validate_requirements()
        
        charset = self._build_character_set()
        required_chars = self._get_required_characters()
        
        # Start with required characters
        password_chars = required_chars.copy()
        
        # Fill remaining length with random characters
        remaining_length = self.length - len(required_chars)
        password_chars.extend(secrets.choice(charset) for _ in range(remaining_length))
        
        # Shuffle the password to avoid predictable patterns
        secrets.SystemRandom().shuffle(password_chars)
        
        return ''.join(password_chars)
    
    def generate_multiple(self, count: int) -> List[str]:
        """Generate multiple passwords with current configuration."""
        if count < 1:
            raise ValueError("Count must be at least 1")
        if count > 100:
            raise ValueError("Cannot generate more than 100 passwords at once")
        
        return [self.generate() for _ in range(count)]
    
    def analyze_strength(self, password: str) -> dict:
        """Analyze password strength and return metrics."""
        if not password:
            return {"score": 0, "strength": "Very Weak", "feedback": ["Password is empty"]}
        
        length = len(password)
        has_lowercase = any(c in string.ascii_lowercase for c in password)
        has_uppercase = any(c in string.ascii_uppercase for c in password)
        has_digits = any(c in string.digits for c in password)
        has_symbols = any(c in self.SYMBOLS for c in password)
        
        # Count character sets used
        char_sets = sum([has_lowercase, has_uppercase, has_digits, has_symbols])
        
        # Calculate base score
        score = 0
        feedback = []
        
        # Length scoring
        if length >= 12:
            score += 25
        elif length >= 8:
            score += 15
            feedback.append("Consider using a longer password (12+ characters)")
        else:
            score += 5
            feedback.append("Password is too short (use 12+ characters)")
        
        # Character set diversity
        score += char_sets * 15
        
        if not has_lowercase:
            feedback.append("Add lowercase letters")
        if not has_uppercase:
            feedback.append("Add uppercase letters")
        if not has_digits:
            feedback.append("Add numbers")
        if not has_symbols:
            feedback.append("Add symbols")
        
        # Bonus for length
        if length >= 16:
            score += 10
        if length >= 20:
            score += 10
        
        # Penalty for patterns (basic check)
        if len(set(password)) < length * 0.7:  # Too many repeated characters
            score -= 10
            feedback.append("Avoid repeating characters")
        
        # Determine strength level
        if score >= 80:
            strength = "Very Strong"
        elif score >= 60:
            strength = "Strong"
        elif score >= 40:
            strength = "Moderate"
        elif score >= 20:
            strength = "Weak"
        else:
            strength = "Very Weak"
        
        return {
            "score": min(100, score),
            "strength": strength,
            "length": length,
            "character_sets": char_sets,
            "has_lowercase": has_lowercase,
            "has_uppercase": has_uppercase,
            "has_digits": has_digits,
            "has_symbols": has_symbols,
            "feedback": feedback if feedback else ["Password meets security requirements"]
        }


# Convenience functions for common use cases
def generate_strong_password(length: int = 16) -> str:
    """Generate a strong password with default secure settings."""
    return PasswordGenerator().set_length(length).generate()


def generate_safe_password(length: int = 16) -> str:
    """Generate a password using only safe symbols (good for system compatibility)."""
    return (PasswordGenerator()
            .set_length(length)
            .set_safe_symbols_only(True)
            .set_exclude_ambiguous(True)
            .generate())


def generate_memorable_password(length: int = 20) -> str:
    """Generate a longer password without ambiguous characters for better memorability."""
    return (PasswordGenerator()
            .set_length(length)
            .set_exclude_ambiguous(True)
            .set_safe_symbols_only(True)
            .set_minimum_requirements(lowercase=2, uppercase=2, digits=2, symbols=1)
            .generate())


def generate_pin(length: int = 6) -> str:
    """Generate a numeric PIN."""
    if length < 4 or length > 12:
        raise ValueError("PIN length must be between 4 and 12 digits")
    
    return (PasswordGenerator()
            .set_length(length)
            .set_character_sets(lowercase=False, uppercase=False, digits=True, symbols=False)
            .set_exclude_ambiguous(False)  # All digits are clear
            .generate())


def analyze_password_strength(password: str) -> dict:
    """Analyze the strength of a given password."""
    return PasswordGenerator().analyze_strength(password)