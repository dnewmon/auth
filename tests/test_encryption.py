"""
Unit tests for app.utils.encryption module.

Tests all encryption, decryption, key derivation, and recovery key functionality.
"""
import pytest
import os
import base64
import string
from unittest.mock import patch, Mock

# Import the encryption module functions
from app.utils.encryption import (
    derive_key,
    encrypt_data,
    decrypt_data,
    generate_master_encryption_key,
    encrypt_master_key,
    decrypt_master_key,
    generate_recovery_key,
    generate_recovery_keys,
    hash_recovery_key,
    encrypt_master_key_with_recovery_key,
    decrypt_master_key_with_recovery_key,
    PBKDF2_ITERATIONS
)


class TestKeyDerivation:
    """Tests for PBKDF2 key derivation function."""
    
    def test_derive_key_basic(self):
        """Test basic key derivation functionality."""
        password = "test_password"
        salt = b"test_salt_16_bytes_long"
        
        key = derive_key(password, salt)
        
        assert isinstance(key, bytes)
        assert len(key) == 32  # 256 bits
    
    def test_derive_key_consistency(self):
        """Test that same inputs produce same key."""
        password = "test_password"
        salt = b"test_salt_16_bytes_long"
        
        key1 = derive_key(password, salt)
        key2 = derive_key(password, salt)
        
        assert key1 == key2
    
    def test_derive_key_different_passwords(self):
        """Test that different passwords produce different keys."""
        salt = b"test_salt_16_bytes_long"
        
        key1 = derive_key("password1", salt)
        key2 = derive_key("password2", salt)
        
        assert key1 != key2
    
    def test_derive_key_different_salts(self):
        """Test that different salts produce different keys."""
        password = "test_password"
        
        key1 = derive_key(password, b"salt1_16_bytes_long")
        key2 = derive_key(password, b"salt2_16_bytes_long")
        
        assert key1 != key2
    
    def test_derive_key_unicode_password(self):
        """Test key derivation with unicode password."""
        password = "test_password_🔐"
        salt = b"test_salt_16_bytes_long"
        
        key = derive_key(password, salt)
        
        assert isinstance(key, bytes)
        assert len(key) == 32


class TestEncryptionDecryption:
    """Tests for AES-GCM encryption and decryption."""
    
    def test_encrypt_decrypt_basic(self):
        """Test basic encryption and decryption."""
        key = os.urandom(32)
        plaintext = "Hello, World!"
        
        encrypted = encrypt_data(key, plaintext)
        decrypted = decrypt_data(key, encrypted)
        
        assert decrypted == plaintext
    
    def test_encrypt_data_format(self):
        """Test that encrypted data is properly formatted."""
        key = os.urandom(32)
        plaintext = "test data"
        
        encrypted = encrypt_data(key, plaintext)
        
        # Should be base64 encoded string
        assert isinstance(encrypted, str)
        # Should be valid base64
        decoded = base64.urlsafe_b64decode(encrypted.encode())
        # Should contain nonce (12 bytes) + ciphertext
        assert len(decoded) >= 13
    
    def test_encrypt_data_invalid_input(self):
        """Test encryption with invalid input types."""
        key = os.urandom(32)
        
        with pytest.raises(TypeError, match="Plaintext must be a string"):
            encrypt_data(key, 123)
        
        with pytest.raises(TypeError, match="Plaintext must be a string"):
            encrypt_data(key, None)
    
    def test_decrypt_data_invalid_base64(self):
        """Test decryption with invalid base64 data."""
        key = os.urandom(32)
        
        with pytest.raises(ValueError, match="Invalid encrypted data format"):
            decrypt_data(key, "invalid_base64!")
    
    def test_decrypt_data_too_short(self):
        """Test decryption with data too short to contain nonce + ciphertext."""
        key = os.urandom(32)
        short_data = base64.urlsafe_b64encode(b"short").decode()
        
        with pytest.raises(ValueError, match="Invalid encrypted data length"):
            decrypt_data(key, short_data)
    
    def test_decrypt_data_wrong_key(self):
        """Test decryption with wrong key fails gracefully."""
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        plaintext = "secret message"
        
        encrypted = encrypt_data(key1, plaintext)
        
        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt_data(key2, encrypted)
    
    def test_encrypt_decrypt_empty_string(self):
        """Test encryption and decryption of empty string."""
        key = os.urandom(32)
        plaintext = ""
        
        encrypted = encrypt_data(key, plaintext)
        decrypted = decrypt_data(key, encrypted)
        
        assert decrypted == plaintext
    
    def test_encrypt_decrypt_unicode_text(self):
        """Test encryption and decryption of unicode text."""
        key = os.urandom(32)
        plaintext = "Unicode test: 🔐 안녕하세요 مرحبا"
        
        encrypted = encrypt_data(key, plaintext)
        decrypted = decrypt_data(key, encrypted)
        
        assert decrypted == plaintext
    
    def test_encrypt_decrypt_large_text(self):
        """Test encryption and decryption of large text."""
        key = os.urandom(32)
        plaintext = "A" * 10000  # 10KB of data
        
        encrypted = encrypt_data(key, plaintext)
        decrypted = decrypt_data(key, encrypted)
        
        assert decrypted == plaintext
    
    def test_encrypt_nonce_uniqueness(self):
        """Test that each encryption uses a unique nonce."""
        key = os.urandom(32)
        plaintext = "same message"
        
        encrypted1 = encrypt_data(key, plaintext)
        encrypted2 = encrypt_data(key, plaintext)
        
        # Same plaintext should produce different ciphertext due to unique nonces
        assert encrypted1 != encrypted2
        
        # But both should decrypt to the same plaintext
        assert decrypt_data(key, encrypted1) == plaintext
        assert decrypt_data(key, encrypted2) == plaintext


class TestMasterKeyGeneration:
    """Tests for master encryption key generation."""
    
    def test_generate_master_encryption_key(self):
        """Test master key generation."""
        key = generate_master_encryption_key()
        
        assert isinstance(key, bytes)
        assert len(key) == 32  # 256 bits
    
    def test_generate_master_encryption_key_uniqueness(self):
        """Test that generated keys are unique."""
        key1 = generate_master_encryption_key()
        key2 = generate_master_encryption_key()
        
        assert key1 != key2


class TestMasterKeyEncryption:
    """Tests for master key encryption and decryption with passwords."""
    
    def test_encrypt_decrypt_master_key(self):
        """Test master key encryption and decryption."""
        master_key = generate_master_encryption_key()
        password = "user_password"
        salt = os.urandom(16)
        
        encrypted_master_key = encrypt_master_key(master_key, password, salt)
        decrypted_master_key = decrypt_master_key(encrypted_master_key, password, salt)
        
        assert decrypted_master_key == master_key
    
    def test_encrypt_master_key_wrong_password(self):
        """Test that wrong password fails to decrypt master key."""
        master_key = generate_master_encryption_key()
        password = "user_password"
        wrong_password = "wrong_password"
        salt = os.urandom(16)
        
        encrypted_master_key = encrypt_master_key(master_key, password, salt)
        
        with pytest.raises(ValueError):
            decrypt_master_key(encrypted_master_key, wrong_password, salt)
    
    def test_encrypt_master_key_wrong_salt(self):
        """Test that wrong salt fails to decrypt master key."""
        master_key = generate_master_encryption_key()
        password = "user_password"
        salt1 = os.urandom(16)
        salt2 = os.urandom(16)
        
        encrypted_master_key = encrypt_master_key(master_key, password, salt1)
        
        with pytest.raises(ValueError):
            decrypt_master_key(encrypted_master_key, password, salt2)


class TestRecoveryKeys:
    """Tests for recovery key generation and management."""
    
    def test_generate_recovery_key_default(self):
        """Test default recovery key generation."""
        key = generate_recovery_key()
        
        # Should be formatted as XXXX-XXXX-XXXX-XXXX
        assert len(key) == 19  # 16 chars + 3 hyphens
        assert key.count('-') == 3
        
        # Split and check each part
        parts = key.split('-')
        assert len(parts) == 4
        for part in parts:
            assert len(part) == 4
            # Should only contain allowed characters
            allowed_chars = set(string.ascii_uppercase + string.digits) - set("O01IL")
            assert all(c in allowed_chars for c in part)
    
    def test_generate_recovery_key_custom_length(self):
        """Test recovery key generation with custom length."""
        key = generate_recovery_key(length=8)
        
        assert len(key) == 8
        assert '-' not in key  # No formatting for non-16 length
        
        allowed_chars = set(string.ascii_uppercase + string.digits) - set("O01IL")
        assert all(c in allowed_chars for c in key)
    
    def test_generate_recovery_key_uniqueness(self):
        """Test that generated recovery keys are unique."""
        keys = [generate_recovery_key() for _ in range(100)]
        
        # All keys should be unique
        assert len(set(keys)) == len(keys)
    
    def test_generate_recovery_keys(self):
        """Test generation of multiple recovery keys."""
        keys = generate_recovery_keys(count=5)
        
        assert len(keys) == 5
        assert len(set(keys)) == 5  # All unique
        
        for key in keys:
            assert len(key) == 19  # Properly formatted
    
    def test_generate_recovery_keys_default_count(self):
        """Test default count for recovery keys generation."""
        keys = generate_recovery_keys()
        
        assert len(keys) == 5  # Default count
    
    def test_hash_recovery_key(self):
        """Test recovery key hashing."""
        recovery_key = "ABCD-EFGH-IJKM-NPQR"
        
        hashed = hash_recovery_key(recovery_key)
        
        assert isinstance(hashed, str)
        # Should be base64 encoded SHA256 hash
        decoded = base64.urlsafe_b64decode(hashed.encode())
        assert len(decoded) == 32  # SHA256 is 32 bytes
    
    def test_hash_recovery_key_consistency(self):
        """Test that same recovery key produces same hash."""
        recovery_key = "ABCD-EFGH-IJKM-NPQR"
        
        hash1 = hash_recovery_key(recovery_key)
        hash2 = hash_recovery_key(recovery_key)
        
        assert hash1 == hash2
    
    def test_hash_recovery_key_formatting_ignored(self):
        """Test that formatting is ignored in hashing."""
        key_formatted = "ABCD-EFGH-IJKM-NPQR"
        key_unformatted = "ABCDEFGHIJKMNPQR"
        
        hash1 = hash_recovery_key(key_formatted)
        hash2 = hash_recovery_key(key_unformatted)
        
        assert hash1 == hash2


class TestMasterKeyRecovery:
    """Tests for master key encryption/decryption with recovery keys."""
    
    def test_encrypt_decrypt_master_key_with_recovery_key(self):
        """Test master key encryption and decryption with recovery key."""
        master_key = generate_master_encryption_key()
        recovery_key = generate_recovery_key()
        
        salt, encrypted_master_key, key_hash = encrypt_master_key_with_recovery_key(
            master_key, recovery_key
        )
        
        decrypted_master_key = decrypt_master_key_with_recovery_key(
            encrypted_master_key, recovery_key, salt
        )
        
        assert decrypted_master_key == master_key
        assert isinstance(salt, bytes)
        assert len(salt) == 16
        assert isinstance(key_hash, str)
    
    def test_encrypt_master_key_with_recovery_key_hash_verification(self):
        """Test that the returned hash matches the recovery key."""
        master_key = generate_master_encryption_key()
        recovery_key = generate_recovery_key()
        
        salt, encrypted_master_key, key_hash = encrypt_master_key_with_recovery_key(
            master_key, recovery_key
        )
        
        expected_hash = hash_recovery_key(recovery_key)
        assert key_hash == expected_hash
    
    def test_decrypt_master_key_wrong_recovery_key(self):
        """Test that wrong recovery key fails to decrypt master key."""
        master_key = generate_master_encryption_key()
        recovery_key = generate_recovery_key()
        wrong_recovery_key = generate_recovery_key()
        
        salt, encrypted_master_key, key_hash = encrypt_master_key_with_recovery_key(
            master_key, recovery_key
        )
        
        with pytest.raises(ValueError, match="Invalid recovery key"):
            decrypt_master_key_with_recovery_key(
                encrypted_master_key, wrong_recovery_key, salt
            )
    
    def test_decrypt_master_key_wrong_salt(self):
        """Test that wrong salt fails to decrypt master key."""
        master_key = generate_master_encryption_key()
        recovery_key = generate_recovery_key()
        
        salt, encrypted_master_key, key_hash = encrypt_master_key_with_recovery_key(
            master_key, recovery_key
        )
        
        wrong_salt = os.urandom(16)
        
        with pytest.raises(ValueError, match="Invalid recovery key"):
            decrypt_master_key_with_recovery_key(
                encrypted_master_key, recovery_key, wrong_salt
            )
    
    def test_recovery_key_formatting_handling(self):
        """Test that recovery key formatting is handled properly."""
        master_key = generate_master_encryption_key()
        recovery_key_formatted = "ABCD-EFGH-IJKM-NPQR"
        recovery_key_unformatted = "ABCDEFGHIJKMNPQR"
        
        # Encrypt with formatted key
        salt, encrypted_master_key, key_hash = encrypt_master_key_with_recovery_key(
            master_key, recovery_key_formatted
        )
        
        # Decrypt with unformatted key should work
        decrypted_master_key = decrypt_master_key_with_recovery_key(
            encrypted_master_key, recovery_key_unformatted, salt
        )
        
        assert decrypted_master_key == master_key


class TestIntegrationScenarios:
    """Integration tests for complete encryption workflows."""
    
    def test_full_user_encryption_workflow(self):
        """Test complete user encryption workflow."""
        # User setup
        user_password = "user_password_123"
        user_salt = os.urandom(16)
        
        # Generate and encrypt master key
        master_key = generate_master_encryption_key()
        encrypted_master_key = encrypt_master_key(master_key, user_password, user_salt)
        
        # Generate recovery keys
        recovery_keys = generate_recovery_keys(count=3)
        recovery_data = []
        
        for recovery_key in recovery_keys:
            salt, encrypted_mk, key_hash = encrypt_master_key_with_recovery_key(
                master_key, recovery_key
            )
            recovery_data.append((salt, encrypted_mk, key_hash))
        
        # User encrypts some data
        user_data = "sensitive user credential"
        encrypted_user_data = encrypt_data(master_key, user_data)
        
        # Scenario 1: User logs in normally
        decrypted_master_key = decrypt_master_key(encrypted_master_key, user_password, user_salt)
        decrypted_user_data = decrypt_data(decrypted_master_key, encrypted_user_data)
        assert decrypted_user_data == user_data
        
        # Scenario 2: User uses recovery key
        recovery_key = recovery_keys[1]  # Use second recovery key
        salt, encrypted_mk, key_hash = recovery_data[1]
        
        recovered_master_key = decrypt_master_key_with_recovery_key(
            encrypted_mk, recovery_key, salt
        )
        decrypted_user_data = decrypt_data(recovered_master_key, encrypted_user_data)
        assert decrypted_user_data == user_data
        assert recovered_master_key == master_key
    
    def test_key_rotation_scenario(self):
        """Test key rotation scenario."""
        # Original setup
        old_password = "old_password"
        new_password = "new_password"
        salt = os.urandom(16)
        
        master_key = generate_master_encryption_key()
        old_encrypted_master_key = encrypt_master_key(master_key, old_password, salt)
        
        # Encrypt some data
        user_data = "important data"
        encrypted_data = encrypt_data(master_key, user_data)
        
        # Password change: decrypt with old, encrypt with new
        decrypted_master_key = decrypt_master_key(old_encrypted_master_key, old_password, salt)
        new_encrypted_master_key = encrypt_master_key(decrypted_master_key, new_password, salt)
        
        # Verify data can be accessed with new password
        recovered_master_key = decrypt_master_key(new_encrypted_master_key, new_password, salt)
        decrypted_data = decrypt_data(recovered_master_key, encrypted_data)
        
        assert decrypted_data == user_data
        assert recovered_master_key == master_key
    
    @patch('app.utils.encryption.os.urandom')
    def test_mocked_randomness_for_deterministic_testing(self, mock_urandom):
        """Test with mocked randomness for deterministic results."""
        # Mock os.urandom to return predictable values
        mock_urandom.side_effect = [
            b'1234567890123456',  # For salt
            b'nonce_123456',      # For encryption nonce
        ]
        
        password = "test_password"
        plaintext = "test_data"
        
        # This should be deterministic with mocked randomness
        key = derive_key(password, b'fixed_salt_16_b')
        encrypted = encrypt_data(key, plaintext)
        decrypted = decrypt_data(key, encrypted)
        
        assert decrypted == plaintext


class TestEdgeCasesAndErrorHandling:
    """Tests for edge cases and error conditions."""
    
    def test_pbkdf2_iterations_constant(self):
        """Test that PBKDF2 iterations constant is properly set."""
        assert PBKDF2_ITERATIONS == 600000  # OWASP recommendation
    
    def test_decrypt_data_error_logging(self, capsys):
        """Test that decryption errors are logged appropriately."""
        key = os.urandom(32)
        invalid_data = base64.urlsafe_b64encode(b"invalid_ciphertext").decode()
        
        with pytest.raises(ValueError):
            decrypt_data(key, invalid_data)
        
        # Check that error was printed (in real app, this would be logged)
        captured = capsys.readouterr()
        assert "Decryption failed" in captured.out
    
    def test_all_recovery_key_characters_valid(self):
        """Test that recovery keys only use safe characters."""
        forbidden_chars = {"O", "0", "1", "I", "L"}
        allowed_chars = set(string.ascii_uppercase + string.digits) - forbidden_chars
        
        # Generate many keys to test character distribution
        for _ in range(100):
            key = generate_recovery_key()
            clean_key = key.replace("-", "")
            for char in clean_key:
                assert char in allowed_chars
                assert char not in forbidden_chars