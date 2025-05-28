"""
Unit tests for User and RecoveryKey models.
"""

import pytest
import datetime
from datetime import timezone
from unittest.mock import patch, MagicMock
from app.models.user import User, RecoveryKey, _password_hasher
from app.models.database import db
from argon2.exceptions import VerifyMismatchError
import uuid


def make_unique_username(base="testuser"):
    """Generate a unique username for testing."""
    return f"{base}_{str(uuid.uuid4())[:8]}"


class TestRecoveryKey:
    """Test cases for the RecoveryKey model."""

    def test_mark_as_used(self, app_context):
        """Test marking a recovery key as used."""
        # Create a recovery key
        recovery_key = RecoveryKey(
            user_id=1,
            key_hash='test_hash',
            salt=b'test_salt_32_chars_long_enough!!',
            encrypted_master_key='encrypted_key'
        )
        
        # Initially used_at should be None
        assert recovery_key.used_at is None
        
        # Mark as used
        recovery_key.mark_as_used()
        
        # Check that used_at is set to current time
        assert recovery_key.used_at is not None
        assert isinstance(recovery_key.used_at, datetime.datetime)
        assert recovery_key.used_at.tzinfo is timezone.utc
        
        # Check that the timestamp is recent (within last 5 seconds)
        now = datetime.datetime.now(timezone.utc)
        time_diff = (now - recovery_key.used_at).total_seconds()
        assert time_diff < 5

    def test_recovery_key_creation(self, app_context):
        """Test RecoveryKey model creation and attributes."""
        user = User(
            username=make_unique_username(),
            email=f'{uuid.uuid4()}@example.com',
            password_hash='hashed_password',
            encryption_salt=b'test_salt_32_chars_long_enough!!'
        )
        db.session.add(user)
        db.session.commit()
        
        recovery_key = RecoveryKey(
            user_id=user.id,
            key_hash='test_hash_123',
            salt=b'recovery_salt',
            encrypted_master_key='encrypted_master_key_data'
        )
        db.session.add(recovery_key)
        db.session.commit()
        
        # Verify attributes
        assert recovery_key.user_id == user.id
        assert recovery_key.key_hash == 'test_hash_123'
        assert recovery_key.salt == b'recovery_salt'
        assert recovery_key.encrypted_master_key == 'encrypted_master_key_data'
        assert recovery_key.created_at is not None
        assert recovery_key.used_at is None
        
        # Verify relationship
        assert recovery_key.user == user
        assert recovery_key in user.recovery_keys


class TestUser:
    """Test cases for the User model."""

    def test_user_creation(self, app_context):
        """Test User model creation and basic attributes."""
        username = make_unique_username()
        email = f'{uuid.uuid4()}@example.com'
        user = User(
            username=username,
            email=email,
            password_hash='hashed_password',
            encryption_salt=b'test_salt_32_chars_long_enough!!'
        )
        db.session.add(user)
        db.session.commit()
        
        assert user.id is not None
        assert user.username == username
        assert user.email == email
        assert user.password_hash == 'hashed_password'
        assert user.encryption_salt == b'test_salt_32_chars_long_enough!!'
        assert user.session_version == 1
        assert user.otp_enabled is False
        assert user.email_mfa_enabled is False
        assert user.created_at is not None
        assert user.updated_at is not None

    def test_set_password(self, app_context):
        """Test password setting and hashing."""
        user = User(
            username=make_unique_username(),
            email=f'{uuid.uuid4()}@example.com',
            encryption_salt=b'test_salt_32_chars_long_enough!!'
        )
        
        original_session_version = user.session_version or 1
        user.set_password('validpassword123')
        
        # Check that password is hashed
        assert user.password_hash is not None
        assert user.password_hash != 'validpassword123'
        assert user.password_hash.startswith('$argon2')
        
        # Check that session version is incremented
        assert user.session_version == original_session_version + 1

    def test_check_password_valid(self, app_context):
        """Test password verification with valid password."""
        user = User(
            username=make_unique_username(),
            email=f'{uuid.uuid4()}@example.com',
            encryption_salt=b'test_salt_32_chars_long_enough!!'
        )
        user.set_password('validpassword123')
        
        assert user.check_password('validpassword123') is True

    def test_check_password_invalid(self, app_context):
        """Test password verification with invalid password."""
        user = User(
            username=make_unique_username(),
            email=f'{uuid.uuid4()}@example.com',
            encryption_salt=b'test_salt_32_chars_long_enough!!'
        )
        user.set_password('validpassword123')
        
        assert user.check_password('wrongpassword') is False

    def test_check_password_with_rehash(self, app_context):
        """Test password verification that triggers rehashing."""
        user = User(
            username=make_unique_username(),
            email=f'{uuid.uuid4()}@example.com',
            encryption_salt=b'test_salt_32_chars_long_enough!!'
        )
        user.set_password('validpassword123')
        old_hash = user.password_hash
        
        # Mock check_needs_rehash to return True by patching the entire hasher
        mock_hasher = MagicMock()
        mock_hasher.verify.return_value = None  # No exception means success
        mock_hasher.check_needs_rehash.return_value = True
        mock_hasher.hash.return_value = 'new_hash_value'
        
        with patch('app.models.user._password_hasher', mock_hasher):
            result = user.check_password('validpassword123')
            
        assert result is True
        # Password hash should be updated
        assert user.password_hash == 'new_hash_value'

    def test_increment_session_version(self, app_context):
        """Test session version increment."""
        user = User(
            username=make_unique_username(),
            email=f'{uuid.uuid4()}@example.com',
            encryption_salt=b'test_salt_32_chars_long_enough!!'
        )
        
        # Test with default session version
        original_version = user.session_version or 1
        user.increment_session_version()
        assert user.session_version == original_version + 1
        
        # Test with None session version
        user.session_version = None
        user.increment_session_version()
        assert user.session_version == 2

    def test_update_last_login(self, app_context):
        """Test updating last login timestamp."""
        user = User(
            username=make_unique_username(),
            email=f'{uuid.uuid4()}@example.com',
            password_hash='hashed_password',
            encryption_salt=b'test_salt_32_chars_long_enough!!'
        )
        db.session.add(user)
        db.session.commit()
        
        # Initially last_login should be None
        assert user.last_login is None
        
        user.update_last_login()
        
        # Check that last_login is set
        assert user.last_login is not None
        assert isinstance(user.last_login, datetime.datetime)
        
        # Check that the timestamp is recent (SQLite strips timezone info)
        now = datetime.datetime.now()
        time_diff = (now - user.last_login).total_seconds()
        assert time_diff < 5

    def test_user_repr(self, app_context):
        """Test string representation of User."""
        username = make_unique_username()
        user = User(
            username=username,
            email=f'{uuid.uuid4()}@example.com',
            encryption_salt=b'test_salt_32_chars_long_enough!!'
        )
        
        assert repr(user) == f'<User {username}>'

    @patch('app.utils.encryption.generate_master_encryption_key')
    @patch('app.utils.encryption.encrypt_master_key')
    @patch('app.utils.encryption.generate_recovery_keys')
    @patch('app.utils.encryption.encrypt_master_key_with_recovery_key')
    def test_initialize_encryption(self, mock_encrypt_with_recovery, mock_generate_keys, 
                                 mock_encrypt_master, mock_generate_master, app_context):
        """Test encryption initialization."""
        user = User(
            username=make_unique_username(),
            email=f'{uuid.uuid4()}@example.com',
            password_hash='hashed_password',
            encryption_salt=b'test_salt_32_chars_long_enough!!'
        )
        db.session.add(user)
        db.session.commit()
        
        # Mock return values
        mock_master_key = b'master_key_bytes'
        mock_generate_master.return_value = mock_master_key
        mock_encrypt_master.return_value = 'encrypted_master_key'
        mock_recovery_keys = ['KEY1-KEY1-KEY1-KEY1', 'KEY2-KEY2-KEY2-KEY2']
        mock_generate_keys.return_value = mock_recovery_keys
        mock_encrypt_with_recovery.side_effect = [
            (b'salt1', 'encrypted1', 'hash1'),
            (b'salt2', 'encrypted2', 'hash2')
        ]
        
        result = user.initialize_encryption('password123')
        
        # Verify method calls
        mock_generate_master.assert_called_once()
        mock_encrypt_master.assert_called_once_with(mock_master_key, 'password123', user.encryption_salt)
        mock_generate_keys.assert_called_once_with(5)
        assert mock_encrypt_with_recovery.call_count == 2
        
        # Verify user state
        assert user.encrypted_master_key == 'encrypted_master_key'
        assert result == mock_recovery_keys
        
        # Verify recovery keys were created
        recovery_keys_in_db = RecoveryKey.query.filter_by(user_id=user.id).all()
        assert len(recovery_keys_in_db) == 2

    @patch('app.utils.encryption.generate_master_encryption_key')
    @patch('app.utils.encryption.encrypt_master_key')
    @patch('app.utils.encryption.generate_recovery_keys')
    @patch('app.utils.encryption.encrypt_master_key_with_recovery_key')
    def test_initialize_encryption_with_provided_master_key(self, mock_encrypt_with_recovery, 
                                                          mock_generate_keys, mock_encrypt_master, 
                                                          mock_generate_master, app_context):
        """Test encryption initialization with provided master key."""
        user = User(
            username=make_unique_username(),
            email=f'{uuid.uuid4()}@example.com',
            password_hash='hashed_password',
            encryption_salt=b'test_salt_32_chars_long_enough!!'
        )
        db.session.add(user)
        db.session.commit()
        
        provided_master_key = b'provided_master_key'
        mock_encrypt_master.return_value = 'encrypted_master_key'
        mock_generate_keys.return_value = ['KEY1-KEY1-KEY1-KEY1']
        mock_encrypt_with_recovery.return_value = (b'salt1', 'encrypted1', 'hash1')
        
        user.initialize_encryption('password123', provided_master_key)
        
        # Should not generate master key when one is provided
        mock_generate_master.assert_not_called()
        mock_encrypt_master.assert_called_once_with(provided_master_key, 'password123', user.encryption_salt)

    @patch('app.utils.encryption.decrypt_master_key')
    def test_get_master_key_success(self, mock_decrypt, app_context):
        """Test successful master key retrieval."""
        user = User(
            username=make_unique_username(),
            email=f'{uuid.uuid4()}@example.com',
            encryption_salt=b'test_salt_32_chars_long_enough!!'
        )
        user.set_password('password123')
        user.encrypted_master_key = 'encrypted_master_key'
        
        mock_decrypt.return_value = b'decrypted_master_key'
        
        result = user.get_master_key('password123')
        
        assert result == b'decrypted_master_key'
        mock_decrypt.assert_called_once_with('encrypted_master_key', 'password123', user.encryption_salt)

    def test_get_master_key_invalid_password(self, app_context):
        """Test master key retrieval with invalid password."""
        user = User(
            username=make_unique_username(),
            email=f'{uuid.uuid4()}@example.com',
            encryption_salt=b'test_salt_32_chars_long_enough!!'
        )
        user.set_password('password123')
        user.encrypted_master_key = 'encrypted_master_key'
        
        with pytest.raises(ValueError, match="Invalid password"):
            user.get_master_key('wrongpassword')

    def test_get_master_key_no_encryption_initialized(self, app_context):
        """Test master key retrieval when encryption not initialized."""
        user = User(
            username=make_unique_username(),
            email=f'{uuid.uuid4()}@example.com',
            encryption_salt=b'test_salt_32_chars_long_enough!!'
        )
        user.set_password('password123')
        # No encrypted_master_key set
        
        with pytest.raises(ValueError, match="Encryption has not been initialized"):
            user.get_master_key('password123')

    @patch('app.utils.encryption.hash_recovery_key')
    def test_find_recovery_key_entry_success(self, mock_hash, app_context):
        """Test finding recovery key entry successfully."""
        user = User(
            username=make_unique_username(),
            email=f'{uuid.uuid4()}@example.com',
            password_hash='hashed_password',
            encryption_salt=b'test_salt_32_chars_long_enough!!'
        )
        db.session.add(user)
        db.session.commit()
        
        # Create recovery key
        recovery_key = RecoveryKey(
            user_id=user.id,
            key_hash='test_hash',
            salt=b'test_salt_32_chars_long_enough!!',
            encrypted_master_key='encrypted_key'
        )
        db.session.add(recovery_key)
        db.session.commit()
        
        mock_hash.return_value = 'test_hash'
        
        result = user.find_recovery_key_entry('ABCD-EFGH-IJKL-MNOP')
        
        assert result == recovery_key
        mock_hash.assert_called_once_with('ABCD-EFGH-IJKL-MNOP')

    @patch('app.utils.encryption.hash_recovery_key')
    def test_find_recovery_key_entry_not_found(self, mock_hash, app_context):
        """Test finding recovery key entry when not found."""
        user = User(
            username=make_unique_username(),
            email=f'{uuid.uuid4()}@example.com',
            password_hash='hashed_password',
            encryption_salt=b'test_salt_32_chars_long_enough!!'
        )
        db.session.add(user)
        db.session.commit()
        
        mock_hash.return_value = 'nonexistent_hash'
        
        result = user.find_recovery_key_entry('ABCD-EFGH-IJKL-MNOP')
        
        assert result is None

    @patch('app.utils.encryption.decrypt_master_key_with_recovery_key')
    @patch('app.utils.encryption.encrypt_master_key')
    def test_recover_with_recovery_key_success(self, mock_encrypt, mock_decrypt, app_context):
        """Test successful account recovery with recovery key."""
        user = User(
            username=make_unique_username(),
            email=f'{uuid.uuid4()}@example.com',
            password_hash='hashed_password',
            encryption_salt=b'test_salt_32_chars_long_enough!!'
        )
        db.session.add(user)
        db.session.commit()
        
        # Create recovery key
        recovery_key = RecoveryKey(
            user_id=user.id,
            key_hash='test_hash',
            salt=b'test_salt_32_chars_long_enough!!',
            encrypted_master_key='encrypted_key'
        )
        db.session.add(recovery_key)
        db.session.commit()
        
        # Mock methods
        with patch.object(user, 'find_recovery_key_entry', return_value=recovery_key):
            mock_decrypt.return_value = b'decrypted_master_key'
            mock_encrypt.return_value = 'new_encrypted_master_key'
            
            result = user.recover_with_recovery_key('ABCD-EFGH-IJKL-MNOP', 'validnewpassword123')
            
            assert result is True
            assert user.encrypted_master_key == 'new_encrypted_master_key'
            assert recovery_key.used_at is not None
            mock_decrypt.assert_called_once_with('encrypted_key', 'ABCD-EFGH-IJKL-MNOP', b'test_salt_32_chars_long_enough!!')
            mock_encrypt.assert_called_once_with(b'decrypted_master_key', 'validnewpassword123', user.encryption_salt)

    def test_recover_with_recovery_key_invalid_key(self, app_context):
        """Test account recovery with invalid recovery key."""
        user = User(
            username=make_unique_username(),
            email=f'{uuid.uuid4()}@example.com',
            password_hash='hashed_password',
            encryption_salt=b'test_salt_32_chars_long_enough!!'
        )
        db.session.add(user)
        db.session.commit()
        
        with patch.object(user, 'find_recovery_key_entry', return_value=None):
            with pytest.raises(ValueError, match="Invalid recovery key"):
                user.recover_with_recovery_key('INVALID-KEY', 'validnewpassword123')

    @patch('app.utils.encryption.decrypt_master_key_with_recovery_key')
    def test_recover_with_recovery_key_decrypt_error(self, mock_decrypt, app_context):
        """Test account recovery when decryption fails."""
        user = User(
            username=make_unique_username(),
            email=f'{uuid.uuid4()}@example.com',
            password_hash='hashed_password',
            encryption_salt=b'test_salt_32_chars_long_enough!!'
        )
        db.session.add(user)
        db.session.commit()
        
        recovery_key = RecoveryKey(
            user_id=user.id,
            key_hash='test_hash',
            salt=b'test_salt_32_chars_long_enough!!',
            encrypted_master_key='encrypted_key'
        )
        db.session.add(recovery_key)
        db.session.commit()
        
        with patch.object(user, 'find_recovery_key_entry', return_value=recovery_key):
            mock_decrypt.side_effect = Exception("Decryption failed")
            
            with pytest.raises(ValueError, match="Recovery failed: Decryption failed"):
                user.recover_with_recovery_key('ABCD-EFGH-IJKL-MNOP', 'validnewpassword123')

    @patch('app.utils.encryption.generate_recovery_keys')
    @patch('app.utils.encryption.encrypt_master_key_with_recovery_key')
    def test_regenerate_recovery_keys_success(self, mock_encrypt_with_recovery, 
                                            mock_generate_keys, app_context):
        """Test successful recovery key regeneration."""
        user = User(
            username=make_unique_username(),
            email=f'{uuid.uuid4()}@example.com',
            encryption_salt=b'test_salt_32_chars_long_enough!!'
        )
        user.set_password('password123')
        user.encrypted_master_key = 'encrypted_master_key'
        db.session.add(user)
        db.session.commit()
        
        # Create existing recovery keys
        old_key1 = RecoveryKey(user_id=user.id, key_hash='old1', salt=b'salt1111111111111111111111111111', encrypted_master_key='enc1')
        old_key2 = RecoveryKey(user_id=user.id, key_hash='old2', salt=b'salt2222222222222222222222222222', encrypted_master_key='enc2')
        db.session.add_all([old_key1, old_key2])
        db.session.commit()
        
        # Mock methods
        mock_master_key = b'master_key_bytes'
        mock_new_keys = ['NEW1-NEW1-NEW1-NEW1', 'NEW2-NEW2-NEW2-NEW2', 'NEW3-NEW3-NEW3-NEW3', 'NEW4-NEW4-NEW4-NEW4', 'NEW5-NEW5-NEW5-NEW5']
        mock_generate_keys.return_value = mock_new_keys
        mock_encrypt_with_recovery.side_effect = [
            (b'new_salt1', 'new_enc1', 'new_hash1'),
            (b'new_salt2', 'new_enc2', 'new_hash2'),
            (b'new_salt3', 'new_enc3', 'new_hash3'),
            (b'new_salt4', 'new_enc4', 'new_hash4'),
            (b'new_salt5', 'new_enc5', 'new_hash5')
        ]
        
        with patch.object(user, 'get_master_key', return_value=mock_master_key):
            result = user.regenerate_recovery_keys('password123')
            
            assert result == mock_new_keys
            
            # Verify old keys are deleted and new keys created
            db.session.commit()
            new_keys = RecoveryKey.query.filter_by(user_id=user.id).all()
            assert len(new_keys) == 5
            # Verify new keys have new hashes
            expected_hashes = ['new_hash1', 'new_hash2', 'new_hash3', 'new_hash4', 'new_hash5']
            assert all(key.key_hash in expected_hashes for key in new_keys)

    def test_regenerate_recovery_keys_invalid_password(self, app_context):
        """Test recovery key regeneration with invalid password."""
        user = User(
            username=make_unique_username(),
            email=f'{uuid.uuid4()}@example.com',
            encryption_salt=b'test_salt_32_chars_long_enough!!'
        )
        user.set_password('password123')
        user.encrypted_master_key = 'encrypted_master_key'
        
        with patch.object(user, 'get_master_key', side_effect=ValueError("Invalid password")):
            with pytest.raises(ValueError, match="Cannot regenerate recovery keys: Invalid password"):
                user.regenerate_recovery_keys('wrongpassword')