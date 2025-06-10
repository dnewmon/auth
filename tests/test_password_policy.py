"""
Unit tests for password policy enforcement.

Tests the password policy validation and enforcement functionality.
"""

import pytest
import json
from unittest.mock import patch, Mock

from app.models import db, User, Credential
from app.utils.password_policy import PasswordPolicyValidator, validate_credential_password, get_password_policy


class TestPasswordPolicyValidator:
    """Tests for the PasswordPolicyValidator class."""
    
    def test_basic_validation_success(self):
        """Test successful password validation with default policy."""
        validator = PasswordPolicyValidator()
        password = "StrongPassword142!"
        user_info = {"username": "testuser", "email": "test@example.com"}
        
        is_valid, errors, warnings = validator.validate_password(password, user_info, "create")
        
        assert is_valid == True
        assert len(errors) == 0
    
    def test_length_validation(self):
        """Test password length validation."""
        validator = PasswordPolicyValidator()
        
        # Too short
        password_short = "Ab1!"
        is_valid, errors, warnings = validator.validate_password(password_short, {}, "create")
        assert not is_valid
        assert any("at least" in error and "characters long" in error for error in errors)
        
        # Too long (assuming max length of 128)
        password_long = "A" * 129
        is_valid, errors, warnings = validator.validate_password(password_long, {}, "create")
        assert not is_valid
        assert any("no more than" in error and "characters long" in error for error in errors)
    
    def test_character_requirements(self):
        """Test character type requirements."""
        validator = PasswordPolicyValidator()
        
        # No uppercase
        password = "lowercase123!"
        is_valid, errors, warnings = validator.validate_password(password, {}, "create")
        assert not is_valid
        assert any("uppercase" in error for error in errors)
        
        # No lowercase
        password = "UPPERCASE123!"
        is_valid, errors, warnings = validator.validate_password(password, {}, "create")
        assert not is_valid
        assert any("lowercase" in error for error in errors)
        
        # No digits
        password = "PasswordOnly!"
        is_valid, errors, warnings = validator.validate_password(password, {}, "create")
        assert not is_valid
        assert any("digit" in error for error in errors)
        
        # No symbols
        password = "Password123"
        is_valid, errors, warnings = validator.validate_password(password, {}, "create")
        assert not is_valid
        assert any("special character" in error for error in errors)
    
    def test_forbidden_passwords(self):
        """Test forbidden password list."""
        validator = PasswordPolicyValidator()
        
        # Test common password
        password = "password"
        is_valid, errors, warnings = validator.validate_password(password, {}, "create")
        assert not is_valid
        assert any("commonly used" in error for error in errors)
        
        # Test case insensitivity
        password = "PASSWORD"
        is_valid, errors, warnings = validator.validate_password(password, {}, "create")
        assert not is_valid
        assert any("commonly used" in error for error in errors)
    
    def test_common_patterns(self):
        """Test common pattern detection."""
        validator = PasswordPolicyValidator()
        
        # Sequential characters
        password = "Password123abc"
        is_valid, errors, warnings = validator.validate_password(password, {}, "create")
        assert not is_valid
        assert any("sequential" in error for error in errors)
        
        # Repeated characters
        password = "Passwordaaa123!"
        is_valid, errors, warnings = validator.validate_password(password, {}, "create")
        assert not is_valid
        assert any("repeated" in error for error in errors)
        
        # Keyboard patterns
        password = "Qwerty123!"
        is_valid, errors, warnings = validator.validate_password(password, {}, "create")
        assert not is_valid
        assert any("keyboard patterns" in error for error in errors)
    
    def test_personal_info_validation(self):
        """Test personal information validation."""
        validator = PasswordPolicyValidator()
        user_info = {
            "username": "johndoe",
            "email": "john.doe@example.com",
            "first_name": "John",
            "last_name": "Doe"
        }
        
        # Contains username
        password = "johndoe123!"
        is_valid, errors, warnings = validator.validate_password(password, user_info, "create")
        assert not is_valid
        assert any("username" in error for error in errors)
        
        # Contains email part
        password = "john.doe123!"
        is_valid, errors, warnings = validator.validate_password(password, user_info, "create")
        assert not is_valid
        assert any("email" in error for error in errors)
        
        # Contains first name
        password = "john123456!"
        is_valid, errors, warnings = validator.validate_password(password, user_info, "create")
        assert not is_valid
        assert any("first name" in error for error in errors)
    
    def test_policy_disabled(self):
        """Test behavior when policy is disabled."""
        with patch('app.utils.password_policy.get_config_value') as mock_config:
            mock_config.side_effect = lambda key, default: False if key == "PASSWORD_POLICY_ENABLED" else default
            
            validator = PasswordPolicyValidator()
            password = "weak"
            is_valid, errors, warnings = validator.validate_password(password, {}, "create")
            
            assert is_valid == True
            assert len(errors) == 0
    
    def test_warn_only_mode(self):
        """Test warn-only mode behavior."""
        with patch('app.utils.password_policy.get_config_value') as mock_config:
            def config_side_effect(key, default):
                if key == "PASSWORD_POLICY_WARN_ONLY":
                    return True
                return default
            mock_config.side_effect = config_side_effect
            
            validator = PasswordPolicyValidator()
            password = "weak"  # This should fail normal validation
            is_valid, errors, warnings = validator.validate_password(password, {}, "create")
            
            assert is_valid == True  # Should be valid in warn-only mode
            assert len(errors) == 0
            assert len(warnings) > 0  # Should have warnings
    
    def test_operation_type_enforcement(self):
        """Test that enforcement respects operation type."""
        with patch('app.utils.password_policy.get_config_value') as mock_config:
            def config_side_effect(key, default):
                if key == "PASSWORD_POLICY_ENFORCE_ON_UPDATE":
                    return False  # Disable enforcement on update
                return default
            mock_config.side_effect = config_side_effect
            
            validator = PasswordPolicyValidator()
            password = "weak"  # This would normally fail
            
            # Should fail on create
            is_valid, errors, warnings = validator.validate_password(password, {}, "create")
            assert not is_valid
            
            # Should pass on update (enforcement disabled)
            is_valid, errors, warnings = validator.validate_password(password, {}, "update")
            assert is_valid


class TestPasswordPolicyIntegration:
    """Tests for password policy integration with credential routes."""
    
    def test_create_credential_with_weak_password(self, client, app_context):
        """Test credential creation with weak password is rejected."""
        # Create user
        user = User(username="testuser", email="test@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        user.initialize_encryption("password123")
        
        with patch('flask_login.utils._get_user', return_value=user):
            response = client.post('/api/credentials/',
                                 json={
                                     'service_name': 'Test Service',
                                     'username': 'testuser',
                                     'password': 'weak',  # Violates policy
                                     'master_password': 'password123'
                                 },
                                 content_type='application/json')
        
        assert response.status_code == 400
        response_data = json.loads(response.data)
        assert 'policy violation' in response_data['message'].lower()
    
    def test_create_credential_with_strong_password(self, client, app_context):
        """Test credential creation with strong password succeeds."""
        # Create user
        user = User(username="testuser", email="test@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        user.initialize_encryption("password123")
        
        with patch('flask_login.utils._get_user', return_value=user):
            response = client.post('/api/credentials/',
                                 json={
                                     'service_name': 'Test Service',
                                     'username': 'testuser',
                                     'password': 'StrongPassword!2024',
                                     'master_password': 'password123'
                                 },
                                 content_type='application/json')
        
        assert response.status_code == 201
        response_data = json.loads(response.data)
        assert response_data['status'] == 'success'
    
    def test_update_credential_with_weak_password(self, client, app_context):
        """Test credential update with weak password is rejected."""
        # Create user
        user = User(username="testuser", email="test@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        user.initialize_encryption("password123")
        
        # Create credential
        from app.utils.encryption import encrypt_data
        master_key = user.get_master_key("password123")
        credential = Credential(
            user_id=user.id,
            service_name="Test Service",
            username="testuser",
            encrypted_password=encrypt_data(master_key, "StrongPassword123!")
        )
        db.session.add(credential)
        db.session.commit()
        
        with patch('flask_login.utils._get_user', return_value=user):
            response = client.put(f'/api/credentials/{credential.id}',
                                json={
                                    'password': 'weak',  # Violates policy
                                    'master_password': 'password123'
                                },
                                content_type='application/json')
        
        assert response.status_code == 400
        response_data = json.loads(response.data)
        assert 'policy violation' in response_data['message'].lower()
    
    def test_get_password_policy_endpoint(self, client, app_context):
        """Test getting password policy configuration."""
        user = User(username="testuser", email="test@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        with patch('flask_login.utils._get_user', return_value=user):
            response = client.get('/api/utils/password-policy',
                                content_type='application/json')
        
        assert response.status_code == 200
        response_data = json.loads(response.data)
        assert response_data['status'] == 'success'
        assert 'enabled' in response_data['data']
        assert 'min_length' in response_data['data']
    
    def test_password_policy_with_warnings(self, client, app_context):
        """Test password policy in warn-only mode."""
        # Mock warn-only mode
        with patch('app.utils.password_policy.get_config_value') as mock_config:
            def config_side_effect(key, default):
                if key == "PASSWORD_POLICY_WARN_ONLY":
                    return True
                return default
            mock_config.side_effect = config_side_effect
            
            # Create user
            user = User(username="testuser", email="test@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
            user.set_password("password123")
            db.session.add(user)
            db.session.commit()
            
            user.initialize_encryption("password123")
            
            with patch('flask_login.utils._get_user', return_value=user):
                response = client.post('/api/credentials/',
                                     json={
                                         'service_name': 'Test Service',
                                         'username': 'testuser',
                                         'password': 'weak',  # Would normally violate policy
                                         'master_password': 'password123'
                                     },
                                     content_type='application/json')
            
            assert response.status_code == 201
            response_data = json.loads(response.data)
            assert response_data['status'] == 'success'
            # Should include warnings
            assert 'password_policy_warnings' in response_data['data']
            assert len(response_data['data']['password_policy_warnings']) > 0


class TestPasswordPolicyUtilityFunctions:
    """Tests for utility functions in password policy module."""
    
    def test_validate_credential_password_function(self):
        """Test the convenience function for credential password validation."""
        password = "StrongPassword!2024"
        user_info = {"username": "testuser", "email": "test@example.com"}
        
        is_valid, errors, warnings = validate_credential_password(password, user_info, "create")
        
        assert is_valid == True
        assert len(errors) == 0
    
    def test_get_password_policy_function(self):
        """Test the get password policy function."""
        policy = get_password_policy()
        
        assert isinstance(policy, dict)
        assert 'enabled' in policy
        
        if policy['enabled']:
            assert 'min_length' in policy
            assert 'max_length' in policy
            assert 'require_uppercase' in policy