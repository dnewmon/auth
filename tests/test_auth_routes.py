"""
Unit tests for authentication routes.
"""

import pytest
import json
from unittest.mock import patch, MagicMock, Mock
from app.models.user import User
from app.models.database import db
import uuid


def make_unique_username(base="testuser"):
    """Generate a unique username for testing."""
    return f"{base}_{str(uuid.uuid4())[:8]}"


def make_unique_secret(base="secret"):
    """Generate a unique secret for testing."""
    return f"{base}_{str(uuid.uuid4())[:8]}"


class TestRegisterRoute:
    """Test cases for the /auth/register endpoint."""

    def test_register_success(self, client, app_context):
        """Test successful user registration."""
        username = make_unique_username()
        email = f'{uuid.uuid4()}@example.com'
        
        with patch.object(User, 'initialize_encryption', return_value=['KEY1-KEY1-KEY1-KEY1', 'KEY2-KEY2-KEY2-KEY2']):
            response = client.post('/api/auth/register', 
                                 json={
                                     'username': username,
                                     'email': email,
                                     'password': 'validpassword123'
                                 })
        
        assert response.status_code == 201
        data = response.get_json()
        assert data['status'] == 'success'
        assert data['data']['username'] == username
        assert data['data']['email'] == email
        assert 'recovery_keys' in data['data']
        assert 'recovery_message' in data['data']
        
        # Verify user was created in database
        user = User.query.filter_by(username=username).first()
        assert user is not None
        assert user.email == email

    def test_register_missing_json(self, client, app_context):
        """Test registration with missing JSON data."""
        response = client.post('/api/auth/register')
        
        assert response.status_code == 415
        data = response.get_json()
        assert data['status'] == 'error'
        assert 'Content-Type' in data['message'] and 'application/json' in data['message']

    def test_register_missing_fields(self, client, app_context):
        """Test registration with missing required fields."""
        # Missing username
        response = client.post('/api/auth/register',
                             json={'email': 'test@example.com', 'password': 'validpassword123'})
        assert response.status_code == 400
        
        # Missing email
        response = client.post('/api/auth/register',
                             json={'username': 'testuser', 'password': 'validpassword123'})
        assert response.status_code == 400
        
        # Missing password
        response = client.post('/api/auth/register',
                             json={'username': 'testuser', 'email': 'test@example.com'})
        assert response.status_code == 400

    def test_register_invalid_email(self, client, app_context):
        """Test registration with invalid email format."""
        response = client.post('/api/auth/register',
                             json={
                                 'username': 'testuser',
                                 'email': 'invalid-email',
                                 'password': 'validpassword123'
                             })
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'Invalid email address' in data['message']

    @patch('app.auth.routes.get_config_value')
    def test_register_short_password(self, mock_config, client, app_context):
        """Test registration with password too short."""
        mock_config.return_value = 8  # MIN_PASSWORD_LENGTH
        
        response = client.post('/api/auth/register',
                             json={
                                 'username': 'testuser',
                                 'email': 'test@example.com',
                                 'password': 'short'
                             })
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'Password must be at least 8 characters long' in data['message']

    def test_register_duplicate_username(self, client, app_context):
        """Test registration with existing username."""
        username = make_unique_username()
        email1 = f'{uuid.uuid4()}@example.com'
        email2 = f'{uuid.uuid4()}@example.com'
        
        # Create first user
        user = User(username=username, email=email1, encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password('validpassword123')
        db.session.add(user)
        db.session.commit()
        
        # Try to register with same username
        response = client.post('/api/auth/register',
                             json={
                                 'username': username,
                                 'email': email2,
                                 'password': 'validpassword123'
                             })
        
        assert response.status_code == 409
        data = response.get_json()
        assert 'Username or email already exists' in data['message']

    def test_register_duplicate_email(self, client, app_context):
        """Test registration with existing email."""
        username1 = make_unique_username()
        username2 = make_unique_username()
        email = f'{uuid.uuid4()}@example.com'
        
        # Create first user
        user = User(username=username1, email=email, encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password('validpassword123')
        db.session.add(user)
        db.session.commit()
        
        # Try to register with same email
        response = client.post('/api/auth/register',
                             json={
                                 'username': username2,
                                 'email': email,
                                 'password': 'validpassword123'
                             })
        
        assert response.status_code == 409
        data = response.get_json()
        assert 'Username or email already exists' in data['message']


class TestLoginRoute:
    """Test cases for the /auth/login endpoint."""

    def test_login_success_no_otp(self, client, app_context):
        """Test successful login without OTP."""
        username = make_unique_username()
        email = f'{uuid.uuid4()}@example.com'
        
        # Create user
        user = User(username=username, email=email, encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password('validpassword123')
        db.session.add(user)
        db.session.commit()
        
        response = client.post('/api/auth/login',
                             json={'username': username, 'password': 'validpassword123'})
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'success'
        assert data['data']['message'] == 'Login successful'

    def test_login_success_with_otp_required(self, client, app_context):
        """Test login with OTP enabled returns MFA required."""
        username = make_unique_username()
        email = f'{uuid.uuid4()}@example.com'
        
        # Create user with OTP enabled
        user = User(username=username, email=email, encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password('validpassword123')
        user.otp_enabled = True
        user.otp_secret = make_unique_secret()
        db.session.add(user)
        db.session.commit()
        
        with patch('app.auth.routes.get_config_value') as mock_config:
            mock_config.return_value = 'otp_user_id'
            
            response = client.post('/api/auth/login',
                                 json={'username': username, 'password': 'validpassword123'})
        
        assert response.status_code == 202
        data = response.get_json()
        assert data['status'] == 'success'
        assert data['data']['mfa_required'] == 'otp'

    def test_login_missing_json(self, client, app_context):
        """Test login with missing JSON data."""
        response = client.post('/api/auth/login')
        
        assert response.status_code == 415
        data = response.get_json()
        assert data['status'] == 'error'
        assert 'Content-Type' in data['message'] and 'application/json' in data['message']

    def test_login_missing_credentials(self, client, app_context):
        """Test login with missing username or password."""
        # Missing username
        response = client.post('/api/auth/login',
                             json={'password': 'validpassword123'})
        assert response.status_code == 400
        
        # Missing password
        response = client.post('/api/auth/login',
                             json={'username': 'testuser'})
        assert response.status_code == 400

    def test_login_invalid_username(self, client, app_context):
        """Test login with non-existent username."""
        response = client.post('/api/auth/login',
                             json={'username': 'nonexistent', 'password': 'validpassword123'})
        
        assert response.status_code == 401
        data = response.get_json()
        assert 'Invalid username or password' in data['message']

    def test_login_invalid_password(self, client, app_context):
        """Test login with wrong password."""
        username = make_unique_username()
        email = f'{uuid.uuid4()}@example.com'
        
        # Create user
        user = User(username=username, email=email, encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password('validpassword123')
        db.session.add(user)
        db.session.commit()
        
        response = client.post('/api/auth/login',
                             json={'username': username, 'password': 'wrongpassword'})
        
        assert response.status_code == 401
        data = response.get_json()
        assert 'Invalid username or password' in data['message']

    @patch('app.models.MfaVerificationCode.create_for_user')
    @patch('app.auth.routes.send_email')
    @patch('app.auth.routes.render_template')
    @patch('app.auth.routes.get_config_value')
    def test_login_with_email_mfa(self, mock_config, mock_render, mock_send_email, mock_create_code, client, app_context):
        """Test login with email MFA enabled."""
        username = make_unique_username()
        email = f'{uuid.uuid4()}@example.com'
        
        # Create user with email MFA enabled
        user = User(username=username, email=email, encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password('validpassword123')
        user.email_mfa_enabled = True
        db.session.add(user)
        db.session.commit()
        
        # Mock verification code creation
        mock_verification_code = Mock()
        mock_verification_code.code = '123456'
        mock_create_code.return_value = mock_verification_code
        
        mock_config.return_value = 'SESSION_KEY_EMAIL_MFA_USER_ID'
        mock_render.return_value = '<html>Verification code email</html>'
        
        response = client.post('/api/auth/login',
                             json={'username': username, 'password': 'validpassword123'})
        
        assert response.status_code == 202
        data = response.get_json()
        assert data['status'] == 'success'
        assert data['data']['mfa_required'] == 'email'
        mock_send_email.assert_called_once_with(email, "Login Verification Code", '<html>Verification code email</html>')


class TestLoginVerifyOtpRoute:
    """Test cases for the /auth/login/verify-otp endpoint."""

    @patch('pyotp.TOTP')
    @patch('app.auth.routes.get_config_value')
    def test_verify_otp_success(self, mock_config, mock_totp_class, client, app_context):
        """Test successful OTP verification."""
        username = make_unique_username()
        email = f'{uuid.uuid4()}@example.com'
        
        # Create user with OTP enabled
        user = User(username=username, email=email, encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password('validpassword123')
        user.otp_enabled = True
        user.otp_secret = make_unique_secret()
        db.session.add(user)
        db.session.commit()
        
        mock_config.return_value = 'otp_user_id'
        mock_totp = MagicMock()
        mock_totp.verify.return_value = True
        mock_totp_class.return_value = mock_totp
        
        # Simulate session with user ID from first factor
        with client.session_transaction() as sess:
            sess['otp_user_id'] = user.id
        
        response = client.post('/api/auth/login/verify-otp',
                             json={'otp_token': '123456'})
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'success'
        assert data['data']['message'] == 'Login successful'

    @patch('app.auth.routes.get_config_value')
    def test_verify_otp_no_session(self, mock_config, client, app_context):
        """Test OTP verification without session."""
        mock_config.return_value = 'otp_user_id'
        
        response = client.post('/api/auth/login/verify-otp',
                             json={'otp_token': '123456'})
        
        assert response.status_code == 401
        data = response.get_json()
        assert 'Primary authentication step not completed' in data['message']

    @patch('app.auth.routes.get_config_value')
    def test_verify_otp_missing_token(self, mock_config, client, app_context):
        """Test OTP verification with missing token."""
        mock_config.return_value = 'otp_user_id'
        
        # Set up session to simulate successful initial login
        with client.session_transaction() as sess:
            sess['otp_user_id'] = 1  # Some user ID
        
        response = client.post('/api/auth/login/verify-otp', json={})
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'Missing OTP token' in data['message']

    @patch('pyotp.TOTP')
    @patch('app.auth.routes.get_config_value')
    def test_verify_otp_invalid_token(self, mock_config, mock_totp_class, client, app_context):
        """Test OTP verification with invalid token."""
        username = make_unique_username()
        email = f'{uuid.uuid4()}@example.com'
        
        # Create user with OTP enabled
        user = User(username=username, email=email, encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password('validpassword123')
        user.otp_enabled = True
        user.otp_secret = make_unique_secret()
        db.session.add(user)
        db.session.commit()
        
        mock_config.return_value = 'otp_user_id'
        mock_totp = MagicMock()
        mock_totp.verify.return_value = False
        mock_totp_class.return_value = mock_totp
        
        # Simulate session with user ID from first factor
        with client.session_transaction() as sess:
            sess['otp_user_id'] = user.id
        
        response = client.post('/api/auth/login/verify-otp',
                             json={'otp_token': '123456'})
        
        assert response.status_code == 401
        data = response.get_json()
        assert 'Invalid OTP token' in data['message']


class TestLogoutRoute:
    """Test cases for the /auth/logout endpoint."""

    def test_logout_success(self, client, app_context):
        """Test successful logout."""
        username = make_unique_username()
        email = f'{uuid.uuid4()}@example.com'
        
        # Create and login user
        user = User(username=username, email=email, encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password('validpassword123')
        db.session.add(user)
        db.session.commit()
        
        # Login first
        client.post('/api/auth/login',
                   json={'username': username, 'password': 'validpassword123'})
        
        # Now logout
        response = client.post('/api/auth/logout')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'success'
        assert data['data']['message'] == 'Successfully logged out'

    def test_logout_not_authenticated(self, client, app_context):
        """Test logout when not authenticated."""
        response = client.post('/api/auth/logout')
        
        # Should redirect to login or return 401
        assert response.status_code in [302, 401]


class TestGetCurrentUserRoute:
    """Test cases for the /auth/me endpoint."""

    def test_get_current_user_success(self, client, app_context):
        """Test getting current user info when authenticated."""
        username = make_unique_username()
        email = f'{uuid.uuid4()}@example.com'
        
        # Create and login user
        user = User(username=username, email=email, encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password('validpassword123')
        db.session.add(user)
        db.session.commit()
        
        # Login first
        client.post('/api/auth/login',
                   json={'username': username, 'password': 'validpassword123'})
        
        # Get current user
        response = client.get('/api/auth/me')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'success'
        assert data['data']['username'] == username

    def test_get_current_user_not_authenticated(self, client, app_context):
        """Test getting current user when not authenticated."""
        response = client.get('/api/auth/me')
        
        # Should redirect to login or return 401
        assert response.status_code in [302, 401]


class TestRecoveryKeyRoutes:
    """Test cases for recovery key management endpoints."""

    def test_get_recovery_key_status_success(self, client, app_context):
        """Test getting recovery key status."""
        username = make_unique_username()
        email = f'{uuid.uuid4()}@example.com'
        
        # Create and login user
        user = User(username=username, email=email, encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password('validpassword123')
        db.session.add(user)
        db.session.commit()
        
        # Login first
        client.post('/api/auth/login',
                   json={'username': username, 'password': 'validpassword123'})
        
        response = client.get('/api/auth/recovery-keys')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'success'
        assert 'total_keys' in data['data']
        assert 'unused_keys' in data['data']
        assert 'has_keys' in data['data']

    def test_get_recovery_key_status_not_authenticated(self, client, app_context):
        """Test getting recovery key status when not authenticated."""
        response = client.get('/api/auth/recovery-keys')
        
        # Should redirect to login or return 401
        assert response.status_code in [302, 401]

    @patch.object(User, 'regenerate_recovery_keys')
    def test_regenerate_recovery_keys_success(self, mock_regenerate, client, app_context):
        """Test successful recovery key regeneration."""
        username = make_unique_username()
        email = f'{uuid.uuid4()}@example.com'
        
        # Create and login user
        user = User(username=username, email=email, encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password('validpassword123')
        db.session.add(user)
        db.session.commit()
        
        # Login first
        client.post('/api/auth/login',
                   json={'username': username, 'password': 'validpassword123'})
        
        mock_regenerate.return_value = ['NEW1-NEW1-NEW1-NEW1', 'NEW2-NEW2-NEW2-NEW2']
        
        response = client.post('/api/auth/recovery-keys',
                             json={'password': 'validpassword123'})
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'success'
        assert 'recovery_keys' in data['data']
        assert 'recovery_message' in data['data']

    def test_regenerate_recovery_keys_missing_password(self, client, app_context):
        """Test recovery key regeneration with missing password."""
        username = make_unique_username()
        email = f'{uuid.uuid4()}@example.com'
        
        # Create and login user
        user = User(username=username, email=email, encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password('validpassword123')
        db.session.add(user)
        db.session.commit()
        
        # Login first
        client.post('/api/auth/login',
                   json={'username': username, 'password': 'validpassword123'})
        
        response = client.post('/api/auth/recovery-keys', json={})
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'Current password is required' in data['message']

    @patch.object(User, 'regenerate_recovery_keys')
    def test_regenerate_recovery_keys_invalid_password(self, mock_regenerate, client, app_context):
        """Test recovery key regeneration with invalid password."""
        username = make_unique_username()
        email = f'{uuid.uuid4()}@example.com'
        
        # Create and login user
        user = User(username=username, email=email, encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password('validpassword123')
        db.session.add(user)
        db.session.commit()
        
        # Login first
        client.post('/api/auth/login',
                   json={'username': username, 'password': 'validpassword123'})
        
        mock_regenerate.side_effect = ValueError("Invalid password")
        
        response = client.post('/api/auth/recovery-keys',
                             json={'password': 'wrongpassword'})
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'Invalid password' in data['message']

    def test_regenerate_recovery_keys_not_authenticated(self, client, app_context):
        """Test recovery key regeneration when not authenticated."""
        response = client.post('/api/auth/recovery-keys',
                             json={'password': 'validpassword123'})
        
        # Should redirect to login or return 401
        assert response.status_code in [302, 401]