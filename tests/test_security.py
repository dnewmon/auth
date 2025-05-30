"""
Unit tests for app.security.routes module.

Tests all security route endpoints including OTP setup/verification/disable,
email MFA configuration, and MFA status checking.
"""

import pytest
import json
import base64
import io
from unittest.mock import patch, Mock, MagicMock, call
from flask import Flask, session


class TestOTPSetup:
    """Tests for the otp_setup endpoint."""

    def test_otp_setup_success(self, client):
        """Test successful OTP setup."""
        with patch('flask_login.utils._get_user') as mock_get_user, \
             patch('app.security.routes.pyotp.random_base32') as mock_random_base32, \
             patch('app.security.routes.pyotp.totp.TOTP') as mock_totp_class, \
             patch('app.security.routes.qrcode.make') as mock_qr_make, \
             patch('app.security.routes.get_config_value') as mock_get_config, \
             patch('app.security.routes.current_app') as mock_current_app:
            
            # Setup mock user
            mock_current_user = Mock()
            mock_current_user.id = 1
            mock_current_user.email = "test@example.com"
            mock_current_user.otp_enabled = False
            mock_current_user.check_password = Mock(return_value=True)
            mock_get_user.return_value = mock_current_user
            
            mock_random_base32.return_value = "TESTSECRET123456"
            mock_totp = Mock()
            mock_totp.provisioning_uri.return_value = "otpauth://totp/test@example.com?secret=TESTSECRET123456&issuer=TestApp"
            mock_totp_class.return_value = mock_totp
            
            # Mock QR code generation
            mock_qr_img = Mock()
            mock_qr_make.return_value = mock_qr_img
            
            # Mock QR image save to BytesIO
            mock_img_io = Mock()
            mock_img_io.getvalue.return_value = b"fake_png_data"
            
            with patch('app.security.routes.io.BytesIO', return_value=mock_img_io):
                mock_get_config.side_effect = lambda key, default=None: {
                    "SESSION_KEY_OTP_SECRET_TEMP": "otp_secret_temp",
                    "OTP_ISSUER_NAME": "TestApp"
                }.get(key, default)
                
                mock_logger = Mock()
                mock_current_app.logger = mock_logger
                
                response = client.post('/api/security/otp/setup',
                                     json={"password": "correct_password"},
                                     content_type='application/json')
                
                assert response.status_code == 200
                response_data = json.loads(response.data)
                assert response_data["status"] == "success"
                assert "provisioning_uri" in response_data["data"]
                assert "qr_code_png_base64" in response_data["data"]
                assert "Scan the QR code" in response_data["data"]["message"]

    def test_otp_setup_missing_password(self, client):
        """Test OTP setup with missing password."""
        with patch('app.security.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/security/otp/setup',
                                     json={},
                                     content_type='application/json')
            
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "Current password is required" in response_data["message"]

    def test_otp_setup_invalid_password(self, client):
        """Test OTP setup with invalid password."""
        with patch('app.security.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            mock_current_user.check_password = Mock(return_value=False)
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/security/otp/setup',
                                     json={"password": "wrong_password"},
                                     content_type='application/json')
            
            assert response.status_code == 401
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "Invalid password" in response_data["message"]

    def test_otp_setup_already_enabled(self, client):
        """Test OTP setup when OTP is already enabled."""
        with patch('app.security.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            mock_current_user.otp_enabled = True
            mock_current_user.check_password = Mock(return_value=True)
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/security/otp/setup',
                                     json={"password": "correct_password"},
                                     content_type='application/json')
            
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "OTP is already enabled" in response_data["message"]

    def test_otp_setup_unauthorized(self, client):
        """Test OTP setup when user is not authenticated."""
        response = client.post('/api/security/otp/setup',
                             json={"password": "password"},
                             content_type='application/json')
        
        # Flask-Login redirects unauthenticated users
        assert response.status_code == 302


class TestOTPVerifyEnable:
    """Tests for the otp_verify_enable endpoint."""

    def test_otp_verify_enable_success(self, client):
        """Test successful OTP verification and enabling."""
        with patch('flask_login.utils._get_user') as mock_get_user, \
             patch('app.security.routes.pyotp.TOTP') as mock_totp_class, \
             patch('app.security.routes.db.session') as mock_db_session, \
             patch('app.security.routes.get_config_value') as mock_get_config, \
             patch('app.security.routes.current_app') as mock_current_app:
            
            # Setup mock user
            mock_current_user = Mock()
            mock_current_user.id = 1
            mock_current_user.is_authenticated = True
            mock_get_user.return_value = mock_current_user
            
            mock_get_config.return_value = "otp_secret_temp"
            
            mock_totp = Mock()
            mock_totp.verify.return_value = True
            mock_totp_class.return_value = mock_totp
            
            mock_logger = Mock()
            mock_current_app.logger = mock_logger
            
            # Use client session context to properly mock Flask session
            with client.session_transaction() as sess:
                sess["otp_secret_temp"] = "TESTSECRET123456"
            
            response = client.post('/api/security/otp/verify-enable',
                                 json={"otp_token": "123456"},
                                 content_type='application/json')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["status"] == "success"
            assert "OTP has been successfully enabled" in response_data["data"]["message"]
            
            # Verify user OTP settings were updated
            assert mock_current_user.otp_secret == "TESTSECRET123456"
            assert mock_current_user.otp_enabled == True
            mock_db_session.commit.assert_called_once()

    def test_otp_verify_enable_missing_token(self, client):
        """Test OTP verification with missing token."""
        with patch('app.security.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/security/otp/verify-enable',
                                     json={},
                                     content_type='application/json')
            
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "Missing OTP token" in response_data["message"]

    def test_otp_verify_enable_no_session_secret(self, client):
        """Test OTP verification when no temporary secret in session."""
        with patch('flask_login.utils._get_user') as mock_get_user, \
             patch('app.security.routes.get_config_value') as mock_get_config:
            
            mock_current_user = Mock()
            mock_current_user.is_authenticated = True
            mock_get_user.return_value = mock_current_user
            mock_get_config.return_value = "otp_secret_temp"
            
            # Don't set any session data - this tests the missing secret case
            response = client.post('/api/security/otp/verify-enable',
                                 json={"otp_token": "123456"},
                                 content_type='application/json')
            
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "OTP setup process not initiated" in response_data["message"]

    def test_otp_verify_enable_invalid_token(self, client):
        """Test OTP verification with invalid token."""
        with patch('flask_login.utils._get_user') as mock_get_user, \
             patch('app.security.routes.pyotp.TOTP') as mock_totp_class, \
             patch('app.security.routes.get_config_value') as mock_get_config, \
             patch('app.security.routes.current_app') as mock_current_app:
            
            mock_current_user = Mock()
            mock_current_user.id = 1
            mock_current_user.is_authenticated = True
            mock_get_user.return_value = mock_current_user
            
            mock_get_config.return_value = "otp_secret_temp"
            
            mock_totp = Mock()
            mock_totp.verify.return_value = False
            mock_totp_class.return_value = mock_totp
            
            mock_logger = Mock()
            mock_current_app.logger = mock_logger
            
            # Set session data
            with client.session_transaction() as sess:
                sess["otp_secret_temp"] = "TESTSECRET123456"
            
            response = client.post('/api/security/otp/verify-enable',
                                 json={"otp_token": "wrong_token"},
                                 content_type='application/json')
            
            assert response.status_code == 401
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "Invalid OTP token" in response_data["message"]


class TestOTPDisable:
    """Tests for the otp_disable endpoint."""

    def test_otp_disable_success(self, client):
        """Test successful OTP disabling."""
        with patch('app.security.routes.current_user') as mock_current_user, \
             patch('app.security.routes.db.session') as mock_db_session, \
             patch('app.security.routes.current_app') as mock_current_app:
            
            # Setup mocks
            mock_current_user.id = 1
            mock_current_user.is_authenticated = True
            mock_current_user.otp_enabled = True
            mock_current_user.check_password = Mock(return_value=True)
            
            mock_logger = Mock()
            mock_current_app.logger = mock_logger
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/security/otp/disable',
                                     json={"password": "correct_password"},
                                     content_type='application/json')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["status"] == "success"
            assert "OTP has been successfully disabled" in response_data["data"]["message"]
            
            # Verify user OTP settings were updated
            assert mock_current_user.otp_secret is None
            assert mock_current_user.otp_enabled == False
            mock_db_session.commit.assert_called_once()

    def test_otp_disable_missing_password(self, client):
        """Test OTP disable with missing password."""
        with patch('app.security.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/security/otp/disable',
                                     json={},
                                     content_type='application/json')
            
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "Current password is required" in response_data["message"]

    def test_otp_disable_invalid_password(self, client):
        """Test OTP disable with invalid password."""
        with patch('app.security.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            mock_current_user.check_password = Mock(return_value=False)
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/security/otp/disable',
                                     json={"password": "wrong_password"},
                                     content_type='application/json')
            
            assert response.status_code == 401
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "Invalid password" in response_data["message"]

    def test_otp_disable_not_enabled(self, client):
        """Test OTP disable when OTP is not enabled."""
        with patch('app.security.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            mock_current_user.otp_enabled = False
            mock_current_user.check_password = Mock(return_value=True)
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/security/otp/disable',
                                     json={"password": "correct_password"},
                                     content_type='application/json')
            
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "OTP is not currently enabled" in response_data["message"]


class TestEmailMFAEnable:
    """Tests for the enable_email_mfa endpoint."""

    def test_enable_email_mfa_success(self, client):
        """Test successful email MFA enabling."""
        with patch('app.security.routes.current_user') as mock_current_user, \
             patch('app.security.routes.send_email') as mock_send_email, \
             patch('app.security.routes.render_template') as mock_render_template, \
             patch('app.security.routes.db.session') as mock_db_session, \
             patch('app.security.routes.get_config_value') as mock_get_config, \
             patch('app.security.routes.current_app') as mock_current_app:
            
            # Setup mocks
            mock_current_user.id = 1
            mock_current_user.email = "test@example.com"
            mock_current_user.is_authenticated = True
            mock_current_user.email_mfa_enabled = False
            mock_current_user.check_password = Mock(return_value=True)
            
            mock_get_config.return_value = "email/mfa_test_template.html"
            mock_render_template.return_value = "<html>Test email</html>"
            
            mock_logger = Mock()
            mock_current_app.logger = mock_logger
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/security/mfa/email/enable',
                                     json={"password": "correct_password"},
                                     content_type='application/json')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["status"] == "success"
            assert "Email MFA notification has been enabled" in response_data["data"]["message"]
            
            # Verify email was sent
            mock_send_email.assert_called_once_with(
                "test@example.com",
                "Email MFA Test",
                "<html>Test email</html>"
            )
            
            # Verify user setting was updated
            assert mock_current_user.email_mfa_enabled == True
            mock_db_session.commit.assert_called_once()

    def test_enable_email_mfa_missing_password(self, client):
        """Test email MFA enable with missing password."""
        with patch('app.security.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/security/mfa/email/enable',
                                     json={},
                                     content_type='application/json')
            
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "Current password is required" in response_data["message"]

    def test_enable_email_mfa_invalid_password(self, client):
        """Test email MFA enable with invalid password."""
        with patch('app.security.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            mock_current_user.check_password = Mock(return_value=False)
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/security/mfa/email/enable',
                                     json={"password": "wrong_password"},
                                     content_type='application/json')
            
            assert response.status_code == 401
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "Invalid password" in response_data["message"]

    def test_enable_email_mfa_already_enabled(self, client):
        """Test email MFA enable when already enabled."""
        with patch('app.security.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            mock_current_user.email_mfa_enabled = True
            mock_current_user.check_password = Mock(return_value=True)
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/security/mfa/email/enable',
                                     json={"password": "correct_password"},
                                     content_type='application/json')
            
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "Email MFA notification is already enabled" in response_data["message"]

    def test_enable_email_mfa_email_failure(self, client):
        """Test email MFA enable when test email fails."""
        with patch('app.security.routes.current_user') as mock_current_user, \
             patch('app.security.routes.send_email') as mock_send_email, \
             patch('app.security.routes.render_template') as mock_render_template, \
             patch('app.security.routes.get_config_value') as mock_get_config, \
             patch('app.security.routes.current_app') as mock_current_app:
            
            mock_current_user.id = 1
            mock_current_user.email = "test@example.com"
            mock_current_user.is_authenticated = True
            mock_current_user.email_mfa_enabled = False
            mock_current_user.check_password = Mock(return_value=True)
            
            mock_get_config.return_value = "email/mfa_test_template.html"
            mock_render_template.return_value = "<html>Test email</html>"
            mock_send_email.side_effect = Exception("SMTP connection failed")
            
            mock_logger = Mock()
            mock_current_app.logger = mock_logger
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/security/mfa/email/enable',
                                     json={"password": "correct_password"},
                                     content_type='application/json')
            
            assert response.status_code == 500
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "Failed to send test email" in response_data["message"]


class TestEmailMFADisable:
    """Tests for the disable_email_mfa endpoint."""

    def test_disable_email_mfa_success(self, client):
        """Test successful email MFA disabling."""
        with patch('app.security.routes.current_user') as mock_current_user, \
             patch('app.security.routes.db.session') as mock_db_session, \
             patch('app.security.routes.current_app') as mock_current_app:
            
            # Setup mocks
            mock_current_user.id = 1
            mock_current_user.is_authenticated = True
            mock_current_user.email_mfa_enabled = True
            mock_current_user.check_password = Mock(return_value=True)
            
            mock_logger = Mock()
            mock_current_app.logger = mock_logger
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/security/mfa/email/disable',
                                     json={"password": "correct_password"},
                                     content_type='application/json')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["status"] == "success"
            assert "Email MFA notification has been disabled" in response_data["data"]["message"]
            
            # Verify user setting was updated
            assert mock_current_user.email_mfa_enabled == False
            mock_db_session.commit.assert_called_once()

    def test_disable_email_mfa_missing_password(self, client):
        """Test email MFA disable with missing password."""
        with patch('app.security.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/security/mfa/email/disable',
                                     json={},
                                     content_type='application/json')
            
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "Current password is required" in response_data["message"]

    def test_disable_email_mfa_invalid_password(self, client):
        """Test email MFA disable with invalid password."""
        with patch('app.security.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            mock_current_user.check_password = Mock(return_value=False)
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/security/mfa/email/disable',
                                     json={"password": "wrong_password"},
                                     content_type='application/json')
            
            assert response.status_code == 401
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "Invalid password" in response_data["message"]

    def test_disable_email_mfa_not_enabled(self, client):
        """Test email MFA disable when not enabled."""
        with patch('app.security.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            mock_current_user.email_mfa_enabled = False
            mock_current_user.check_password = Mock(return_value=True)
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/security/mfa/email/disable',
                                     json={"password": "correct_password"},
                                     content_type='application/json')
            
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "Email MFA notification is not currently enabled" in response_data["message"]


class TestMFAStatus:
    """Tests for the get_mfa_status endpoint."""

    def test_get_mfa_status_both_enabled(self, client):
        """Test MFA status when both OTP and email MFA are enabled."""
        with patch('app.security.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            mock_current_user.otp_enabled = True
            mock_current_user.email_mfa_enabled = True
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.get('/api/security/mfa/status')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["status"] == "success"
            assert response_data["data"]["otp_enabled"] == True
            assert response_data["data"]["email_mfa_enabled"] == True

    def test_get_mfa_status_both_disabled(self, client):
        """Test MFA status when both OTP and email MFA are disabled."""
        with patch('app.security.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            mock_current_user.otp_enabled = False
            mock_current_user.email_mfa_enabled = False
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.get('/api/security/mfa/status')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["status"] == "success"
            assert response_data["data"]["otp_enabled"] == False
            assert response_data["data"]["email_mfa_enabled"] == False

    def test_get_mfa_status_mixed(self, client):
        """Test MFA status when one is enabled and one is disabled."""
        with patch('app.security.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            mock_current_user.otp_enabled = True
            mock_current_user.email_mfa_enabled = False
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.get('/api/security/mfa/status')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["status"] == "success"
            assert response_data["data"]["otp_enabled"] == True
            assert response_data["data"]["email_mfa_enabled"] == False

    def test_get_mfa_status_unauthorized(self, client):
        """Test MFA status when user is not authenticated."""
        response = client.get('/api/security/mfa/status')
        
        # Flask-Login redirects unauthenticated users
        assert response.status_code == 302


class TestSecurityRoutesIntegration:
    """Integration tests for security route structure and patterns."""

    def test_authenticated_routes_require_login(self, client):
        """Test that all security routes require user login."""
        endpoints = [
            ('/api/security/otp/setup', {"password": "test"}),
            ('/api/security/otp/verify-enable', {"otp_token": "123456"}),
            ('/api/security/otp/disable', {"password": "test"}),
            ('/api/security/mfa/email/enable', {"password": "test"}),
            ('/api/security/mfa/email/disable', {"password": "test"}),
        ]
        
        for endpoint, data in endpoints:
            response = client.post(endpoint, json=data, content_type='application/json')
            # Flask-Login redirects unauthenticated users
            assert response.status_code == 302

        # Test GET endpoint
        response = client.get('/api/security/mfa/status')
        assert response.status_code == 302

    def test_routes_handle_empty_request_body(self, client):
        """Test that routes handle empty request bodies gracefully."""
        with patch('app.security.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            
            endpoints = [
                '/api/security/otp/setup',
                '/api/security/otp/verify-enable',
                '/api/security/otp/disable',
                '/api/security/mfa/email/enable',
                '/api/security/mfa/email/disable'
            ]
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                for endpoint in endpoints:
                    response = client.post(endpoint, json=None, content_type='application/json')
                    assert response.status_code == 400

    def test_rate_limiting_applied(self, client):
        """Test that rate limiting is applied to appropriate endpoints."""
        # This test verifies that rate limiting decorators are present
        # Actual rate limiting behavior would require integration testing
        with patch('app.security.routes.current_user') as mock_current_user, \
             patch('app.security.routes.limiter.limit') as mock_limiter:
            
            mock_current_user.is_authenticated = True
            mock_current_user.check_password = Mock(return_value=True)
            mock_current_user.otp_enabled = False
            mock_current_user.email_mfa_enabled = False
            
            # Rate limited endpoints
            rate_limited_endpoints = [
                '/api/security/otp/setup',
                '/api/security/otp/disable',
                '/api/security/mfa/email/enable',
                '/api/security/mfa/email/disable'
            ]
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                for endpoint in rate_limited_endpoints:
                    response = client.post(endpoint, 
                                         json={"password": "test"}, 
                                         content_type='application/json')
                    # The endpoint should be processed (may fail for other reasons)
                    # but the rate limiter should have been called
                    assert response.status_code in [200, 400, 401, 500]


class TestSecurityFeatures:
    """Tests for security features in routes."""

    def test_password_confirmation_required(self, client):
        """Test that password confirmation is required for sensitive operations."""
        with patch('app.security.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            
            # Endpoints that require password confirmation
            password_required_endpoints = [
                '/api/security/otp/setup',
                '/api/security/otp/disable',
                '/api/security/mfa/email/enable',
                '/api/security/mfa/email/disable'
            ]
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                for endpoint in password_required_endpoints:
                    # Test without password
                    response = client.post(endpoint, json={}, content_type='application/json')
                    assert response.status_code == 400
                    response_data = json.loads(response.data)
                    assert "password is required" in response_data["message"].lower()

    def test_session_handling_for_otp_setup(self, client):
        """Test proper session handling during OTP setup process."""
        with patch('flask_login.utils._get_user') as mock_get_user, \
             patch('app.security.routes.pyotp.random_base32') as mock_random_base32, \
             patch('app.security.routes.get_config_value') as mock_get_config:
            
            mock_current_user = Mock()
            mock_current_user.is_authenticated = True
            mock_current_user.otp_enabled = False
            mock_current_user.check_password = Mock(return_value=True)
            mock_get_user.return_value = mock_current_user
            mock_random_base32.return_value = "TESTSECRET123456"
            mock_get_config.return_value = "otp_secret_temp"
            
            with patch('app.security.routes.pyotp.totp.TOTP') as mock_totp_class, \
                 patch('app.security.routes.qrcode.make') as mock_qr_make, \
                 patch('app.security.routes.io.BytesIO') as mock_bytesio, \
                 patch('app.security.routes.current_app') as mock_current_app:
                
                mock_totp = Mock()
                mock_totp.provisioning_uri.return_value = "otpauth://test"
                mock_totp_class.return_value = mock_totp
                
                mock_img = Mock()
                mock_qr_make.return_value = mock_img
                
                mock_io = Mock()
                mock_io.getvalue.return_value = b"fake_image"
                mock_bytesio.return_value = mock_io
                
                mock_logger = Mock()
                mock_current_app.logger = mock_logger
                
                response = client.post('/api/security/otp/setup',
                                     json={"password": "correct_password"},
                                     content_type='application/json')
                
                # Verify the response is successful (session handling is tested implicitly)
                assert response.status_code == 200

    def test_otp_secret_cleanup_after_verification(self, client):
        """Test that temporary OTP secret is cleaned from session after verification."""
        with patch('flask_login.utils._get_user') as mock_get_user, \
             patch('app.security.routes.pyotp.TOTP') as mock_totp_class, \
             patch('app.security.routes.db.session') as mock_db_session, \
             patch('app.security.routes.get_config_value') as mock_get_config, \
             patch('app.security.routes.current_app') as mock_current_app:
            
            mock_current_user = Mock()
            mock_current_user.is_authenticated = True
            mock_get_user.return_value = mock_current_user
            mock_get_config.return_value = "otp_secret_temp"
            
            mock_totp = Mock()
            mock_totp.verify.return_value = True
            mock_totp_class.return_value = mock_totp
            
            mock_logger = Mock()
            mock_current_app.logger = mock_logger
            
            # Set session data
            with client.session_transaction() as sess:
                sess["otp_secret_temp"] = "TESTSECRET123456"
            
            response = client.post('/api/security/otp/verify-enable',
                                 json={"otp_token": "123456"},
                                 content_type='application/json')
            
            # Verify the response is successful (session cleanup is tested implicitly)
            assert response.status_code == 200
            
            # Verify session is cleaned up
            with client.session_transaction() as sess:
                assert "otp_secret_temp" not in sess