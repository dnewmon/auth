"""
Unit tests for app.utils.routes module.

Tests all utility route endpoints including password reset, account recovery,
and credential import/export functionality.
"""

import pytest
import json
import os
import tempfile
import csv
import io
from unittest.mock import patch, Mock, MagicMock, mock_open, call
from flask import Flask, url_for


class TestForgotPassword:
    """Tests for the forgot_password endpoint."""

    def test_forgot_password_success(self, client):
        """Test successful password reset initiation."""
        with patch('app.utils.routes.send_email') as mock_send_email, \
             patch('app.utils.routes.render_template') as mock_render_template, \
             patch('app.utils.routes.url_for') as mock_url_for, \
             patch('app.utils.routes.get_config_value') as mock_get_config, \
             patch('app.utils.routes.db.session') as mock_db_session, \
             patch('app.utils.routes.PasswordResetToken') as mock_token_model, \
             patch('app.utils.routes.User') as mock_user_model:
            
            # Setup mocks
            mock_user = Mock()
            mock_user.id = 1
            mock_user.email = "user@example.com"
            mock_user.recovery_keys = [Mock(), Mock()]  # Has 2 recovery keys
            mock_user.recovery_keys[0].used_at = None  # Unused
            mock_user.recovery_keys[1].used_at = "2023-01-01"  # Used
            mock_user_model.query.filter_by.return_value.first.return_value = mock_user
            
            mock_token = Mock()
            mock_token_model.generate_token.return_value = "raw_token_123"
            mock_token_model.return_value = mock_token
            
            mock_get_config.return_value = "email/reset_template.html"
            mock_url_for.return_value = "https://example.com/reset/raw_token_123"
            mock_render_template.return_value = "<html>Reset email</html>"
            
            # Make the request
            response = client.post('/api/utils/forgot-password',
                                 json={"email": "user@example.com"},
                                 content_type='application/json')
            
            # Verify the response
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["status"] == "success"
            assert "password reset link has been sent" in response_data["message"]
            
            # Verify database operations
            mock_db_session.add.assert_called_once_with(mock_token)
            mock_db_session.commit.assert_called_once()
            
            # Verify email was sent
            mock_send_email.assert_called_once_with(
                to="user@example.com",
                subject="Password Reset Request",
                template="<html>Reset email</html>"
            )

    def test_forgot_password_no_email(self, client):
        """Test forgot password with missing email."""
        response = client.post('/api/utils/forgot-password',
                             json={},
                             content_type='application/json')
        
        assert response.status_code == 400
        response_data = json.loads(response.data)
        assert response_data["status"] == "error"
        assert "Email is required" in response_data["message"]

    def test_forgot_password_user_not_found(self, client):
        """Test forgot password with non-existent user - should return success for security."""
        with patch('app.utils.routes.User') as mock_user_model:
            mock_user_model.query.filter_by.return_value.first.return_value = None
            
            response = client.post('/api/utils/forgot-password',
                                 json={"email": "nonexistent@example.com"},
                                 content_type='application/json')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["status"] == "success"
            assert "password reset link has been sent" in response_data["message"]


class TestResetPasswordWithToken:
    """Tests for the reset_password_with_token endpoint."""

    def test_reset_password_success(self, client):
        """Test successful password reset."""
        with patch('app.utils.routes.PasswordResetToken') as mock_token_model, \
             patch('app.utils.routes.User') as mock_user_model, \
             patch('app.utils.routes.db.session') as mock_db_session, \
             patch('app.utils.routes.get_config_value') as mock_get_config:
            
            # Setup mocks
            mock_token = Mock()
            mock_token.user_id = 1
            mock_token.is_valid.return_value = True
            mock_token.user = Mock()
            mock_token.user.id = 1
            mock_token.user.credentials = []  # No existing credentials
            mock_token.user.set_password = Mock()
            mock_token.user.increment_session_version = Mock()
            mock_token.mark_as_used = Mock()
            mock_token_model.find_by_token.return_value = mock_token
            
            mock_get_config.return_value = 8  # Min password length
            
            response = client.post('/api/utils/reset-password/valid_token',
                                 json={"new_password": "validnewpassword123"},
                                 content_type='application/json')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["status"] == "success"
            assert "Password has been reset successfully" in response_data["data"]["message"]
            
            # Verify password was set
            mock_token.user.set_password.assert_called_once_with("validnewpassword123")
            
            # Verify token was marked as used
            mock_token.mark_as_used.assert_called_once()

    def test_reset_password_missing_password(self, client):
        """Test reset password with missing new password."""
        response = client.post('/api/utils/reset-password/valid_token',
                             json={},
                             content_type='application/json')
        
        assert response.status_code == 400
        response_data = json.loads(response.data)
        assert response_data["status"] == "error"
        assert "New password is required" in response_data["message"]

    def test_reset_password_invalid_token(self, client):
        """Test reset password with invalid token."""
        with patch('app.utils.routes.PasswordResetToken') as mock_token_model:
            mock_token_model.find_by_token.return_value = None
            
            response = client.post('/api/utils/reset-password/invalid_token',
                                 json={"new_password": "validnewpassword123"},
                                 content_type='application/json')
            
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "Invalid or expired password reset token" in response_data["message"]

    def test_reset_password_with_recovery_key_migration(self, client):
        """Test password reset with recovery key for credential migration."""
        with patch('app.utils.routes.PasswordResetToken') as mock_token_model, \
             patch('app.utils.routes.db.session') as mock_db_session, \
             patch('app.utils.routes.get_config_value') as mock_get_config:
            
            # Setup mocks
            mock_token = Mock()
            mock_token.user_id = 1
            mock_token.is_valid.return_value = True
            mock_token.user = Mock()
            mock_token.user.id = 1
            mock_token.user.credentials = [Mock(), Mock()]  # Has existing credentials
            mock_token.user.recover_with_recovery_key = Mock(return_value=True)
            mock_token.user.increment_session_version = Mock()
            mock_token.mark_as_used = Mock()
            mock_token_model.find_by_token.return_value = mock_token
            
            mock_get_config.return_value = 8  # Min password length
            
            response = client.post('/api/utils/reset-password/valid_token',
                                 json={
                                     "new_password": "validnewpassword123",
                                     "recovery_key": "valid_recovery_key"
                                 },
                                 content_type='application/json')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["status"] == "success"
            assert "credentials have been preserved" in response_data["data"]["message"]
            
            # Verify recovery was attempted
            mock_token.user.recover_with_recovery_key.assert_called_once_with("valid_recovery_key", "validnewpassword123")


class TestRecoverWithRecoveryKey:
    """Tests for the recover_with_recovery_key endpoint."""

    def test_recover_success(self, client):
        """Test successful account recovery with recovery key."""
        with patch('app.utils.routes.User') as mock_user_model, \
             patch('app.utils.routes.db.session') as mock_db_session, \
             patch('app.utils.routes.get_config_value') as mock_get_config:
            
            mock_user = Mock()
            mock_user.id = 1
            mock_user.recover_with_recovery_key = Mock(return_value=True)
            mock_user.increment_session_version = Mock()
            mock_user_model.query.filter_by.return_value.first.return_value = mock_user
            
            mock_get_config.return_value = 8  # Min password length
            
            response = client.post('/api/utils/recover-with-key',
                                 json={
                                     "email": "user@example.com",
                                     "recovery_key": "valid_recovery_key",
                                     "new_password": "validnewpassword123"
                                 },
                                 content_type='application/json')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["status"] == "success"
            assert "Account recovered successfully" in response_data["data"]["message"]
            
            # Verify recovery was attempted
            mock_user.recover_with_recovery_key.assert_called_once_with("valid_recovery_key", "validnewpassword123")

    def test_recover_missing_fields(self, client):
        """Test account recovery with missing fields."""
        test_cases = [
            {},  # All missing
            {"email": "user@example.com"},  # Missing recovery key and password
            {"recovery_key": "key123"},  # Missing email and password
            {"email": "user@example.com", "recovery_key": "key123"},  # Missing password
        ]
        
        for data in test_cases:
            response = client.post('/api/utils/recover-with-key',
                                 json=data,
                                 content_type='application/json')
            
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"

    def test_recover_user_not_found(self, client):
        """Test account recovery with non-existent user."""
        with patch('app.utils.routes.User') as mock_user_model:
            mock_user_model.query.filter_by.return_value.first.return_value = None
            
            response = client.post('/api/utils/recover-with-key',
                                 json={
                                     "email": "nonexistent@example.com",
                                     "recovery_key": "valid_recovery_key",
                                     "new_password": "validnewpassword123"
                                 },
                                 content_type='application/json')
            
            assert response.status_code == 401
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "Invalid email or recovery key" in response_data["message"]

    def test_recover_invalid_recovery_key(self, client):
        """Test account recovery with invalid recovery key."""
        with patch('app.utils.routes.User') as mock_user_model:
            mock_user = Mock()
            mock_user.recover_with_recovery_key = Mock(side_effect=ValueError("Invalid recovery key"))
            mock_user_model.query.filter_by.return_value.first.return_value = mock_user
            
            response = client.post('/api/utils/recover-with-key',
                                 json={
                                     "email": "user@example.com",
                                     "recovery_key": "invalid_recovery_key",
                                     "new_password": "validnewpassword123"
                                 },
                                 content_type='application/json')
            
            assert response.status_code == 401
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "Invalid email or recovery key" in response_data["message"]


class TestExportCredentials:
    """Tests for the export_credentials endpoint."""

    def test_export_success(self, client):
        """Test successful credential export."""
        with patch('app.utils.routes.current_user') as mock_current_user, \
             patch('app.utils.routes.Credential') as mock_credential_model, \
             patch('app.utils.routes.decrypt_data') as mock_decrypt, \
             patch('app.utils.routes.tempfile.NamedTemporaryFile') as mock_temp_file, \
             patch('app.utils.routes.pyminizip.compress') as mock_zip, \
             patch('app.utils.routes.open', mock_open(read_data=b"zip_content")) as mock_file_open, \
             patch('app.utils.routes.os.unlink') as mock_unlink, \
             patch('app.utils.master_verification.MasterVerificationManager') as mock_verification:
            
            # Setup mocks
            mock_current_user.id = 1
            mock_current_user.is_authenticated = True
            mock_verification.get_master_key_from_session.return_value = "master_key"
            
            mock_credential = Mock()
            mock_credential.id = 1
            mock_credential.service_name = "example.com"
            mock_credential.service_url = "https://example.com"
            mock_credential.username = "user@example.com"
            mock_credential.encrypted_password = "encrypted_password"
            mock_credential.notes = "Test notes"
            mock_credential_model.query.filter_by.return_value.all.return_value = [mock_credential]
            
            mock_decrypt.return_value = "decrypted_password"
            
            # Mock temporary file
            mock_temp = Mock()
            mock_temp.name = "/tmp/test_file.csv"
            mock_temp_file.return_value.__enter__.return_value = mock_temp
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/utils/export',
                                     json={
                                         "session_token": "valid_session_token",
                                         "export_password": "export123"
                                     },
                                     content_type='application/json')
            
            assert response.status_code == 200
            assert response.content_type == 'application/zip'

    def test_export_missing_master_password(self, client):
        """Test export with missing session token."""
        with patch('app.utils.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/utils/export',
                                     json={"export_password": "export123"},
                                     content_type='application/json')
            
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "Session token is required" in response_data["message"]

    def test_export_missing_export_password(self, client):
        """Test export with missing export password."""
        with patch('app.utils.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/utils/export',
                                     json={"session_token": "valid_session_token"},
                                     content_type='application/json')
            
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "Export password is required" in response_data["message"]

    def test_export_no_credentials(self, client):
        """Test export when user has no credentials."""
        with patch('app.utils.routes.current_user') as mock_current_user, \
             patch('app.utils.routes.Credential') as mock_credential_model:
            
            mock_current_user.id = 1
            mock_current_user.is_authenticated = True
            mock_credential_model.query.filter_by.return_value.all.return_value = []
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/utils/export',
                                     json={
                                         "session_token": "valid_session_token",
                                         "export_password": "export123"
                                     },
                                     content_type='application/json')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["status"] == "success"
            assert "no credentials stored to export" in response_data["message"]

    def test_export_unauthorized(self, client):
        """Test export when user is not authenticated."""
        response = client.post('/api/utils/export',
                             json={
                                 "master_password": "master123",
                                 "export_password": "export123"
                             },
                             content_type='application/json')
        
        # Flask-Login redirects unauthenticated users
        assert response.status_code == 302


class TestImportCredentials:
    """Tests for the import_credentials endpoint."""

    def test_import_success(self, client):
        """Test successful credential import."""
        with patch('app.utils.routes.current_user') as mock_current_user, \
             patch('app.utils.routes.encrypt_data') as mock_encrypt, \
             patch('app.utils.routes.Credential') as mock_credential_model, \
             patch('app.utils.routes.db.session') as mock_db_session, \
             patch('app.utils.master_verification.MasterVerificationManager') as mock_verification:
            
            mock_current_user.id = 1
            mock_current_user.is_authenticated = True
            mock_verification.get_master_key_from_session.return_value = "master_key"
            
            mock_encrypt.return_value = "encrypted_data"
            
            # Create test credential data
            credentials_data = [
                {
                    "service_name": "example.com",
                    "service_url": "https://example.com",
                    "username": "user@example.com",
                    "password": "password123",
                    "notes": "Test notes"
                }
            ]
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/utils/import',
                                     json={
                                         "session_token": "valid_session_token",
                                         "credentials": credentials_data
                                     },
                                     content_type='application/json')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["status"] == "success"
            assert "Credentials imported successfully" in response_data["message"]

    def test_import_missing_master_password(self, client):
        """Test import with missing session token."""
        with patch('app.utils.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/utils/import',
                                     json={"credentials": []},
                                     content_type='application/json')
                
                assert response.status_code == 400
                response_data = json.loads(response.data)
                assert response_data["status"] == "error"
                assert "Session token is required" in response_data["message"]

    def test_import_missing_credentials(self, client):
        """Test import with missing credentials data."""
        with patch('app.utils.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/utils/import',
                                     json={"session_token": "valid_session_token"},
                                     content_type='application/json')
            
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "Credentials data is required" in response_data["message"]

    def test_import_unauthorized(self, client):
        """Test import when user is not authenticated."""
        response = client.post('/api/utils/import',
                             json={
                                 "master_password": "master123",
                                 "credentials": []
                             },
                             content_type='application/json')
        
        # Flask-Login redirects unauthenticated users
        assert response.status_code == 302

    def test_import_invalid_master_password(self, client):
        """Test import with invalid session token."""
        with patch('app.utils.routes.current_user') as mock_current_user, \
             patch('app.utils.master_verification.MasterVerificationManager') as mock_verification:
            mock_current_user.id = 1
            mock_current_user.is_authenticated = True
            mock_verification.get_master_key_from_session.side_effect = ValueError("Invalid session token")
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/utils/import',
                                     json={
                                         "session_token": "invalid_token",
                                         "credentials": [{"service_name": "test"}]
                                     },
                                     content_type='application/json')
            
            assert response.status_code == 401
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"


class TestRoutesIntegration:
    """Integration tests for route structure and patterns."""

    def test_routes_require_json_content_type(self, client):
        """Test that routes properly handle JSON content type requirements."""
        endpoints = [
            '/api/utils/forgot-password',
            '/api/utils/reset-password/token123',
            '/api/utils/recover-with-key'
        ]
        
        for endpoint in endpoints:
            response = client.post(endpoint, data="not json")
            assert response.status_code in [400, 415]  # Bad request or unsupported media type

    def test_routes_handle_empty_request_body(self, client):
        """Test that routes handle empty request bodies gracefully."""
        endpoints = [
            '/api/utils/forgot-password',
            '/api/utils/reset-password/token123',
            '/api/utils/recover-with-key'
        ]
        
        for endpoint in endpoints:
            response = client.post(endpoint, json=None, content_type='application/json')
            assert response.status_code == 400

    def test_authenticated_routes_require_login(self, client):
        """Test that authenticated routes require user login."""
        authenticated_endpoints = [
            ('/api/utils/export', {"session_token": "test", "export_password": "test"}),
            ('/api/utils/import', {"session_token": "test", "credentials": []})
        ]
        
        for endpoint, data in authenticated_endpoints:
            response = client.post(endpoint, json=data, content_type='application/json')
            # Flask-Login redirects unauthenticated users
            assert response.status_code == 302


class TestRouteSecurityFeatures:
    """Tests for security features in routes."""

    def test_forgot_password_prevents_user_enumeration(self, client):
        """Test that forgot password doesn't reveal if user exists."""
        with patch('app.utils.routes.User') as mock_user_model, \
             patch('app.utils.routes.PasswordResetToken') as mock_token_model, \
             patch('app.utils.routes.db') as mock_db, \
             patch('app.utils.routes.send_email') as mock_send_email, \
             patch('app.utils.routes.render_template', return_value="fake_html") as mock_render:
            
            # Setup mock for existing user case
            mock_user = Mock()
            mock_user.id = 1
            mock_user.recovery_keys = []  # Mock the recovery_keys attribute
            mock_user_model.query.filter_by.return_value.first.return_value = mock_user
            mock_token_model.generate_token.return_value = "fake_token"
            
            response1 = client.post('/api/utils/forgot-password',
                                   json={"email": "existing@example.com"},
                                   content_type='application/json')
            
            # Test with non-existing user
            mock_user_model.query.filter_by.return_value.first.return_value = None
            response2 = client.post('/api/utils/forgot-password',
                                   json={"email": "nonexisting@example.com"},
                                   content_type='application/json')
            
            # Both should return the same response
            assert response1.status_code == response2.status_code
            assert json.loads(response1.data)["message"] == json.loads(response2.data)["message"]

    def test_recovery_prevents_user_enumeration(self, client):
        """Test that recovery endpoint doesn't reveal if user exists."""
        with patch('app.utils.routes.User') as mock_user_model, \
             patch('app.utils.routes.get_config_value', return_value=12):
            
            # Mock for non-existing user
            mock_user_model.query.filter_by.return_value.first.return_value = None
            response1 = client.post('/api/utils/recover-with-key',
                                   json={
                                       "email": "nonexisting@example.com", 
                                       "recovery_key": "key123",
                                       "new_password": "validnewpassword123"
                                   },
                                   content_type='application/json')
            
            # Mock for existing user with invalid key
            mock_user = Mock()
            mock_user.recover_with_recovery_key = Mock(side_effect=ValueError("Invalid key"))
            mock_user_model.query.filter_by.return_value.first.return_value = mock_user
            response2 = client.post('/api/utils/recover-with-key',
                                   json={
                                       "email": "existing@example.com", 
                                       "recovery_key": "invalid_key",
                                       "new_password": "validnewpassword123"
                                   },
                                   content_type='application/json')
            
            # Both should return similar error messages
            assert response1.status_code == response2.status_code
            assert "Invalid email or recovery key" in json.loads(response1.data)["message"]
            assert "Invalid email or recovery key" in json.loads(response2.data)["message"]

    def test_password_reset_token_security(self, client):
        """Test security measures for password reset tokens."""
        with patch('app.utils.routes.current_app') as mock_app:
            mock_logger = Mock()
            mock_app.logger = mock_logger
            
            # Test with potentially malicious token
            response = client.post('/api/utils/reset-password/malicious_token',
                                 json={"new_password": "newpass123"},
                                 content_type='application/json')
            
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"


class TestChangePasswordWithMfa:
    """Tests for the change_password endpoint with MFA verification."""

    def test_change_password_success_no_mfa(self, client):
        """Test successful password change without MFA enabled."""
        with patch('app.utils.routes.current_user') as mock_user, \
             patch('app.utils.routes.db.session') as mock_db_session, \
             patch('app.utils.routes.MasterVerificationManager') as mock_master_mgr, \
             patch('app.utils.routes.current_app') as mock_app, \
             patch('flask_login.utils._get_user', return_value=mock_user):
            
            # Setup mock user
            mock_user.id = 1
            mock_user.credentials = []  # No existing credentials
            mock_user.otp_enabled = False
            mock_user.email_mfa_enabled = False
            mock_user.check_password.return_value = True
            mock_user.set_password = Mock()
            mock_user.is_authenticated = True
            
            mock_master_mgr.verify_and_store.return_value = "new_session_token_123"
            mock_app.logger = Mock()
            
            response = client.post('/api/utils/change-password',
                                 json={
                                     "current_password": "oldpassword123",
                                     "new_password": "newpassword456"
                                 },
                                 content_type='application/json')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["status"] == "success"
            assert "Password changed successfully" in response_data["data"]["message"]
            assert response_data["data"]["session_token"] == "new_session_token_123"
            assert response_data["data"]["credentials_preserved"] == True
            
            # Verify password was changed
            mock_user.set_password.assert_called_once_with("newpassword456")
            mock_db_session.commit.assert_called_once()

    def test_change_password_success_with_credentials(self, client):
        """Test successful password change with existing credentials."""
        with patch('app.utils.routes.current_user') as mock_user, \
             patch('flask_login.utils._get_user', return_value=mock_user) as mock_get_user, \
             patch('app.utils.routes.db.session') as mock_db_session, \
             patch('app.utils.routes.MasterVerificationManager') as mock_master_mgr, \
             patch('app.utils.routes.current_app') as mock_app:
            
            # Setup mock user with credentials
            mock_user.id = 1
            mock_user.is_authenticated = True
            mock_user.credentials = [Mock(), Mock()]  # Has credentials
            mock_user.otp_enabled = False
            mock_user.email_mfa_enabled = False
            mock_user.check_password.return_value = True
            mock_user.change_password_preserving_keys.return_value = True
            
            mock_master_mgr.verify_and_store.return_value = "new_session_token_123"
            mock_app.logger = Mock()
            
            response = client.post('/api/utils/change-password',
                                 json={
                                     "current_password": "oldpassword123",
                                     "new_password": "newpassword456"
                                 },
                                 content_type='application/json')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["status"] == "success"
            assert "Password changed successfully" in response_data["data"]["message"]
            assert response_data["data"]["credentials_preserved"] == True
            
            # Verify the new method was called
            mock_user.change_password_preserving_keys.assert_called_once_with("oldpassword123", "newpassword456")

    def test_change_password_success_with_otp(self, client):
        """Test successful password change with OTP verification."""
        with patch('app.utils.routes.current_user') as mock_user, \
             patch('flask_login.utils._get_user', return_value=mock_user) as mock_get_user, \
             patch('app.utils.routes.db.session') as mock_db_session, \
             patch('app.utils.routes.MasterVerificationManager') as mock_master_mgr, \
             patch('app.utils.routes.pyotp.TOTP') as mock_totp, \
             patch('app.utils.routes.current_app') as mock_app:
            
            # Setup mock user with OTP enabled
            mock_user.id = 1
            mock_user.is_authenticated = True
            mock_user.credentials = []
            mock_user.otp_enabled = True
            mock_user.email_mfa_enabled = False
            mock_user.otp_secret = "base32secret"
            mock_user.check_password.return_value = True
            mock_user.set_password = Mock()
            
            mock_totp_instance = Mock()
            mock_totp_instance.verify.return_value = True
            mock_totp.return_value = mock_totp_instance
            
            mock_master_mgr.verify_and_store.return_value = "new_session_token_123"
            mock_app.logger = Mock()
            
            response = client.post('/api/utils/change-password',
                                 json={
                                     "current_password": "oldpassword123",
                                     "new_password": "newpassword456",
                                     "otp_token": "123456"
                                 },
                                 content_type='application/json')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["status"] == "success"
            
            # Verify OTP was verified
            mock_totp.assert_called_once_with("base32secret")
            mock_totp_instance.verify.assert_called_once_with("123456")

    def test_change_password_success_with_email_mfa(self, client):
        """Test successful password change with email MFA verification."""
        with patch('app.utils.routes.current_user') as mock_user, \
             patch('flask_login.utils._get_user', return_value=mock_user) as mock_get_user, \
             patch('app.utils.routes.db.session') as mock_db_session, \
             patch('app.utils.routes.MasterVerificationManager') as mock_master_mgr, \
             patch('app.utils.routes.MfaVerificationCode') as mock_code_model, \
             patch('app.utils.routes.current_app') as mock_app:
            
            # Setup mock user with email MFA enabled
            mock_user.id = 1
            mock_user.is_authenticated = True
            mock_user.credentials = []
            mock_user.otp_enabled = False
            mock_user.email_mfa_enabled = True
            mock_user.check_password.return_value = True
            mock_user.set_password = Mock()
            
            # Setup mock verification code
            mock_code = Mock()
            mock_code.mark_as_used = Mock()
            mock_code_model.find_valid_code.return_value = mock_code
            
            mock_master_mgr.verify_and_store.return_value = "new_session_token_123"
            mock_app.logger = Mock()
            
            response = client.post('/api/utils/change-password',
                                 json={
                                     "current_password": "oldpassword123",
                                     "new_password": "newpassword456",
                                     "verification_code": "123456"
                                 },
                                 content_type='application/json')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["status"] == "success"
            
            # Verify email code was validated and marked as used
            mock_code_model.find_valid_code.assert_called_once_with(1, "123456", "password_change")
            mock_code.mark_as_used.assert_called_once()

    def test_change_password_missing_current_password(self, client):
        """Test password change with missing current password."""
        with patch('app.utils.routes.current_user') as mock_user, \
             patch('flask_login.utils._get_user', return_value=mock_user) as mock_get_user:

            mock_user.id = 1
            mock_user.is_authenticated = True
            response = client.post('/api/utils/change-password',
                                 json={"new_password": "newpassword456"},
                                 content_type='application/json')

            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "Current password is required" in response_data["message"]

    def test_change_password_invalid_current_password(self, client):
        """Test password change with invalid current password."""
        with patch('app.utils.routes.current_user') as mock_user, \
             patch('flask_login.utils._get_user', return_value=mock_user) as mock_get_user, \
             patch('app.utils.routes.current_app') as mock_app:
            
            mock_user.id = 1
            mock_user.is_authenticated = True
            mock_user.otp_enabled = False
            mock_user.email_mfa_enabled = False
            mock_user.check_password = Mock(return_value=False)
            mock_user.set_password = Mock()
            mock_app.logger = Mock()
            
            response = client.post('/api/utils/change-password',
                                 json={
                                     "current_password": "wrongpassword",
                                     "new_password": "newpassword456"
                                 },
                                 content_type='application/json')
            
            assert response.status_code == 401
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "Invalid current password" in response_data["message"]

    def test_change_password_otp_required_missing(self, client):
        """Test password change when OTP is required but not provided."""
        with patch('app.utils.routes.current_user') as mock_user, \
             patch('flask_login.utils._get_user', return_value=mock_user) as mock_get_user:
            mock_user.id = 1
            mock_user.is_authenticated = True
            mock_user.otp_enabled = True
            mock_user.email_mfa_enabled = False
            mock_user.check_password.return_value = True
            
            response = client.post('/api/utils/change-password',
                                 json={
                                     "current_password": "oldpassword123",
                                     "new_password": "newpassword456"
                                 },
                                 content_type='application/json')
            
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "OTP token is required" in response_data["message"]

    def test_change_password_invalid_otp(self, client):
        """Test password change with invalid OTP token."""
        with patch('app.utils.routes.current_user') as mock_user, \
             patch('flask_login.utils._get_user', return_value=mock_user) as mock_get_user, \
             patch('app.utils.routes.pyotp.TOTP') as mock_totp, \
             patch('app.utils.routes.current_app') as mock_app:
            
            mock_user.id = 1
            mock_user.is_authenticated = True
            mock_user.otp_enabled = True
            mock_user.otp_secret = "base32secret"
            mock_user.check_password.return_value = True
            
            mock_totp_instance = Mock()
            mock_totp_instance.verify.return_value = False
            mock_totp.return_value = mock_totp_instance
            
            mock_app.logger = Mock()
            
            response = client.post('/api/utils/change-password',
                                 json={
                                     "current_password": "oldpassword123",
                                     "new_password": "newpassword456",
                                     "otp_token": "999999"
                                 },
                                 content_type='application/json')
            
            assert response.status_code == 401
            response_data = json.loads(response.data)
            assert response_data["status"] == "error"
            assert "Invalid OTP token" in response_data["message"]


class TestRequestPasswordChangeCode:
    """Tests for the request_password_change_code endpoint."""

    def test_request_code_success(self, client):
        """Test successful email code request for password change."""
        with patch('app.utils.routes.current_user') as mock_user, \
             patch('flask_login.utils._get_user', return_value=mock_user) as mock_get_user, \
             patch('app.utils.routes.MfaVerificationCode') as mock_code_model, \
             patch('app.utils.routes.render_template') as mock_render, \
             patch('app.utils.routes.send_email') as mock_send_email, \
             patch('app.utils.routes.current_app') as mock_app:
            
            mock_user.id = 1
            mock_user.is_authenticated = True
            mock_user.email = "user@example.com"
            mock_user.email_mfa_enabled = True
            
            mock_code = Mock()
            mock_code.code = "123456"
            mock_code_model.create_for_user.return_value = mock_code
            
            mock_render.return_value = "<html>Verification code email</html>"
            mock_app.logger = Mock()
            
            response = client.post('/api/utils/request-password-change-code',
                                 content_type='application/json')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["status"] == "success"
            assert "Verification code sent" in response_data["data"]["message"]
            
            # Verify code creation and email sending
            mock_code_model.create_for_user.assert_called_once_with(1, 'password_change')
            mock_send_email.assert_called_once_with(
                "user@example.com",
                "Password Change Verification Code",
                "<html>Verification code email</html>"
            )