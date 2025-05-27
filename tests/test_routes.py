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
            assert response_data["success"] is True
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
        assert response_data["success"] is False
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
            assert response_data["success"] is True
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
                                 json={"new_password": "newpassword123"},
                                 content_type='application/json')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["success"] is True
            assert "Password has been reset successfully" in response_data["message"]
            
            # Verify password was set
            mock_token.user.set_password.assert_called_once_with("newpassword123")
            
            # Verify token was marked as used
            mock_token.mark_as_used.assert_called_once()

    def test_reset_password_missing_password(self, client):
        """Test reset password with missing new password."""
        response = client.post('/api/utils/reset-password/valid_token',
                             json={},
                             content_type='application/json')
        
        assert response.status_code == 400
        response_data = json.loads(response.data)
        assert response_data["success"] is False
        assert "New password is required" in response_data["message"]

    def test_reset_password_invalid_token(self, client):
        """Test reset password with invalid token."""
        with patch('app.utils.routes.PasswordResetToken') as mock_token_model:
            mock_token_model.find_by_token.return_value = None
            
            response = client.post('/api/utils/reset-password/invalid_token',
                                 json={"new_password": "newpassword123"},
                                 content_type='application/json')
            
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert response_data["success"] is False
            assert "Invalid or expired reset token" in response_data["message"]

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
                                     "new_password": "newpassword123",
                                     "recovery_key": "valid_recovery_key"
                                 },
                                 content_type='application/json')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["success"] is True
            assert "credentials have been preserved" in response_data["message"]
            
            # Verify recovery was attempted
            mock_token.user.recover_with_recovery_key.assert_called_once_with("valid_recovery_key", "newpassword123")


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
                                     "new_password": "newpassword123"
                                 },
                                 content_type='application/json')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["success"] is True
            assert "Account recovered successfully" in response_data["message"]
            
            # Verify recovery was attempted
            mock_user.recover_with_recovery_key.assert_called_once_with("valid_recovery_key", "newpassword123")

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
            assert response_data["success"] is False

    def test_recover_user_not_found(self, client):
        """Test account recovery with non-existent user."""
        with patch('app.utils.routes.User') as mock_user_model:
            mock_user_model.query.filter_by.return_value.first.return_value = None
            
            response = client.post('/api/utils/recover-with-key',
                                 json={
                                     "email": "nonexistent@example.com",
                                     "recovery_key": "valid_recovery_key",
                                     "new_password": "newpassword123"
                                 },
                                 content_type='application/json')
            
            assert response.status_code == 401
            response_data = json.loads(response.data)
            assert response_data["success"] is False
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
                                     "new_password": "newpassword123"
                                 },
                                 content_type='application/json')
            
            assert response.status_code == 401
            response_data = json.loads(response.data)
            assert response_data["success"] is False
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
             patch('app.utils.routes.os.unlink') as mock_unlink:
            
            # Setup mocks
            mock_current_user.id = 1
            mock_current_user.is_authenticated = True
            mock_current_user.get_master_key = Mock(return_value="master_key")
            
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
                                         "master_password": "master123",
                                         "export_password": "export123"
                                     },
                                     content_type='application/json')
            
            assert response.status_code == 200
            assert response.content_type == 'application/zip'

    def test_export_missing_master_password(self, client):
        """Test export with missing master password."""
        with patch('app.utils.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/utils/export',
                                     json={"export_password": "export123"},
                                     content_type='application/json')
            
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert response_data["success"] is False
            assert "Master password is required" in response_data["message"]

    def test_export_missing_export_password(self, client):
        """Test export with missing export password."""
        with patch('app.utils.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/utils/export',
                                     json={"master_password": "master123"},
                                     content_type='application/json')
            
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert response_data["success"] is False
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
                                         "master_password": "master123",
                                         "export_password": "export123"
                                     },
                                     content_type='application/json')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["success"] is True
            assert "no credentials stored to export" in response_data["message"]

    def test_export_unauthorized(self, client):
        """Test export when user is not authenticated."""
        response = client.post('/api/utils/export',
                             json={
                                 "master_password": "master123",
                                 "export_password": "export123"
                             },
                             content_type='application/json')
        
        assert response.status_code == 401


class TestImportCredentials:
    """Tests for the import_credentials endpoint."""

    def test_import_success(self, client):
        """Test successful credential import."""
        with patch('app.utils.routes.current_user') as mock_current_user, \
             patch('app.utils.routes.encrypt_data') as mock_encrypt, \
             patch('app.utils.routes.Credential') as mock_credential_model, \
             patch('app.utils.routes.db.session') as mock_db_session:
            
            mock_current_user.id = 1
            mock_current_user.is_authenticated = True
            mock_current_user.get_master_key = Mock(return_value="master_key")
            
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
                                         "master_password": "master123",
                                         "credentials": credentials_data
                                     },
                                     content_type='application/json')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data["success"] is True
            assert "Credentials imported successfully" in response_data["message"]

    def test_import_missing_master_password(self, client):
        """Test import with missing master password."""
        with patch('app.utils.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/utils/import',
                                     json={"credentials": []},
                                     content_type='application/json')
                
                assert response.status_code == 400
                response_data = json.loads(response.data)
                assert response_data["success"] is False
                assert "Master password is required" in response_data["message"]

    def test_import_missing_credentials(self, client):
        """Test import with missing credentials data."""
        with patch('app.utils.routes.current_user') as mock_current_user:
            mock_current_user.is_authenticated = True
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/utils/import',
                                     json={"master_password": "master123"},
                                     content_type='application/json')
            
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert response_data["success"] is False
            assert "Credentials data is required" in response_data["message"]

    def test_import_unauthorized(self, client):
        """Test import when user is not authenticated."""
        response = client.post('/api/utils/import',
                             json={
                                 "master_password": "master123",
                                 "credentials": []
                             },
                             content_type='application/json')
        
        assert response.status_code == 401

    def test_import_invalid_master_password(self, client):
        """Test import with invalid master password."""
        with patch('app.utils.routes.current_user') as mock_current_user:
            mock_current_user.id = 1
            mock_current_user.is_authenticated = True
            mock_current_user.get_master_key = Mock(side_effect=ValueError("Invalid master password"))
            
            with patch('flask_login.utils._get_user', return_value=mock_current_user):
                response = client.post('/api/utils/import',
                                     json={
                                         "master_password": "wrongpassword",
                                         "credentials": [{"service_name": "test"}]
                                     },
                                     content_type='application/json')
            
            assert response.status_code == 401
            response_data = json.loads(response.data)
            assert response_data["success"] is False


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
            ('/api/utils/export', {"master_password": "test", "export_password": "test"}),
            ('/api/utils/import', {"master_password": "test", "credentials": []})
        ]
        
        for endpoint, data in authenticated_endpoints:
            response = client.post(endpoint, json=data, content_type='application/json')
            assert response.status_code == 401


class TestRouteSecurityFeatures:
    """Tests for security features in routes."""

    def test_forgot_password_prevents_user_enumeration(self, client):
        """Test that forgot password doesn't reveal if user exists."""
        with patch('app.utils.routes.User') as mock_user_model:
            # Test with existing user
            mock_user_model.query.filter_by.return_value.first.return_value = Mock()
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
        with patch('app.utils.routes.User') as mock_user_model:
            # Mock for non-existing user
            mock_user_model.query.filter_by.return_value.first.return_value = None
            response1 = client.post('/api/utils/recover-with-key',
                                   json={
                                       "email": "nonexisting@example.com", 
                                       "recovery_key": "key123",
                                       "new_password": "newpass123"
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
                                       "new_password": "newpass123"
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
            assert response_data["success"] is False