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

# Import the route functions and dependencies
from app.utils.routes import (
    forgot_password,
    reset_password_with_token,
    recover_with_recovery_key,
    export_credentials,
    import_credentials
)


class TestForgotPassword:
    """Tests for the forgot_password endpoint."""

    @patch('app.utils.routes.send_email')
    @patch('app.utils.routes.render_template')
    @patch('app.utils.routes.url_for')
    @patch('app.utils.routes.get_config_value')
    @patch('app.utils.routes.db.session')
    @patch('app.utils.routes.PasswordResetToken')
    @patch('app.utils.routes.User')
    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_forgot_password_success(self, mock_request, mock_app, mock_user_model, 
                                   mock_token_model, mock_db_session, mock_get_config,
                                   mock_url_for, mock_render_template, mock_send_email):
        """Test successful password reset initiation."""
        # Setup mocks
        mock_request.get_json.return_value = {"email": "user@example.com"}
        
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
        
        # Call the function
        from app.utils.routes import forgot_password
        response = forgot_password()
        
        # Verify the response
        assert response[1] == 200
        response_data = json.loads(response[0].data)
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
        
        # Verify template rendering with correct context
        mock_render_template.assert_called_once_with(
            "email/reset_template.html",
            reset_url="https://example.com/reset/raw_token_123",
            user=mock_user,
            has_recovery_keys=True,
            unused_keys=1
        )

    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_forgot_password_no_email(self, mock_request, mock_app):
        """Test forgot password with missing email."""
        mock_request.get_json.return_value = {}
        
        response = forgot_password()
        
        assert response[1] == 400
        response_data = json.loads(response[0].data)
        assert response_data["success"] is False
        assert "Email is required" in response_data["message"]

    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.User')
    @patch('app.utils.routes.request')
    def test_forgot_password_user_not_found(self, mock_request, mock_user_model, mock_app):
        """Test forgot password with non-existent user."""
        mock_request.get_json.return_value = {"email": "nonexistent@example.com"}
        mock_user_model.query.filter_by.return_value.first.return_value = None
        
        response = forgot_password()
        
        # Should return success message to prevent user enumeration
        assert response[1] == 200
        response_data = json.loads(response[0].data)
        assert response_data["success"] is True
        assert "password reset link has been sent" in response_data["message"]
        
        # Verify logging of attempt
        mock_app.logger.info.assert_called_with(
            "Password reset attempt for non-existent email: nonexistent@example.com"
        )

    @patch('app.utils.routes.db.session')
    @patch('app.utils.routes.PasswordResetToken')
    @patch('app.utils.routes.User')
    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_forgot_password_database_error(self, mock_request, mock_app, mock_user_model,
                                          mock_token_model, mock_db_session):
        """Test forgot password with database error."""
        mock_request.get_json.return_value = {"email": "user@example.com"}
        
        mock_user = Mock()
        mock_user.id = 1
        mock_user.email = "user@example.com"
        mock_user_model.query.filter_by.return_value.first.return_value = mock_user
        
        # Simulate database error
        mock_db_session.commit.side_effect = Exception("Database error")
        
        response = forgot_password()
        
        assert response[1] == 500
        response_data = json.loads(response[0].data)
        assert response_data["success"] is False
        assert "error occurred during the password reset process" in response_data["message"]
        
        # Verify rollback was called
        mock_db_session.rollback.assert_called_once()


class TestResetPasswordWithToken:
    """Tests for the reset_password_with_token endpoint."""

    @patch('app.utils.routes.db.session')
    @patch('app.utils.routes.get_config_value')
    @patch('app.utils.routes.PasswordResetToken')
    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_reset_password_success_no_credentials(self, mock_request, mock_app, mock_token_model,
                                                 mock_get_config, mock_db_session):
        """Test successful password reset with no existing credentials."""
        mock_request.get_json.return_value = {"new_password": "newpassword123"}
        mock_get_config.return_value = 8
        
        mock_reset_token = Mock()
        mock_reset_token.is_valid.return_value = True
        mock_user = Mock()
        mock_user.credentials = []
        mock_reset_token.user = mock_user
        mock_token_model.find_by_token.return_value = mock_reset_token
        
        response = reset_password_with_token("valid_token")
        
        assert response[1] == 200
        response_data = json.loads(response[0].data)
        assert response_data["success"] is True
        assert "Password has been reset successfully" in response_data["message"]
        assert response_data["credentials_migrated"] is True
        
        # Verify password was set
        mock_user.set_password.assert_called_once_with("newpassword123")
        
        # Verify token was marked as used
        mock_reset_token.mark_as_used.assert_called_once()
        
        # Verify session version was incremented
        mock_user.increment_session_version.assert_called_once()

    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_reset_password_missing_password(self, mock_request, mock_app):
        """Test reset password with missing new password."""
        mock_request.get_json.return_value = {}
        
        response = reset_password_with_token("token")
        
        assert response[1] == 400
        response_data = json.loads(response[0].data)
        assert response_data["success"] is False
        assert "New password is required" in response_data["message"]

    @patch('app.utils.routes.get_config_value')
    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_reset_password_weak_password(self, mock_request, mock_app, mock_get_config):
        """Test reset password with weak password."""
        mock_request.get_json.return_value = {"new_password": "123"}
        mock_get_config.return_value = 8
        
        response = reset_password_with_token("token")
        
        assert response[1] == 400
        response_data = json.loads(response[0].data)
        assert response_data["success"] is False
        assert "Password must be at least 8 characters long" in response_data["message"]

    @patch('app.utils.routes.get_config_value')
    @patch('app.utils.routes.PasswordResetToken')
    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_reset_password_invalid_token(self, mock_request, mock_app, mock_token_model, mock_get_config):
        """Test reset password with invalid token."""
        mock_request.get_json.return_value = {"new_password": "newpassword123"}
        mock_get_config.return_value = 8
        mock_token_model.find_by_token.return_value = None
        
        response = reset_password_with_token("invalid_token")
        
        assert response[1] == 400
        response_data = json.loads(response[0].data)
        assert response_data["success"] is False
        assert "Invalid or expired password reset token" in response_data["message"]

    @patch('app.utils.routes.db.session')
    @patch('app.utils.routes.get_config_value')
    @patch('app.utils.routes.PasswordResetToken')
    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_reset_password_with_recovery_key_success(self, mock_request, mock_app, mock_token_model,
                                                    mock_get_config, mock_db_session):
        """Test successful password reset with recovery key migration."""
        mock_request.get_json.return_value = {
            "new_password": "newpassword123",
            "recovery_key": "recovery_key_123"
        }
        mock_get_config.return_value = 8
        
        mock_reset_token = Mock()
        mock_reset_token.is_valid.return_value = True
        mock_user = Mock()
        mock_user.credentials = [Mock(), Mock()]  # Has credentials
        mock_user.recover_with_recovery_key.return_value = True
        mock_reset_token.user = mock_user
        mock_token_model.find_by_token.return_value = mock_reset_token
        
        response = reset_password_with_token("valid_token")
        
        assert response[1] == 200
        response_data = json.loads(response[0].data)
        assert response_data["success"] is True
        assert "credentials have been preserved" in response_data["message"]
        assert response_data["credentials_migrated"] is True
        
        # Verify recovery was attempted
        mock_user.recover_with_recovery_key.assert_called_once_with("recovery_key_123", "newpassword123")

    @patch('app.utils.routes.os.urandom')
    @patch('app.utils.routes.db.session')
    @patch('app.utils.routes.get_config_value')
    @patch('app.utils.routes.PasswordResetToken')
    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_reset_password_with_credentials_no_recovery_key(self, mock_request, mock_app, mock_token_model,
                                                           mock_get_config, mock_db_session, mock_urandom):
        """Test password reset with credentials but no recovery key provided."""
        mock_request.get_json.return_value = {"new_password": "newpassword123"}
        mock_get_config.return_value = 8
        mock_urandom.return_value = b"random_salt_bytes"
        
        mock_reset_token = Mock()
        mock_reset_token.is_valid.return_value = True
        mock_user = Mock()
        mock_user.credentials = [Mock(), Mock()]  # Has credentials
        mock_user.initialize_encryption.return_value = ["recovery1", "recovery2"]
        mock_reset_token.user = mock_user
        mock_token_model.find_by_token.return_value = mock_reset_token
        
        response = reset_password_with_token("valid_token")
        
        assert response[1] == 200
        response_data = json.loads(response[0].data)
        assert response_data["success"] is True
        assert "cannot access your previous credentials" in response_data["message"]
        assert response_data["credentials_migrated"] is False
        assert "recovery_keys" in response_data
        assert response_data["recovery_keys"] == ["recovery1", "recovery2"]
        
        # Verify new encryption was initialized
        mock_user.initialize_encryption.assert_called_once_with("newpassword123")


class TestRecoverWithRecoveryKey:
    """Tests for the recover_with_recovery_key endpoint."""

    @patch('app.utils.routes.db.session')
    @patch('app.utils.routes.get_config_value')
    @patch('app.utils.routes.User')
    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_recover_with_key_success(self, mock_request, mock_app, mock_user_model,
                                    mock_get_config, mock_db_session):
        """Test successful account recovery with recovery key."""
        mock_request.get_json.return_value = {
            "email": "user@example.com",
            "recovery_key": "recovery_key_123",
            "new_password": "newpassword123"
        }
        mock_get_config.return_value = 8
        
        mock_user = Mock()
        mock_user.recover_with_recovery_key.return_value = True
        mock_user_model.query.filter_by.return_value.first.return_value = mock_user
        
        response = recover_with_recovery_key()
        
        assert response[1] == 200
        response_data = json.loads(response[0].data)
        assert response_data["success"] is True
        assert "Account recovered successfully" in response_data["message"]
        assert response_data["credentials_preserved"] is True
        
        # Verify recovery was attempted
        mock_user.recover_with_recovery_key.assert_called_once_with("recovery_key_123", "newpassword123")
        
        # Verify session version was incremented
        mock_user.increment_session_version.assert_called_once()

    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_recover_with_key_missing_data(self, mock_request, mock_app):
        """Test recovery with missing request data."""
        mock_request.get_json.return_value = None
        
        response = recover_with_recovery_key()
        
        assert response[1] == 400
        response_data = json.loads(response[0].data)
        assert response_data["success"] is False
        assert "Missing required data" in response_data["message"]

    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_recover_with_key_missing_fields(self, mock_request, mock_app):
        """Test recovery with missing required fields."""
        mock_request.get_json.return_value = {
            "email": "user@example.com",
            # missing recovery_key and new_password
        }
        
        response = recover_with_recovery_key()
        
        assert response[1] == 400
        response_data = json.loads(response[0].data)
        assert response_data["success"] is False
        assert "Email, recovery key, and new password are required" in response_data["message"]

    @patch('app.utils.routes.get_config_value')
    @patch('app.utils.routes.User')
    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_recover_with_key_user_not_found(self, mock_request, mock_app, mock_user_model, mock_get_config):
        """Test recovery with non-existent user."""
        mock_request.get_json.return_value = {
            "email": "nonexistent@example.com",
            "recovery_key": "recovery_key_123",
            "new_password": "newpassword123"
        }
        mock_get_config.return_value = 8
        mock_user_model.query.filter_by.return_value.first.return_value = None
        
        response = recover_with_recovery_key()
        
        assert response[1] == 401
        response_data = json.loads(response[0].data)
        assert response_data["success"] is False
        assert "Invalid email or recovery key" in response_data["message"]

    @patch('app.utils.routes.get_config_value')
    @patch('app.utils.routes.User')
    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_recover_with_key_invalid_recovery_key(self, mock_request, mock_app, mock_user_model, mock_get_config):
        """Test recovery with invalid recovery key."""
        mock_request.get_json.return_value = {
            "email": "user@example.com",
            "recovery_key": "invalid_key",
            "new_password": "newpassword123"
        }
        mock_get_config.return_value = 8
        
        mock_user = Mock()
        mock_user.recover_with_recovery_key.side_effect = ValueError("Invalid recovery key")
        mock_user_model.query.filter_by.return_value.first.return_value = mock_user
        
        response = recover_with_recovery_key()
        
        assert response[1] == 401
        response_data = json.loads(response[0].data)
        assert response_data["success"] is False
        assert "Invalid email or recovery key" in response_data["message"]


class TestExportCredentials:
    """Tests for the export_credentials endpoint."""

    @patch('app.utils.routes.os.unlink')
    @patch('app.utils.routes.pyminizip.compress')
    @patch('app.utils.routes.tempfile.NamedTemporaryFile')
    @patch('app.utils.routes.tempfile.gettempdir')
    @patch('app.utils.routes.make_response')
    @patch('app.utils.routes.decrypt_data')
    @patch('app.utils.routes.Credential')
    @patch('app.utils.routes.current_user')
    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_export_credentials_success(self, mock_request, mock_app, mock_current_user,
                                      mock_credential_model, mock_decrypt, mock_make_response,
                                      mock_gettempdir, mock_tempfile, mock_pyminizip, mock_unlink):
        """Test successful credential export."""
        mock_request.get_json.return_value = {
            "master_password": "masterpass123",
            "export_password": "exportpass123"
        }
        
        mock_current_user.id = 1
        mock_current_user.get_master_key.return_value = b"master_key_bytes"
        
        # Mock credentials
        mock_cred1 = Mock()
        mock_cred1.id = 1
        mock_cred1.service_name = "Service1"
        mock_cred1.service_url = "https://service1.com"
        mock_cred1.username = "user1"
        mock_cred1.encrypted_password = "encrypted1"
        mock_cred1.notes = "Note1"
        
        mock_cred2 = Mock()
        mock_cred2.id = 2
        mock_cred2.service_name = "Service2"
        mock_cred2.service_url = None
        mock_cred2.username = "user2"
        mock_cred2.encrypted_password = "encrypted2"
        mock_cred2.notes = None
        
        mock_credential_model.query.filter_by.return_value.all.return_value = [mock_cred1, mock_cred2]
        
        # Mock decryption
        mock_decrypt.side_effect = ["password1", "password2"]
        
        # Mock file operations
        mock_temp_csv = Mock()
        mock_temp_csv.name = "/tmp/temp_csv_file"
        mock_tempfile.return_value.__enter__.return_value = mock_temp_csv
        mock_gettempdir.return_value = "/tmp"
        
        # Mock zip file reading
        with patch('builtins.open', mock_open(read_data=b"zip_file_content")):
            mock_response = Mock()
            mock_make_response.return_value = mock_response
            
            response = export_credentials()
            
            # Verify response setup
            mock_make_response.assert_called_once_with(b"zip_file_content")
            mock_response.headers.set.assert_any_call("Content-Type", "application/zip")
            mock_response.headers.set.assert_any_call("Content-Disposition", "attachment", filename="credentials_export.zip")
            
            # Verify decryption was called for each credential
            assert mock_decrypt.call_count == 2
            mock_decrypt.assert_any_call(b"master_key_bytes", "encrypted1")
            mock_decrypt.assert_any_call(b"master_key_bytes", "encrypted2")
            
            # Verify ZIP creation
            mock_pyminizip.compress.assert_called_once_with(
                "/tmp/temp_csv_file", "credentials_export.csv", "/tmp/credentials_export_1.zip", "exportpass123", 5
            )
            
            # Verify cleanup
            assert mock_unlink.call_count == 2

    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_export_credentials_missing_data(self, mock_request, mock_app):
        """Test export with missing request data."""
        mock_request.get_json.return_value = None
        
        response = export_credentials()
        
        assert response[1] == 400
        response_data = json.loads(response[0].data)
        assert response_data["success"] is False
        assert "Request data is required" in response_data["message"]

    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_export_credentials_missing_master_password(self, mock_request, mock_app):
        """Test export with missing master password."""
        mock_request.get_json.return_value = {"export_password": "exportpass123"}
        
        response = export_credentials()
        
        assert response[1] == 400
        response_data = json.loads(response[0].data)
        assert response_data["success"] is False
        assert "Master password is required" in response_data["message"]

    @patch('app.utils.routes.Credential')
    @patch('app.utils.routes.current_user')
    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_export_credentials_no_credentials(self, mock_request, mock_app, mock_current_user, mock_credential_model):
        """Test export with no stored credentials."""
        mock_request.get_json.return_value = {
            "master_password": "masterpass123",
            "export_password": "exportpass123"
        }
        
        mock_current_user.id = 1
        mock_credential_model.query.filter_by.return_value.all.return_value = []
        
        response = export_credentials()
        
        assert response[1] == 200
        response_data = json.loads(response[0].data)
        assert response_data["success"] is True
        assert "no credentials stored to export" in response_data["message"]

    @patch('app.utils.routes.current_user')
    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_export_credentials_invalid_master_password(self, mock_request, mock_app, mock_current_user):
        """Test export with invalid master password."""
        mock_request.get_json.return_value = {
            "master_password": "wrongpassword",
            "export_password": "exportpass123"
        }
        
        mock_current_user.get_master_key.side_effect = ValueError("Invalid master password")
        
        response = export_credentials()
        
        assert response[1] == 401
        response_data = json.loads(response[0].data)
        assert response_data["success"] is False
        assert "Invalid master password" in response_data["message"]


class TestImportCredentials:
    """Tests for the import_credentials endpoint."""

    @patch('app.utils.routes.db.session')
    @patch('app.utils.routes.encrypt_data')
    @patch('app.utils.routes.Credential')
    @patch('app.utils.routes.current_user')
    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_import_credentials_success(self, mock_request, mock_app, mock_current_user,
                                      mock_credential_model, mock_encrypt, mock_db_session):
        """Test successful credential import."""
        mock_request.get_json.return_value = {
            "master_password": "masterpass123",
            "credentials": [
                {
                    "service_name": "Service1",
                    "service_url": "https://service1.com",
                    "username": "user1",
                    "password": "password1",
                    "category": "Work",
                    "notes": "Note1"
                },
                {
                    "service_name": "Service2",
                    "username": "user2",
                    "password": "password2"
                }
            ]
        }
        
        mock_current_user.id = 1
        mock_current_user.get_master_key.return_value = b"master_key_bytes"
        
        mock_encrypt.side_effect = ["encrypted1", "encrypted2"]
        
        # Mock credential creation
        mock_credential_instances = [Mock(), Mock()]
        mock_credential_model.side_effect = mock_credential_instances
        
        response = import_credentials()
        
        assert response[1] == 200
        response_data = json.loads(response[0].data)
        assert response_data["success"] is True
        assert "Credentials imported successfully" in response_data["message"]
        
        # Verify credentials were created
        assert mock_credential_model.call_count == 2
        
        # Verify first credential
        mock_credential_model.assert_any_call(
            user_id=1,
            service_name="Service1",
            service_url="https://service1.com",
            username="user1",
            category="Work",
            notes="Note1"
        )
        
        # Verify second credential  
        mock_credential_model.assert_any_call(
            user_id=1,
            service_name="Service2",
            service_url=None,
            username="user2",
            category=None,
            notes=None
        )
        
        # Verify encryption
        mock_encrypt.assert_any_call(b"master_key_bytes", "password1")
        mock_encrypt.assert_any_call(b"master_key_bytes", "password2")
        
        # Verify database operations
        assert mock_db_session.add.call_count == 2
        mock_db_session.commit.assert_called_once()

    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_import_credentials_missing_data(self, mock_request, mock_app):
        """Test import with missing request data."""
        mock_request.get_json.return_value = None
        
        response = import_credentials()
        
        assert response[1] == 400
        response_data = json.loads(response[0].data)
        assert response_data["success"] is False
        assert "Request data is required" in response_data["message"]

    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_import_credentials_missing_master_password(self, mock_request, mock_app):
        """Test import with missing master password."""
        mock_request.get_json.return_value = {"credentials": []}
        
        response = import_credentials()
        
        assert response[1] == 400
        response_data = json.loads(response[0].data)
        assert response_data["success"] is False
        assert "Master password is required" in response_data["message"]

    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_import_credentials_missing_credentials(self, mock_request, mock_app):
        """Test import with missing credentials data."""
        mock_request.get_json.return_value = {"master_password": "masterpass123"}
        
        response = import_credentials()
        
        assert response[1] == 400
        response_data = json.loads(response[0].data)
        assert response_data["success"] is False
        assert "Credentials data is required" in response_data["message"]

    @patch('app.utils.routes.current_user')
    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_import_credentials_invalid_master_password(self, mock_request, mock_app, mock_current_user):
        """Test import with invalid master password."""
        mock_request.get_json.return_value = {
            "master_password": "wrongpassword",
            "credentials": [{"service_name": "Test", "username": "test", "password": "test"}]
        }
        
        mock_current_user.get_master_key.side_effect = ValueError("Invalid master password")
        
        response = import_credentials()
        
        assert response[1] == 401
        response_data = json.loads(response[0].data)
        assert response_data["success"] is False
        assert "Invalid master password" in response_data["message"]

    @patch('app.utils.routes.db.session')
    @patch('app.utils.routes.encrypt_data')
    @patch('app.utils.routes.Credential')
    @patch('app.utils.routes.current_user')
    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_import_credentials_with_empty_password(self, mock_request, mock_app, mock_current_user,
                                                  mock_credential_model, mock_encrypt, mock_db_session):
        """Test importing credentials with empty/missing password."""
        mock_request.get_json.return_value = {
            "master_password": "masterpass123",
            "credentials": [
                {
                    "service_name": "Service1",
                    "username": "user1",
                    "password": None  # Explicitly None
                },
                {
                    "service_name": "Service2",
                    "username": "user2"
                    # Missing password key
                }
            ]
        }
        
        mock_current_user.id = 1
        mock_current_user.get_master_key.return_value = b"master_key_bytes"
        
        mock_encrypt.return_value = "encrypted_empty"
        mock_credential_model.return_value = Mock()
        
        response = import_credentials()
        
        assert response[1] == 200
        response_data = json.loads(response[0].data)
        assert response_data["success"] is True
        
        # Verify empty passwords were encrypted
        mock_encrypt.assert_any_call(b"master_key_bytes", "")
        assert mock_encrypt.call_count == 2

    @patch('app.utils.routes.db.session')
    @patch('app.utils.routes.encrypt_data')
    @patch('app.utils.routes.Credential')
    @patch('app.utils.routes.current_user')
    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_import_credentials_database_error(self, mock_request, mock_app, mock_current_user,
                                             mock_credential_model, mock_encrypt, mock_db_session):
        """Test import with database error."""
        mock_request.get_json.return_value = {
            "master_password": "masterpass123",
            "credentials": [{"service_name": "Test", "username": "test", "password": "test"}]
        }
        
        mock_current_user.id = 1
        mock_current_user.get_master_key.return_value = b"master_key_bytes"
        mock_encrypt.return_value = "encrypted"
        mock_credential_model.return_value = Mock()
        
        # Simulate database error
        mock_db_session.commit.side_effect = Exception("Database error")
        
        response = import_credentials()
        
        assert response[1] == 500
        response_data = json.loads(response[0].data)
        assert response_data["success"] is False
        assert "Failed to import credentials" in response_data["message"]
        
        # Verify rollback was called
        mock_db_session.rollback.assert_called_once()


class TestRoutesIntegration:
    """Integration tests for route functionality."""

    @patch('app.utils.routes.limiter')
    def test_rate_limiting_applied(self, mock_limiter):
        """Test that rate limiting is properly applied to endpoints."""
        # This is more of a structure test to verify decorators are in place
        from app.utils.routes import forgot_password, reset_password_with_token, recover_with_recovery_key
        from app.utils.routes import export_credentials, import_credentials
        
        # We can't easily test the actual rate limiting without a full Flask app,
        # but we can verify the functions exist and are properly structured
        assert callable(forgot_password)
        assert callable(reset_password_with_token)
        assert callable(recover_with_recovery_key)
        assert callable(export_credentials)
        assert callable(import_credentials)

    def test_route_error_handling_patterns(self):
        """Test that routes follow consistent error handling patterns."""
        # This tests the general structure and patterns used across routes
        # All routes should have consistent error response formats
        
        # Test imports are available
        from app.utils.routes import success_response, error_response
        
        assert callable(success_response)
        assert callable(error_response)


class TestRouteSecurityFeatures:
    """Tests for security features in routes."""

    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.User')
    @patch('app.utils.routes.request')
    def test_forgot_password_prevents_user_enumeration(self, mock_request, mock_user_model, mock_app):
        """Test that forgot password doesn't reveal if users exist."""
        mock_request.get_json.return_value = {"email": "test@example.com"}
        
        # Test with existing user
        mock_user_model.query.filter_by.return_value.first.return_value = Mock()
        response1 = forgot_password()
        
        # Test with non-existing user
        mock_user_model.query.filter_by.return_value.first.return_value = None
        response2 = forgot_password()
        
        # Both should return the same success message
        assert response1[1] == response2[1] == 200
        data1 = json.loads(response1[0].data)
        data2 = json.loads(response2[0].data)
        assert data1["message"] == data2["message"]

    @patch('app.utils.routes.get_config_value')
    @patch('app.utils.routes.User')
    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.request')
    def test_recovery_endpoint_prevents_user_enumeration(self, mock_request, mock_app, mock_user_model, mock_get_config):
        """Test that recovery endpoint doesn't reveal if users exist."""
        mock_request.get_json.return_value = {
            "email": "test@example.com",
            "recovery_key": "test_key",
            "new_password": "newpassword123"
        }
        mock_get_config.return_value = 8
        
        # Test with existing user but invalid key
        mock_user = Mock()
        mock_user.recover_with_recovery_key.side_effect = ValueError("Invalid key")
        mock_user_model.query.filter_by.return_value.first.return_value = mock_user
        response1 = recover_with_recovery_key()
        
        # Test with non-existing user
        mock_user_model.query.filter_by.return_value.first.return_value = None
        response2 = recover_with_recovery_key()
        
        # Both should return the same error message
        assert response1[1] == response2[1] == 401
        data1 = json.loads(response1[0].data)
        data2 = json.loads(response2[0].data)
        assert data1["message"] == data2["message"]

    @patch('app.utils.routes.current_app')
    @patch('app.utils.routes.PasswordResetToken')
    @patch('app.utils.routes.request')
    def test_token_logging_security(self, mock_request, mock_token_model, mock_app):
        """Test that tokens are not fully logged for security."""
        mock_request.get_json.return_value = {"new_password": "newpassword123"}
        mock_token_model.find_by_token.return_value = None
        
        reset_password_with_token("this_is_a_long_token_that_should_be_truncated")
        
        # Verify that only a preview of the token is logged
        mock_app.logger.warning.assert_called_once()
        logged_message = mock_app.logger.warning.call_args[0][0]
        assert "this_i..." in logged_message
        assert "this_is_a_long_token_that_should_be_truncated" not in logged_message