"""
Unit tests for backup and restore functionality.

Tests the backup creation and restore endpoints.
"""

import pytest
import json
import zipfile
import tempfile
import os
from unittest.mock import patch, Mock
from datetime import datetime, timezone

from app.models import db, User, Credential, SharedCredential


class TestBackupRestore:
    """Tests for backup and restore functionality."""
    
    def test_create_backup_success(self, client, app_context):
        """Test successful backup creation."""
        # Create user
        user = User(username="testuser", email="test@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        # Initialize encryption
        user.initialize_encryption("password123")
        
        # Create some credentials
        from app.utils.encryption import encrypt_data
        master_key = user.get_master_key("password123")
        
        credential1 = Credential(
            user_id=user.id,
            service_name="Gmail",
            username="user@gmail.com",
            encrypted_password=encrypt_data(master_key, "gmail_password"),
            category="email"
        )
        credential2 = Credential(
            user_id=user.id,
            service_name="Facebook",
            username="testuser",
            encrypted_password=encrypt_data(master_key, "fb_password"),
            category="social"
        )
        db.session.add(credential1)
        db.session.add(credential2)
        db.session.commit()
        
        with patch('flask_login.utils._get_user', return_value=user):
            response = client.post('/api/utils/backup',
                                 json={
                                     'master_password': 'password123',
                                     'backup_password': 'backup_pass123'
                                 },
                                 content_type='application/json')
        
        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'application/zip'
        assert 'backup_testuser_' in response.headers['Content-Disposition']
        
        # Verify the ZIP file contains valid data
        assert len(response.data) > 0
    
    def test_create_backup_invalid_master_password(self, client, app_context):
        """Test backup creation with invalid master password."""
        # Create user
        user = User(username="testuser2", email="test2@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        user.initialize_encryption("password123")
        
        with patch('flask_login.utils._get_user', return_value=user):
            response = client.post('/api/utils/backup',
                                 json={
                                     'master_password': 'wrong_password',
                                     'backup_password': 'backup_pass123'
                                 },
                                 content_type='application/json')
        
        assert response.status_code == 401
        response_data = json.loads(response.data)
        assert 'password' in response_data['message'].lower()
    
    def test_create_backup_missing_backup_password(self, client, app_context):
        """Test backup creation without backup password."""
        user = User(username="testuser3", email="test3@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        with patch('flask_login.utils._get_user', return_value=user):
            response = client.post('/api/utils/backup',
                                 json={
                                     'master_password': 'password123'
                                 },
                                 content_type='application/json')
        
        assert response.status_code == 400
        response_data = json.loads(response.data)
        assert 'backup password' in response_data['message'].lower()
    
    def test_restore_backup_success(self, client, app_context):
        """Test successful backup restore."""
        # Create user
        user = User(username="testuser4", email="test4@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        user.initialize_encryption("password123")
        
        # Create mock backup data
        backup_data = {
            "version": "1.0",
            "created_at": datetime.now().isoformat(),
            "user_info": {
                "username": "testuser",
                "email": "test@example.com"
            },
            "credentials": [
                {
                    "service_name": "Gmail",
                    "username": "user@gmail.com",
                    "password": "gmail_password",
                    "category": "email",
                    "notes": "Personal email"
                },
                {
                    "service_name": "Facebook", 
                    "username": "testuser",
                    "password": "fb_password",
                    "category": "social"
                }
            ]
        }
        
        with patch('flask_login.utils._get_user', return_value=user):
            response = client.post('/api/utils/restore',
                                 json={
                                     'master_password': 'password123',
                                     'backup_data': backup_data,
                                     'skip_existing': True
                                 },
                                 content_type='application/json')
        
        assert response.status_code == 200
        response_data = json.loads(response.data)
        assert response_data['status'] == 'success'
        assert response_data['data']['restored_count'] == 2
        assert response_data['data']['error_count'] == 0
        
        # Verify credentials were created
        credentials = Credential.query.filter_by(user_id=user.id).all()
        assert len(credentials) == 2
        
        # Verify passwords were encrypted correctly
        master_key = user.get_master_key("password123")
        from app.utils.encryption import decrypt_data
        gmail_cred = Credential.query.filter_by(service_name="Gmail").first()
        decrypted_password = decrypt_data(master_key, gmail_cred.encrypted_password)
        assert decrypted_password == "gmail_password"
    
    def test_restore_backup_skip_existing(self, client, app_context):
        """Test restore with skip_existing option."""
        # Create user
        user = User(username="testuser5", email="test5@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        user.initialize_encryption("password123")
        
        # Create an existing credential
        from app.utils.encryption import encrypt_data
        master_key = user.get_master_key("password123")
        existing_cred = Credential(
            user_id=user.id,
            service_name="Gmail",
            username="user@gmail.com",
            encrypted_password=encrypt_data(master_key, "existing_password")
        )
        db.session.add(existing_cred)
        db.session.commit()
        
        # Create backup data with same credential
        backup_data = {
            "version": "1.0",
            "credentials": [
                {
                    "service_name": "Gmail",
                    "username": "user@gmail.com", 
                    "password": "new_password"
                }
            ]
        }
        
        with patch('flask_login.utils._get_user', return_value=user):
            response = client.post('/api/utils/restore',
                                 json={
                                     'master_password': 'password123',
                                     'backup_data': backup_data,
                                     'skip_existing': True
                                 },
                                 content_type='application/json')
        
        assert response.status_code == 200
        response_data = json.loads(response.data)
        assert response_data['data']['skipped_count'] == 1
        assert response_data['data']['restored_count'] == 0
        
        # Verify original password is unchanged
        from app.utils.encryption import decrypt_data
        gmail_cred = Credential.query.filter_by(service_name="Gmail").first()
        decrypted_password = decrypt_data(master_key, gmail_cred.encrypted_password)
        assert decrypted_password == "existing_password"
    
    def test_restore_backup_invalid_master_password(self, client, app_context):
        """Test restore with invalid master password."""
        user = User(username="testuser6", email="test6@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        backup_data = {
            "version": "1.0",
            "credentials": []
        }
        
        with patch('flask_login.utils._get_user', return_value=user):
            response = client.post('/api/utils/restore',
                                 json={
                                     'master_password': 'wrong_password',
                                     'backup_data': backup_data
                                 },
                                 content_type='application/json')
        
        assert response.status_code == 401
        response_data = json.loads(response.data)
        assert 'password' in response_data['message'].lower()
    
    def test_restore_backup_invalid_format(self, client, app_context):
        """Test restore with invalid backup data format."""
        user = User(username="testuser7", email="test7@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        user.initialize_encryption("password123")
        
        # Invalid backup data (missing credentials key)
        backup_data = {
            "version": "1.0",
            "user_info": {}
        }
        
        with patch('flask_login.utils._get_user', return_value=user):
            response = client.post('/api/utils/restore',
                                 json={
                                     'master_password': 'password123',
                                     'backup_data': backup_data
                                 },
                                 content_type='application/json')
        
        assert response.status_code == 400
        response_data = json.loads(response.data)
        assert 'invalid backup data format' in response_data['message'].lower()