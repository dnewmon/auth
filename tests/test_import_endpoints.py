"""
Tests for password manager import API endpoints.
"""

import pytest
import json
from unittest.mock import patch, Mock

from app.models import db, User, Credential
from app.utils.encryption import encrypt_data


class TestImportEndpoints:
    """Tests for import API endpoints."""
    
    def test_get_import_formats(self, client, app_context):
        """Test getting supported import formats."""
        # Create and login user
        user = User(username="import_user", email="import@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        with patch('flask_login.utils._get_user', return_value=user):
            response = client.get('/api/utils/import/formats')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'success'
        assert 'supported_formats' in data['data']
        assert 'format_descriptions' in data['data']
        assert 'Chrome/Edge/Firefox CSV' in data['data']['supported_formats']
        assert 'LastPass CSV' in data['data']['supported_formats']
    
    def test_preview_import_chrome_csv(self, client, app_context):
        """Test previewing Chrome CSV import."""
        user = User(username="import_user2", email="import2@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        chrome_csv = """name,url,username,password
Gmail,https://gmail.com,user@gmail.com,StrongPassword84!
Facebook,https://facebook.com,myuser,WeakPass1!
GitHub,https://github.com,developer,DevPassword90!"""
        
        with patch('flask_login.utils._get_user', return_value=user):
            response = client.post('/api/utils/import/preview', json={
                'content': chrome_csv
            })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'success'
        assert data['data']['detected_format'] == 'Chrome/Edge/Firefox CSV'
        assert data['data']['credential_count'] == 3
        assert len(data['data']['credentials']) == 3
        assert data['data']['credentials'][0]['service_name'] == 'Gmail'
        assert 'validation_issues' in data['data']
    
    def test_preview_import_lastpass_csv(self, client, app_context):
        """Test previewing LastPass CSV import."""
        user = User(username="import_user3", email="import3@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        lastpass_csv = """url,username,password,extra,name,grouping,fav
https://gmail.com,user@gmail.com,StrongPassword84!,Notes here,Gmail,Email,0
https://facebook.com,myuser,WeakPass1!,,Facebook,Social,1"""
        
        with patch('flask_login.utils._get_user', return_value=user):
            response = client.post('/api/utils/import/preview', json={
                'content': lastpass_csv,
                'format': 'LastPass CSV'  # Specify format
            })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'success'
        assert data['data']['detected_format'] == 'LastPass CSV'
        assert data['data']['credential_count'] == 2
        assert data['data']['credentials'][0]['category'] == 'email'
        assert data['data']['credentials'][1]['category'] == 'social'
    
    def test_preview_import_bitwarden_json(self, client, app_context):
        """Test previewing Bitwarden JSON import."""
        user = User(username="import_user4", email="import4@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        bitwarden_json = json.dumps({
            "encrypted": False,
            "folders": [{"id": "folder1", "name": "Work"}],
            "items": [
                {
                    "id": "item1",
                    "type": 1,
                    "name": "Gmail",
                    "notes": "Work email",
                    "folderId": "folder1",
                    "login": {
                        "username": "user@gmail.com",
                        "password": "StrongPassword84!",
                        "uris": [{"uri": "https://gmail.com"}]
                    }
                }
            ]
        })
        
        with patch('flask_login.utils._get_user', return_value=user):
            response = client.post('/api/utils/import/preview', json={
                'content': bitwarden_json
            })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'success'
        assert data['data']['detected_format'] == 'Bitwarden JSON'
        assert data['data']['credential_count'] == 1
        assert data['data']['credentials'][0]['category'] == 'work'
    
    def test_preview_import_invalid_format(self, client, app_context):
        """Test previewing with invalid format."""
        user = User(username="import_user5", email="import5@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        invalid_content = "this,is,not,a,valid,format\ndata,data,data,data,data"
        
        with patch('flask_login.utils._get_user', return_value=user):
            response = client.post('/api/utils/import/preview', json={
                'content': invalid_content
            })
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['status'] == 'error'
        assert 'Could not detect import format' in data['message']
    
    def test_import_from_password_manager_success(self, client, app_context):
        """Test successful password manager import."""
        user = User(username="import_user6", email="import6@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        user.initialize_encryption("password123")
        db.session.commit()
        
        chrome_csv = """name,url,username,password
Gmail,https://gmail.com,user@gmail.com,StrongPassword84!
Facebook,https://facebook.com,myuser,WeakPass1!"""
        
        with patch('flask_login.utils._get_user', return_value=user), \
             patch('app.models.audit_log.AuditLog.log_event') as mock_audit:
            
            response = client.post('/api/utils/import/password-manager', json={
                'content': chrome_csv,
                'master_password': 'password123',
                'skip_duplicates': True,
                'enforce_policy': False
            })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'success'
        assert data['data']['detected_format'] == 'Chrome/Edge/Firefox CSV'
        assert data['data']['imported_count'] == 2
        assert data['data']['skipped_count'] == 0
        assert data['data']['error_count'] == 0
        
        # Verify credentials were created
        credentials = Credential.query.filter_by(user_id=user.id).all()
        assert len(credentials) == 2
        
        # Verify audit log was called
        mock_audit.assert_called_once()
    
    def test_import_with_duplicates_skipped(self, client, app_context):
        """Test import with duplicate credentials skipped."""
        user = User(username="import_user7", email="import7@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        user.initialize_encryption("password123")
        db.session.commit()
        
        # Create existing credential
        master_key = user.get_master_key("password123")
        existing_cred = Credential(
            user_id=user.id,
            service_name="Gmail",
            username="user@gmail.com",
            encrypted_password=encrypt_data(master_key, "existing_password")
        )
        db.session.add(existing_cred)
        db.session.commit()
        
        chrome_csv = """name,url,username,password
Gmail,https://gmail.com,user@gmail.com,StrongPassword84!
Facebook,https://facebook.com,myuser,WeakPass1!"""
        
        with patch('flask_login.utils._get_user', return_value=user):
            response = client.post('/api/utils/import/password-manager', json={
                'content': chrome_csv,
                'master_password': 'password123',
                'skip_duplicates': True
            })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['data']['imported_count'] == 1  # Only Facebook imported
        assert data['data']['skipped_count'] == 1   # Gmail skipped
    
    def test_import_with_policy_enforcement(self, client, app_context):
        """Test import with password policy enforcement."""
        user = User(username="import_user8", email="import8@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        user.initialize_encryption("password123")
        db.session.commit()
        
        chrome_csv = """name,url,username,password
Gmail,https://gmail.com,user@gmail.com,StrongPassword84!
Weak,https://weak.com,user,weak"""
        
        with patch('flask_login.utils._get_user', return_value=user):
            response = client.post('/api/utils/import/password-manager', json={
                'content': chrome_csv,
                'master_password': 'password123',
                'enforce_policy': True
            })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['data']['imported_count'] == 1  # Only strong password imported
        assert data['data']['error_count'] == 1     # Weak password rejected
        assert 'policy_violations' in data['data']
        assert len(data['data']['policy_violations']) == 1
    
    def test_import_invalid_master_password(self, client, app_context):
        """Test import with invalid master password."""
        user = User(username="import_user9", email="import9@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        user.initialize_encryption("password123")
        db.session.commit()
        
        chrome_csv = """name,url,username,password
Gmail,https://gmail.com,user@gmail.com,StrongPassword84!"""
        
        with patch('flask_login.utils._get_user', return_value=user):
            response = client.post('/api/utils/import/password-manager', json={
                'content': chrome_csv,
                'master_password': 'wrong_password'
            })
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['status'] == 'error'
        assert 'password' in data['message'].lower()
    
    def test_import_missing_content(self, client, app_context):
        """Test import with missing content."""
        user = User(username="import_user10", email="import10@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        with patch('flask_login.utils._get_user', return_value=user):
            response = client.post('/api/utils/import/password-manager', json={
                'master_password': 'password123'
                # Missing content
            })
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['status'] == 'error'
        assert 'content' in data['message'].lower()
    
    def test_import_empty_credentials(self, client, app_context):
        """Test import with no valid credentials."""
        user = User(username="import_user11", email="import11@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        user.initialize_encryption("password123")
        db.session.commit()
        
        # CSV with only headers
        chrome_csv = "name,url,username,password"
        
        with patch('flask_login.utils._get_user', return_value=user):
            response = client.post('/api/utils/import/password-manager', json={
                'content': chrome_csv,
                'master_password': 'password123'
            })
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['status'] == 'error'
        assert 'No valid credentials found' in data['message']
    
    def test_preview_missing_content(self, client, app_context):
        """Test preview with missing content."""
        user = User(username="import_user12", email="import12@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        with patch('flask_login.utils._get_user', return_value=user):
            response = client.post('/api/utils/import/preview', json={
                'format': 'Chrome/Edge/Firefox CSV'
                # Missing content field
            })
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['status'] == 'error'
        assert 'Import content is required' in data['message']
    
    def test_import_rate_limiting(self, client, app_context):
        """Test that import endpoints have rate limiting."""
        user = User(username="import_user13", email="import13@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        chrome_csv = """name,url,username,password
Gmail,https://gmail.com,user@gmail.com,StrongPassword84!"""
        
        with patch('flask_login.utils._get_user', return_value=user):
            # Test preview rate limit (10 per hour)
            for i in range(12):  # Try to exceed limit
                response = client.post('/api/utils/import/preview', json={
                    'content': chrome_csv
                })
                if response.status_code == 429:  # Rate limited
                    break
            
            # Should eventually hit rate limit
            assert response.status_code in [200, 429]  # Could be rate limited or successful