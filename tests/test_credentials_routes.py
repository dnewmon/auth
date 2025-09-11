"""
Unit tests for app/credentials/routes.py
"""

import pytest
import json
import time
import uuid
from unittest.mock import patch, MagicMock
from flask import session
from app import db
from app.models.user import User
from app.models.credential import Credential
from app.utils.master_verification import MasterVerificationManager


def make_unique_username(base="testuser"):
    """Generate a unique username for testing."""
    return f"{base}_{str(uuid.uuid4())[:8]}"


@pytest.fixture
def test_user(app_context):
    """Create a test user with encryption initialized."""
    username = make_unique_username()
    email = f'{uuid.uuid4()}@example.com'
    user = User(
        username=username,
        email=email,
        encryption_salt=b"test_salt_16_bytes_exactly"
    )
    user.set_password("testpassword")
    db.session.add(user)
    db.session.commit()
    
    # Initialize encryption
    recovery_keys = user.initialize_encryption("testpassword")
    db.session.commit()
    
    yield user
    
    # Cleanup
    try:
        db.session.delete(user)
        db.session.commit()
    except:
        db.session.rollback()


@pytest.fixture
def test_credential(app_context, test_user):
    """Create a test credential for the test user."""
    # Get master key and encrypt a test password
    master_key = test_user.get_master_key("testpassword")
    from app.utils.encryption import encrypt_data
    encrypted_password = encrypt_data(master_key, "secretpassword")
    
    credential = Credential(
        user_id=test_user.id,
        service_name="Test Service",
        service_url="https://test.com",
        username="testusername",
        encrypted_password=encrypted_password,
        notes="Test notes",
        category="work"
    )
    db.session.add(credential)
    db.session.commit()
    
    yield credential
    
    # Cleanup
    try:
        db.session.delete(credential)
        db.session.commit()
    except:
        db.session.rollback()


class TestVerifyMasterPassword:
    """Test the /verify-master endpoint."""
    
    def test_verify_master_password_success(self, client, test_user):
        """Test successful master password verification."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                response = client.post(
                    '/api/credentials/verify-master',
                    json={'master_password': 'testpassword'},
                    content_type='application/json'
                )
                
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['status'] == "success"
                assert data['data']['message'] == "Master password verified."

    def test_verify_master_password_invalid(self, client, test_user):
        """Test verification with invalid master password."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                response = client.post(
                    '/api/credentials/verify-master',
                    json={'master_password': 'wrongpassword'},
                    content_type='application/json'
                )
                
                assert response.status_code == 401
                data = json.loads(response.data)
                assert data['status'] == "error"
                assert data['message'] == "Invalid master password."

    def test_verify_master_password_missing_password(self, client, test_user):
        """Test verification without providing password."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                response = client.post(
                    '/api/credentials/verify-master',
                    json={},
                    content_type='application/json'
                )
                
                assert response.status_code == 400
                data = json.loads(response.data)
                assert data['status'] == "error"
                assert data['message'] == "Master password is required."

    def test_verify_master_password_no_json(self, client, test_user):
        """Test verification with empty JSON data."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                response = client.post(
                    '/api/credentials/verify-master',
                    json={},
                    content_type='application/json'
                )
                
                assert response.status_code == 400
                data = json.loads(response.data)
                assert data['status'] == "error"
                assert data['message'] == "Master password is required."

    def test_verify_master_password_unauthenticated(self, client, test_user):
        """Test verification without authentication."""
        # Don't mock anything - test actual unauthenticated request
        response = client.post(
            '/api/credentials/verify-master',
            json={'master_password': 'testpassword'},
            content_type='application/json'
        )
        
        # Flask-Login redirects unauthenticated users
        assert response.status_code == 302


class TestCheckMasterVerificationStatus:
    """Test the /verify-master/status endpoint."""
    
    def test_status_not_verified(self, client, test_user):
        """Test status when master password is not verified."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                response = client.get('/api/credentials/verify-master/status')
                
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['status'] == "success"
                assert data['data']['verified'] is False
                assert data['data']['expires_at'] is None
                assert data['data']['time_remaining'] == 0

    def test_status_verified(self, client, test_user):
        """Test status when master password is verified."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                # First verify the password
                client.post(
                    '/api/credentials/verify-master',
                    json={'master_password': 'testpassword'},
                    content_type='application/json'
                )
                
                response = client.get('/api/credentials/verify-master/status')
                
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['status'] == "success"
                assert data['data']['verified'] is True
                assert data['data']['expires_at'] is not None
                assert data['data']['time_remaining'] > 0

    def test_status_expired_verification(self, client, test_user):
        """Test status when verification has expired."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                # Manually set expired verification in session
                with client.session_transaction() as sess:
                    sess[MasterVerificationManager.SESSION_KEY] = {
                        'verified': True,
                        'timestamp': int(time.time()) - MasterVerificationManager.TIMEOUT_SECONDS - 1
                    }
                
                response = client.get('/api/credentials/verify-master/status')
                
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['status'] == "success"
                assert data['data']['verified'] is False
                assert data['data']['time_remaining'] == 0

    def test_status_unauthenticated(self, client, test_user):
        """Test status without authentication."""
        # Don't mock anything - test actual unauthenticated request
        response = client.get('/api/credentials/verify-master/status')
        
        # Flask-Login redirects unauthenticated users
        assert response.status_code == 302


class TestCreateCredential:
    """Test the credential creation endpoint."""
    
    def test_create_credential_success(self, client, test_user):
        """Test successful credential creation."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                # First verify master password to get session token
                verify_response = client.post(
                    '/api/credentials/verify-master',
                    json={'master_password': 'testpassword'},
                    content_type='application/json'
                )
                session_token = json.loads(verify_response.data)['data']['session_token']
                
                credential_data = {
                    'service_name': 'New Service',
                    'service_url': 'https://newservice.com',
                    'username': 'newuser',
                    'password': 'newpassword',
                    'notes': 'New notes',
                    'category': 'personal',
                    'session_token': session_token
                }
                
                response = client.post(
                    '/api/credentials/',
                    json=credential_data,
                    content_type='application/json'
                )
                
                assert response.status_code == 201
                data = json.loads(response.data)
                assert data['status'] == "success"
                assert data['data']['service_name'] == 'New Service'
                assert data['data']['username'] == 'newuser'
                assert data['data']['category'] == 'personal'
                assert 'id' in data['data']

    def test_create_credential_without_master_verification(self, client, test_user):
        """Test credential creation without master password verification."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                credential_data = {
                    'service_name': 'New Service',
                    'username': 'newuser',
                    'password': 'newpassword',
                    'session_token': 'invalid_token'
                }
                
                response = client.post(
                    '/api/credentials/',
                    json=credential_data,
                    content_type='application/json'
                )
                
                assert response.status_code == 401
                data = json.loads(response.data)
                assert data['status'] == "error"
                assert data['message'] == "Master password verification required."

    def test_create_credential_missing_required_fields(self, client, test_user):
        """Test credential creation with missing required fields."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                # First verify master password
                client.post(
                    '/api/credentials/verify-master',
                    json={'master_password': 'testpassword'},
                    content_type='application/json'
                )
                
                # First get session token
                verify_response = client.post(
                    '/api/credentials/verify-master',
                    json={'master_password': 'testpassword'},
                    content_type='application/json'
                )
                session_token = json.loads(verify_response.data)['data']['session_token']
                
                credential_data = {
                    'service_name': 'New Service',
                    'username': 'newuser',
                    # Missing password
                    'session_token': session_token
                }
                
                response = client.post(
                    '/api/credentials/',
                    json=credential_data,
                    content_type='application/json'
                )
                
                assert response.status_code == 400
                data = json.loads(response.data)
                assert data['status'] == "error"
                assert "Missing required fields: service_name, username, password, session_token" in data['message']

    def test_create_credential_unauthenticated(self, client, test_user):
        """Test credential creation without authentication."""
        # Don't mock anything - test actual unauthenticated request
        credential_data = {
            'service_name': 'New Service',
            'username': 'newuser',
            'password': 'newpassword',
            'master_password': 'testpassword'
        }
        
        response = client.post(
            '/api/credentials/',
            json=credential_data,
            content_type='application/json'
        )
        
        # Flask-Login redirects unauthenticated users
        assert response.status_code == 302


class TestListCredentials:
    """Test the credential listing endpoint."""
    
    def test_list_credentials_success(self, client, test_user, test_credential):
        """Test successful credential listing."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                response = client.get('/api/credentials/')
                
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['status'] == "success"
                assert len(data['data']) == 1
                
                credential = data['data'][0]
                assert credential['id'] == test_credential.id
                assert credential['service_name'] == 'Test Service'
                assert credential['username'] == 'testusername'
                assert credential['service_url'] == 'https://test.com'
                assert credential['category'] == 'work'

    def test_list_credentials_empty(self, client, test_user):
        """Test listing credentials when user has none."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                response = client.get('/api/credentials/')
                
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['status'] == "success"
                assert len(data['data']) == 0

    def test_list_credentials_unauthenticated(self, client, test_user):
        """Test listing credentials without authentication."""
        # Don't mock anything - test actual unauthenticated request
        response = client.get('/api/credentials/')
        
        # Flask-Login redirects unauthenticated users
        assert response.status_code == 302

    def test_list_credentials_multiple_users(self, client, test_user, test_credential, app_context):
        """Test that users only see their own credentials."""
        # Create another user with a credential
        other_username = make_unique_username("otheruser")
        other_email = f'{uuid.uuid4()}@example.com'
        other_user = User(
            username=other_username,
            email=other_email,
            encryption_salt=b"other_salt_16_by"
        )
        other_user.set_password("otherpassword")
        db.session.add(other_user)
        db.session.commit()
        
        other_user.initialize_encryption("otherpassword")
        db.session.commit()
        
        # Create credential for other user
        other_master_key = other_user.get_master_key("otherpassword")
        from app.utils.encryption import encrypt_data
        other_encrypted_password = encrypt_data(other_master_key, "otherpassword")
        
        other_credential = Credential(
            user_id=other_user.id,
            service_name="Other Service",
            username="otheruser",
            encrypted_password=other_encrypted_password
        )
        db.session.add(other_credential)
        db.session.commit()
        
        # Test that test_user only sees their own credential
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                response = client.get('/api/credentials/')
                
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['status'] == "success"
                assert len(data['data']) == 1
                assert data['data'][0]['service_name'] == 'Test Service'


class TestGetCredential:
    """Test the credential retrieval endpoint."""
    
    def test_get_credential_success(self, client, test_user, test_credential):
        """Test successful credential retrieval."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                # First verify master password to get session token
                verify_response = client.post(
                    '/api/credentials/verify-master',
                    json={'master_password': 'testpassword'},
                    content_type='application/json'
                )
                session_token = json.loads(verify_response.data)['data']['session_token']
                
                response = client.post(
                    f'/api/credentials/{test_credential.id}',
                    json={'session_token': session_token},
                    content_type='application/json'
                )
                
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['status'] == "success"
                
                credential = data['data']
                assert credential['id'] == test_credential.id
                assert credential['service_name'] == 'Test Service'
                assert credential['username'] == 'testusername'
                assert credential['password'] == 'secretpassword'  # Decrypted
                assert credential['notes'] == 'Test notes'
                assert credential['category'] == 'work'

    def test_get_credential_invalid_master_password(self, client, test_user, test_credential):
        """Test credential retrieval with invalid session token."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                response = client.post(
                    f'/api/credentials/{test_credential.id}',
                    json={'session_token': 'invalid_token'},
                    content_type='application/json'
                )
                
                assert response.status_code == 401
                data = json.loads(response.data)
                assert data['status'] == "error"
                assert data['message'] == "Invalid session token. Please verify your password again."

    def test_get_credential_missing_master_password(self, client, test_user, test_credential):
        """Test credential retrieval without session token."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                response = client.post(
                    f'/api/credentials/{test_credential.id}',
                    json={},
                    content_type='application/json'
                )
                
                assert response.status_code == 400
                data = json.loads(response.data)
                assert data['status'] == "error"
                assert data['message'] == "Session token required."

    def test_get_credential_not_found(self, client, test_user):
        """Test retrieval of non-existent credential."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                # First verify master password to get session token
                verify_response = client.post(
                    '/api/credentials/verify-master',
                    json={'master_password': 'testpassword'},
                    content_type='application/json'
                )
                session_token = json.loads(verify_response.data)['data']['session_token']
                
                response = client.post(
                    '/api/credentials/99999',
                    json={'session_token': session_token},
                    content_type='application/json'
                )
                
                assert response.status_code == 404

    def test_get_credential_unauthorized_user(self, client, test_user, app_context):
        """Test that users cannot access other users' credentials."""
        # Create another user with a credential
        other_username = make_unique_username("otheruser")
        other_email = f'{uuid.uuid4()}@example.com'
        other_user = User(
            username=other_username,
            email=other_email,
            encryption_salt=b"other_salt_16_by"
        )
        other_user.set_password("otherpassword")
        db.session.add(other_user)
        db.session.commit()
        
        other_user.initialize_encryption("otherpassword")
        db.session.commit()
        
        # Create credential for other user
        other_master_key = other_user.get_master_key("otherpassword")
        from app.utils.encryption import encrypt_data
        other_encrypted_password = encrypt_data(other_master_key, "otherpassword")
        
        other_credential = Credential(
            user_id=other_user.id,
            service_name="Other Service",
            username="otheruser",
            encrypted_password=other_encrypted_password
        )
        db.session.add(other_credential)
        db.session.commit()
        
        # Test that test_user cannot access other user's credential
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                # First verify master password to get session token
                verify_response = client.post(
                    '/api/credentials/verify-master',
                    json={'master_password': 'testpassword'},
                    content_type='application/json'
                )
                session_token = json.loads(verify_response.data)['data']['session_token']
                
                response = client.post(
                    f'/api/credentials/{other_credential.id}',
                    json={'session_token': session_token},
                    content_type='application/json'
                )
                
                assert response.status_code == 403
                data = json.loads(response.data)
                assert data['status'] == "error"
                assert "You do not have permission" in data['message']

    def test_get_credential_unauthenticated(self, client, test_user, test_credential):
        """Test credential retrieval without authentication."""
        # Don't mock anything - test actual unauthenticated request
        response = client.post(
            f'/api/credentials/{test_credential.id}',
            json={'master_password': 'testpassword'},
            content_type='application/json'
        )
        
        # Flask-Login redirects unauthenticated users
        assert response.status_code == 302


class TestUpdateCredential:
    """Test the credential update endpoint."""
    
    def test_update_credential_success(self, client, test_user, test_credential):
        """Test successful credential update."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                # First verify master password to get session token
                verify_response = client.post(
                    '/api/credentials/verify-master',
                    json={'master_password': 'testpassword'},
                    content_type='application/json'
                )
                session_token = json.loads(verify_response.data)['data']['session_token']
                
                update_data = {
                    'service_name': 'Updated Service',
                    'username': 'updateduser',
                    'password': 'updatedpassword',
                    'notes': 'Updated notes',
                    'category': 'personal',
                    'session_token': session_token
                }
                
                response = client.put(
                    f'/api/credentials/{test_credential.id}',
                    json=update_data,
                    content_type='application/json'
                )
                
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['status'] == "success"
                assert data['data']['service_name'] == 'Updated Service'
                assert data['data']['username'] == 'updateduser'
                assert data['data']['category'] == 'personal'

    def test_update_credential_partial(self, client, test_user, test_credential):
        """Test partial credential update."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                # First verify master password to get session token
                verify_response = client.post(
                    '/api/credentials/verify-master',
                    json={'master_password': 'testpassword'},
                    content_type='application/json'
                )
                session_token = json.loads(verify_response.data)['data']['session_token']
                
                update_data = {
                    'service_name': 'Partially Updated Service',
                    'session_token': session_token
                }
                
                response = client.put(
                    f'/api/credentials/{test_credential.id}',
                    json=update_data,
                    content_type='application/json'
                )
                
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['status'] == "success"
                assert data['data']['service_name'] == 'Partially Updated Service'

    def test_update_credential_no_changes(self, client, test_user, test_credential):
        """Test update with no actual changes."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                # First verify master password to get session token
                verify_response = client.post(
                    '/api/credentials/verify-master',
                    json={'master_password': 'testpassword'},
                    content_type='application/json'
                )
                session_token = json.loads(verify_response.data)['data']['session_token']
                
                update_data = {
                    'session_token': session_token
                }
                
                response = client.put(
                    f'/api/credentials/{test_credential.id}',
                    json=update_data,
                    content_type='application/json'
                )
                
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['status'] == "success"
                assert data['data']['message'] == "No changes detected"

    def test_update_credential_missing_master_password(self, client, test_user, test_credential):
        """Test credential update without session token."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                update_data = {
                    'service_name': 'Updated Service'
                }
                
                response = client.put(
                    f'/api/credentials/{test_credential.id}',
                    json=update_data,
                    content_type='application/json'
                )
                
                assert response.status_code == 400
                data = json.loads(response.data)
                assert data['status'] == "error"
                assert data['message'] == "Session token required."

    def test_update_credential_not_found(self, client, test_user):
        """Test update of non-existent credential."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                # First verify master password to get session token
                verify_response = client.post(
                    '/api/credentials/verify-master',
                    json={'master_password': 'testpassword'},
                    content_type='application/json'
                )
                session_token = json.loads(verify_response.data)['data']['session_token']
                
                update_data = {
                    'service_name': 'Updated Service',
                    'session_token': session_token
                }
                
                response = client.put(
                    '/api/credentials/99999',
                    json=update_data,
                    content_type='application/json'
                )
                
                assert response.status_code == 404

    def test_update_credential_unauthenticated(self, client, test_user, test_credential):
        """Test credential update without authentication."""
        # Don't mock anything - test actual unauthenticated request
        update_data = {
            'service_name': 'Updated Service',
            'master_password': 'testpassword'
        }
        
        response = client.put(
            f'/api/credentials/{test_credential.id}',
            json=update_data,
            content_type='application/json'
        )
        
        # Flask-Login redirects unauthenticated users
        assert response.status_code == 302

    def test_update_credential_no_data(self, client, test_user, test_credential):
        """Test credential update without any data."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                response = client.put(
                    f'/api/credentials/{test_credential.id}',
                    json={},
                    content_type='application/json'
                )
                
                assert response.status_code == 400
                data = json.loads(response.data)
                assert data['status'] == "error"
                assert data['message'] == "No update data provided."


class TestDeleteCredential:
    """Test the credential deletion endpoint."""
    
    def test_delete_credential_success(self, client, test_user, test_credential):
        """Test successful credential deletion."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                response = client.delete(f'/api/credentials/{test_credential.id}')
                
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['status'] == "success"
                assert data['data'] == "Credential deleted successfully"
                
                # Verify credential is actually deleted
                deleted_credential = db.session.get(Credential, test_credential.id)
                assert deleted_credential is None

    def test_delete_credential_not_found(self, client, test_user):
        """Test deletion of non-existent credential."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                response = client.delete('/api/credentials/99999')
                
                assert response.status_code == 404

    def test_delete_credential_unauthorized_user(self, client, test_user, app_context):
        """Test that users cannot delete other users' credentials."""
        # Create another user with a credential
        other_username = make_unique_username("otheruser")
        other_email = f'{uuid.uuid4()}@example.com'
        other_user = User(
            username=other_username,
            email=other_email,
            encryption_salt=b"other_salt_16_by"
        )
        other_user.set_password("otherpassword")
        db.session.add(other_user)
        db.session.commit()
        
        other_user.initialize_encryption("otherpassword")
        db.session.commit()
        
        # Create credential for other user
        other_master_key = other_user.get_master_key("otherpassword")
        from app.utils.encryption import encrypt_data
        other_encrypted_password = encrypt_data(other_master_key, "otherpassword")
        
        other_credential = Credential(
            user_id=other_user.id,
            service_name="Other Service",
            username="otheruser",
            encrypted_password=other_encrypted_password
        )
        db.session.add(other_credential)
        db.session.commit()
        
        # Test that test_user cannot delete other user's credential
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                response = client.delete(f'/api/credentials/{other_credential.id}')
                
                assert response.status_code == 403
                data = json.loads(response.data)
                assert data['status'] == "error"
                assert "You do not have permission" in data['message']

    def test_delete_credential_unauthenticated(self, client, test_user, test_credential):
        """Test credential deletion without authentication."""
        # Don't mock anything - test actual unauthenticated request
        response = client.delete(f'/api/credentials/{test_credential.id}')
        
        # Flask-Login redirects unauthenticated users
        assert response.status_code == 302


class TestRequireMasterPassword:
    """Test the require_master_password helper function."""
    
    def test_require_master_password_not_verified(self, client, test_user):
        """Test that require_master_password returns False when not verified."""
        from app.credentials.routes import require_master_password
        
        with client.application.test_request_context():
            result = require_master_password()
            assert result is False

    def test_require_master_password_verified(self, client, test_user):
        """Test that require_master_password returns True when verified."""
        from app.credentials.routes import require_master_password
        
        with client.application.test_request_context():
            # Set session data directly in the request context
            from flask import session
            session[MasterVerificationManager.SESSION_KEY] = {
                'verified': True,
                'timestamp': int(time.time())
            }
            
            result = require_master_password()
            assert result is True

    def test_require_master_password_expired(self, client, test_user):
        """Test that require_master_password returns False when verification is expired."""
        from app.credentials.routes import require_master_password
        
        with client.application.test_request_context():
            with client.session_transaction() as sess:
                # Set expired verification
                sess[MasterVerificationManager.SESSION_KEY] = {
                    'verified': True,
                    'timestamp': int(time.time()) - MasterVerificationManager.TIMEOUT_SECONDS - 1
                }
            
            result = require_master_password()
            assert result is False


class TestIntegration:
    """Integration tests for the complete credential workflow."""
    
    def test_complete_credential_workflow(self, client, test_user):
        """Test the complete workflow: verify -> create -> list -> get -> update -> delete."""
        with patch('app.credentials.routes.current_user', test_user):
            with patch('flask_login.utils._get_user', return_value=test_user):
                # 1. Verify master password
                response = client.post(
                    '/api/credentials/verify-master',
                    json={'master_password': 'testpassword'},
                    content_type='application/json'
                )
                assert response.status_code == 200
                
                # Get session token for subsequent operations
                session_token = json.loads(response.data)['data']['session_token']
                
                # 2. Create credential
                credential_data = {
                    'service_name': 'Integration Test Service',
                    'username': 'testuser',
                    'password': 'testpassword123',
                    'session_token': session_token
                }
                
                response = client.post(
                    '/api/credentials/',
                    json=credential_data,
                    content_type='application/json'
                )
                assert response.status_code == 201
                credential_id = json.loads(response.data)['data']['id']
                
                # 3. List credentials
                response = client.get('/api/credentials/')
                assert response.status_code == 200
                credentials = json.loads(response.data)['data']
                assert len(credentials) >= 1  # At least our new credential
                
                # 4. Get credential
                response = client.post(
                    f'/api/credentials/{credential_id}',
                    json={'session_token': session_token},
                    content_type='application/json'
                )
                assert response.status_code == 200
                credential = json.loads(response.data)['data']
                assert credential['password'] == 'testpassword123'
                
                # 5. Update credential
                update_data = {
                    'service_name': 'Updated Integration Service',
                    'session_token': session_token
                }
                response = client.put(
                    f'/api/credentials/{credential_id}',
                    json=update_data,
                    content_type='application/json'
                )
                assert response.status_code == 200
                
                # 6. Delete credential
                response = client.delete(f'/api/credentials/{credential_id}')
                assert response.status_code == 200