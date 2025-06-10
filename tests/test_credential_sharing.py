"""
Unit tests for credential sharing functionality.

Tests the SharedCredential model and sharing endpoints.
"""

import pytest
import json
from unittest.mock import patch, Mock
from datetime import datetime, timezone, timedelta

from app.models import db, User, Credential, SharedCredential


class TestSharedCredentialModel:
    """Tests for the SharedCredential model."""
    
    def test_create_shared_credential(self, app_context):
        """Test creating a shared credential."""
        # Create users
        owner = User(username="owner", email="owner@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        owner.set_password("password123")
        recipient = User(username="recipient", email="recipient@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test2')
        recipient.set_password("password123")
        
        db.session.add(owner)
        db.session.add(recipient)
        db.session.commit()
        
        # Create credential
        credential = Credential(
            user_id=owner.id,
            service_name="Test Service",
            username="testuser",
            encrypted_password="encrypted_test_password",
            category="test"
        )
        db.session.add(credential)
        db.session.commit()
        
        # Create shared credential
        share = SharedCredential(
            credential_id=credential.id,
            owner_id=owner.id,
            recipient_id=recipient.id,
            encrypted_data_for_recipient="encrypted_data",
            can_view=True,
            can_edit=False,
            message="Test share"
        )
        
        db.session.add(share)
        db.session.commit()
        
        # Test properties
        assert share.credential_id == credential.id
        assert share.owner_id == owner.id
        assert share.recipient_id == recipient.id
        assert share.status == 'pending'
        assert share.can_view == True
        assert share.can_edit == False
        assert not share.is_expired()
        assert not share.is_active()  # Pending, not accepted yet
    
    def test_shared_credential_expiration(self, app_context):
        """Test shared credential expiration functionality."""
        # Create users
        owner = User(username="owner2", email="owner2@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        owner.set_password("password123")
        recipient1 = User(username="recipient2", email="recipient2@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test2')
        recipient1.set_password("password123")
        recipient2 = User(username="recipient3", email="recipient3@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test3')
        recipient2.set_password("password123")
        db.session.add(owner)
        db.session.add(recipient1)
        db.session.add(recipient2)
        db.session.commit()
        
        # Create credential
        credential = Credential(
            user_id=owner.id,
            service_name="Test Service",
            username="testuser",
            encrypted_password="encrypted_test_password"
        )
        db.session.add(credential)
        db.session.commit()
        
        # Create expired shared credential
        expired_share = SharedCredential(
            credential_id=credential.id,
            owner_id=owner.id,
            recipient_id=recipient1.id,
            encrypted_data_for_recipient="encrypted_data",
            expires_at=datetime.now() - timedelta(days=1)  # Expired yesterday
        )
        
        # Create active shared credential with different recipient
        active_share = SharedCredential(
            credential_id=credential.id,
            owner_id=owner.id,
            recipient_id=recipient2.id,
            encrypted_data_for_recipient="encrypted_data",
            expires_at=datetime.now() + timedelta(days=1)  # Expires tomorrow
        )
        
        db.session.add(expired_share)
        db.session.add(active_share)
        db.session.commit()
        
        # Accept the share after it's been committed
        active_share.accept()
        db.session.commit()
        
        # Test expiration
        assert expired_share.is_expired()
        assert not expired_share.is_active()
        
        assert not active_share.is_expired()
        assert active_share.is_active()
    
    def test_shared_credential_status_changes(self, app_context):
        """Test shared credential status change methods."""
        # Create users
        owner = User(username="owner3", email="owner3@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        owner.set_password("password123")
        recipient = User(username="recipient4", email="recipient4@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test2')
        recipient.set_password("password123")
        db.session.add(owner)
        db.session.add(recipient)
        db.session.commit()
        
        # Create credential
        credential = Credential(
            user_id=owner.id,
            service_name="Test Service",
            username="testuser",
            encrypted_password="encrypted_test_password"
        )
        db.session.add(credential)
        db.session.commit()
        
        # Create shared credential
        share = SharedCredential(
            credential_id=credential.id,
            owner_id=owner.id,
            recipient_id=recipient.id,
            encrypted_data_for_recipient="encrypted_data"
        )
        db.session.add(share)
        db.session.commit()
        
        # Test acceptance
        assert share.status == 'pending'
        assert share.accept() == True
        assert share.status == 'accepted'
        assert share.accepted_at is not None
        
        # Test that accept fails if not pending
        assert share.accept() == False
        
        # Create new credential for rejection test
        credential2 = Credential(
            user_id=owner.id,
            service_name="Test Service 2",
            username="testuser2",
            encrypted_password="encrypted_test_password2"
        )
        db.session.add(credential2)
        db.session.commit()
        
        # Create new share to test rejection
        share2 = SharedCredential(
            credential_id=credential2.id,
            owner_id=owner.id,
            recipient_id=recipient.id,
            encrypted_data_for_recipient="encrypted_data"
        )
        db.session.add(share2)
        db.session.commit()
        
        # Test rejection
        assert share2.reject() == True
        assert share2.status == 'rejected'
        
        # Test revocation
        assert share.revoke() == True
        assert share.status == 'revoked'
    
    def test_shared_credential_to_dict(self, app_context):
        """Test shared credential dictionary conversion."""
        # Create users
        owner = User(username="owner4", email="owner4@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        owner.set_password("password123")
        recipient = User(username="recipient5", email="recipient5@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test2')
        recipient.set_password("password123")
        db.session.add(owner)
        db.session.add(recipient)
        db.session.commit()
        
        # Create credential
        credential = Credential(
            user_id=owner.id,
            service_name="Test Service",
            username="testuser",
            encrypted_password="encrypted_test_password"
        )
        db.session.add(credential)
        db.session.commit()
        
        # Create shared credential
        share = SharedCredential(
            credential_id=credential.id,
            owner_id=owner.id,
            recipient_id=recipient.id,
            encrypted_data_for_recipient="encrypted_data",
            message="Test message"
        )
        db.session.add(share)
        db.session.commit()
        
        # Test to_dict without encrypted data
        share_dict = share.to_dict()
        assert 'id' in share_dict
        assert 'credential_id' in share_dict
        assert 'owner_id' in share_dict
        assert 'recipient_id' in share_dict
        assert 'status' in share_dict
        assert 'message' in share_dict
        assert 'encrypted_data_for_recipient' not in share_dict
        
        # Test to_dict with encrypted data
        share_dict_with_data = share.to_dict(include_encrypted_data=True)
        assert 'encrypted_data_for_recipient' in share_dict_with_data


class TestCredentialSharingEndpoints:
    """Tests for credential sharing API endpoints."""
    
    def test_share_credential_success(self, client, app_context):
        """Test successful credential sharing."""
        # Create users
        owner = User(username="owner5", email="owner5@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        owner.set_password("password123")
        
        recipient = User(username="recipient6", email="recipient6@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test2')
        recipient.set_password("password123")
        
        db.session.add(owner)
        db.session.add(recipient)
        db.session.commit()
        
        # Initialize encryption after users are committed
        owner.initialize_encryption("password123")
        recipient.initialize_encryption("password123")
        
        # Create credential
        from app.utils.encryption import encrypt_data
        master_key = owner.get_master_key("password123")
        encrypted_password = encrypt_data(master_key, "secret_password")
        
        credential = Credential(
            user_id=owner.id,
            service_name="Test Service",
            username="testuser",
            encrypted_password=encrypted_password,
            category="test"
        )
        db.session.add(credential)
        db.session.commit()
        
        with patch('flask_login.utils._get_user', return_value=owner), \
             patch('app.utils.email.send_email') as mock_send_email, \
             patch('flask.render_template', return_value="<html>Email</html>"):
            
            response = client.post(f'/api/credentials/{credential.id}/share',
                                 json={
                                     'recipient_email': 'recipient6@example.com',
                                     'master_password': 'password123',
                                     'can_edit': False,
                                     'message': 'Sharing test credential',
                                     'expires_days': 30
                                 },
                                 content_type='application/json')
        
        assert response.status_code == 200
        response_data = json.loads(response.data)
        assert response_data['status'] == 'success'
        assert 'share_id' in response_data['data']
        assert response_data['data']['recipient_email'] == 'recipient6@example.com'
        
        # Verify share was created in database
        share = SharedCredential.query.filter_by(credential_id=credential.id).first()
        assert share is not None
        assert share.owner_id == owner.id
        assert share.recipient_id == recipient.id
        assert share.status == 'pending'
        
        # Verify email was sent
        mock_send_email.assert_called_once()
    
    def test_share_credential_invalid_recipient(self, client, app_context):
        """Test sharing with non-existent recipient."""
        # Create owner
        owner = User(username="owner6", email="owner6@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        owner.set_password("password123")
        db.session.add(owner)
        db.session.commit()
        
        # Initialize encryption after user is committed
        owner.initialize_encryption("password123")
        
        # Create credential
        from app.utils.encryption import encrypt_data
        master_key = owner.get_master_key("password123")
        encrypted_password = encrypt_data(master_key, "secret_password")
        
        credential = Credential(
            user_id=owner.id,
            service_name="Test Service",
            username="testuser",
            encrypted_password=encrypted_password
        )
        db.session.add(credential)
        db.session.commit()
        
        with patch('flask_login.utils._get_user', return_value=owner):
            response = client.post(f'/api/credentials/{credential.id}/share',
                                 json={
                                     'recipient_email': 'nonexistent@example.com',
                                     'master_password': 'password123'
                                 },
                                 content_type='application/json')
        
        assert response.status_code == 404
        response_data = json.loads(response.data)
        assert 'Recipient user not found' in response_data['message']
    
    def test_get_shared_credentials(self, client, app_context):
        """Test getting shared credentials."""
        # Create users
        owner = User(username="owner7", email="owner7@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        owner.set_password("password123")
        recipient = User(username="recipient7", email="recipient7@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test2')
        recipient.set_password("password123")
        db.session.add(owner)
        db.session.add(recipient)
        db.session.commit()
        
        # Create credential
        credential = Credential(
            user_id=owner.id,
            service_name="Test Service",
            username="testuser",
            encrypted_password="encrypted_password"
        )
        db.session.add(credential)
        db.session.commit()
        
        # Create shared credential
        share = SharedCredential(
            credential_id=credential.id,
            owner_id=owner.id,
            recipient_id=recipient.id,
            encrypted_data_for_recipient="encrypted_data",
            status='accepted'
        )
        db.session.add(share)
        db.session.commit()
        
        with patch('flask_login.utils._get_user', return_value=recipient):
            response = client.get('/api/credentials/shared',
                                content_type='application/json')
        
        assert response.status_code == 200
        response_data = json.loads(response.data)
        assert response_data['status'] == 'success'
        assert response_data['data']['total'] == 1
        assert len(response_data['data']['shared_credentials']) == 1
        
        shared_cred = response_data['data']['shared_credentials'][0]
        assert shared_cred['credential']['service_name'] == 'Test Service'
        assert shared_cred['owner']['username'] == 'owner7'
    
    def test_accept_shared_credential(self, client, app_context):
        """Test accepting a shared credential."""
        # Create users
        owner = User(username="owner8", email="owner8@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        owner.set_password("password123")
        recipient = User(username="recipient8", email="recipient8@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test2')
        recipient.set_password("password123")
        db.session.add(owner)
        db.session.add(recipient)
        db.session.commit()
        
        # Initialize encryption after users are committed
        recipient.initialize_encryption("password123")
        
        # Create credential
        credential = Credential(
            user_id=owner.id,
            service_name="Test Service",
            username="testuser",
            encrypted_password="encrypted_password"
        )
        db.session.add(credential)
        db.session.commit()
        
        # Create properly encrypted shared credential data
        from app.utils.encryption import encrypt_data, derive_key
        import json
        
        credential_data = {
            'service_name': 'Test Service',
            'username': 'testuser', 
            'password': 'testpassword',
            'category': 'test',
            'notes': 'Test notes'
        }
        
        # Encrypt using the sharing key pattern we implemented
        sharing_key = derive_key(f"share_{owner.id}_{recipient.id}", recipient.encryption_salt)
        encrypted_data = encrypt_data(sharing_key, json.dumps(credential_data))
        
        # Create shared credential
        share = SharedCredential(
            credential_id=credential.id,
            owner_id=owner.id,
            recipient_id=recipient.id,
            encrypted_data_for_recipient=encrypted_data,
            status='pending'
        )
        db.session.add(share)
        db.session.commit()
        
        with patch('flask_login.utils._get_user', return_value=recipient):
            response = client.post(f'/api/credentials/shared/{share.id}/accept',
                                 json={'master_password': 'password123'},
                                 content_type='application/json')
        
        assert response.status_code == 200
        response_data = json.loads(response.data)
        assert response_data['status'] == 'success'
        assert 'new_credential_id' in response_data['data']
        
        # Verify status changed in database
        db.session.refresh(share)
        assert share.status == 'accepted'
        assert share.accepted_at is not None
        
        # Verify new credential was created for recipient
        new_credential = Credential.query.get(response_data['data']['new_credential_id'])
        assert new_credential is not None
        assert new_credential.user_id == recipient.id
        assert new_credential.service_name == 'Test Service'
        assert new_credential.username == 'testuser'
    
    def test_reject_shared_credential(self, client, app_context):
        """Test rejecting a shared credential."""
        # Create users
        owner = User(username="owner9", email="owner9@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        owner.set_password("password123")
        recipient = User(username="recipient9", email="recipient9@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test2')
        recipient.set_password("password123")
        db.session.add(owner)
        db.session.add(recipient)
        db.session.commit()
        
        # Create credential
        credential = Credential(
            user_id=owner.id,
            service_name="Test Service",
            username="testuser",
            encrypted_password="encrypted_password"
        )
        db.session.add(credential)
        db.session.commit()
        
        # Create shared credential
        share = SharedCredential(
            credential_id=credential.id,
            owner_id=owner.id,
            recipient_id=recipient.id,
            encrypted_data_for_recipient="encrypted_data",
            status='pending'
        )
        db.session.add(share)
        db.session.commit()
        
        with patch('flask_login.utils._get_user', return_value=recipient):
            response = client.post(f'/api/credentials/shared/{share.id}/reject',
                                 content_type='application/json')
        
        assert response.status_code == 200
        response_data = json.loads(response.data)
        assert response_data['status'] == 'success'
        
        # Verify status changed in database
        db.session.refresh(share)
        assert share.status == 'rejected'
    
    def test_revoke_shared_credential(self, client, app_context):
        """Test revoking a shared credential."""
        # Create users
        owner = User(username="owner10", email="owner10@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        owner.set_password("password123")
        recipient = User(username="recipient10", email="recipient10@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test2')
        recipient.set_password("password123")
        db.session.add(owner)
        db.session.add(recipient)
        db.session.commit()
        
        # Create credential
        credential = Credential(
            user_id=owner.id,
            service_name="Test Service",
            username="testuser",
            encrypted_password="encrypted_password"
        )
        db.session.add(credential)
        db.session.commit()
        
        # Create shared credential
        share = SharedCredential(
            credential_id=credential.id,
            owner_id=owner.id,
            recipient_id=recipient.id,
            encrypted_data_for_recipient="encrypted_data",
            status='accepted'
        )
        db.session.add(share)
        db.session.commit()
        
        with patch('flask_login.utils._get_user', return_value=owner):
            response = client.post(f'/api/credentials/shared/{share.id}/revoke',
                                 content_type='application/json')
        
        assert response.status_code == 200
        response_data = json.loads(response.data)
        assert response_data['status'] == 'success'
        
        # Verify status changed in database
        db.session.refresh(share)
        assert share.status == 'revoked'