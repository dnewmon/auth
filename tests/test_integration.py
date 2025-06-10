"""
Integration tests for the password manager system.

Tests end-to-end workflows across multiple features and components.
"""

import pytest
import json
import time
from unittest.mock import patch, Mock
from datetime import datetime, timezone, timedelta

from app.models import db, User, Credential, SharedCredential


class TestCredentialWorkflow:
    """Integration tests for credential management workflow."""
    
    def test_complete_credential_lifecycle(self, client, app_context):
        """Test complete credential lifecycle with password policy enforcement."""
        # 1. Register user
        response = client.post('/api/auth/register', json={
            'username': 'integration_testuser',
            'email': 'integration_test@example.com', 
            'password': 'TestPassword123!'
        })
        assert response.status_code == 201
        
        # 2. Login
        response = client.post('/api/auth/login', json={
            'username': 'integration_testuser',
            'password': 'TestPassword123!'
        })
        assert response.status_code == 200
        
        # 3. Try to create credential with weak password (should fail due to policy)
        response = client.post('/api/credentials/', json={
            'service_name': 'Gmail',
            'username': 'user@gmail.com',
            'password': 'weak',  # Violates password policy
            'master_password': 'TestPassword123!'
        })
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'policy violation' in data['message'].lower()
        
        # 4. Create credential with strong password
        response = client.post('/api/credentials/', json={
            'service_name': 'Gmail',
            'username': 'user@gmail.com',
            'password': 'StrongGmailPass142!',
            'master_password': 'TestPassword123!',
            'category': 'email'
        })
        assert response.status_code == 201
        data = json.loads(response.data)
        credential_id = data['data']['id']
        
        # 5. List credentials
        response = client.get('/api/credentials/')
        assert response.status_code == 200
        data = json.loads(response.data)
        credentials = data['data']['credentials'] if 'credentials' in data['data'] else data['data']
        assert len(credentials) == 1
        assert credentials[0]['service_name'] == 'Gmail'
        
        # 6. Update credential
        response = client.put(f'/api/credentials/{credential_id}', json={
            'service_name': 'Gmail Personal',
            'notes': 'Personal email account',
            'master_password': 'TestPassword123!'
        })
        assert response.status_code == 200
        
        # 7. Get password health report
        response = client.post('/api/utils/password-health-report', json={
            'master_password': 'TestPassword123!'
        })
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'total_credentials' in data['data']
        assert data['data']['total_credentials'] == 1
        
        # 8. Test completed - credential lifecycle working


class TestCredentialSharingWorkflow:
    """Integration tests for credential sharing workflow."""
    
    def test_complete_sharing_workflow(self, client, app_context):
        """Test complete credential sharing workflow."""
        # Setup users
        owner = User(username="sharing_owner", email="sharing_owner@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        owner.set_password("password123")
        recipient = User(username="sharing_recipient", email="sharing_recipient@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test2')
        recipient.set_password("password123")
        db.session.add(owner)
        db.session.add(recipient)
        db.session.commit()
        
        # Initialize encryption
        owner.initialize_encryption("password123")
        recipient.initialize_encryption("password123")
        db.session.commit()
        
        # Create credential
        from app.utils.encryption import encrypt_data
        master_key = owner.get_master_key("password123")
        credential = Credential(
            user_id=owner.id,
            service_name="Netflix",
            username="shared@netflix.com",
            encrypted_password=encrypt_data(master_key, "NetflixPass142!"),
            category="entertainment"
        )
        db.session.add(credential)
        db.session.commit()
        
        with patch('flask_login.utils._get_user', return_value=owner), \
             patch('app.utils.email.send_email') as mock_send_email, \
             patch('flask.render_template', return_value="<html>Email</html>"):
            
            # 1. Share credential
            response = client.post(f'/api/credentials/{credential.id}/share', json={
                'recipient_email': 'sharing_recipient@example.com',
                'can_view': True,
                'can_edit': False,
                'expires_days': 30,
                'message': 'Netflix account for family use',
                'master_password': 'password123'
            })
            # Credential sharing might return 200 for existing shares or 201 for new shares
            assert response.status_code in [200, 201]
            data = json.loads(response.data)
            share_id = data['data']['share_id']
            
            # Verify email notification was sent
            assert mock_send_email.called
        
        with patch('flask_login.utils._get_user', return_value=recipient):
            # 2. Get shared credentials (recipient view)
            response = client.get('/api/credentials/shared')
            assert response.status_code == 200
            data = json.loads(response.data)
            shared_creds = data['data']['shared_credentials'] if 'shared_credentials' in data['data'] else data['data']
            assert len(shared_creds) == 1
            assert shared_creds[0]['credential']['service_name'] == 'Netflix'
            assert shared_creds[0]['status'] == 'pending'
            
            # 3. Accept shared credential
            response = client.post(f'/api/credentials/shared/{share_id}/accept', json={
                'master_password': 'password123'
            })
            assert response.status_code == 200
            
            # 4. Verify access to shared credential
            response = client.get('/api/credentials/shared')
            assert response.status_code == 200
            data = json.loads(response.data)
            shared_creds = data['data']['shared_credentials'] if 'shared_credentials' in data['data'] else data['data']
            assert shared_creds[0]['status'] == 'accepted'
        
        with patch('flask_login.utils._get_user', return_value=owner):
            # 5. Check shares from owner perspective
            response = client.get(f'/api/credentials/{credential.id}/shares')
            assert response.status_code == 200
            data = json.loads(response.data)
            shares = data['data']['shares'] if 'shares' in data['data'] else data['data']
            assert len(shares) == 1
            assert shares[0]['status'] == 'accepted'
            
            # 6. Revoke share
            response = client.post(f'/api/credentials/shared/{share_id}/revoke')
            assert response.status_code == 200


class TestBackupRestoreWorkflow:
    """Integration tests for backup and restore workflow."""
    
    def test_backup_and_restore_workflow(self, client, app_context):
        """Test complete backup and restore workflow."""
        # Setup user with credentials
        user = User(username="backupuser", email="backup@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        user.initialize_encryption("password123")
        
        # Create multiple credentials
        from app.utils.encryption import encrypt_data
        master_key = user.get_master_key("password123")
        
        credentials = [
            Credential(
                user_id=user.id,
                service_name="GitHub",
                username="backupuser",
                encrypted_password=encrypt_data(master_key, "GitHubPass142!"),
                category="development"
            ),
            Credential(
                user_id=user.id,
                service_name="AWS",
                username="aws-user",
                encrypted_password=encrypt_data(master_key, "AWSSecret591#"),
                category="cloud"
            )
        ]
        for cred in credentials:
            db.session.add(cred)
        db.session.commit()
        
        with patch('flask_login.utils._get_user', return_value=user):
            # 1. Create backup
            response = client.post('/api/utils/backup', json={
                'master_password': 'password123',
                'backup_password': 'backup_secret_123'
            })
            assert response.status_code == 200
            assert response.headers['Content-Type'] == 'application/zip'
            backup_data = response.data
            assert len(backup_data) > 0
            
            # 2. Delete all credentials (simulate data loss)
            for cred in credentials:
                db.session.delete(cred)
            db.session.commit()
            
            # Verify credentials are gone
            response = client.get('/api/credentials/')
            assert response.status_code == 200
            data = json.loads(response.data)
            credentials = data['data']['credentials'] if 'credentials' in data['data'] else data['data']
            assert len(credentials) == 0
            
            # 3. Restore from backup (simulated)
            # In a real test, we'd extract the ZIP and parse the JSON
            # For this test, we'll simulate the restore data
            restore_data = {
                "version": "1.0",
                "credentials": [
                    {
                        "service_name": "GitHub",
                        "username": "backupuser",
                        "password": "GitHubPass142!",
                        "category": "development"
                    },
                    {
                        "service_name": "AWS", 
                        "username": "aws-user",
                        "password": "AWSSecret591#",
                        "category": "cloud"
                    }
                ]
            }
            
            response = client.post('/api/utils/restore', json={
                'master_password': 'password123',
                'backup_data': restore_data,
                'skip_existing': True
            })
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['data']['restored_count'] == 2
            assert data['data']['error_count'] == 0
            
            # 4. Verify credentials are restored
            response = client.get('/api/credentials/')
            assert response.status_code == 200
            data = json.loads(response.data)
            credentials = data['data']['credentials'] if 'credentials' in data['data'] else data['data']
            assert len(credentials) == 2
            
            service_names = [cred['service_name'] for cred in credentials]
            assert 'GitHub' in service_names
            assert 'AWS' in service_names


class TestPasswordPolicyIntegration:
    """Integration tests for password policy across different endpoints."""
    
    def test_password_policy_across_operations(self, client, app_context):
        """Test password policy enforcement across different operations."""
        # Create user
        user = User(username="policyuser", email="policy@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        user.initialize_encryption("password123")
        
        with patch('flask_login.utils._get_user', return_value=user):
            # 1. Get password policy
            response = client.get('/api/utils/password-policy')
            assert response.status_code == 200
            data = json.loads(response.data)
            policy = data['data']
            assert policy['enabled'] is True
            assert policy['min_length'] >= 8
            
            # 2. Try creating credential with policy violations
            violations = [
                ('short', 400),  # Too short
                ('nouppercase123!', 400),  # No uppercase
                ('NOLOWERCASE123!', 400),  # No lowercase
                ('NoDigitsHere!', 400),  # No digits
                ('NoSymbolsHere123', 400),  # No symbols
                ('password', 400),  # Forbidden password
                ('PolicyUser123!', 400)  # Contains username
            ]
            
            for weak_password, expected_status in violations:
                response = client.post('/api/credentials/', json={
                    'service_name': 'Test Service',
                    'username': 'testuser',
                    'password': weak_password,
                    'master_password': 'password123'
                })
                assert response.status_code == expected_status
                if expected_status == 400:
                    data = json.loads(response.data)
                    assert 'policy violation' in data['message'].lower()
            
            # 3. Create credential with compliant password
            response = client.post('/api/credentials/', json={
                'service_name': 'Compliant Service',
                'username': 'user@service.com',
                'password': 'CompliantPass142!',
                'master_password': 'password123'
            })
            assert response.status_code == 201
            data = json.loads(response.data)
            credential_id = data['data']['id']
            
            # 4. Try updating with weak password
            response = client.put(f'/api/credentials/{credential_id}', json={
                'password': 'weak',
                'master_password': 'password123'
            })
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'policy violation' in data['message'].lower()
            
            # 5. Update with compliant password
            response = client.put(f'/api/credentials/{credential_id}', json={
                'password': 'UpdatedPass142!',
                'master_password': 'password123'
            })
            assert response.status_code == 200


class TestSecurityWorkflow:
    """Integration tests for security features."""
    
    def test_audit_logging_workflow(self, client, app_context):
        """Test that security events are properly logged."""
        # Create user
        user = User(username="audituser", email="audit@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        user.initialize_encryption("password123")
        
        with patch('flask_login.utils._get_user', return_value=user):
            # 1. Create credential (should generate audit log)
            response = client.post('/api/credentials/', json={
                'service_name': 'Security Test',
                'username': 'security@test.com',
                'password': 'SecureTestPassword142!',  # Avoid 'audit' to pass policy
                'master_password': 'password123'
            })
            assert response.status_code == 201
            
            # 2. Check audit logs
            from app.models.audit_log import AuditLog
            logs = AuditLog.query.filter_by(user_id=user.id).all()
            assert len(logs) > 0
            
            # Look for credential creation log
            creation_logs = [log for log in logs if 'credential' in log.event_type.lower()]
            assert len(creation_logs) > 0


class TestErrorHandlingIntegration:
    """Integration tests for error handling across the application."""
    
    def test_comprehensive_error_scenarios(self, client, app_context):
        """Test error handling in various scenarios."""
        # 1. Invalid JSON
        response = client.post('/api/auth/login',
                             data='invalid json',
                             content_type='application/json')
        assert response.status_code == 400
        
        # 2. Missing required fields
        response = client.post('/api/auth/login', json={
            'username': 'testuser'
            # Missing password
        })
        assert response.status_code == 400
        
        # 3. Invalid credentials
        response = client.post('/api/auth/login', json={
            'username': 'nonexistent',
            'password': 'wrongpassword'
        })
        assert response.status_code == 401
        
        # 4. Access without authentication
        response = client.get('/api/credentials/')
        # Flask-Login redirects to login page, but API endpoints should return 401
        assert response.status_code in [401, 302]  # 302 is redirect to login
        
        # 5. Invalid endpoint
        response = client.get('/api/nonexistent/endpoint')
        assert response.status_code == 404
        
        # 6. Wrong HTTP method
        response = client.put('/api/auth/login')
        assert response.status_code == 405


class TestPerformanceAndScalability:
    """Integration tests for performance and scalability."""
    
    def test_multiple_credentials_performance(self, client, app_context):
        """Test system performance with multiple credentials."""
        # Create user
        user = User(username="perfuser", email="perf@example.com", encryption_salt=b'salt_32_chars_long_enough_for_test')
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        user.initialize_encryption("password123")
        
        # Create multiple credentials
        from app.utils.encryption import encrypt_data
        master_key = user.get_master_key("password123")
        
        credentials = []
        for i in range(50):  # Create 50 credentials
            cred = Credential(
                user_id=user.id,
                service_name=f"Service {i:03d}",
                username=f"user{i}@service.com",
                encrypted_password=encrypt_data(master_key, f"Password{i:03d}!"),
                category="test"
            )
            credentials.append(cred)
        
        db.session.add_all(credentials)
        db.session.commit()
        
        with patch('flask_login.utils._get_user', return_value=user):
            # Test listing performance
            start_time = time.time()
            response = client.get('/api/credentials/?per_page=100')  # Request more than default pagination
            end_time = time.time()
            
            assert response.status_code == 200
            data = json.loads(response.data)
            credentials = data['data']['credentials'] if 'credentials' in data['data'] else data['data']
            assert len(credentials) == 50
            
            # Should complete within reasonable time (less than 1 second)
            assert (end_time - start_time) < 1.0
            
            # Test password health report performance
            start_time = time.time()
            response = client.post('/api/utils/password-health-report', json={
                'master_password': 'password123'
            })
            end_time = time.time()
            
            assert response.status_code == 200
            # Should complete within reasonable time (less than 2 seconds for analysis)
            assert (end_time - start_time) < 2.0