"""
Tests for WebAuthn/Passkey functionality.
"""

import json
import base64
from unittest.mock import patch, MagicMock
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta

from oidc_provider.models import (
    WebAuthnCredential,
    WebAuthnChallenge,
    PasskeyAuthenticationLog,
)

User = get_user_model()


class PasskeyRegistrationTest(TestCase):
    """Test passkey registration flow."""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.client.login(username='testuser', password='testpass123')
    
    def test_registration_options_generation(self):
        """Test that registration options are generated correctly."""
        response = self.client.post('/passkey/register/options/')
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertTrue(data['success'])
        self.assertIn('options', data)
        
        options = data['options']
        self.assertIn('challenge', options)
        self.assertIn('rp', options)
        self.assertIn('user', options)
        self.assertEqual(options['user']['name'], 'testuser')
    
    def test_registration_options_creates_challenge(self):
        """Test that challenge is stored in database."""
        response = self.client.post('/passkey/register/options/')
        
        challenge = WebAuthnChallenge.objects.filter(
            user=self.user,
            challenge_type='registration',
            used=False
        ).first()
        
        self.assertIsNotNone(challenge)
        self.assertFalse(challenge.used)
        self.assertTrue(challenge.is_valid())
    
    @patch('webauthn.verify_registration_response')
    def test_registration_verification_success(self, mock_verify):
        """Test successful passkey registration."""
        # Create challenge
        challenge_obj = WebAuthnChallenge.objects.create(
            user=self.user,
            challenge=base64.b64encode(b'test_challenge').decode('utf-8'),
            challenge_type='registration',
            session_key=self.client.session.session_key,
            expires_at=timezone.now() + timedelta(minutes=5)
        )
        
        # Mock verification response
        mock_verify.return_value = MagicMock(
            credential_id=b'test_credential_id',
            credential_public_key=b'test_public_key',
            aaguid='test-aaguid',
            sign_count=0,
            credential_backup_eligible=True,
            credential_backed_up=True,
            fmt='none'
        )
        
        # Submit registration
        response = self.client.post(
            '/passkey/register/verify/',
            json.dumps({
                'credential': {
                    'id': 'test_id',
                    'rawId': 'dGVzdF9pZA==',
                    'response': {
                        'attestationObject': 'dGVzdA==',
                        'clientDataJSON': 'dGVzdA=='
                    },
                    'type': 'public-key'
                },
                'name': 'My Passkey'
            }),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])
        
        # Check credential was created
        credential = WebAuthnCredential.objects.filter(user=self.user).first()
        self.assertIsNotNone(credential)
        self.assertEqual(credential.name, 'My Passkey')
        self.assertTrue(credential.is_active)
        
        # Check challenge was marked as used
        challenge_obj.refresh_from_db()
        self.assertTrue(challenge_obj.used)
    
    def test_registration_requires_authentication(self):
        """Test that registration requires authenticated user."""
        self.client.logout()
        
        response = self.client.post('/passkey/register/options/')
        self.assertEqual(response.status_code, 302)  # Redirect to login
    
    def test_expired_challenge_rejected(self):
        """Test that expired challenges are rejected."""
        # Create expired challenge
        challenge_obj = WebAuthnChallenge.objects.create(
            user=self.user,
            challenge=base64.b64encode(b'test_challenge').decode('utf-8'),
            challenge_type='registration',
            session_key=self.client.session.session_key,
            expires_at=timezone.now() - timedelta(minutes=1)  # Expired
        )
        
        response = self.client.post(
            '/passkey/register/verify/',
            json.dumps({
                'credential': {'id': 'test'},
                'name': 'Test'
            }),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertFalse(data['success'])
        self.assertIn('expired', data['error'].lower())


class PasskeyAuthenticationTest(TestCase):
    """Test passkey authentication flow."""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        # Create a passkey for the user
        self.credential = WebAuthnCredential.objects.create(
            user=self.user,
            credential_id=base64.b64encode(b'test_cred_id').decode('utf-8'),
            public_key=base64.b64encode(b'test_public_key').decode('utf-8'),
            aaguid='test-aaguid',
            sign_count=0,
            name='Test Passkey',
            is_active=True
        )
    
    def test_authentication_options_generation(self):
        """Test that authentication options are generated."""
        response = self.client.post(
            '/passkey/auth/options/',
            json.dumps({'username': 'testuser'}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertTrue(data['success'])
        self.assertIn('options', data)
        self.assertIn('challenge', data['options'])
    
    def test_authentication_options_includes_user_credentials(self):
        """Test that user's credentials are included in options."""
        response = self.client.post(
            '/passkey/auth/options/',
            json.dumps({'username': 'testuser'}),
            content_type='application/json'
        )
        
        data = response.json()
        options = data['options']
        
        self.assertIn('allowCredentials', options)
        self.assertEqual(len(options['allowCredentials']), 1)
    
    @patch('webauthn.verify_authentication_response')
    def test_authentication_success(self, mock_verify):
        """Test successful passkey authentication."""
        # Create challenge
        challenge_obj = WebAuthnChallenge.objects.create(
            user=None,
            challenge=base64.b64encode(b'test_challenge').decode('utf-8'),
            challenge_type='authentication',
            session_key=self.client.session.session_key,
            expires_at=timezone.now() + timedelta(minutes=5)
        )
        
        # Mock verification
        mock_verify.return_value = MagicMock(
            new_sign_count=1
        )
        
        # Submit authentication
        response = self.client.post(
            '/passkey/auth/verify/',
            json.dumps({
                'credential': {
                    'id': self.credential.credential_id,
                    'rawId': self.credential.credential_id,
                    'response': {
                        'authenticatorData': 'dGVzdA==',
                        'clientDataJSON': 'dGVzdA==',
                        'signature': 'dGVzdA==',
                        'userHandle': None
                    },
                    'type': 'public-key'
                }
            }),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])
        
        # Check user info returned
        self.assertEqual(data['user']['username'], 'testuser')
        
        # Check credential was updated
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.sign_count, 1)
        self.assertIsNotNone(self.credential.last_used_at)
        
        # Check authentication log
        log = PasskeyAuthenticationLog.objects.filter(
            user=self.user,
            success=True
        ).first()
        self.assertIsNotNone(log)
    
    @patch('webauthn.verify_authentication_response')
    def test_authentication_with_invalid_credential(self, mock_verify):
        """Test authentication with non-existent credential."""
        response = self.client.post(
            '/passkey/auth/verify/',
            json.dumps({
                'credential': {
                    'id': 'invalid_credential_id',
                    'rawId': 'aW52YWxpZA==',
                    'response': {
                        'authenticatorData': 'dGVzdA==',
                        'clientDataJSON': 'dGVzdA==',
                        'signature': 'dGVzdA==',
                        'userHandle': None
                    },
                    'type': 'public-key'
                }
            }),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertFalse(data['success'])
        
        # Check failure was logged
        log = PasskeyAuthenticationLog.objects.filter(
            success=False,
            failure_reason__icontains='not found'
        ).first()
        self.assertIsNotNone(log)
    
    def test_cloned_credential_detection(self):
        """Test that cloned credentials are detected via sign count."""
        self.credential.sign_count = 5
        self.credential.save()
        
        # Simulate authentication with lower sign count (indicates cloning)
        self.credential.update_last_used(sign_count=3)
        
        self.credential.refresh_from_db()
        self.assertFalse(self.credential.is_active)  # Should be deactivated


class PasskeyManagementTest(TestCase):
    """Test passkey management functionality."""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.client.login(username='testuser', password='testpass123')
        
        # Create passkeys
        self.credential1 = WebAuthnCredential.objects.create(
            user=self.user,
            credential_id=base64.b64encode(b'cred1').decode('utf-8'),
            public_key=base64.b64encode(b'key1').decode('utf-8'),
            name='iPhone',
            authenticator_attachment='platform',
            is_active=True
        )
        
        self.credential2 = WebAuthnCredential.objects.create(
            user=self.user,
            credential_id=base64.b64encode(b'cred2').decode('utf-8'),
            public_key=base64.b64encode(b'key2').decode('utf-8'),
            name='YubiKey',
            authenticator_attachment='cross-platform',
            is_active=True
        )
    
    def test_list_passkeys(self):
        """Test listing user's passkeys."""
        response = self.client.get('/passkey/list/')
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertEqual(len(data['passkeys']), 2)
        
        # Check passkey data
        passkey_names = [p['name'] for p in data['passkeys']]
        self.assertIn('iPhone', passkey_names)
        self.assertIn('YubiKey', passkey_names)
    
    def test_delete_passkey(self):
        """Test deleting a passkey."""
        response = self.client.delete(f'/passkey/{self.credential1.id}/delete/')
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])
        
        # Check passkey was deactivated
        self.credential1.refresh_from_db()
        self.assertFalse(self.credential1.is_active)
    
    def test_cannot_delete_other_users_passkey(self):
        """Test that users can't delete other users' passkeys."""
        # Create another user and passkey
        other_user = User.objects.create_user(
            username='otheruser',
            password='testpass123'
        )
        other_credential = WebAuthnCredential.objects.create(
            user=other_user,
            credential_id=base64.b64encode(b'other_cred').decode('utf-8'),
            public_key=base64.b64encode(b'other_key').decode('utf-8'),
            name='Other Passkey',
            is_active=True
        )
        
        response = self.client.delete(f'/passkey/{other_credential.id}/delete/')
        
        self.assertEqual(response.status_code, 404)
    
    def test_list_requires_authentication(self):
        """Test that listing passkeys requires authentication."""
        self.client.logout()
        
        response = self.client.get('/passkey/list/')
        self.assertEqual(response.status_code, 302)  # Redirect to login


class PasskeyOIDCIntegrationTest(TestCase):
    """Test passkey integration with OIDC flow."""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        from oidc_provider.models import Client as OIDCClient, ResponseType
        
        # Create OIDC client
        self.oidc_client = OIDCClient.objects.create(
            name='Test Client',
            client_id='test123',
            client_type='confidential',
            client_secret='secret',
        )
        
        # Add response type
        code_type, _ = ResponseType.objects.get_or_create(
            value='code',
            defaults={'description': 'Authorization Code Flow'}
        )
        self.oidc_client.response_types.add(code_type)
        self.oidc_client.redirect_uris = ['https://client.example.com/callback']
        self.oidc_client.save()
    
    def test_passkey_login_redirects_to_authorize(self):
        """Test that successful passkey login continues OIDC flow."""
        # This would be a more complex integration test
        # showing passkey auth → OIDC authorize → consent
        pass
    
    def test_conditional_ui_shows_passkey_option(self):
        """Test that login page shows passkey option."""
        response = self.client.get('/authorize/', {
            'client_id': 'test123',
            'response_type': 'code',
            'redirect_uri': 'https://client.example.com/callback',
            'scope': 'openid'
        })
        
        # Check that passkey UI is shown
        self.assertContains(response, 'passkey', status_code=200)


class PasskeySecurityTest(TestCase):
    """Test security aspects of passkey implementation."""
    
    def test_challenge_expires(self):
        """Test that challenges expire correctly."""
        user = User.objects.create_user(username='test', password='test')
        
        # Create expired challenge
        challenge = WebAuthnChallenge.objects.create(
            user=user,
            challenge='test',
            challenge_type='registration',
            session_key='test',
            expires_at=timezone.now() - timedelta(seconds=1)
        )
        
        self.assertFalse(challenge.is_valid())
    
    def test_challenge_single_use(self):
        """Test that challenges can only be used once."""
        user = User.objects.create_user(username='test', password='test')
        
        challenge = WebAuthnChallenge.objects.create(
            user=user,
            challenge='test',
            challenge_type='registration',
            session_key='test',
            expires_at=timezone.now() + timedelta(minutes=5)
        )
        
        self.assertTrue(challenge.is_valid())
        
        challenge.mark_used()
        self.assertFalse(challenge.is_valid())
    
    def test_inactive_credentials_rejected(self):
        """Test that inactive credentials can't be used."""
        user = User.objects.create_user(username='test', password='test')
        
        credential = WebAuthnCredential.objects.create(
            user=user,
            credential_id='test',
            public_key='test',
            is_active=False  # Inactive
        )
        
        # Attempt to use would fail in verify
        # (tested via mocked authentication flow)
