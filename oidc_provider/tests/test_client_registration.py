"""
Tests for Dynamic Client Registration (RFC 7591, RFC 7592)
"""
import json
from django.test import TestCase, Client as TestClient
from django.urls import reverse

from oidc_provider.models import Client


class DynamicClientRegistrationTestCase(TestCase):
    """Test Dynamic Client Registration endpoint"""
    
    def setUp(self):
        self.test_client = TestClient()
    
    def test_register_client_minimal(self):
        """Test registering a client with minimal data"""
        data = {
            'redirect_uris': ['https://client.example.com/callback'],
        }
        
        response = self.test_client.post(
            '/oidc/register/',
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 201)
        
        result = json.loads(response.content)
        self.assertIn('client_id', result)
        self.assertIn('client_secret', result)
        self.assertEqual(result['redirect_uris'], data['redirect_uris'])
        
        # Verify client was created
        client = Client.objects.get(client_id=result['client_id'])
        self.assertEqual(client.redirect_uris, data['redirect_uris'])
    
    def test_register_client_full(self):
        """Test registering a client with full metadata"""
        data = {
            'redirect_uris': ['https://app.example.com/callback'],
            'client_name': 'My Application',
            'client_uri': 'https://app.example.com',
            'logo_uri': 'https://app.example.com/logo.png',
            'contacts': ['admin@example.com'],
            'grant_types': ['authorization_code', 'refresh_token'],
            'response_types': ['code'],
            'scope': 'openid profile email',
            'token_endpoint_auth_method': 'client_secret_post',
            'application_type': 'web',
        }
        
        response = self.test_client.post(
            '/oidc/register/',
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 201)
        
        result = json.loads(response.content)
        self.assertEqual(result['client_name'], data['client_name'])
        self.assertEqual(result['redirect_uris'], data['redirect_uris'])
        self.assertEqual(result['grant_types'], data['grant_types'])
        self.assertEqual(result['response_types'], data['response_types'])
        self.assertEqual(result['scope'], data['scope'])
        
        # Verify client
        client = Client.objects.get(client_id=result['client_id'])
        self.assertEqual(client.name, data['client_name'])
        self.assertEqual(client.website_url, data['client_uri'])
    
    def test_register_public_client(self):
        """Test registering a public client (no secret)"""
        data = {
            'redirect_uris': ['https://app.example.com/callback'],
            'client_name': 'Public App',
            'token_endpoint_auth_method': 'none',
        }
        
        response = self.test_client.post(
            '/oidc/register/',
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 201)
        
        result = json.loads(response.content)
        self.assertIn('client_id', result)
        self.assertNotIn('client_secret', result)  # Public clients don't get secrets
        
        # Verify client type
        client = Client.objects.get(client_id=result['client_id'])
        self.assertEqual(client.client_type, 'public')
    
    def test_register_missing_redirect_uris(self):
        """Test registration fails without redirect_uris"""
        data = {
            'client_name': 'My App',
        }
        
        response = self.test_client.post(
            '/oidc/register/',
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        result = json.loads(response.content)
        self.assertEqual(result['error'], 'invalid_redirect_uri')
    
    def test_register_invalid_json(self):
        """Test registration fails with invalid JSON"""
        response = self.test_client.post(
            '/oidc/register/',
            data='invalid json',
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        result = json.loads(response.content)
        self.assertEqual(result['error'], 'invalid_client_metadata')


class ClientManagementTestCase(TestCase):
    """Test Client Management endpoint (RFC 7592)"""
    
    def setUp(self):
        self.test_client = TestClient()
        
        # Create a test client
        self.client = Client.objects.create(
            name='Test Client',
            client_id='test-client-123',
            client_secret='secret123',
            client_type='confidential',
            _redirect_uris='https://example.com/callback',
        )
    
    def test_get_client_configuration(self):
        """Test retrieving client configuration"""
        response = self.test_client.get(f'/oidc/register/{self.client.client_id}/')
        
        self.assertEqual(response.status_code, 200)
        
        result = json.loads(response.content)
        self.assertEqual(result['client_id'], self.client.client_id)
        self.assertEqual(result['client_name'], self.client.name)
        self.assertEqual(result['redirect_uris'], self.client.redirect_uris)
    
    def test_update_client_configuration(self):
        """Test updating client configuration"""
        data = {
            'client_name': 'Updated Client Name',
            'redirect_uris': ['https://new.example.com/callback'],
        }
        
        response = self.test_client.put(
            f'/oidc/register/{self.client.client_id}/',
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        
        # Verify update
        self.client.refresh_from_db()
        self.assertEqual(self.client.name, data['client_name'])
        self.assertEqual(self.client.redirect_uris, data['redirect_uris'])
    
    def test_delete_client(self):
        """Test deleting a client"""
        response = self.test_client.delete(f'/oidc/register/{self.client.client_id}/')
        
        self.assertEqual(response.status_code, 204)
        
        # Verify deletion
        self.assertFalse(Client.objects.filter(client_id=self.client.client_id).exists())
    
    def test_get_nonexistent_client(self):
        """Test getting a non-existent client returns 404"""
        response = self.test_client.get('/oidc/register/nonexistent/')
        
        self.assertEqual(response.status_code, 404)
        result = json.loads(response.content)
        self.assertEqual(result['error'], 'invalid_client_id')
