"""
Tests for origin validation and tracking.
"""

from django.test import TestCase, RequestFactory, Client as TestClient
from django.contrib.auth import get_user_model
from oidc_provider.models import Client, ResponseType, Token, Code
from oidc_provider.middleware_origin import (
    OriginValidationMiddleware,
    OriginTrackingMiddleware,
    get_request_origin,
    get_request_origin_domain,
)
from oidc_provider.lib.utils.token_origin import (
    validate_origin_for_client,
    get_allowed_origins_for_client,
)

User = get_user_model()


class OriginValidationTest(TestCase):
    """Test origin validation functionality."""
    
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        # Create OIDC client
        self.oidc_client = Client.objects.create(
            name='Test Client',
            client_id='test123',
            client_type='confidential',
            client_secret='secret',
            strict_origin_validation=True,
            allowed_origins='https://app.example.com',
        )
        
        code_type, _ = ResponseType.objects.get_or_create(
            value='code',
            defaults={'description': 'Authorization Code Flow'}
        )
        self.oidc_client.response_types.add(code_type)
        self.oidc_client.redirect_uris = ['https://app.example.com/callback']
        self.oidc_client.save()
    
    def test_validate_origin_for_allowed_domain(self):
        """Test that allowed origin passes validation."""
        result = validate_origin_for_client(
            'https://app.example.com',
            self.oidc_client
        )
        self.assertTrue(result)
    
    def test_validate_origin_rejects_unlisted_domain(self):
        """Test that unlisted origin is rejected."""
        result = validate_origin_for_client(
            'https://evil.com',
            self.oidc_client
        )
        self.assertFalse(result)
    
    def test_wildcard_origin_pattern(self):
        """Test wildcard domain patterns."""
        self.oidc_client.allowed_origins = 'https://*.example.com'
        self.oidc_client.save()
        
        # Should allow subdomains
        self.assertTrue(validate_origin_for_client(
            'https://app.example.com',
            self.oidc_client
        ))
        self.assertTrue(validate_origin_for_client(
            'https://portal.example.com',
            self.oidc_client
        ))
        self.assertTrue(validate_origin_for_client(
            'https://admin.example.com',
            self.oidc_client
        ))
        
        # Should reject non-subdomains
        self.assertFalse(validate_origin_for_client(
            'https://example.com.evil.com',
            self.oidc_client
        ))
    
    def test_get_allowed_origins_from_redirect_uris(self):
        """Test that redirect_uri domains are auto-allowed."""
        self.oidc_client.allowed_origins = ''
        self.oidc_client.save()
        
        origins = get_allowed_origins_for_client(self.oidc_client)
        
        # Should include redirect_uri origin
        self.assertIn('https://app.example.com', origins)
    
    def test_permissive_mode_allows_all(self):
        """Test that permissive mode allows all origins."""
        self.oidc_client.strict_origin_validation = False
        self.oidc_client.allowed_origins = ''
        self.oidc_client.save()
        
        result = validate_origin_for_client(
            'https://any-domain.com',
            self.oidc_client
        )
        self.assertTrue(result)


class OriginTrackingTest(TestCase):
    """Test origin tracking in tokens."""
    
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        
        self.client = Client.objects.create(
            name='Test Client',
            client_id='test123',
            include_origin_in_tokens=True,
        )
    
    def test_get_origin_from_origin_header(self):
        """Test extracting origin from Origin header."""
        request = self.factory.get(
            '/authorize',
            HTTP_ORIGIN='https://app.example.com'
        )
        
        origin = get_request_origin(request)
        self.assertEqual(origin, 'https://app.example.com')
    
    def test_get_origin_from_referer_header(self):
        """Test extracting origin from Referer header."""
        request = self.factory.get(
            '/authorize',
            HTTP_REFERER='https://app.example.com/login'
        )
        
        origin = get_request_origin(request)
        self.assertEqual(origin, 'https://app.example.com')
    
    def test_get_origin_domain(self):
        """Test extracting domain from origin."""
        request = self.factory.get(
            '/authorize',
            HTTP_ORIGIN='https://app.example.com'
        )
        
        domain = get_request_origin_domain(request)
        self.assertEqual(domain, 'app.example.com')
    
    def test_token_stores_origin_domain(self):
        """Test that tokens store origin domain."""
        from oidc_provider.lib.utils.token_origin import create_token_with_origin
        
        request = self.factory.get(
            '/token',
            HTTP_ORIGIN='https://app.example.com'
        )
        
        # Add middleware attributes
        request.oidc_origin = 'https://app.example.com'
        request.oidc_origin_domain = 'app.example.com'
        
        token = create_token_with_origin(
            user=self.user,
            client=self.client,
            scope=['openid'],
            request=request
        )
        
        self.assertEqual(token.origin_domain, 'app.example.com')
    
    def test_code_stores_origin_domain(self):
        """Test that authorization codes store origin domain."""
        from oidc_provider.lib.utils.token_origin import create_code_with_origin
        
        request = self.factory.get(
            '/authorize',
            HTTP_ORIGIN='https://portal.example.com'
        )
        
        request.oidc_origin = 'https://portal.example.com'
        request.oidc_origin_domain = 'portal.example.com'
        
        code = create_code_with_origin(
            user=self.user,
            client=self.client,
            scope=['openid'],
            nonce='test',
            is_authentication=True,
            request=request
        )
        
        self.assertEqual(code.origin_domain, 'portal.example.com')


class OriginInJWTTest(TestCase):
    """Test origin claims in JWT tokens."""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        
        self.client = Client.objects.create(
            name='Test Client',
            client_id='test123',
            jwt_alg='HS256',
            client_secret='secret' * 8,
            include_origin_in_tokens=True,
        )
        
        self.factory = RequestFactory()
    
    def test_origin_included_in_id_token(self):
        """Test that origin is included in ID token claims."""
        from oidc_provider.lib.utils.token import create_id_token
        from oidc_provider.lib.utils.token_origin import add_origin_to_id_token, create_token_with_origin
        
        request = self.factory.get(
            '/authorize',
            HTTP_ORIGIN='https://app.example.com'
        )
        request.oidc_origin = 'https://app.example.com'
        request.oidc_origin_domain = 'app.example.com'
        
        token = create_token_with_origin(
            user=self.user,
            client=self.client,
            scope=['openid'],
            request=request
        )
        
        id_token_dic = create_id_token(
            token=token,
            user=self.user,
            aud=self.client.client_id,
            request=request,
        )
        
        id_token_dic = add_origin_to_id_token(id_token_dic, self.client, request)
        
        self.assertEqual(id_token_dic['origin'], 'https://app.example.com')
        self.assertEqual(id_token_dic['origin_domain'], 'app.example.com')
    
    def test_origin_not_included_when_disabled(self):
        """Test that origin is not included when feature disabled."""
        from oidc_provider.lib.utils.token import create_id_token
        from oidc_provider.lib.utils.token_origin import add_origin_to_id_token, create_token_with_origin
        
        self.client.include_origin_in_tokens = False
        self.client.save()
        
        request = self.factory.get(
            '/authorize',
            HTTP_ORIGIN='https://app.example.com'
        )
        request.oidc_origin = 'https://app.example.com'
        
        token = create_token_with_origin(
            user=self.user,
            client=self.client,
            scope=['openid'],
            request=request
        )
        
        id_token_dic = create_id_token(
            token=token,
            user=self.user,
            aud=self.client.client_id,
            request=request,
        )
        
        id_token_dic = add_origin_to_id_token(id_token_dic, self.client, request)
        
        self.assertNotIn('origin', id_token_dic)
        self.assertNotIn('origin_domain', id_token_dic)


class OriginMiddlewareTest(TestCase):
    """Test origin validation middleware."""
    
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = OriginValidationMiddleware(get_response=lambda r: None)
        
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        
        self.client = Client.objects.create(
            name='Test Client',
            client_id='test123',
            strict_origin_validation=True,
            allowed_origins='https://app.example.com',
        )
    
    def test_middleware_allows_valid_origin(self):
        """Test middleware allows valid origin."""
        request = self.factory.get(
            '/authorize?client_id=test123',
            HTTP_ORIGIN='https://app.example.com'
        )
        
        response = self.middleware.process_request(request)
        self.assertIsNone(response)  # None means continue
        self.assertEqual(request.oidc_origin, 'https://app.example.com')
    
    def test_middleware_rejects_invalid_origin(self):
        """Test middleware rejects invalid origin."""
        request = self.factory.get(
            '/authorize?client_id=test123',
            HTTP_ORIGIN='https://evil.com'
        )
        
        response = self.middleware.process_request(request)
        self.assertIsNotNone(response)  # Response means rejected
        self.assertEqual(response.status_code, 403)
    
    def test_middleware_skips_non_oidc_endpoints(self):
        """Test middleware doesn't validate non-OIDC endpoints."""
        request = self.factory.get('/admin/')
        
        response = self.middleware.process_request(request)
        self.assertIsNone(response)  # Should pass through
    
    def test_middleware_stores_origin_in_request(self):
        """Test middleware stores origin in request object."""
        tracking_middleware = OriginTrackingMiddleware(get_response=lambda r: None)
        
        request = self.factory.get(
            '/authorize',
            HTTP_ORIGIN='https://app.example.com'
        )
        
        tracking_middleware.process_request(request)
        
        self.assertEqual(request.oidc_origin, 'https://app.example.com')
        self.assertEqual(request.oidc_origin_domain, 'app.example.com')


class OriginIntegrationTest(TestCase):
    """Test full origin validation integration with OIDC flows."""
    
    def setUp(self):
        self.test_client = TestClient()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        self.oidc_client = Client.objects.create(
            name='Test Client',
            client_id='test123',
            client_type='confidential',
            client_secret='secret',
            strict_origin_validation=True,
            allowed_origins='https://app.example.com\nhttps://portal.example.com',
            include_origin_in_tokens=True,
        )
        
        code_type, _ = ResponseType.objects.get_or_create(
            value='code',
            defaults={'description': 'Authorization Code Flow'}
        )
        self.oidc_client.response_types.add(code_type)
        self.oidc_client.redirect_uris = ['https://app.example.com/callback']
        self.oidc_client.save()
    
    def test_authorize_endpoint_validates_origin(self):
        """Test that authorize endpoint validates origin."""
        self.test_client.login(username='testuser', password='testpass123')
        
        # Valid origin
        response = self.test_client.get(
            '/authorize/',
            {
                'client_id': 'test123',
                'response_type': 'code',
                'redirect_uri': 'https://app.example.com/callback',
                'scope': 'openid',
            },
            HTTP_ORIGIN='https://app.example.com'
        )
        
        # Should not be rejected (would show consent or redirect)
        self.assertNotEqual(response.status_code, 403)
    
    def test_authorize_endpoint_rejects_invalid_origin(self):
        """Test that authorize endpoint rejects invalid origin."""
        self.test_client.login(username='testuser', password='testpass123')
        
        # Invalid origin
        response = self.test_client.get(
            '/authorize/',
            {
                'client_id': 'test123',
                'response_type': 'code',
                'redirect_uri': 'https://app.example.com/callback',
                'scope': 'openid',
            },
            HTTP_ORIGIN='https://evil.com'
        )
        
        # Should be rejected
        self.assertEqual(response.status_code, 403)
    
    def test_multiple_allowed_origins(self):
        """Test client with multiple allowed origins."""
        # Test first origin
        result1 = validate_origin_for_client(
            'https://app.example.com',
            self.oidc_client
        )
        self.assertTrue(result1)
        
        # Test second origin
        result2 = validate_origin_for_client(
            'https://portal.example.com',
            self.oidc_client
        )
        self.assertTrue(result2)
        
        # Test invalid origin
        result3 = validate_origin_for_client(
            'https://other.com',
            self.oidc_client
        )
        self.assertFalse(result3)


class OriginAnalyticsTest(TestCase):
    """Test origin analytics and reporting."""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        
        self.client = Client.objects.create(
            name='Test Client',
            client_id='test123',
        )
    
    def test_query_tokens_by_origin(self):
        """Test querying tokens by origin domain."""
        # Create tokens from different origins
        token1 = Token.objects.create(
            user=self.user,
            client=self.client,
            access_token='token1',
            refresh_token='refresh1',
            origin_domain='app.example.com',
            scope=['openid'],
        )
        
        token2 = Token.objects.create(
            user=self.user,
            client=self.client,
            access_token='token2',
            refresh_token='refresh2',
            origin_domain='portal.example.com',
            scope=['openid'],
        )
        
        # Query by origin
        app_tokens = Token.objects.filter(origin_domain='app.example.com')
        self.assertEqual(app_tokens.count(), 1)
        self.assertEqual(app_tokens.first().access_token, 'token1')
    
    def test_origin_analytics_aggregation(self):
        """Test origin analytics aggregation."""
        from django.db.models import Count
        
        # Create multiple tokens from same origin
        for i in range(5):
            Token.objects.create(
                user=self.user,
                client=self.client,
                access_token=f'token{i}',
                refresh_token=f'refresh{i}',
                origin_domain='app.example.com',
                scope=['openid'],
            )
        
        # Aggregate by origin
        stats = Token.objects.values('origin_domain').annotate(
            count=Count('id')
        )
        
        app_stat = next(s for s in stats if s['origin_domain'] == 'app.example.com')
        self.assertEqual(app_stat['count'], 5)
