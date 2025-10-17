"""
Security middleware for OIDC provider.
Adds security headers and implements best practices.
"""

from django.utils.deprecation import MiddlewareMixin
from oidc_provider import settings


class OIDCSecurityHeadersMiddleware(MiddlewareMixin):
    """
    Add security headers to OIDC provider responses.
    """
    
    def process_response(self, request, response):
        # Only apply to OIDC provider endpoints
        if not request.path.startswith(('/authorize', '/token', '/userinfo', '/jwks', '/.well-known')):
            return response
        
        # Prevent clickjacking (except for check-session-iframe)
        if '/check-session-iframe' not in request.path:
            response['X-Frame-Options'] = 'DENY'
            response['Content-Security-Policy'] = "frame-ancestors 'none'"
        
        # Prevent MIME type sniffing
        response['X-Content-Type-Options'] = 'nosniff'
        
        # Enable XSS protection
        response['X-XSS-Protection'] = '1; mode=block'
        
        # Strict Transport Security (HTTPS only)
        if request.is_secure():
            response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        # Referrer policy
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Permissions policy
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        return response


class OIDCCORSMiddleware(MiddlewareMixin):
    """
    Handle CORS for OIDC provider endpoints.
    """
    
    def process_request(self, request):
        # Handle preflight requests
        if request.method == 'OPTIONS':
            return self._create_preflight_response(request)
        return None
    
    def process_response(self, request, response):
        # Only apply to API endpoints
        if request.path.startswith(('/token', '/userinfo', '/jwks', '/.well-known', '/introspect')):
            # Get allowed origins from settings or use wildcard for public endpoints
            if request.path in ['/jwks', '/.well-known/openid-configuration']:
                # Public endpoints - allow all origins
                response['Access-Control-Allow-Origin'] = '*'
            else:
                # Protected endpoints - check allowed origins
                origin = request.META.get('HTTP_ORIGIN', '')
                allowed_origins = settings.get('OIDC_CORS_ALLOWED_ORIGINS', default=['*'])
                
                if '*' in allowed_origins or origin in allowed_origins:
                    response['Access-Control-Allow-Origin'] = origin or '*'
                    response['Access-Control-Allow-Credentials'] = 'true'
            
            # CORS headers
            response['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            response['Access-Control-Allow-Headers'] = 'Authorization, Content-Type, Accept'
            response['Access-Control-Max-Age'] = '86400'  # 24 hours
        
        return response
    
    def _create_preflight_response(self, request):
        from django.http import HttpResponse
        
        response = HttpResponse()
        response['Access-Control-Allow-Origin'] = request.META.get('HTTP_ORIGIN', '*')
        response['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response['Access-Control-Allow-Headers'] = 'Authorization, Content-Type, Accept'
        response['Access-Control-Max-Age'] = '86400'
        
        return response


class OIDCRateLimitMiddleware(MiddlewareMixin):
    """
    Simple rate limiting for OIDC endpoints.
    For production, use Django Ratelimit or similar.
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.rate_limit_cache = {}
    
    def process_request(self, request):
        # Only rate limit sensitive endpoints
        if request.path in ['/token', '/authorize'] and request.method == 'POST':
            # Get client identifier
            client_id = self._get_client_identifier(request)
            
            # Check rate limit (implement your own logic)
            # This is a simple example - use Django cache or Redis in production
            if self._is_rate_limited(client_id):
                from django.http import JsonResponse
                return JsonResponse({
                    'error': 'too_many_requests',
                    'error_description': 'Rate limit exceeded. Please try again later.'
                }, status=429)
        
        return None
    
    def _get_client_identifier(self, request):
        # Use client_id or IP address
        client_id = request.POST.get('client_id', '')
        if client_id:
            return f'client:{client_id}'
        return f'ip:{self._get_client_ip(request)}'
    
    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def _is_rate_limited(self, identifier):
        # Implement your rate limiting logic here
        # This is a placeholder - use proper rate limiting in production
        import time
        from collections import defaultdict
        
        if not hasattr(self, '_rate_data'):
            self._rate_data = defaultdict(list)
        
        now = time.time()
        window = 60  # 1 minute window
        max_requests = 60  # Max requests per window
        
        # Clean old requests
        self._rate_data[identifier] = [
            req_time for req_time in self._rate_data[identifier]
            if now - req_time < window
        ]
        
        # Check limit
        if len(self._rate_data[identifier]) >= max_requests:
            return True
        
        # Add current request
        self._rate_data[identifier].append(now)
        return False
