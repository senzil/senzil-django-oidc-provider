"""
Origin validation middleware for OIDC provider.
Validates request origins against client allowed domains.
"""

from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


class OriginValidationMiddleware(MiddlewareMixin):
    """
    Validate request origin against client's allowed origins.
    """
    
    # OIDC endpoints that require origin validation
    PROTECTED_PATHS = [
        '/authorize',
        '/token',
        '/userinfo',
        '/introspect',
    ]
    
    def process_request(self, request):
        # Only validate protected endpoints
        if not any(request.path.startswith(path) for path in self.PROTECTED_PATHS):
            return None
        
        # Get client_id from request
        client_id = self._get_client_id(request)
        if not client_id:
            # No client_id, let the endpoint handle validation
            return None
        
        # Get client
        from oidc_provider.models import Client
        try:
            client = Client.objects.get(client_id=client_id)
        except Client.DoesNotExist:
            # Invalid client, let endpoint handle it
            return None
        
        # Check if strict origin validation is enabled
        if not client.strict_origin_validation:
            # Store origin for tracking anyway
            origin = self._get_origin(request)
            if origin:
                request.oidc_origin = origin
            return None
        
        # Get and validate origin
        origin = self._get_origin(request)
        
        if not origin:
            logger.warning(f'No origin header for client {client_id}')
            return JsonResponse({
                'error': 'invalid_request',
                'error_description': 'Origin header required'
            }, status=400)
        
        # Check if origin is allowed
        if not self._is_origin_allowed(origin, client):
            logger.warning(f'Origin {origin} not allowed for client {client_id}')
            return JsonResponse({
                'error': 'invalid_request',
                'error_description': f'Origin {origin} not allowed for this client'
            }, status=403)
        
        # Store validated origin in request
        request.oidc_origin = origin
        return None
    
    def _get_client_id(self, request):
        """Extract client_id from request."""
        # Check GET params (authorize endpoint)
        client_id = request.GET.get('client_id')
        if client_id:
            return client_id
        
        # Check POST params (token endpoint)
        client_id = request.POST.get('client_id')
        if client_id:
            return client_id
        
        # Check Authorization header (Basic auth)
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if auth_header.startswith('Basic '):
            try:
                import base64
                decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
                client_id = decoded.split(':')[0]
                return client_id
            except:
                pass
        
        # Check Bearer token (introspection)
        if request.path.startswith('/introspect'):
            # Client auth in POST
            return request.POST.get('client_id')
        
        return None
    
    def _get_origin(self, request):
        """Extract origin from request headers."""
        # Try Origin header first (CORS requests)
        origin = request.META.get('HTTP_ORIGIN')
        if origin:
            return self._normalize_origin(origin)
        
        # Fallback to Referer header
        referer = request.META.get('HTTP_REFERER')
        if referer:
            parsed = urlparse(referer)
            return f"{parsed.scheme}://{parsed.netloc}"
        
        # Last resort: construct from Host header
        host = request.META.get('HTTP_HOST')
        if host:
            scheme = 'https' if request.is_secure() else 'http'
            return f"{scheme}://{host}"
        
        return None
    
    def _normalize_origin(self, origin):
        """Normalize origin URL."""
        # Remove trailing slash
        origin = origin.rstrip('/')
        
        # Ensure it has a scheme
        if not origin.startswith(('http://', 'https://')):
            origin = f'https://{origin}'
        
        return origin
    
    def _is_origin_allowed(self, origin, client):
        """Check if origin is in client's allowed list."""
        # Get allowed origins
        allowed_origins = self._get_allowed_origins(client)
        
        # If no origins configured, allow all
        if not allowed_origins:
            return True
        
        # Normalize origin for comparison
        origin = self._normalize_origin(origin)
        
        # Check exact match
        if origin in allowed_origins:
            return True
        
        # Check wildcard patterns
        parsed_origin = urlparse(origin)
        origin_domain = parsed_origin.netloc
        
        for allowed in allowed_origins:
            # Support wildcards like https://*.example.com
            if '*' in allowed:
                allowed_pattern = allowed.replace('https://*.', '')
                allowed_pattern = allowed_pattern.replace('http://*.', '')
                
                if origin_domain.endswith(allowed_pattern):
                    return True
            
            # Check if redirect_uri domain matches origin
            if allowed in client.redirect_uris:
                allowed_parsed = urlparse(allowed)
                if allowed_parsed.netloc == origin_domain:
                    return True
        
        return False
    
    def _get_allowed_origins(self, client):
        """Get list of allowed origins for client."""
        origins = []
        
        # From allowed_origins field (primary)
        if client.allowed_origins:
            origins.extend([
                self._normalize_origin(origin.strip())
                for origin in client.allowed_origins.split('\n')
                if origin.strip()
            ])
        
        # From allowed_domains field (legacy)
        if hasattr(client, 'allowed_domains') and client.allowed_domains:
            domains = [d.strip() for d in client.allowed_domains.split(',') if d.strip()]
            for domain in domains:
                if not domain.startswith(('http://', 'https://')):
                    # Assume HTTPS for legacy domains
                    origins.append(f'https://{domain}')
                else:
                    origins.append(self._normalize_origin(domain))
        
        # Automatically include redirect_uri domains
        for redirect_uri in client.redirect_uris:
            parsed = urlparse(redirect_uri)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            if origin not in origins:
                origins.append(origin)
        
        return origins


class OriginTrackingMiddleware(MiddlewareMixin):
    """
    Track origin domain in OIDC requests for audit and analytics.
    """
    
    def process_request(self, request):
        # Extract and store origin for all OIDC requests
        origin = self._get_origin(request)
        
        if origin:
            request.oidc_origin = origin
            request.oidc_origin_domain = self._extract_domain(origin)
        
        return None
    
    def _get_origin(self, request):
        """Extract origin from request."""
        # Origin header
        origin = request.META.get('HTTP_ORIGIN')
        if origin:
            return origin.rstrip('/')
        
        # Referer header
        referer = request.META.get('HTTP_REFERER')
        if referer:
            parsed = urlparse(referer)
            return f"{parsed.scheme}://{parsed.netloc}"
        
        # Host header
        host = request.META.get('HTTP_HOST')
        if host:
            scheme = 'https' if request.is_secure() else 'http'
            return f"{scheme}://{host}"
        
        return None
    
    def _extract_domain(self, origin):
        """Extract domain from origin URL."""
        if not origin:
            return None
        
        parsed = urlparse(origin)
        return parsed.netloc


def get_request_origin(request):
    """
    Helper function to get origin from request.
    Returns normalized origin URL.
    """
    # Check if already extracted by middleware
    if hasattr(request, 'oidc_origin'):
        return request.oidc_origin
    
    # Extract manually
    origin = request.META.get('HTTP_ORIGIN')
    if origin:
        return origin.rstrip('/')
    
    referer = request.META.get('HTTP_REFERER')
    if referer:
        parsed = urlparse(referer)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    host = request.META.get('HTTP_HOST')
    if host:
        scheme = 'https' if request.is_secure() else 'http'
        return f"{scheme}://{host}"
    
    return None


def get_request_origin_domain(request):
    """
    Helper function to get origin domain from request.
    Returns just the domain part (e.g., 'example.com').
    """
    # Check if already extracted by middleware
    if hasattr(request, 'oidc_origin_domain'):
        return request.oidc_origin_domain
    
    origin = get_request_origin(request)
    if origin:
        parsed = urlparse(origin)
        return parsed.netloc
    
    return None
