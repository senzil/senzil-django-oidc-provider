"""
Dynamic Client Registration
Implements RFC 7591 and OpenID Connect Dynamic Client Registration 1.0
"""
import json
import secrets
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils.decorators import method_decorator
from django.views import View

from oidc_provider.models import Client, ResponseType
from oidc_provider.lib.errors import ClientRegistrationError


def generate_client_id():
    """Generate a unique client ID."""
    return secrets.token_urlsafe(32)


def generate_client_secret():
    """Generate a client secret."""
    return secrets.token_urlsafe(48)


@csrf_exempt
@require_http_methods(["POST"])
def client_registration(request):
    """
    Dynamic Client Registration Endpoint
    
    RFC 7591 - OAuth 2.0 Dynamic Client Registration Protocol
    OpenID Connect Dynamic Client Registration 1.0
    
    POST /oidc/register/
    
    Request body (JSON):
    {
        "redirect_uris": ["https://client.example.com/callback"],
        "client_name": "My Application",
        "client_uri": "https://client.example.com",
        "logo_uri": "https://client.example.com/logo.png",
        "contacts": ["admin@example.com"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": "openid profile email",
        "token_endpoint_auth_method": "client_secret_post",
        "application_type": "web",
        "jwks_uri": "https://client.example.com/jwks",
        "subject_type": "public"
    }
    
    Response:
    {
        "client_id": "...",
        "client_secret": "...",
        "client_id_issued_at": 1234567890,
        "client_secret_expires_at": 0,
        "redirect_uris": [...],
        "grant_types": [...],
        "response_types": [...],
        ...
    }
    """
    try:
        # Parse request body
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({
                'error': 'invalid_client_metadata',
                'error_description': 'Invalid JSON in request body'
            }, status=400)
        
        # Validate required fields
        redirect_uris = data.get('redirect_uris', [])
        if not redirect_uris:
            return JsonResponse({
                'error': 'invalid_redirect_uri',
                'error_description': 'At least one redirect_uri is required'
            }, status=400)
        
        # Extract metadata
        client_name = data.get('client_name', 'Dynamically Registered Client')
        client_uri = data.get('client_uri', '')
        logo_uri = data.get('logo_uri', '')
        contacts = data.get('contacts', [])
        grant_types = data.get('grant_types', ['authorization_code'])
        response_types = data.get('response_types', ['code'])
        scope = data.get('scope', 'openid')
        token_endpoint_auth_method = data.get('token_endpoint_auth_method', 'client_secret_post')
        application_type = data.get('application_type', 'web')
        
        # Determine client type
        if token_endpoint_auth_method == 'none':
            client_type = 'public'
        else:
            client_type = 'confidential'
        
        # Generate credentials
        client_id = generate_client_id()
        client_secret = generate_client_secret() if client_type == 'confidential' else None
        
        # Create client
        client = Client.objects.create(
            name=client_name,
            client_id=client_id,
            client_secret=client_secret,
            client_type=client_type,
            _redirect_uris=' '.join(redirect_uris),
            website_url=client_uri,
            logo=logo_uri,
            contact_email=contacts[0] if contacts else '',
            _scope=' '.join(scope.split()),
            
            # Algorithm defaults
            jwt_alg='ES256',
            access_token_jwt_alg='ES256',
            
            # Dynamic registration flag
            require_consent=True,
            reuse_consent=True,
        )
        
        # Add response types
        for response_type in response_types:
            try:
                rt = ResponseType.objects.get(value=response_type)
                client.response_types.add(rt)
            except ResponseType.DoesNotExist:
                pass
        
        # Build response (RFC 7591 format)
        import time
        response_data = {
            'client_id': client.client_id,
            'client_id_issued_at': int(time.time()),
            'client_secret_expires_at': 0,  # Never expires
            'redirect_uris': redirect_uris,
            'grant_types': grant_types,
            'response_types': response_types,
            'client_name': client_name,
            'token_endpoint_auth_method': token_endpoint_auth_method,
            'application_type': application_type,
        }
        
        if client_secret:
            response_data['client_secret'] = client_secret
        
        if client_uri:
            response_data['client_uri'] = client_uri
        
        if logo_uri:
            response_data['logo_uri'] = logo_uri
        
        if contacts:
            response_data['contacts'] = contacts
        
        if scope:
            response_data['scope'] = scope
        
        return JsonResponse(response_data, status=201)
        
    except Exception as e:
        return JsonResponse({
            'error': 'server_error',
            'error_description': str(e)
        }, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class ClientManagementView(View):
    """
    Client Configuration Endpoint
    
    RFC 7592 - OAuth 2.0 Dynamic Client Registration Management Protocol
    
    GET /oidc/register/<client_id>/ - Get client configuration
    PUT /oidc/register/<client_id>/ - Update client configuration
    DELETE /oidc/register/<client_id>/ - Delete client
    """
    
    def get(self, request, client_id):
        """Get client configuration"""
        try:
            client = Client.objects.get(client_id=client_id)
            
            # Build response
            response_data = {
                'client_id': client.client_id,
                'client_name': client.name,
                'redirect_uris': client.redirect_uris,
                'response_types': [rt.value for rt in client.response_types.all()],
                'grant_types': ['authorization_code', 'refresh_token'],
                'scope': client.scope,
                'token_endpoint_auth_method': 'client_secret_post' if client.client_type == 'confidential' else 'none',
                'application_type': 'web',
            }
            
            if client.website_url:
                response_data['client_uri'] = client.website_url
            
            return JsonResponse(response_data)
            
        except Client.DoesNotExist:
            return JsonResponse({
                'error': 'invalid_client_id',
                'error_description': 'Client not found'
            }, status=404)
    
    def put(self, request, client_id):
        """Update client configuration"""
        try:
            client = Client.objects.get(client_id=client_id)
            
            # Parse request
            data = json.loads(request.body)
            
            # Update allowed fields
            if 'client_name' in data:
                client.name = data['client_name']
            
            if 'redirect_uris' in data:
                client._redirect_uris = ' '.join(data['redirect_uris'])
            
            if 'client_uri' in data:
                client.website_url = data['client_uri']
            
            if 'logo_uri' in data:
                client.logo = data['logo_uri']
            
            if 'scope' in data:
                client._scope = ' '.join(data['scope'].split())
            
            client.save()
            
            # Return updated configuration
            return JsonResponse({
                'client_id': client.client_id,
                'client_name': client.name,
                'redirect_uris': client.redirect_uris,
                'client_uri': client.website_url,
            })
            
        except Client.DoesNotExist:
            return JsonResponse({
                'error': 'invalid_client_id',
                'error_description': 'Client not found'
            }, status=404)
        except json.JSONDecodeError:
            return JsonResponse({
                'error': 'invalid_request',
                'error_description': 'Invalid JSON'
            }, status=400)
    
    def delete(self, request, client_id):
        """Delete client"""
        try:
            client = Client.objects.get(client_id=client_id)
            client.delete()
            
            return JsonResponse({
                'message': 'Client deleted successfully'
            }, status=204)
            
        except Client.DoesNotExist:
            return JsonResponse({
                'error': 'invalid_client_id',
                'error_description': 'Client not found'
            }, status=404)
