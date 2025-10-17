# Dynamic Client Registration

Complete guide to Dynamic Client Registration API endpoints.

## Overview

Dynamic Client Registration allows clients to register themselves programmatically without manual admin intervention.

**Standards:**
- **RFC 7591** - OAuth 2.0 Dynamic Client Registration Protocol
- **RFC 7592** - OAuth 2.0 Dynamic Client Registration Management Protocol
- **OpenID Connect Dynamic Client Registration 1.0**

## Configuration

### Enable/Disable

```python
# settings.py

# Enable dynamic client registration (default: True)
OIDC_DYNAMIC_CLIENT_REGISTRATION_ENABLE = True
```

## Registration Endpoint

### Register New Client

**Endpoint:** `POST /oidc/register/`

**Request:**
```http
POST /oidc/register/
Content-Type: application/json

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
  "application_type": "web"
}
```

**Response (201 Created):**
```json
{
  "client_id": "automatically-generated-id",
  "client_secret": "automatically-generated-secret",
  "client_id_issued_at": 1234567890,
  "client_secret_expires_at": 0,
  "redirect_uris": ["https://client.example.com/callback"],
  "client_name": "My Application",
  "client_uri": "https://client.example.com",
  "logo_uri": "https://client.example.com/logo.png",
  "contacts": ["admin@example.com"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid profile email",
  "token_endpoint_auth_method": "client_secret_post",
  "application_type": "web"
}
```

### Request Parameters

#### Required
- `redirect_uris` (array) - Redirect URIs for the client

#### Optional
- `client_name` (string) - Human-readable client name
- `client_uri` (string) - Client homepage URL
- `logo_uri` (string) - Client logo URL
- `contacts` (array) - Contact email addresses
- `grant_types` (array) - OAuth 2.0 grant types
- `response_types` (array) - OAuth 2.0 response types
- `scope` (string) - Space-separated scopes
- `token_endpoint_auth_method` (string) - Authentication method
- `application_type` (string) - `web` or `native`
- `jwks_uri` (string) - URL for client's JWK Set

### Client Types

**Confidential Client (with secret):**
```json
{
  "redirect_uris": ["https://app.example.com/callback"],
  "client_name": "My Web App",
  "token_endpoint_auth_method": "client_secret_post"
}
```

**Public Client (no secret):**
```json
{
  "redirect_uris": ["https://app.example.com/callback"],
  "client_name": "My SPA",
  "token_endpoint_auth_method": "none"
}
```

## Client Management Endpoints

### Get Client Configuration

**Endpoint:** `GET /oidc/register/{client_id}/`

**Response:**
```json
{
  "client_id": "abc123",
  "client_name": "My Application",
  "redirect_uris": ["https://client.example.com/callback"],
  "response_types": ["code"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scope": "openid profile email",
  "token_endpoint_auth_method": "client_secret_post",
  "application_type": "web"
}
```

### Update Client Configuration

**Endpoint:** `PUT /oidc/register/{client_id}/`

**Request:**
```json
{
  "client_name": "Updated Application Name",
  "redirect_uris": ["https://new.example.com/callback"],
  "logo_uri": "https://new.example.com/logo.png"
}
```

**Response:**
```json
{
  "client_id": "abc123",
  "client_name": "Updated Application Name",
  "redirect_uris": ["https://new.example.com/callback"],
  "logo_uri": "https://new.example.com/logo.png"
}
```

### Delete Client

**Endpoint:** `DELETE /oidc/register/{client_id}/`

**Response:** `204 No Content`

## Examples

### Python Example

```python
import requests

# Register new client
registration_data = {
    'redirect_uris': ['https://myapp.com/callback'],
    'client_name': 'My Python App',
    'scope': 'openid profile email',
    'grant_types': ['authorization_code', 'refresh_token'],
    'response_types': ['code'],
}

response = requests.post(
    'https://your-oidc-provider.com/oidc/register/',
    json=registration_data
)

client_info = response.json()
print(f"Client ID: {client_info['client_id']}")
print(f"Client Secret: {client_info['client_secret']}")

# Save these credentials securely
client_id = client_info['client_id']
client_secret = client_info['client_secret']
```

### cURL Example

```bash
# Register client
curl -X POST https://your-oidc-provider.com/oidc/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["https://app.example.com/callback"],
    "client_name": "My App",
    "scope": "openid profile email"
  }'

# Get client configuration
curl https://your-oidc-provider.com/oidc/register/CLIENT_ID/

# Update client
curl -X PUT https://your-oidc-provider.com/oidc/register/CLIENT_ID/ \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Updated App Name"
  }'

# Delete client
curl -X DELETE https://your-oidc-provider.com/oidc/register/CLIENT_ID/
```

### JavaScript Example

```javascript
// Register new client
const registrationData = {
  redirect_uris: ['https://myapp.com/callback'],
  client_name: 'My JavaScript App',
  scope: 'openid profile email',
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
};

const response = await fetch('https://your-oidc-provider.com/oidc/register/', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify(registrationData),
});

const clientInfo = await response.json();
console.log('Client ID:', clientInfo.client_id);
console.log('Client Secret:', clientInfo.client_secret);

// Store credentials securely
localStorage.setItem('client_id', clientInfo.client_id);
// Never store client_secret in browser storage for web apps!
```

## Error Responses

### Invalid Redirect URI
```json
{
  "error": "invalid_redirect_uri",
  "error_description": "At least one redirect_uri is required"
}
```

### Invalid Metadata
```json
{
  "error": "invalid_client_metadata",
  "error_description": "Invalid JSON in request body"
}
```

### Client Not Found
```json
{
  "error": "invalid_client_id",
  "error_description": "Client not found"
}
```

## Security Considerations

### 1. Protect Client Credentials

- Store `client_secret` securely (encrypted in database)
- Never expose secrets in browser/mobile apps
- Use `token_endpoint_auth_method: "none"` for public clients

### 2. Validate Redirect URIs

- Always use HTTPS (except localhost for development)
- Validate exact URI matches (no wildcards)
- Reject open redirectors

### 3. Limit Registration

Consider adding:
- Rate limiting
- CAPTCHA for public registration
- Initial Access Tokens (RFC 7591 Section 3.1)
- Admin approval workflow

### 4. Monitor Clients

- Log all registrations
- Monitor for abuse
- Implement client expiration
- Regular cleanup of unused clients

## Advanced Configuration

### Require Initial Access Token

```python
# settings.py

def validate_registration_token(request):
    """Validate initial access token for registration."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    # Your validation logic
    return token == 'your-secret-registration-token'

OIDC_REGISTRATION_TOKEN_VALIDATOR = 'myapp.utils.validate_registration_token'
```

### Custom Client Defaults

```python
# settings.py

OIDC_REGISTRATION_DEFAULTS = {
    'jwt_alg': 'ES256',
    'access_token_jwt_alg': 'ES256',
    'require_consent': True,
    'reuse_consent': True,
}
```

## Integration with Discovery

The registration endpoint is included in the discovery document:

```json
{
  "issuer": "https://your-oidc-provider.com/oidc",
  "registration_endpoint": "https://your-oidc-provider.com/oidc/register/",
  ...
}
```

Clients can discover it at: `/.well-known/openid-configuration`

## Testing

```bash
# Run registration tests
python manage.py test oidc_provider.tests.test_client_registration
```

## Summary

Dynamic Client Registration allows:
- ✅ Self-service client registration
- ✅ Programmatic client management
- ✅ Standards-compliant implementation (RFC 7591, RFC 7592)
- ✅ Support for confidential and public clients
- ✅ Full CRUD operations on clients

See [Configuration Guide](configuration.md) for additional settings.
