# Configuration Reference

Complete configuration guide for Django OIDC Provider.

## Table of Contents
- [Basic Configuration](#basic-configuration)
- [Security Settings](#security-settings)
- [Token Settings](#token-settings)
- [Passkey Settings](#passkey-settings)
- [Origin Security](#origin-security)
- [Client Configuration](#client-configuration)

## Basic Configuration

### Required Settings

```python
# settings.py

# Installed Apps
INSTALLED_APPS = [
    # ...
    'oidc_provider',
]

# Middleware
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    # ... other middleware ...
    'oidc_provider.middleware_origin.OriginTrackingMiddleware',
    'oidc_provider.middleware_origin.OriginValidationMiddleware',
    'oidc_provider.middleware_security.OIDCSecurityHeadersMiddleware',
]

# URLs
# In urls.py:
path('oidc/', include('oidc_provider.urls', namespace='oidc_provider')),
path('oidc/', include('oidc_provider.urls_passkey')),
```

## Security Settings

### HTTPS Configuration

```python
# Production HTTPS settings
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
```

### Security Headers

```python
# Automatically applied by middleware
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
# Strict-Transport-Security: max-age=31536000
# Content-Security-Policy: default-src 'self'
# Referrer-Policy: strict-origin-when-cross-origin
```

## Token Settings

### Token Expiration

```python
# Token lifetimes (in seconds)
OIDC_TOKEN_EXPIRE = 3600  # Access token: 1 hour
OIDC_IDTOKEN_EXPIRE = 600  # ID token: 10 minutes
OIDC_CODE_EXPIRE = 600     # Authorization code: 10 minutes
```

### Access Token Configuration

```python
# JWT format for access tokens
OIDC_ACCESS_TOKEN_JWT = True

# Access token audience (resource server)
def api_audience(client, request=None):
    return "https://api.example.com"

OIDC_TOKEN_JWT_AUD = 'myapp.utils.api_audience'
```

### Subject Generator

```python
# Default: uses user.id
OIDC_IDTOKEN_SUB_GENERATOR = 'oidc_provider.lib.utils.common.default_sub_generator'

# Custom:
def custom_sub(user):
    return f"user_{user.id}"

OIDC_IDTOKEN_SUB_GENERATOR = 'myapp.utils.custom_sub'
```

## Passkey Settings

### WebAuthn Configuration

```python
# Required for passkey support
WEBAUTHN_RP_ID = 'your-domain.com'  # Your domain (no https://)
WEBAUTHN_RP_NAME = 'Your Application Name'
WEBAUTHN_RP_ORIGIN = 'https://your-domain.com'  # Full URL with https://

# Optional
WEBAUTHN_CHALLENGE_TIMEOUT = 300  # 5 minutes
WEBAUTHN_USER_VERIFICATION = 'preferred'  # or 'required', 'discouraged'
WEBAUTHN_ATTESTATION = 'none'  # or 'indirect', 'direct'
WEBAUTHN_RESIDENT_KEY = 'preferred'  # or 'required', 'discouraged'
WEBAUTHN_AUTHENTICATOR_ATTACHMENT = 'platform,cross-platform'
```

## Origin Security

### Global Origin Settings

```python
# Require Origin header
OIDC_REQUIRE_ORIGIN_HEADER = False  # Set True to require

# Auto-include redirect URIs in allowed origins
OIDC_AUTO_INCLUDE_REDIRECT_ORIGINS = True
```

### Per-Client Configuration

```python
client = Client.objects.create(
    # ...
    allowed_origins="""
https://app.example.com
https://admin.example.com
https://*.subdomain.example.com
""",
    strict_origin_validation=True,
    include_origin_in_tokens=True,
)
```

## Client Configuration

### Algorithm Selection

```python
client = Client.objects.create(
    # ID token algorithm
    jwt_alg='ES256',  # ES256, ES384, ES512, RS256, PS256, HS256, etc.
    
    # Access token algorithm (optional, inherits from jwt_alg)
    access_token_jwt_alg='ES256',
    
    # Refresh token algorithm (optional, inherits from access_token_jwt_alg)
    refresh_token_jwt_alg='ES256',
)
```

### Token Encryption

```python
client = Client.objects.create(
    # ID token encryption
    id_token_encrypted_response_alg='RSA-OAEP',
    id_token_encrypted_response_enc='A256GCM',
    
    # Access token encryption
    access_token_encrypted_response_alg='RSA-OAEP',
    access_token_encrypted_response_enc='A256GCM',
    
    # Refresh token encryption
    refresh_token_encrypted_response_alg='RSA-OAEP',
    refresh_token_encrypted_response_enc='A256GCM',
)
```

### Refresh Token Configuration

```python
client = Client.objects.create(
    # Format
    refresh_token_format='jwt',  # or 'opaque'
    
    # Rotation
    enable_refresh_token_rotation=True,
    detect_refresh_token_reuse=True,
    refresh_token_grace_period_seconds=10,
    
    # Expiration
    refresh_token_expire_seconds=30 * 24 * 60 * 60,  # 30 days
)
```

## Advanced Configuration

### Custom Claims

```python
# settings.py

from oidc_provider.lib.claims import ScopeClaims

class MyCustomClaims(ScopeClaims):
    def scope_profile(self):
        dic = super().scope_profile()
        dic['custom_field'] = self.user.custom_attribute
        return dic

OIDC_EXTRA_SCOPE_CLAIMS = 'myapp.claims.MyCustomClaims'
```

### Processing Hooks

```python
# ID token processing hook
def id_token_hook(id_token, user, token, request):
    id_token['custom_claim'] = 'custom_value'
    return id_token

OIDC_IDTOKEN_PROCESSING_HOOK = 'myapp.hooks.id_token_hook'
```

### Session Management

```python
# Enable session management
OIDC_SESSION_MANAGEMENT_ENABLE = True

# Check session iframe
OIDC_CHECKSESSION_IFRAME_ENABLE = True
```

## Complete Settings Example

```python
# settings.py - Complete Configuration

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'oidc_provider',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'oidc_provider.middleware_origin.OriginTrackingMiddleware',
    'oidc_provider.middleware_origin.OriginValidationMiddleware',
    'oidc_provider.middleware_security.OIDCSecurityHeadersMiddleware',
]

# HTTPS
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

# OIDC Token Settings
OIDC_TOKEN_EXPIRE = 3600
OIDC_IDTOKEN_EXPIRE = 600
OIDC_CODE_EXPIRE = 600
OIDC_ACCESS_TOKEN_JWT = True

# Subject generator
OIDC_IDTOKEN_SUB_GENERATOR = 'oidc_provider.lib.utils.common.default_sub_generator'

# Access token audience
def api_audience(client, request=None):
    return "https://api.example.com"

OIDC_TOKEN_JWT_AUD = 'myapp.utils.api_audience'

# WebAuthn/Passkey
WEBAUTHN_RP_ID = 'your-domain.com'
WEBAUTHN_RP_NAME = 'Your App'
WEBAUTHN_RP_ORIGIN = 'https://your-domain.com'
WEBAUTHN_CHALLENGE_TIMEOUT = 300
WEBAUTHN_USER_VERIFICATION = 'preferred'
WEBAUTHN_ATTESTATION = 'none'
WEBAUTHN_RESIDENT_KEY = 'preferred'
```

## Environment Variables

For production deployment:

```bash
# .env
SECRET_KEY=your-django-secret-key
DEBUG=False
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com

DATABASE_URL=postgres://user:pass@host/db

# WebAuthn
WEBAUTHN_RP_ID=yourdomain.com
WEBAUTHN_RP_NAME=Your App
WEBAUTHN_RP_ORIGIN=https://yourdomain.com
```

## Summary

Complete your configuration by following these guides:
- [Security Guide](security.md) for production security
- [Passkey Guide](passkeys.md) for WebAuthn setup
- [Customization Guide](customization.md) for extensions
