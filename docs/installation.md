# Installation & Quick Start

## Overview

This guide will help you install and set up the modernized Django OIDC Provider with all new features including passkeys, modern algorithms, and enhanced security.

## Prerequisites

- Python 3.8+
- Django 3.2+ or 4.0+
- PostgreSQL, MySQL, or SQLite database

## Installation

### 1. Install Package

```bash
pip install django-oidc-provider
```

Or from requirements.txt:

```bash
pip install -r requirements.txt
```

### 2. Add to Django Project

```python
# settings.py

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'oidc_provider',  # Add this
]
```

### 3. Add Middleware

```python
# settings.py

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    # Add OIDC middleware
    'oidc_provider.middleware_origin.OriginTrackingMiddleware',
    'oidc_provider.middleware_origin.OriginValidationMiddleware',
    'oidc_provider.middleware_security.OIDCSecurityHeadersMiddleware',
]
```

### 4. Configure URLs

```python
# urls.py

from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('oidc/', include('oidc_provider.urls', namespace='oidc_provider')),
    path('oidc/', include('oidc_provider.urls_passkey')),  # Passkey support
]
```

### 5. Run Migrations

```bash
python manage.py migrate oidc_provider
```

### 6. Generate Keys

```bash
# Generate RSA key (for RS256, RS384, RS512, PS256, PS384, PS512)
python manage.py creatersakey

# Generate EC keys (for ES256, ES384, ES512)
python manage.py createeckey --curve P-256  # ES256
python manage.py createeckey --curve P-384  # ES384
python manage.py createeckey --curve P-521  # ES512
```

## Configuration

### Basic Settings

```python
# settings.py

# HTTPS Configuration (REQUIRED for production)
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

# OIDC Settings
OIDC_USERINFO = 'myapp.oidc.userinfo'
OIDC_IDTOKEN_SUB_GENERATOR = 'oidc_provider.lib.utils.common.default_sub_generator'

# Token Settings
OIDC_TOKEN_EXPIRE = 3600  # 1 hour
OIDC_IDTOKEN_EXPIRE = 600  # 10 minutes
OIDC_CODE_EXPIRE = 600     # 10 minutes
```

### WebAuthn/Passkey Settings

```python
# settings.py

# WebAuthn Configuration
WEBAUTHN_RP_ID = 'your-domain.com'
WEBAUTHN_RP_NAME = 'Your Application Name'
WEBAUTHN_RP_ORIGIN = 'https://your-domain.com'
WEBAUTHN_CHALLENGE_TIMEOUT = 300  # 5 minutes
WEBAUTHN_USER_VERIFICATION = 'preferred'
WEBAUTHN_ATTESTATION = 'none'
WEBAUTHN_RESIDENT_KEY = 'preferred'
WEBAUTHN_AUTHENTICATOR_ATTACHMENT = 'platform,cross-platform'
```

### API Audience Configuration

```python
# settings.py

def api_audience(client, request=None):
    """Return the API/resource server that will validate access tokens."""
    return "https://api.yourdomain.com"

OIDC_TOKEN_JWT_AUD = 'myapp.oidc.api_audience'
```

## Create Your First Client

### Via Django Admin

1. Go to `/admin/`
2. Navigate to "OIDC Provider" → "Clients"
3. Click "Add Client"
4. Fill in:
   - **Name:** My Application
   - **Client type:** Confidential
   - **Response types:** code (Authorization Code Flow)
   - **Redirect URIs:** `https://yourapp.com/callback`
   - **JWT Algorithm:** ES256
   - **Allowed Origins:** `https://yourapp.com`
   - **Strict Origin Validation:** ✓ (check)

### Via Python Code

```python
from oidc_provider.models import Client, ResponseType

# Create client
client = Client.objects.create(
    name='My Application',
    client_type='confidential',
    client_secret='your-secure-secret',
    
    # Algorithms
    jwt_alg='ES256',
    access_token_jwt_alg='ES256',
    
    # Refresh token settings
    refresh_token_format='jwt',
    enable_refresh_token_rotation=True,
    refresh_token_expire_seconds=30 * 24 * 60 * 60,  # 30 days
    
    # Origin security
    allowed_origins='https://yourapp.com',
    strict_origin_validation=True,
    include_origin_in_tokens=True,
    
    # Consent
    require_consent=True,
    reuse_consent=True,
)

# Add response type
code_type = ResponseType.objects.get(value='code')
client.response_types.add(code_type)

# Set redirect URIs
client.redirect_uris = ['https://yourapp.com/callback']
client.save()

print(f'Client ID: {client.client_id}')
print(f'Client Secret: {client.client_secret}')
```

## Test Your Setup

### 1. Run Development Server

```bash
python manage.py runserver
```

### 2. Access Discovery Endpoint

Visit: `http://localhost:8000/oidc/.well-known/openid-configuration`

You should see:
```json
{
  "issuer": "http://localhost:8000/oidc",
  "authorization_endpoint": "http://localhost:8000/oidc/authorize/",
  "token_endpoint": "http://localhost:8000/oidc/token/",
  "userinfo_endpoint": "http://localhost:8000/oidc/userinfo/",
  "jwks_uri": "http://localhost:8000/oidc/jwks/",
  ...
}
```

### 3. Check JWKS Endpoint

Visit: `http://localhost:8000/oidc/jwks/`

You should see your public keys.

### 4. Run Tests

```bash
python manage.py test oidc_provider
```

Expected output:
```
Ran 50+ tests in X.XXXs

OK
```

## Next Steps

1. **Configure Security:** Read [Security Guide](security.md)
2. **Set Up Passkeys:** See [Passkey Guide](passkeys.md)
3. **Understand Flows:** Check [OIDC Flows](oidc-flows.md)
4. **Customize:** Explore [Customization Guide](customization.md)

## Quick Example: Authorization Code Flow

### 1. Authorization Request

```
https://yourdomain.com/oidc/authorize/?
  client_id=YOUR_CLIENT_ID
  &response_type=code
  &redirect_uri=https://yourapp.com/callback
  &scope=openid+profile+email
  &state=random_state_value
```

### 2. User Authenticates & Consents

User logs in and approves the consent screen.

### 3. Authorization Code Returned

```
https://yourapp.com/callback?
  code=AUTHORIZATION_CODE
  &state=random_state_value
```

### 4. Token Exchange

```bash
curl -X POST https://yourdomain.com/oidc/token/ \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "redirect_uri=https://yourapp.com/callback"
```

Response:
```json
{
  "access_token": "...",
  "token_type": "bearer",
  "expires_in": 3600,
  "refresh_token": "...",
  "id_token": "..."
}
```

## Troubleshooting

### Common Issues

**1. "No keys found"**
```bash
# Generate keys
python manage.py creatersakey
python manage.py createeckey --curve P-256
```

**2. "Origin not allowed"**
```python
# Add to client
client.allowed_origins = 'https://yourapp.com'
client.save()
```

**3. "Invalid redirect_uri"**
```python
# Set redirect URIs
client.redirect_uris = ['https://yourapp.com/callback']
client.save()
```

**4. WebAuthn not working**
```python
# Check settings
WEBAUTHN_RP_ID = 'yourdomain.com'  # Without https://
WEBAUTHN_RP_ORIGIN = 'https://yourdomain.com'  # With https://
```

## Production Checklist

- [ ] HTTPS enabled (`SECURE_SSL_REDIRECT = True`)
- [ ] Security headers configured
- [ ] Generated RSA and EC keys
- [ ] Configured allowed origins for all clients
- [ ] Enabled strict origin validation
- [ ] Set up WebAuthn for passkeys
- [ ] Configured API audience
- [ ] Tested all flows
- [ ] Set up monitoring
- [ ] Reviewed security guide

## Getting Help

- **Documentation:** [docs/README.md](README.md)
- **Examples:** [docs/examples.md](examples.md)
- **Security:** [docs/security.md](security.md)
- **Troubleshooting:** Check individual feature guides

## Summary

You now have a fully functional OIDC provider with:
- ✅ Modern JWT algorithms
- ✅ Token encryption
- ✅ Passkey support
- ✅ Origin security
- ✅ All OIDC flows
- ✅ Production-ready configuration

**Next:** Configure security settings in [Security Guide](security.md)
