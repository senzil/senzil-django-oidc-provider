# Migration Guide

Upgrade guide for existing Django OIDC Provider installations.

## Overview

This guide helps you migrate from older versions to the modernized OIDC provider with all new features.

## Prerequisites

- Backup your database
- Test in a staging environment first
- Review [IMPLEMENTATION_CHANGES.md](../IMPLEMENTATION_CHANGES.md) for all changes

## Step-by-Step Migration

### Step 1: Update Dependencies

```bash
# Update requirements.txt or install new dependencies
pip install -r requirements.txt

# New dependencies:
# - authlib>=1.3.0 (replaces pyjwkest)
# - cryptography>=41.0.0
# - pycryptodomex>=3.19.0
# - webauthn>=2.0.0
# - cbor2>=5.4.0
```

### Step 2: Run Migrations

```bash
python manage.py migrate oidc_provider
```

**Migrations applied:**
1. `0029_add_modern_algorithms_and_encryption` - Algorithm and encryption fields
2. `0030_add_refresh_token_customization` - Refresh token features
3. `0031_add_passkey_support` - WebAuthn models
4. `0032_add_allowed_domains` - Origin security

### Step 3: Update Settings

Add new middleware:

```python
# settings.py

MIDDLEWARE = [
    # ... existing middleware ...
    'oidc_provider.middleware_origin.OriginTrackingMiddleware',
    'oidc_provider.middleware_origin.OriginValidationMiddleware',
    'oidc_provider.middleware_security.OIDCSecurityHeadersMiddleware',
]
```

Add WebAuthn configuration:

```python
# settings.py

WEBAUTHN_RP_ID = 'your-domain.com'
WEBAUTHN_RP_NAME = 'Your Application'
WEBAUTHN_RP_ORIGIN = 'https://your-domain.com'
```

Add API audience configuration:

```python
# settings.py

def api_audience(client, request=None):
    return "https://api.your-domain.com"

OIDC_TOKEN_JWT_AUD = 'myapp.utils.api_audience'
```

### Step 4: Generate New Keys

```bash
# Generate EC keys for ES256/384/512 algorithms
python manage.py createeckey --curve P-256
python manage.py createeckey --curve P-384
python manage.py createeckey --curve P-521

# Optional: Generate additional RSA keys
python manage.py creatersakey
```

### Step 5: Update Clients

```python
from oidc_provider.models import Client

# Update existing clients with new features
for client in Client.objects.all():
    # Use modern algorithm
    client.jwt_alg = 'ES256'
    client.access_token_jwt_alg = 'ES256'
    
    # Configure allowed origins
    # Extract domains from redirect_uris
    if client.redirect_uris:
        from urllib.parse import urlparse
        origins = []
        for uri in client.redirect_uris:
            parsed = urlparse(uri)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            if origin not in origins:
                origins.append(origin)
        client.allowed_origins = '\n'.join(origins)
    
    # Start permissive, enable strict later after testing
    client.strict_origin_validation = False
    client.include_origin_in_tokens = True
    
    # Enable refresh token rotation
    client.refresh_token_format = 'jwt'
    client.enable_refresh_token_rotation = True
    client.detect_refresh_token_reuse = True
    
    client.save()
    print(f'Updated client: {client.name}')
```

### Step 6: Test

```bash
# Run all tests
python manage.py test oidc_provider

# Test specific flows
python manage.py test oidc_provider.tests.test_all_flows
```

### Step 7: Enable Strict Origin Validation (Gradually)

```python
# Start with one client
test_client = Client.objects.get(client_id='test')
test_client.strict_origin_validation = True
test_client.save()

# Test thoroughly

# Enable for all
Client.objects.update(strict_origin_validation=True)
```

## Validation Checklist

After migration:

- [ ] All migrations applied successfully
- [ ] RSA and EC keys generated
- [ ] Middleware added to settings
- [ ] WebAuthn settings configured
- [ ] API audience configured
- [ ] Clients updated with allowed_origins
- [ ] All tests passing
- [ ] Discovery endpoint works
- [ ] JWKS endpoint returns keys
- [ ] Can create authorization codes
- [ ] Can exchange codes for tokens
- [ ] Passkey registration works
- [ ] Passkey authentication works
- [ ] Origin validation working

## Rollback Plan

If you need to rollback:

```bash
# Rollback migrations
python manage.py migrate oidc_provider 0028_add_default_scope_20210503_1257

# Reinstall old dependencies
pip install pyjwkest

# Remove new middleware from settings
```

**Note:** New features won't be available after rollback.

## Troubleshooting

### Issue: Import errors for authlib

**Solution:**
```bash
pip uninstall pyjwkest
pip install authlib>=1.3.0
```

### Issue: WebAuthn not working

**Solution:**
```python
# Check settings
WEBAUTHN_RP_ID = 'domain.com'  # Without https://
WEBAUTHN_RP_ORIGIN = 'https://domain.com'  # With https://
```

### Issue: Origin validation rejecting valid requests

**Solution:**
```python
# Temporarily disable strict validation
client.strict_origin_validation = False
client.save()

# Or add origin to allowed list
client.allowed_origins += '\nhttps://yourapp.com'
client.save()
```

## Post-Migration Tasks

1. Update client applications to validate new audience claims
2. Enable passkeys for users
3. Configure origin allowlists
4. Review security settings
5. Monitor logs for any issues
6. Update documentation for integrators

## Summary

Your OIDC provider is now modernized with:
- ✅ Modern dependencies
- ✅ Extended algorithms
- ✅ Token encryption
- ✅ Passkey support
- ✅ Origin security
- ✅ Enhanced refresh tokens

See [Configuration Reference](configuration.md) for complete settings.
