# Allowed Domains & Origin Tracking Guide

This guide explains how to configure allowed domains/origins and track request origins in JWT tokens for enhanced security and audit capabilities.

## Table of Contents
- [Overview](#overview)
- [Configuration](#configuration)
- [Origin Validation](#origin-validation)
- [Origin in JWT Tokens](#origin-in-jwt-tokens)
- [Security Benefits](#security-benefits)
- [Examples](#examples)

---

## Overview

### What This Feature Provides

1. **Domain Allowlist** - Restrict which domains can initiate OIDC requests
2. **Origin Validation** - Validate request origin against client configuration
3. **Origin Tracking** - Track which domain requests originated from
4. **JWT Origin Claims** - Include origin information in JWT tokens
5. **Audit Trail** - Full visibility of where authentication requests come from

### Use Cases

- ✅ **Multi-tenant SaaS** - Ensure only approved customer domains can authenticate
- ✅ **Partner Integration** - Limit authentication to specific partner domains
- ✅ **Geographic Compliance** - Track and restrict by domain/region
- ✅ **Security Audit** - Know exactly where each token was issued from
- ✅ **Fraud Prevention** - Detect and block unauthorized domains

---

## Configuration

### 1. Update Settings

```python
# settings.py

# Enable origin tracking middleware
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    # ... other middleware ...
    'oidc_provider.middleware_origin.OriginTrackingMiddleware',  # Track all origins
    'oidc_provider.middleware_origin.OriginValidationMiddleware',  # Validate origins
]

# Global origin settings
OIDC_REQUIRE_ORIGIN_HEADER = False  # Require Origin header on all requests
OIDC_AUTO_INCLUDE_REDIRECT_ORIGINS = True  # Auto-allow redirect_uri domains
```

### 2. Run Migration

```bash
python manage.py migrate oidc_provider
```

This adds:
- `allowed_origins` field to Client model
- `strict_origin_validation` flag
- `include_origin_in_tokens` flag
- `origin_domain` tracking to Token and Code models

---

## Origin Validation

### Client Configuration

```python
from oidc_provider.models import Client

client = Client.objects.get(client_id='your-client')

# Method 1: Simple domain list (newline-separated)
client.allowed_origins = """
https://app.example.com
https://portal.example.com
https://dashboard.example.com
"""

# Method 2: Wildcard patterns
client.allowed_origins = """
https://*.example.com
https://app.partner.com
"""

# Enable strict validation
client.strict_origin_validation = True

# Include origin in tokens
client.include_origin_in_tokens = True

client.save()
```

### Validation Modes

#### 1. **Permissive Mode** (Default)
```python
client.strict_origin_validation = False
```
- Allows all origins
- Still tracks origin for audit
- Good for development

#### 2. **Strict Mode**
```python
client.strict_origin_validation = True
```
- Only allows configured origins
- Rejects requests from unlisted domains
- Production recommended

#### 3. **Auto-Allow Redirect URIs**
```python
# Automatically allows domains from redirect_uris
client.redirect_uris = ['https://app.example.com/callback']
# https://app.example.com is automatically allowed
```

---

## Origin in JWT Tokens

### How It Works

When `include_origin_in_tokens = True`, JWT tokens include:

```json
{
  "iss": "https://your-idp.com",
  "sub": "user123",
  "origin": "https://app.example.com",
  "origin_domain": "app.example.com",
  "client_id": "client123",
  "exp": 1234567890,
  "iat": 1234567890
}
```

### Claims Added

| Claim | Description | Example |
|-------|-------------|---------|
| `origin` | Full origin URL | `https://app.example.com` |
| `origin_domain` | Domain only | `app.example.com` |

### ID Token Example

```json
{
  "iss": "https://idp.example.com",
  "sub": "user@example.com",
  "aud": "client123",
  "origin": "https://portal.company.com",
  "origin_domain": "portal.company.com",
  "exp": 1234567890,
  "iat": 1234567890,
  "auth_time": 1234567890,
  "nonce": "abc123"
}
```

### Access Token Example

```json
{
  "iss": "https://idp.example.com",
  "client_id": "client123",
  "sub": "user@example.com",
  "origin": "https://app.partner.com",
  "origin_domain": "app.partner.com",
  "scope": ["openid", "profile", "email"],
  "exp": 1234567890,
  "iat": 1234567890,
  "jti": "token-id-123"
}
```

### Refresh Token Example

```json
{
  "iss": "https://idp.example.com",
  "client_id": "client123",
  "sub": "user@example.com",
  "origin": "https://mobile.app.com",
  "origin_domain": "mobile.app.com",
  "token_type": "refresh",
  "exp": 1234567890,
  "iat": 1234567890,
  "jti": "refresh-token-123"
}
```

---

## Security Benefits

### 1. Domain Whitelisting

**Problem:** Anyone can initiate OIDC flow with your client_id

**Solution:**
```python
client.allowed_origins = "https://approved-app.com"
client.strict_origin_validation = True
```

**Result:** Only `approved-app.com` can authenticate

### 2. Phishing Prevention

**Scenario:** Attacker tries to use your client_id from their domain

```
Attacker domain: https://evil.com
Your allowed:   https://app.example.com

Request from evil.com → ❌ REJECTED
Request from app.example.com → ✅ ALLOWED
```

### 3. Token Binding

**Use Case:** Verify token was issued to correct origin

```python
# Resource server validates token
def validate_token(token):
    claims = decode_jwt(token)
    
    # Check origin matches expected
    if claims['origin'] != 'https://expected-app.com':
        raise SecurityError('Token used from wrong origin')
    
    return claims
```

### 4. Audit Trail

**Track all authentication origins:**

```python
from oidc_provider.models import Token

# Query tokens by origin
tokens_from_partner = Token.objects.filter(
    origin_domain='partner.example.com'
)

# Audit report
for token in tokens_from_partner:
    print(f"User: {token.user.username}")
    print(f"Origin: {token.origin_domain}")
    print(f"Client: {token.client.name}")
    print(f"Created: {token.expires_at}")
```

---

## Examples

### Example 1: Multi-tenant SaaS

```python
# Each tenant gets their own domain
client = Client.objects.create(
    name='Customer A',
    client_id='customer-a',
    
    # Only allow customer's domain
    allowed_origins='https://customer-a.myapp.com',
    strict_origin_validation=True,
    
    # Track origin in tokens
    include_origin_in_tokens=True,
)
```

**Behavior:**
- ✅ `https://customer-a.myapp.com` → Allowed
- ❌ `https://customer-b.myapp.com` → Rejected
- ❌ `https://evil.com` → Rejected

### Example 2: Partner Integration

```python
client = Client.objects.create(
    name='Partner Portal',
    client_id='partner123',
    
    # Allow partner's domains
    allowed_origins="""
https://portal.partner.com
https://admin.partner.com
https://api.partner.com
""",
    
    strict_origin_validation=True,
    include_origin_in_tokens=True,
)
```

**Token includes:**
```json
{
  "origin": "https://portal.partner.com",
  "origin_domain": "portal.partner.com",
  "client_id": "partner123"
}
```

### Example 3: Wildcard Subdomains

```python
client = Client.objects.create(
    name='Enterprise App',
    client_id='enterprise',
    
    # Allow all subdomains
    allowed_origins="""
https://*.company.com
https://partner.external.com
""",
    
    strict_origin_validation=True,
)
```

**Allowed:**
- ✅ `https://app.company.com`
- ✅ `https://dashboard.company.com`
- ✅ `https://admin.company.com`
- ✅ `https://partner.external.com`

**Rejected:**
- ❌ `https://evil.com`
- ❌ `https://company.com.evil.com`

### Example 4: Development vs Production

```python
# Development client - permissive
dev_client = Client.objects.create(
    name='Dev Client',
    client_id='dev123',
    strict_origin_validation=False,  # Allow all
    include_origin_in_tokens=True,   # But still track
)

# Production client - strict
prod_client = Client.objects.create(
    name='Prod Client',
    client_id='prod123',
    allowed_origins='https://app.production.com',
    strict_origin_validation=True,   # Enforce
    include_origin_in_tokens=True,
)
```

### Example 5: Geographic Compliance

```python
# EU region client
eu_client = Client.objects.create(
    name='EU Portal',
    client_id='eu-portal',
    
    # Only EU domains
    allowed_origins="""
https://eu.myapp.com
https://app.eu.myapp.com
""",
    
    strict_origin_validation=True,
    include_origin_in_tokens=True,
)

# US region client
us_client = Client.objects.create(
    name='US Portal',
    client_id='us-portal',
    
    # Only US domains
    allowed_origins="""
https://us.myapp.com
https://app.us.myapp.com
""",
    
    strict_origin_validation=True,
    include_origin_in_tokens=True,
)
```

**Token validation:**
```python
def validate_geographic_compliance(token):
    claims = decode_jwt(token)
    origin = claims.get('origin_domain')
    
    # Ensure EU data stays in EU
    if origin.endswith('.eu.myapp.com'):
        if not is_eu_region():
            raise ComplianceError('EU token used outside EU')
    
    return claims
```

---

## Origin Detection

### Priority Order

The middleware detects origin in this order:

1. **`Origin` header** (CORS requests)
   ```
   Origin: https://app.example.com
   ```

2. **`Referer` header** (fallback)
   ```
   Referer: https://app.example.com/auth
   ```

3. **`Host` header** (last resort)
   ```
   Host: app.example.com
   ```

### Example Request Headers

```http
GET /authorize?client_id=123&redirect_uri=... HTTP/1.1
Host: idp.example.com
Origin: https://app.example.com
Referer: https://app.example.com/login
```

**Extracted:**
- Origin: `https://app.example.com`
- Domain: `app.example.com`

---

## Admin Configuration

### Django Admin

```python
# myapp/admin.py
from django.contrib import admin
from oidc_provider.admin import ClientAdmin
from oidc_provider.models import Client

admin.site.unregister(Client)

@admin.register(Client)
class EnhancedClientAdmin(ClientAdmin):
    fieldsets = ClientAdmin.fieldsets + [
        ('Origin Security', {
            'fields': (
                'allowed_origins',
                'strict_origin_validation',
                'include_origin_in_tokens',
            ),
            'description': 'Configure allowed origins and origin tracking',
        }),
    ]
    
    list_display = ClientAdmin.list_display + ['origin_validation_status']
    
    def origin_validation_status(self, obj):
        if obj.strict_origin_validation:
            return '🔒 Strict'
        return '🔓 Permissive'
    origin_validation_status.short_description = 'Origin Validation'
```

---

## API Response Examples

### Successful Request

```http
POST /token HTTP/1.1
Origin: https://app.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=...
```

**Response:**
```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 3600,
  "id_token": "eyJ...",
  "refresh_token": "eyJ..."
}
```

**Decoded Access Token:**
```json
{
  "iss": "https://idp.example.com",
  "sub": "user123",
  "origin": "https://app.example.com",
  "origin_domain": "app.example.com",
  "client_id": "client123"
}
```

### Rejected Request (Wrong Origin)

```http
POST /token HTTP/1.1
Origin: https://evil.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=...
```

**Response:**
```json
{
  "error": "invalid_request",
  "error_description": "Origin https://evil.com not allowed for this client"
}
```

**HTTP Status:** `403 Forbidden`

---

## Monitoring & Analytics

### Query Tokens by Origin

```python
from oidc_provider.models import Token
from django.db.models import Count

# Tokens by origin domain
origin_stats = Token.objects.values('origin_domain').annotate(
    count=Count('id')
).order_by('-count')

for stat in origin_stats:
    print(f"{stat['origin_domain']}: {stat['count']} tokens")
```

### Detect Anomalies

```python
# Find tokens from unexpected origins
suspicious_tokens = Token.objects.exclude(
    origin_domain__in=[
        'app.example.com',
        'portal.example.com',
        'mobile.example.com'
    ]
).filter(
    expires_at__gte=timezone.now()
)

for token in suspicious_tokens:
    print(f"⚠️ Suspicious: {token.origin_domain} - User: {token.user.username}")
```

### Dashboard Example

```python
# views.py
def origin_analytics_dashboard(request):
    from django.db.models import Count, Q
    from datetime import timedelta
    from django.utils import timezone
    
    last_30_days = timezone.now() - timedelta(days=30)
    
    analytics = {
        # Top origins
        'top_origins': Token.objects.filter(
            expires_at__gte=last_30_days
        ).values('origin_domain').annotate(
            count=Count('id')
        ).order_by('-count')[:10],
        
        # Origins by client
        'by_client': Token.objects.filter(
            expires_at__gte=last_30_days
        ).values('client__name', 'origin_domain').annotate(
            count=Count('id')
        ),
        
        # Failed origin validations (from logs)
        'rejections': get_origin_rejections(last_30_days),
    }
    
    return render(request, 'analytics/origins.html', analytics)
```

---

## Migration Guide

### For Existing Installations

1. **Run migration:**
   ```bash
   python manage.py migrate oidc_provider
   ```

2. **Update middleware:**
   ```python
   # settings.py
   MIDDLEWARE = [
       # ... existing ...
       'oidc_provider.middleware_origin.OriginTrackingMiddleware',
       'oidc_provider.middleware_origin.OriginValidationMiddleware',
   ]
   ```

3. **Configure clients (optional):**
   ```python
   # Only if you want to enable strict validation
   for client in Client.objects.all():
       client.allowed_origins = '\n'.join(client.redirect_uris)
       # Start permissive, enable strict later
       client.strict_origin_validation = False
       client.include_origin_in_tokens = True
       client.save()
   ```

4. **Test with one client:**
   ```python
   test_client = Client.objects.get(client_id='test')
   test_client.strict_origin_validation = True
   test_client.save()
   # Test authentication flow
   ```

5. **Gradually enable:**
   ```python
   # Enable for all clients
   Client.objects.update(strict_origin_validation=True)
   ```

---

## Troubleshooting

### Issue: Origin Header Missing

**Error:** "Origin header required"

**Solutions:**
1. Disable strict validation:
   ```python
   client.strict_origin_validation = False
   ```

2. Or configure browser to send Origin header (CORS requests auto-include it)

### Issue: Wrong Origin Rejected

**Error:** "Origin https://... not allowed"

**Check:**
1. Origin in allowed list:
   ```python
   print(client.allowed_origins)
   ```

2. Wildcard pattern correct:
   ```python
   # Wrong: https://app.*.example.com
   # Right: https://*.example.com
   ```

3. Include in allowed origins:
   ```python
   client.allowed_origins += '\nhttps://new-app.com'
   client.save()
   ```

### Issue: Origin Not in Token

**Check:**
1. Flag enabled:
   ```python
   client.include_origin_in_tokens = True
   ```

2. Middleware installed:
   ```python
   # Must be in MIDDLEWARE list
   'oidc_provider.middleware_origin.OriginTrackingMiddleware'
   ```

---

## Security Checklist

- [ ] Enable strict origin validation for production clients
- [ ] Configure allowed origins for each client
- [ ] Use HTTPS for all origins
- [ ] Enable origin tracking in tokens
- [ ] Monitor origin analytics for anomalies
- [ ] Review allowed origins regularly
- [ ] Use wildcards carefully (only for trusted domains)
- [ ] Document origin requirements for integration partners
- [ ] Test origin validation before production deployment
- [ ] Set up alerts for rejected origin attempts

---

## Summary

✅ **Implemented:**
- Domain allowlist per client
- Strict origin validation
- Origin tracking in tokens
- Wildcard domain patterns
- Auto-include redirect URIs
- Comprehensive audit trail

✅ **Security Benefits:**
- Prevent unauthorized domain access
- Phishing protection
- Token binding to origin
- Full audit capability
- Geographic compliance support

✅ **Flexibility:**
- Permissive mode for development
- Strict mode for production
- Per-client configuration
- Granular control

Your OIDC provider now has enterprise-grade origin security! 🔒
