# Origin Domain Validation - Security Implementation

## Overview

The OIDC provider now **validates that the domain requesting a token is in the client's allowed domains list** before issuing any tokens. This prevents unauthorized domains from obtaining tokens even if they know the client_id.

---

## 🔒 How It Works

### Validation Flow

```
1. Client makes request with Origin header
   ↓
2. System extracts origin domain
   ↓
3. Checks if origin is in client's allowed_origins
   ↓
4. If YES: Issue token with origin as aud ✅
   If NO:  Reject with 403 Forbidden ❌
```

### What Gets Validated

**Every token request checks:**
1. Origin header from HTTP request
2. Client's `allowed_origins` configuration
3. Client's `redirect_uris` (auto-allowed)
4. Wildcard patterns in allowed_origins

---

## ✅ Allowed Origins Configuration

### Method 1: Explicit Domain List

```python
from oidc_provider.models import Client

client = Client.objects.create(
    name='My App',
    client_id='app123',
    
    # List allowed domains (one per line)
    allowed_origins="""
https://app.example.com
https://admin.example.com
https://portal.example.com
""",
    
    # Enable strict validation
    strict_origin_validation=True,
)
```

**Result:**
- ✅ `https://app.example.com` → Allowed
- ✅ `https://admin.example.com` → Allowed
- ✅ `https://portal.example.com` → Allowed
- ❌ `https://evil.com` → Rejected (403)

### Method 2: Wildcard Patterns

```python
client = Client.objects.create(
    name='Multi-Subdomain App',
    client_id='app123',
    
    # Allow all subdomains
    allowed_origins='https://*.example.com',
    strict_origin_validation=True,
)
```

**Result:**
- ✅ `https://app.example.com` → Allowed
- ✅ `https://api.example.com` → Allowed
- ✅ `https://admin.example.com` → Allowed
- ✅ `https://any-subdomain.example.com` → Allowed
- ❌ `https://example.com.evil.com` → Rejected

### Method 3: Auto-Allow from Redirect URIs

```python
client = Client.objects.create(
    name='Simple App',
    client_id='app123',
    
    # No explicit allowed_origins
    # Redirect URI domains are auto-allowed
    strict_origin_validation=True,
)
client.redirect_uris = ['https://myapp.example.com/callback']
client.save()
```

**Result:**
- ✅ `https://myapp.example.com` → Allowed (from redirect_uri)
- ❌ `https://other.com` → Rejected

---

## 🛡️ Security Benefits

### 1. Prevents Token Theft via Client ID

**Problem:** Anyone who knows a client_id could try to get tokens

**Before (No Validation):**
```bash
# Evil site tries to use your client_id
curl https://auth.example.com/authorize \
  -H "Origin: https://evil.com" \
  -d "client_id=your-client-123&..."

# Would succeed! ❌
```

**After (With Validation):**
```bash
# Same attempt
curl https://auth.example.com/authorize \
  -H "Origin: https://evil.com" \
  -d "client_id=your-client-123&..."

# Response: 403 Forbidden ✅
# Error: "Origin https://evil.com not allowed for this client"
```

### 2. Domain Binding

**Tokens are bound to specific domains:**

```python
# Client configuration
client.allowed_origins = 'https://app.example.com'

# Request from app.example.com
Token: {
  "aud": "https://app.example.com",  ✅
  "iss": "https://auth.example.com",
  "sub": "user123"
}

# Request from evil.com
Response: 403 Forbidden ❌
```

### 3. Multi-Tenant Isolation

**Different tenants can't use each other's clients:**

```python
# Tenant A client
tenant_a = Client.objects.create(
    client_id='tenant-a',
    allowed_origins='https://tenant-a.myapp.com',
    strict_origin_validation=True,
)

# Tenant B client
tenant_b = Client.objects.create(
    client_id='tenant-b',
    allowed_origins='https://tenant-b.myapp.com',
    strict_origin_validation=True,
)

# Tenant B tries to use Tenant A's client_id
Request from: https://tenant-b.myapp.com
Client ID: tenant-a
Result: 403 Forbidden ❌
```

---

## 🧪 Testing

### Test Allowed Origin

```python
from oidc_provider.lib.utils.audience import is_origin_allowed_for_client

# Check if origin is allowed
is_allowed = is_origin_allowed_for_client(
    'https://app.example.com',
    client
)

if is_allowed:
    print('✅ Origin is allowed')
else:
    print('❌ Origin is NOT allowed')
```

### Run Tests

```bash
# Test origin validation
python manage.py test oidc_provider.tests.test_origin_allowed_validation

# All tests
python manage.py test oidc_provider
```

---

## 📋 Configuration Modes

### Mode 1: Strict Validation (Recommended for Production)

```python
client = Client.objects.create(
    name='Production App',
    client_id='prod123',
    
    allowed_origins='https://app.example.com',
    strict_origin_validation=True,  # ✅ Enforce validation
)
```

**Behavior:**
- Only listed domains can get tokens
- Unlisted domains get 403 Forbidden
- Maximum security

### Mode 2: Permissive (Development Only)

```python
client = Client.objects.create(
    name='Dev App',
    client_id='dev123',
    
    allowed_origins='',  # Empty
    strict_origin_validation=False,  # ❌ No enforcement
)
```

**Behavior:**
- Any origin can get tokens
- Good for development/testing
- **NOT for production**

### Mode 3: Auto-Allow Redirect URIs

```python
client = Client.objects.create(
    name='Simple App',
    client_id='simple123',
    
    allowed_origins='',  # Not set
    strict_origin_validation=True,
)
client.redirect_uris = ['https://app.example.com/callback']
client.save()
```

**Behavior:**
- Redirect URI domains are auto-allowed
- Convenience + security
- Good for simple apps

---

## 🎯 Real-World Examples

### Example 1: SPA with Multiple Environments

```python
# Production
prod_client = Client.objects.create(
    client_id='spa-prod',
    allowed_origins='https://app.example.com',
    strict_origin_validation=True,
)

# Staging
staging_client = Client.objects.create(
    client_id='spa-staging',
    allowed_origins='https://staging.example.com',
    strict_origin_validation=True,
)

# Development (local)
dev_client = Client.objects.create(
    client_id='spa-dev',
    allowed_origins="""
http://localhost:3000
http://localhost:8080
http://127.0.0.1:3000
""",
    strict_origin_validation=True,
)
```

### Example 2: Partner Integration

```python
# Partner A
partner_a = Client.objects.create(
    client_id='partner-a',
    allowed_origins="""
https://portal.partner-a.com
https://api.partner-a.com
""",
    strict_origin_validation=True,
)

# Partner B
partner_b = Client.objects.create(
    client_id='partner-b',
    allowed_origins='https://*.partner-b.com',  # Wildcard
    strict_origin_validation=True,
)
```

**Security:**
- Partner A can't use Partner B's client_id
- Each partner isolated to their domains
- Full audit trail

### Example 3: Mobile + Web App

```python
client = Client.objects.create(
    client_id='multi-platform',
    allowed_origins="""
https://app.example.com
https://admin.example.com
myapp://callback
""",
    strict_origin_validation=True,
)
client.redirect_uris = [
    'https://app.example.com/callback',
    'https://admin.example.com/callback',
    'myapp://callback',  # Mobile deep link
]
client.save()
```

---

## 🔍 How to Debug

### Check If Origin Is Allowed

```python
from oidc_provider.models import Client
from oidc_provider.lib.utils.audience import (
    is_origin_allowed_for_client,
    get_client_allowed_origins,
)

client = Client.objects.get(client_id='your-client')

# Check specific origin
is_allowed = is_origin_allowed_for_client(
    'https://app.example.com',
    client
)
print(f'Is allowed: {is_allowed}')

# See all allowed origins
allowed = get_client_allowed_origins(client)
print(f'Allowed origins: {allowed}')
```

### Check Request Origin

```python
from oidc_provider.middleware_origin import get_request_origin

# In your view
origin = get_request_origin(request)
print(f'Request origin: {origin}')

# Check if it's allowed
if is_origin_allowed_for_client(origin, client):
    print('✅ Origin is allowed')
else:
    print('❌ Origin is NOT allowed')
```

### View Client Configuration

```python
client = Client.objects.get(client_id='your-client')

print(f'Allowed origins: {client.allowed_origins}')
print(f'Strict validation: {client.strict_origin_validation}')
print(f'Redirect URIs: {client.redirect_uris}')
```

---

## ❗ Common Issues & Solutions

### Issue 1: 403 Forbidden on Valid Request

**Symptom:**
```
403 Forbidden
"Origin https://app.example.com not allowed for this client"
```

**Solution:**
```python
# Check configuration
client = Client.objects.get(client_id='your-client')

# Add the origin
client.allowed_origins = 'https://app.example.com'
client.save()

# OR add to redirect_uris (auto-allowed)
client.redirect_uris = ['https://app.example.com/callback']
client.save()
```

### Issue 2: Wildcard Not Working

**Problem:**
```python
allowed_origins = 'https://example.com'  # Wrong!
# Doesn't match: https://app.example.com
```

**Solution:**
```python
allowed_origins = 'https://*.example.com'  # Correct!
# Matches: https://app.example.com ✅
#          https://admin.example.com ✅
#          https://any.example.com ✅
```

### Issue 3: localhost Not Working

**Problem:**
```python
allowed_origins = 'http://localhost'  # Incomplete!
```

**Solution:**
```python
# Include port number
allowed_origins = """
http://localhost:3000
http://localhost:8080
http://127.0.0.1:3000
"""
```

### Issue 4: No Origin Header

**Symptom:** Origin validation fails even with correct config

**Cause:** Browser not sending Origin header

**Solution:**
```javascript
// Client-side: Ensure CORS request
fetch('https://auth.example.com/token', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        // Origin header automatically added by browser
    },
    credentials: 'include',  // Important for CORS
});
```

---

## 📊 Validation Logic

### Complete Flow

```python
def validate_and_get_audience(client, request):
    """
    Validate origin and get audience for token.
    """
    # 1. Extract origin from request
    origin = get_request_origin(request)
    
    # 2. Check if strict validation enabled
    if client.strict_origin_validation:
        # 3. Validate against allowed origins
        if not is_origin_allowed_for_client(origin, client):
            raise Forbidden('Origin not allowed')
    
    # 4. Use validated origin as audience
    return origin
```

### Allowed Origins Priority

```
1. Check client.allowed_origins
   ↓
2. Check wildcard patterns
   ↓
3. Check redirect_uris domains
   ↓
4. If strict_origin_validation=False, allow all
   ↓
5. Otherwise, reject
```

---

## ✅ Security Checklist

Before deploying to production:

- [ ] Set `strict_origin_validation=True` for all production clients
- [ ] Configure `allowed_origins` for each client
- [ ] Use wildcards carefully (only for trusted domains)
- [ ] Test with actual client applications
- [ ] Monitor 403 errors in logs
- [ ] Document allowed origins for each client
- [ ] Review and update allowed origins regularly
- [ ] Use HTTPS for all origins (not HTTP)
- [ ] Consider separate clients for dev/staging/prod

---

## 📈 Monitoring

### Log Origin Rejections

```python
import logging

logger = logging.getLogger('oidc_provider.security')

# In middleware
if not is_origin_allowed_for_client(origin, client):
    logger.warning(
        f'Origin {origin} rejected for client {client.client_id}. '
        f'Allowed origins: {client.allowed_origins}'
    )
    return JsonResponse({'error': 'forbidden'}, status=403)
```

### Analytics Query

```python
from oidc_provider.models import Token
from django.db.models import Count

# Tokens by origin (for allowed domains)
origin_stats = Token.objects.values('origin_domain').annotate(
    count=Count('id')
).order_by('-count')

for stat in origin_stats:
    print(f"{stat['origin_domain']}: {stat['count']} tokens")
```

---

## 🎉 Summary

### What's Protected

✅ **Token Issuance:**
- Only allowed domains can get tokens
- Client ID alone is not enough
- Domain must be validated

✅ **Token Binding:**
- Tokens include requesting domain as `aud`
- Resource servers can validate origin
- Cross-domain usage prevented

✅ **Multi-Tenant Security:**
- Tenants can't use each other's clients
- Full isolation between domains
- Audit trail available

### Configuration Required

```python
# Minimum for production
client = Client.objects.create(
    client_id='your-client',
    allowed_origins='https://your-app.com',  # ✅ Required
    strict_origin_validation=True,           # ✅ Required
)
```

### Testing

```bash
python manage.py test oidc_provider.tests.test_origin_allowed_validation
```

**Your OIDC provider now validates domains before issuing tokens!** 🔒✅

Only authorized domains can get tokens, preventing unauthorized access even if client_id is known.
