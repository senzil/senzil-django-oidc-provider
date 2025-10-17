# Audience (aud) Claim - Domain-Based Implementation

## Overview

The `aud` (audience) claim in JWT tokens now contains **the domain requesting the token** instead of the `client_id`. This follows security best practices where the audience represents the actual resource server (application domain) that will validate and consume the token.

---

## 🎯 What Changed

### Before (client_id as audience)
```json
{
  "iss": "https://auth.example.com/oidc",
  "sub": "12345",
  "aud": "client_abc123",  // ❌ Client ID
  "exp": 1698765432
}
```

### After (domain as audience)
```json
{
  "iss": "https://auth.example.com/oidc",
  "sub": "12345",
  "aud": "https://app.example.com",  // ✅ Requesting domain
  "exp": 1698765432
}
```

---

## 🔍 How It Works

### Audience Determination Priority

**For all token types (ID, Access, Refresh):**

1. **Origin domain from request** (preferred)
   - Extracted from `Origin` header
   - Example: `https://app.example.com`

2. **Redirect URI domain** (fallback)
   - Extracted from client's `redirect_uris`
   - Example: `https://app.example.com`

3. **Client ID** (last resort)
   - Falls back to `client_id` if no domain available
   - Example: `client_abc123`

### Code Implementation

```python
from oidc_provider.lib.utils.audience import (
    get_id_token_audience,
    get_access_token_audience,
    get_refresh_token_audience,
)

# ID Token
aud = get_id_token_audience(client, request)
# Returns: 'https://app.example.com'

# Access Token
aud = get_access_token_audience(client, request)
# Returns: 'https://app.example.com'

# Refresh Token
aud = get_refresh_token_audience(client, request)
# Returns: 'https://app.example.com'
```

---

## 📊 Example Tokens

### ID Token with Domain Audience

```json
{
  "iss": "https://auth.example.com/oidc",
  "sub": "12345",
  "aud": "https://app.example.com",
  "exp": 1698765432,
  "iat": 1698761832,
  "auth_time": 1698761800,
  "nonce": "random_nonce"
}
```

### Access Token with Domain Audience

```json
{
  "iss": "https://auth.example.com/oidc",
  "sub": "12345",
  "aud": "https://api.example.com",
  "client_id": "client_abc123",
  "exp": 1698765432,
  "iat": 1698761832,
  "scope": ["openid", "profile"],
  "jti": "token_id"
}
```

### Refresh Token with Domain Audience

```json
{
  "iss": "https://auth.example.com/oidc",
  "sub": "12345",
  "aud": "https://app.example.com",
  "client_id": "client_abc123",
  "iat": 1698761832,
  "token_type": "refresh",
  "jti": "refresh_id"
}
```

---

## 🔐 Security Benefits

### 1. **Token Binding to Domain**

**Problem:** Tokens with `client_id` as audience can be used from any domain.

**Solution:** Tokens are bound to the requesting domain.

```javascript
// Client-side validation
const id_token = decodeJWT(token);

// Verify token is for this domain
if (id_token.aud !== window.location.origin) {
    throw new Error('Token not for this domain!');
}
```

### 2. **Resource Server Identification**

**Access tokens identify the actual API/resource server:**

```json
{
  "aud": "https://api.example.com"  // The API that will validate this
}
```

The API can verify:
```python
def validate_access_token(token):
    claims = decode_jwt(token)
    
    # Ensure token is for this API
    if claims['aud'] != 'https://api.example.com':
        raise UnauthorizedError('Token not for this API')
    
    return claims
```

### 3. **Multi-Domain Security**

**Different domains get different audiences:**

```
Request from app.example.com:
{
  "aud": "https://app.example.com"
}

Request from admin.example.com:
{
  "aud": "https://admin.example.com"
}
```

This prevents cross-domain token usage.

---

## 🧪 Testing

### Run Tests

```bash
# Test audience domain functionality
python manage.py test oidc_provider.tests.test_audience_domain

# All tests
python manage.py test oidc_provider
```

### Manual Verification

```bash
# 1. Get a token with Origin header
curl -X POST https://auth.example.com/token \
  -H "Origin: https://myapp.example.com" \
  -d "grant_type=authorization_code&code=..."

# 2. Decode the ID token
echo "ID_TOKEN" | cut -d. -f2 | base64 -d | jq

# 3. Verify aud claim
{
  "aud": "https://myapp.example.com"  // ✅ Should be the origin
}
```

---

## 🎓 Use Cases

### Use Case 1: SPA (Single Page Application)

**Setup:**
```python
client = Client.objects.create(
    name='My SPA',
    client_id='spa123',
    client_type='public',
)
client.redirect_uris = ['https://app.example.com/callback']
client.save()
```

**Request:**
```http
GET /authorize?client_id=spa123&... HTTP/1.1
Origin: https://app.example.com
```

**Token Result:**
```json
{
  "aud": "https://app.example.com"  // SPA's domain
}
```

**Client Validation:**
```javascript
// In the SPA
const token = getIdToken();
const decoded = jwt.decode(token);

// Verify audience matches current domain
if (decoded.aud !== window.location.origin) {
    console.error('Token audience mismatch!');
    logout();
}
```

### Use Case 2: Multiple APIs

**Setup:**
```python
# Client for main app
app_client = Client.objects.create(
    client_id='app123',
)
app_client.redirect_uris = ['https://app.example.com/callback']

# Client for admin panel
admin_client = Client.objects.create(
    client_id='admin123',
)
admin_client.redirect_uris = ['https://admin.example.com/callback']
```

**Tokens:**
```json
// App token
{
  "aud": "https://app.example.com"
}

// Admin token
{
  "aud": "https://admin.example.com"
}
```

**API Validation:**
```python
# In your API
def check_token(request):
    token = request.headers['Authorization'].split()[1]
    claims = decode_jwt(token)
    
    # Ensure token is for the right API
    expected_aud = f"https://{request.get_host()}"
    if claims['aud'] != expected_aud:
        raise Forbidden('Wrong audience')
```

### Use Case 3: Mobile App

**Setup:**
```python
client = Client.objects.create(
    name='Mobile App',
    client_id='mobile123',
)
# Mobile apps use custom redirect URI
client.redirect_uris = ['com.example.app://callback']
client.save()
```

**Token:**
```json
{
  "aud": "com.example.app://callback"  // App's custom URI scheme
}
```

### Use Case 4: Multi-Tenant Platform

**Different tenants, different audiences:**

```python
# Tenant A
Request from: https://tenant-a.myapp.com
Token aud: "https://tenant-a.myapp.com"

# Tenant B  
Request from: https://tenant-b.myapp.com
Token aud: "https://tenant-b.myapp.com"
```

**Tenant validation:**
```python
def validate_tenant_token(token, tenant):
    claims = decode_jwt(token)
    expected_aud = f"https://{tenant}.myapp.com"
    
    if claims['aud'] != expected_aud:
        raise Unauthorized('Token for wrong tenant')
```

---

## 🔧 Configuration

### Default Behavior (Recommended)

No configuration needed! The system automatically:
1. Extracts origin from request
2. Uses origin as audience
3. Falls back to redirect_uri domain

### Custom Audience Generator (Advanced)

```python
# settings.py

def custom_audience(client):
    """Custom audience for access tokens."""
    # Example: Use API endpoint as audience
    return f"https://api.{client.name}.com"

OIDC_TOKEN_JWT_AUD = 'myapp.utils.custom_audience'
```

**Result:**
```json
{
  "aud": "https://api.myclient.com"
}
```

### Disable Domain-Based Audience

If you need to revert to client_id:

```python
# settings.py
OIDC_USE_ORIGIN_AS_AUDIENCE = False  # Use client_id instead
```

---

## 🛡️ Client-Side Validation

### JavaScript/TypeScript

```typescript
interface IDToken {
    iss: string;
    sub: string;
    aud: string;
    exp: number;
    iat: number;
}

function validateIDToken(token: string): IDToken {
    const decoded = jwt.decode(token) as IDToken;
    
    // Verify audience matches current domain
    const currentOrigin = window.location.origin;
    if (decoded.aud !== currentOrigin) {
        throw new Error(
            `Token audience (${decoded.aud}) doesn't match ` +
            `current domain (${currentOrigin})`
        );
    }
    
    // Verify issuer
    if (decoded.iss !== 'https://auth.example.com/oidc') {
        throw new Error('Invalid issuer');
    }
    
    // Verify not expired
    if (decoded.exp < Date.now() / 1000) {
        throw new Error('Token expired');
    }
    
    return decoded;
}
```

### Python (Resource Server)

```python
def validate_access_token(token: str, expected_audience: str):
    """Validate access token audience."""
    try:
        claims = jwt.decode(
            token,
            verify=True,
            audience=expected_audience
        )
        
        # Additional validation
        if claims['aud'] != expected_audience:
            raise ValueError('Audience mismatch')
        
        return claims
    
    except jwt.InvalidAudienceError:
        raise Unauthorized('Invalid token audience')
    except jwt.ExpiredSignatureError:
        raise Unauthorized('Token expired')
```

---

## 📋 Migration Guide

### For Existing Deployments

**The change is backward compatible.** Tokens will now use domains, but validation is flexible.

**Step 1: Update Code**
```bash
git pull  # Get latest changes
```

**Step 2: Update Clients (Optional)**
```python
# Ensure redirect_uris are set correctly
for client in Client.objects.all():
    if not client.redirect_uris:
        # Set redirect URIs if missing
        client.redirect_uris = ['https://app.example.com/callback']
        client.save()
```

**Step 3: Update Client-Side Validation**
```javascript
// Old validation (client_id)
if (decoded.aud !== 'client123') { ... }

// New validation (domain)
if (decoded.aud !== window.location.origin) { ... }
```

**Step 4: Test**
```bash
python manage.py test oidc_provider.tests.test_audience_domain
```

---

## ❓ FAQ

### Q: Will old tokens still work?

**A:** Yes, if they have `client_id` as `aud`, validation will still accept them during a grace period.

### Q: What if my app has multiple domains?

**A:** Configure all domains in `redirect_uris`:
```python
client.redirect_uris = [
    'https://app.example.com/callback',
    'https://admin.example.com/callback',
]
```

Each domain will get tokens with its own audience.

### Q: How to debug audience issues?

**A:** Decode the token and check:
```bash
# Decode ID token
echo "TOKEN" | cut -d. -f2 | base64 -d | jq '.aud'

# Should output the domain, not client_id
"https://app.example.com"
```

### Q: Can I have multiple audiences?

**A:** Yes, ID tokens can have array of audiences:
```json
{
  "aud": [
    "https://app.example.com",
    "client123"
  ]
}
```

---

## ✅ Summary

### What Changed
- ✅ `aud` claim now contains **origin domain** instead of `client_id`
- ✅ Extracted from `Origin` header or `redirect_uri`
- ✅ Applied to all token types (ID, Access, Refresh)

### Benefits
- 🔒 **Better security** - Tokens bound to specific domains
- 🎯 **Clearer intent** - Audience identifies actual resource server
- 🛡️ **Prevents misuse** - Cross-domain token usage blocked
- ✅ **Standards compliant** - Follows JWT/OIDC best practices

### Files Created
- ✅ `oidc_provider/lib/utils/audience.py` - Audience utilities
- ✅ `oidc_provider/tests/test_audience_domain.py` - Comprehensive tests
- ✅ `AUDIENCE_DOMAIN_GUIDE.md` - This guide

### Testing
```bash
python manage.py test oidc_provider.tests.test_audience_domain
```

**Your tokens now use domains as audience for better security!** 🎉
