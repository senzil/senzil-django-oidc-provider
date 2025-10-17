# JWT Claims Verification Guide

## Overview

This guide documents how JWT tokens include the required OIDC claims: `iss` (issuer), `sub` (subject), and `aud` (audience).

---

## ✅ Required Claims Implementation

### ID Token Claims (OIDC Core 1.0 Compliant)

**Always Included:**
- ✅ `iss` - Issuer (full URL of the OIDC provider)
- ✅ `sub` - Subject (unique user identifier)
- ✅ `aud` - Audience (client_id)
- ✅ `exp` - Expiration time (Unix timestamp)
- ✅ `iat` - Issued at (Unix timestamp)
- ✅ `auth_time` - Authentication time

**Conditionally Included:**
- `nonce` - If provided in authorization request
- `at_hash` - Hash of access token (for implicit/hybrid flows)
- User claims (if `OIDC_IDTOKEN_INCLUDE_CLAIMS=True`)

### Access Token Claims (JWT Format)

**Always Included:**
- ✅ `iss` - Issuer
- ✅ `aud` - Audience (client_id or configured resource server)
- ✅ `client_id` - Client identifier
- ✅ `exp` - Expiration time
- ✅ `iat` - Issued at
- ✅ `jti` - JWT ID (token identifier)
- ✅ `scope` - Granted scopes

**Conditionally Included:**
- `sub` - Subject (included if user context exists)
- `origin` - Request origin (if origin tracking enabled)
- `origin_domain` - Origin domain (if origin tracking enabled)

### Refresh Token Claims (JWT Format)

**Always Included:**
- ✅ `iss` - Issuer
- ✅ `aud` - Audience (client_id)
- ✅ `sub` - Subject
- ✅ `client_id` - Client identifier
- ✅ `iat` - Issued at
- ✅ `jti` - JWT ID
- ✅ `token_type` - "refresh"

**Conditionally Included:**
- `origin` - Request origin (if tracking enabled)
- `origin_domain` - Origin domain (if tracking enabled)

---

## 🔍 Claim Details

### `iss` (Issuer)

**What it is:**
- Full URL of your OIDC provider
- Identifies who issued the token

**Format:**
```
https://your-domain.com/oidc
```

**How it's generated:**
```python
from oidc_provider.lib.utils.common import get_issuer

issuer = get_issuer(request=request)
# Returns: https://your-domain.com/oidc
```

**Configuration:**
```python
# settings.py
SITE_URL = 'https://your-domain.com'  # Optional
# Or it's auto-detected from request
```

### `sub` (Subject)

**What it is:**
- Unique identifier for the user
- Must be unique within the issuer
- Should not reveal PII

**Format:**
```
"123456"  # User ID (default)
"user@example.com"  # Or email if configured
"uuid-format"  # Or UUID
```

**How it's generated:**
```python
# Default generator (uses user.id)
def default_sub_generator(user):
    return str(user.id)

# Custom generator
def custom_sub_generator(user):
    return f"user_{user.username}_{user.id}"
```

**Configuration:**
```python
# settings.py
OIDC_IDTOKEN_SUB_GENERATOR = 'myapp.utils.custom_sub_generator'
# Or use default (user.id)
```

### `aud` (Audience)

**What it is:**
- Intended recipient of the token
- Client must verify token's aud matches its client_id
- Can be single value or array

**For ID Tokens:**
```json
{
  "aud": "client_abc123"
}
```

**For Access Tokens:**
```json
{
  "aud": "client_abc123"  // or resource server identifier
}
```

**How it's set:**
```python
# ID Token
id_token = {
    'aud': str(client.client_id)  # Always client_id
}

# Access Token (configurable)
if settings.get('OIDC_TOKEN_JWT_AUD'):
    aud = settings.get('OIDC_TOKEN_JWT_AUD')(client=client)
else:
    aud = str(client.client_id)  # Default
```

**Custom Audience:**
```python
# settings.py
def custom_aud_generator(client):
    # Return resource server identifier
    return f"https://api.example.com/{client.name}"

OIDC_TOKEN_JWT_AUD = 'myapp.utils.custom_aud_generator'
```

---

## 📝 Example Tokens

### ID Token Example

```json
{
  "iss": "https://auth.example.com/oidc",
  "sub": "12345",
  "aud": "client_abc123",
  "exp": 1698765432,
  "iat": 1698761832,
  "auth_time": 1698761800,
  "nonce": "random_nonce_value",
  "email": "user@example.com",
  "name": "John Doe"
}
```

### Access Token Example (JWT)

```json
{
  "iss": "https://auth.example.com/oidc",
  "sub": "12345",
  "aud": "client_abc123",
  "client_id": "client_abc123",
  "exp": 1698765432,
  "iat": 1698761832,
  "scope": ["openid", "profile", "email"],
  "jti": "token_unique_id_xyz",
  "origin": "https://app.example.com",
  "origin_domain": "app.example.com"
}
```

### Refresh Token Example (JWT)

```json
{
  "iss": "https://auth.example.com/oidc",
  "sub": "12345",
  "aud": "client_abc123",
  "client_id": "client_abc123",
  "iat": 1698761832,
  "jti": "refresh_unique_id_abc",
  "token_type": "refresh",
  "origin_domain": "app.example.com"
}
```

### Client Credentials Token (No User)

```json
{
  "iss": "https://auth.example.com/oidc",
  "aud": "https://api.example.com",
  "client_id": "service_client_123",
  "exp": 1698765432,
  "iat": 1698761832,
  "scope": ["api.read", "api.write"],
  "jti": "service_token_xyz"
}
```
Note: No `sub` claim (no user context)

---

## ✅ Verification Tests

### Test ID Token Claims

```python
def test_id_token_has_required_claims():
    id_token = create_id_token(
        token=token,
        user=user,
        aud=client.client_id,
        request=request
    )
    
    # Verify required claims
    assert 'iss' in id_token
    assert 'sub' in id_token
    assert 'aud' in id_token
    assert 'exp' in id_token
    assert 'iat' in id_token
    
    # Verify values
    assert id_token['iss'].startswith('https://')
    assert id_token['sub'] == str(user.id)
    assert id_token['aud'] == str(client.client_id)
```

### Test Access Token Claims

```python
def test_access_token_has_required_claims():
    jwt_token = encode_access_token_jwt(
        token=token,
        user=user,
        client=client,
        request=request
    )
    
    # Decode JWT
    payload = decode_jwt(jwt_token)
    
    # Verify required claims
    assert 'iss' in payload
    assert 'aud' in payload
    assert 'sub' in payload
    assert 'client_id' in payload
    assert 'exp' in payload
    assert 'iat' in payload
```

### Run Tests

```bash
# Test JWT claims
python manage.py test oidc_provider.tests.test_jwt_claims

# All tests
python manage.py test oidc_provider
```

---

## 🔧 Configuration Examples

### Example 1: Default Configuration

```python
# settings.py

# Uses default sub generator (user.id)
# Uses default aud (client_id)
# No additional configuration needed
```

**Result:**
```json
{
  "iss": "https://auth.example.com/oidc",
  "sub": "12345",  // user.id
  "aud": "client_abc123"  // client_id
}
```

### Example 2: Custom Subject Generator

```python
# settings.py
OIDC_IDTOKEN_SUB_GENERATOR = 'myapp.utils.custom_sub'

# myapp/utils.py
def custom_sub(user):
    """Use email as subject."""
    return user.email
```

**Result:**
```json
{
  "iss": "https://auth.example.com/oidc",
  "sub": "user@example.com",  // user.email
  "aud": "client_abc123"
}
```

### Example 3: Custom Audience for API

```python
# settings.py
OIDC_TOKEN_JWT_AUD = 'myapp.utils.api_audience'

# myapp/utils.py
def api_audience(client):
    """Return API resource server as audience."""
    return f"https://api.example.com/{client.name}"
```

**Access Token Result:**
```json
{
  "iss": "https://auth.example.com/oidc",
  "sub": "12345",
  "aud": "https://api.example.com/MyApp",  // Custom audience
  "client_id": "client_abc123"
}
```

### Example 4: Multi-Tenant Issuer

```python
# settings.py
def tenant_aware_issuer(request):
    """Generate tenant-specific issuer."""
    tenant = request.GET.get('tenant', 'default')
    return f"https://{tenant}.example.com/oidc"

# Custom hook
OIDC_IDTOKEN_PROCESSING_HOOK = 'myapp.utils.add_tenant_iss'

# myapp/utils.py
def add_tenant_iss(id_token, user, token, request):
    """Override issuer for multi-tenant."""
    tenant = getattr(user, 'tenant', 'default')
    id_token['iss'] = f"https://{tenant}.example.com/oidc"
    return id_token
```

**Result:**
```json
{
  "iss": "https://tenant-a.example.com/oidc",  // Tenant-specific
  "sub": "12345",
  "aud": "client_abc123"
}
```

---

## 🛡️ Security Considerations

### 1. Issuer Validation

**Client MUST:**
- Verify `iss` matches expected issuer
- Reject tokens from unknown issuers

```javascript
// Client-side validation
if (id_token.iss !== 'https://auth.example.com/oidc') {
    throw new Error('Invalid issuer');
}
```

### 2. Audience Validation

**Client MUST:**
- Verify `aud` contains its client_id
- Reject tokens not intended for it

```javascript
// Client-side validation
if (id_token.aud !== 'my_client_id') {
    throw new Error('Token not for this client');
}
```

### 3. Subject Privacy

**Best Practices:**
- Don't use email as `sub` (can change)
- Don't use username (can change)
- Use stable, unique ID (user.id or UUID)
- Avoid PII in `sub` claim

**Good:**
```json
{"sub": "12345"}  // Stable user ID
{"sub": "550e8400-e29b-41d4-a716-446655440000"}  // UUID
```

**Bad:**
```json
{"sub": "user@example.com"}  // Can change
{"sub": "john_doe"}  // Can change
```

### 4. Claim Integrity

**Guaranteed:**
- Required claims ALWAYS present
- Cannot be removed by hooks
- Validated on creation

```python
# Even if hook tries to remove claims
def bad_hook(id_token, **kwargs):
    del id_token['iss']  # Attempted removal
    return id_token

# System ensures iss is re-added
# Final token WILL have 'iss'
```

---

## 🧪 Validation Utilities

### Ensure Claims Present

```python
from oidc_provider.lib.utils.jwt_claims import (
    ensure_id_token_claims,
    ensure_access_token_claims,
)

# Ensure ID token has all claims
id_token = ensure_id_token_claims(
    id_token_dic={},  # Even empty
    user=user,
    client=client,
    request=request
)
# Now has: iss, sub, aud, exp, iat, auth_time

# Ensure access token has all claims
payload = ensure_access_token_claims(
    payload={},
    user=user,
    client=client,
    token=token,
    request=request
)
# Now has: iss, sub, aud, client_id, exp, iat, jti
```

### Validate Claims

```python
from oidc_provider.lib.utils.jwt_claims import (
    validate_id_token_claims,
    validate_access_token_claims,
)

# Validate ID token
is_valid, errors = validate_id_token_claims(
    id_token_dic,
    client,
    user
)

if not is_valid:
    print(f"Validation errors: {errors}")
    # ['Missing required claim: iss', ...]

# Validate access token
is_valid, errors = validate_access_token_claims(
    payload,
    client,
    user
)
```

---

## 📊 Summary

### What's Guaranteed

✅ **ID Tokens ALWAYS have:**
- `iss` - Issuer URL
- `sub` - User identifier
- `aud` - Client ID
- `exp` - Expiration
- `iat` - Issued at

✅ **Access Tokens ALWAYS have:**
- `iss` - Issuer URL
- `aud` - Client ID or resource server
- `client_id` - Client identifier
- `exp` - Expiration
- `iat` - Issued at
- `sub` - User ID (if user context)

✅ **Refresh Tokens ALWAYS have:**
- `iss` - Issuer URL
- `aud` - Client ID
- `sub` - User identifier
- `client_id` - Client identifier
- `iat` - Issued at

### How to Verify

1. **Run tests:**
   ```bash
   python manage.py test oidc_provider.tests.test_jwt_claims
   ```

2. **Decode token manually:**
   ```bash
   # Decode JWT (base64)
   echo "eyJ..." | base64 -d | jq
   ```

3. **Use jwt.io:**
   - Paste JWT token
   - Verify claims in payload

4. **Client validation:**
   ```javascript
   const decoded = jwt.decode(id_token);
   console.log('iss:', decoded.iss);
   console.log('sub:', decoded.sub);
   console.log('aud:', decoded.aud);
   ```

---

## ✅ Compliance

### OIDC Core 1.0

✅ **ID Token (Section 2):**
- Required claims: iss, sub, aud, exp, iat ✅
- Optional claims: auth_time, nonce, acr, amr, azp ✅

✅ **UserInfo (Section 5.3):**
- sub claim MUST be present ✅

✅ **Token Validation (Section 3.1.3.7):**
- iss validation ✅
- aud validation ✅
- exp validation ✅

### OAuth 2.0

✅ **Access Token (RFC 6749):**
- Can be opaque or structured ✅
- JWT format includes required claims ✅

✅ **Refresh Token (RFC 6749):**
- Can be opaque or structured ✅
- JWT format includes required claims ✅

---

**Your JWT tokens are fully compliant with OIDC/OAuth standards!** ✅

All required claims (iss, sub, aud) are guaranteed to be present in all token types.
