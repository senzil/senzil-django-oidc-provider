# Audience (aud) Standards Compliance Guide

## Overview

This guide explains the **correct standards-compliant usage** of the `aud` (audience) claim in JWT tokens according to OIDC and OAuth 2.0 specifications.

---

## 📋 Standards Summary

### OIDC Core 1.0 (ID Tokens)

**ID Token `aud` MUST be the `client_id`**

> "REQUIRED. Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value."
> 
> — OIDC Core 1.0, Section 2 (ID Token)

### OAuth 2.0 RFC 8707 (Access Tokens)

**Access Token `aud` should be the Resource Server**

> "The audience of an access token is the resource server(s) where the token will be used."
>
> — RFC 8707: Resource Indicators for OAuth 2.0

---

## ✅ Correct Implementation

### ID Token Audience

**MUST be:** `client_id`

**Why:** ID tokens are consumed BY the client application. The client is the audience.

```json
{
  "iss": "https://auth.example.com/oidc",
  "sub": "user123",
  "aud": "client_abc123",  // ✅ client_id (REQUIRED)
  "exp": 1698765432,
  "iat": 1698761832
}
```

### Access Token Audience

**SHOULD be:** Resource Server/API identifier

**Why:** Access tokens are used AT resource servers. The API is the audience.

```json
{
  "iss": "https://auth.example.com/oidc",
  "sub": "user123",
  "aud": "https://api.example.com",  // ✅ API/Resource Server
  "client_id": "client_abc123",
  "exp": 1698765432,
  "iat": 1698761832,
  "scope": ["read", "write"]
}
```

### Refresh Token Audience

**CAN be:** Authorization Server or `client_id`

**Why:** Refresh tokens are used at the token endpoint.

```json
{
  "iss": "https://auth.example.com/oidc",
  "sub": "user123",
  "aud": "client_abc123",  // ✅ client_id or issuer
  "client_id": "client_abc123",
  "token_type": "refresh",
  "iat": 1698761832
}
```

---

## 🎯 Implementation

### ID Token (Automatic - No Config Needed)

```python
# ID tokens automatically use client_id as audience
id_token = create_id_token(
    token=token,
    user=user,
    aud=client.client_id,  # ✅ OIDC compliant
    request=request
)

# Result:
{
  "aud": "client_abc123"  // Always client_id
}
```

### Access Token (Configure Resource Server)

**Option 1: Custom Audience Generator (Recommended)**

```python
# settings.py

def api_audience_generator(client, request=None):
    """Return the API that will validate this token."""
    # Option A: Fixed API endpoint
    return "https://api.example.com"
    
    # Option B: From client metadata
    # return client.api_domain
    
    # Option C: From request origin (the calling API)
    # from oidc_provider.middleware_origin import get_request_origin
    # return get_request_origin(request)

OIDC_TOKEN_JWT_AUD = 'myapp.utils.api_audience_generator'
```

**Result:**
```json
{
  "aud": "https://api.example.com"  // ✅ Resource server
}
```

**Option 2: Client-Specific Resource Server**

```python
# Add field to Client model or use extension
client = Client.objects.create(
    client_id='mobile_app',
    resource_server_identifier='https://api.example.com',
)

# Custom generator
def resource_server_audience(client, request=None):
    if hasattr(client, 'resource_server_identifier'):
        return client.resource_server_identifier
    return 'https://api.example.com'

OIDC_TOKEN_JWT_AUD = 'myapp.utils.resource_server_audience'
```

**Option 3: Multi-Tenant API**

```python
def tenant_api_audience(client, request=None):
    """Multi-tenant API audience."""
    tenant = getattr(client, 'tenant', 'default')
    return f"https://api-{tenant}.example.com"

OIDC_TOKEN_JWT_AUD = 'myapp.utils.tenant_api_audience'
```

**Result:**
```json
// Tenant A
{"aud": "https://api-tenant-a.example.com"}

// Tenant B
{"aud": "https://api-tenant-b.example.com"}
```

---

## 🔍 Why This Matters

### Security Benefits

#### 1. **Token Binding to Destination**

Access tokens are bound to the API they're meant for:

```json
{
  "aud": "https://api.example.com"
}
```

If an attacker steals this token and tries to use it at `https://other-api.com`:
```python
# At other-api.com
claims = decode_jwt(token)
if claims['aud'] != 'https://other-api.com':
    raise Unauthorized('Token not for this API')  # ✅ Rejected
```

#### 2. **Prevents Token Misuse**

```python
# User App gets token for API A
{
  "aud": "https://api-a.example.com"
}

# Tries to use at API B
# API B validates:
if claims['aud'] != 'https://api-b.example.com':
    raise Unauthorized()  # ✅ Rejected
```

#### 3. **Multi-API Architecture**

```python
# Token for User API
{
  "aud": "https://user-api.example.com",
  "scope": ["user.read"]
}

# Token for Payment API
{
  "aud": "https://payment-api.example.com",
  "scope": ["payment.create"]
}

# Each API validates its own audience
```

---

## 📊 Complete Token Examples

### Example 1: Web Application

**ID Token:**
```json
{
  "iss": "https://auth.example.com/oidc",
  "sub": "user@example.com",
  "aud": "web_app_client_123",  // ✅ client_id
  "exp": 1698765432,
  "iat": 1698761832,
  "nonce": "abc123",
  "name": "John Doe",
  "email": "user@example.com"
}
```

**Access Token:**
```json
{
  "iss": "https://auth.example.com/oidc",
  "sub": "user@example.com",
  "aud": "https://api.example.com",  // ✅ API server
  "client_id": "web_app_client_123",
  "exp": 1698765432,
  "iat": 1698761832,
  "scope": ["openid", "profile", "api.read"]
}
```

### Example 2: Mobile App

**ID Token:**
```json
{
  "iss": "https://auth.example.com/oidc",
  "sub": "user123",
  "aud": "mobile_app_ios_456",  // ✅ client_id
  "exp": 1698765432
}
```

**Access Token:**
```json
{
  "iss": "https://auth.example.com/oidc",
  "sub": "user123",
  "aud": "https://mobile-api.example.com",  // ✅ Mobile API
  "client_id": "mobile_app_ios_456",
  "exp": 1698765432,
  "scope": ["mobile.sync", "offline_access"]
}
```

### Example 3: Microservices

**Service A → Service B:**

```json
{
  "iss": "https://auth.example.com/oidc",
  "sub": "service-a",
  "aud": "https://service-b.internal",  // ✅ Target service
  "client_id": "service_a_client",
  "exp": 1698765432,
  "scope": ["service-b.invoke"]
}
```

**Service A → Service C:**

```json
{
  "iss": "https://auth.example.com/oidc",
  "sub": "service-a",
  "aud": "https://service-c.internal",  // ✅ Different target
  "client_id": "service_a_client",
  "exp": 1698765432,
  "scope": ["service-c.query"]
}
```

---

## 🛡️ Resource Server Validation

### API Validates Audience

```python
# At API server (https://api.example.com)
def validate_access_token(token):
    """Validate access token is for this API."""
    claims = jwt.decode(token, verify=True)
    
    # Check audience matches this API
    expected_aud = "https://api.example.com"
    if claims.get('aud') != expected_aud:
        raise Unauthorized(
            f"Token audience '{claims.get('aud')}' "
            f"does not match expected '{expected_aud}'"
        )
    
    # Check issuer
    if claims.get('iss') != 'https://auth.example.com/oidc':
        raise Unauthorized('Invalid issuer')
    
    # Check expiration
    if claims.get('exp', 0) < time.time():
        raise Unauthorized('Token expired')
    
    return claims
```

### Client Validates ID Token

```javascript
// At client application
function validateIDToken(idToken, clientId) {
    const claims = JSON.parse(atob(idToken.split('.')[1]));
    
    // Check audience is client_id
    if (claims.aud !== clientId) {
        throw new Error(
            `ID token audience '${claims.aud}' ` +
            `does not match client_id '${clientId}'`
        );
    }
    
    // Check issuer
    if (claims.iss !== 'https://auth.example.com/oidc') {
        throw new Error('Invalid issuer');
    }
    
    // Check expiration
    if (claims.exp < Date.now() / 1000) {
        throw new Error('Token expired');
    }
    
    return claims;
}
```

---

## 🎓 Real-World Scenarios

### Scenario 1: SPA with Backend API

**Setup:**
```python
# SPA Client
spa_client = Client.objects.create(
    client_id='spa_app',
)

# Configure API as resource server
def api_audience(client, request=None):
    return "https://api.myapp.com"

# settings.py
OIDC_TOKEN_JWT_AUD = 'myapp.utils.api_audience'
```

**Tokens:**
```json
// ID Token (for SPA)
{
  "aud": "spa_app"  // ✅ SPA's client_id
}

// Access Token (for API)
{
  "aud": "https://api.myapp.com"  // ✅ API endpoint
}
```

**Usage:**
```javascript
// SPA validates ID token
const idClaims = validateIDToken(idToken, 'spa_app');

// SPA calls API with access token
fetch('https://api.myapp.com/users', {
    headers: {
        'Authorization': `Bearer ${accessToken}`
    }
});

// API validates access token
// Checks: aud === 'https://api.myapp.com'
```

### Scenario 2: Multi-Tenant Platform

**Setup:**
```python
def tenant_audience(client, request=None):
    tenant = client.tenant
    return f"https://api-{tenant}.platform.com"

OIDC_TOKEN_JWT_AUD = 'myapp.utils.tenant_audience'
```

**Tokens:**
```json
// Tenant A
{
  "aud": "https://api-tenant-a.platform.com",
  "client_id": "tenant_a_client"
}

// Tenant B
{
  "aud": "https://api-tenant-b.platform.com",
  "client_id": "tenant_b_client"
}
```

**API Validation:**
```python
# Tenant A API
if claims['aud'] != 'https://api-tenant-a.platform.com':
    raise Unauthorized('Wrong tenant')
```

### Scenario 3: Microservices Mesh

**Setup:**
```python
def microservice_audience(client, request=None):
    # Determine target service from scope
    scopes = request.POST.get('scope', '').split()
    
    if 'user-service' in scopes:
        return 'https://user-service.internal'
    elif 'payment-service' in scopes:
        return 'https://payment-service.internal'
    
    return 'https://api.internal'

OIDC_TOKEN_JWT_AUD = 'myapp.utils.microservice_audience'
```

**Tokens:**
```json
// For User Service
{
  "aud": "https://user-service.internal",
  "scope": ["user.read", "user.write"]
}

// For Payment Service
{
  "aud": "https://payment-service.internal",
  "scope": ["payment.create"]
}
```

---

## ✅ Standards Compliance Checklist

### ID Tokens
- [ ] `aud` claim is `client_id` ✅
- [ ] Client validates `aud` matches its `client_id` ✅
- [ ] Follows OIDC Core 1.0 Section 2 ✅

### Access Tokens
- [ ] `aud` claim identifies resource server/API ✅
- [ ] NOT just `client_id` (unless fallback) ✅
- [ ] Resource server validates `aud` ✅
- [ ] Follows OAuth 2.0 RFC 8707 best practices ✅

### Refresh Tokens
- [ ] `aud` is authorization server or `client_id` ✅
- [ ] Validated at token endpoint ✅

---

## 🔧 Migration Guide

### Update Audience Configuration

```python
# 1. Define API audience generator
# myapp/utils.py
def get_api_audience(client, request=None):
    """Return API that will validate access tokens."""
    # Your API endpoint
    return "https://api.example.com"
    
    # Or multi-tenant
    # tenant = getattr(client, 'tenant', 'default')
    # return f"https://api-{tenant}.example.com"

# 2. Configure in settings
# settings.py
OIDC_TOKEN_JWT_AUD = 'myapp.utils.get_api_audience'

# 3. ID tokens automatically use client_id (no config needed)
```

### Update Client Validation

```javascript
// OLD (incorrect)
if (decoded.aud !== window.location.origin) { ... }

// NEW (correct)
// For ID tokens
if (decoded.aud !== 'my_client_id') { ... }

// For access tokens
// Just send to API, API validates
```

### Update API Validation

```python
# API server
def validate_token(token):
    claims = jwt.decode(token)
    
    # Validate audience is this API
    if claims['aud'] != 'https://api.example.com':
        raise Unauthorized('Wrong audience')
    
    return claims
```

---

## 📚 Summary

### ✅ Standards-Compliant Audience

| Token Type | Audience (`aud`) | Why |
|------------|------------------|-----|
| **ID Token** | `client_id` | Token is FOR the client (OIDC spec) |
| **Access Token** | Resource Server/API | Token is FOR the API (OAuth spec) |
| **Refresh Token** | Auth Server or `client_id` | Token is FOR the token endpoint |

### ✅ Security Benefits

- **Token Binding** - Tokens bound to specific destinations
- **Prevents Misuse** - APIs reject tokens not meant for them
- **Multi-API Support** - Each API has its own audience
- **Standards Compliance** - Follows OIDC/OAuth specs

### ✅ Configuration

```python
# settings.py
OIDC_TOKEN_JWT_AUD = 'myapp.utils.api_audience_generator'

# myapp/utils.py
def api_audience_generator(client, request=None):
    return "https://api.example.com"
```

**Your OIDC provider is now standards-compliant!** ✅🎉

- ID tokens: `aud` = `client_id` ✅
- Access tokens: `aud` = API/resource server ✅  
- Refresh tokens: `aud` = auth server or `client_id` ✅
