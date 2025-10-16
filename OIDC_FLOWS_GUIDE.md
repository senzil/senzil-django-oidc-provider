# OIDC Flows Implementation Guide

This document describes all supported OpenID Connect and OAuth 2.0 flows in this provider.

## Supported Flows

### 1. Authorization Code Flow ✅
**Response Type:** `code`  
**Grant Type:** `authorization_code`  
**Use Case:** Web applications with backend servers

#### Flow Steps:
1. Client redirects user to authorization endpoint with `response_type=code`
2. User authenticates and grants consent
3. Authorization server returns authorization code
4. Client exchanges code for tokens at token endpoint
5. Client receives access_token, id_token (if OIDC), and refresh_token

#### Security Features:
- ✅ PKCE (Proof Key for Code Exchange) support
- ✅ State parameter for CSRF protection
- ✅ Nonce parameter for replay protection
- ✅ Client authentication required

#### Example Request:
```
GET /authorize?
  response_type=code&
  client_id=YOUR_CLIENT_ID&
  redirect_uri=https://your-app.com/callback&
  scope=openid profile email&
  state=random_state&
  code_challenge=BASE64URL(SHA256(code_verifier))&
  code_challenge_method=S256
```

#### Example Token Exchange:
```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTHORIZATION_CODE&
redirect_uri=https://your-app.com/callback&
client_id=YOUR_CLIENT_ID&
client_secret=YOUR_CLIENT_SECRET&
code_verifier=ORIGINAL_CODE_VERIFIER
```

---

### 2. Implicit Flow ✅
**Response Type:** `id_token`, `id_token token`, or `token`  
**Grant Type:** `implicit`  
**Use Case:** Single Page Applications (SPAs) - **Not Recommended for New Apps**

#### Flow Steps:
1. Client redirects user to authorization endpoint
2. User authenticates and grants consent
3. Authorization server returns tokens in URL fragment
4. Client extracts tokens from fragment

#### Security Considerations:
- ⚠️ Tokens exposed in browser history
- ⚠️ No refresh tokens
- ⚠️ Use Authorization Code Flow with PKCE instead

#### Example Request:
```
GET /authorize?
  response_type=id_token token&
  client_id=YOUR_CLIENT_ID&
  redirect_uri=https://your-app.com/callback&
  scope=openid profile&
  nonce=random_nonce&
  state=random_state
```

---

### 3. Hybrid Flow ✅
**Response Type:** `code id_token`, `code token`, or `code id_token token`  
**Grant Type:** `hybrid`  
**Use Case:** Applications that need immediate access to user info and backend token processing

#### Flow Steps:
1. Client redirects user to authorization endpoint
2. User authenticates and grants consent
3. Authorization server returns both code and tokens in response
4. Client can use tokens immediately and exchange code for additional tokens

#### Security Features:
- ✅ Combines benefits of both code and implicit flows
- ✅ Immediate ID token validation
- ✅ Secure token refresh via code exchange

#### Example Request:
```
GET /authorize?
  response_type=code id_token&
  client_id=YOUR_CLIENT_ID&
  redirect_uri=https://your-app.com/callback&
  scope=openid profile email&
  nonce=random_nonce&
  state=random_state
```

---

### 4. Client Credentials Flow ✅
**Grant Type:** `client_credentials`  
**Use Case:** Machine-to-machine authentication (service accounts)

#### Flow Steps:
1. Client sends credentials to token endpoint
2. Server validates client credentials
3. Server returns access token (no user context)

#### Security Features:
- ✅ Client authentication required
- ✅ No user context (machine-to-machine)
- ✅ Scope-based access control

#### Example Request:
```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&
client_id=YOUR_CLIENT_ID&
client_secret=YOUR_CLIENT_SECRET&
scope=api.read api.write
```

---

### 5. Resource Owner Password Credentials (ROPC) Flow ✅
**Grant Type:** `password`  
**Use Case:** Trusted applications only - **Not Recommended**

⚠️ **Disabled by default** - Set `OIDC_GRANT_TYPE_PASSWORD_ENABLE = True` to enable

#### Security Considerations:
- ⚠️ Client handles user credentials
- ⚠️ No interactive consent
- ⚠️ Use only for highly trusted applications
- ⚠️ Implement rate limiting and brute force protection

#### Example Request:
```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=password&
username=user@example.com&
password=user_password&
client_id=YOUR_CLIENT_ID&
client_secret=YOUR_CLIENT_SECRET&
scope=openid profile
```

---

### 6. Refresh Token Flow ✅
**Grant Type:** `refresh_token`  
**Use Case:** Obtaining new access tokens without user interaction

#### Flow Steps:
1. Client sends refresh token to token endpoint
2. Server validates refresh token
3. Server returns new access token and optionally new refresh token

#### Security Features:
- ✅ Refresh token rotation support
- ✅ Scope reduction allowed
- ✅ Refresh token binding to client

#### Example Request:
```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
refresh_token=REFRESH_TOKEN&
client_id=YOUR_CLIENT_ID&
client_secret=YOUR_CLIENT_SECRET&
scope=openid profile
```

---

## Security Best Practices

### 1. PKCE (Proof Key for Code Exchange)
- ✅ **Required** for public clients (SPAs, mobile apps)
- ✅ **Recommended** for all authorization code flows
- Supported methods: `plain`, `S256` (SHA-256 recommended)

### 2. State Parameter
- ✅ Always use for CSRF protection
- Generate cryptographically random value
- Validate on callback

### 3. Nonce Parameter
- ✅ Required for implicit flow
- ✅ Recommended for all authentication requests
- Prevents replay attacks

### 4. Client Authentication
- Confidential clients: Use `client_secret_post` or `client_secret_basic`
- Public clients: Use PKCE instead

### 5. Token Security
- Access tokens: Short-lived (default 1 hour)
- ID tokens: Include audience (aud) claim
- Refresh tokens: Long-lived, properly secured
- Enable token encryption for sensitive data

---

## Recommended Flows by Application Type

### Single Page Application (SPA)
✅ **Recommended:** Authorization Code Flow + PKCE
```
response_type=code
code_challenge_method=S256
```

### Mobile Application
✅ **Recommended:** Authorization Code Flow + PKCE
```
response_type=code
code_challenge_method=S256
```

### Web Application with Backend
✅ **Recommended:** Authorization Code Flow
```
response_type=code
(with client_secret authentication)
```

### Machine-to-Machine
✅ **Recommended:** Client Credentials Flow
```
grant_type=client_credentials
```

### Trusted First-Party App
✅ **Consider:** Hybrid Flow
```
response_type=code id_token
```

---

## Session Management (Optional)

Enable with: `OIDC_SESSION_MANAGEMENT_ENABLE = True`

Features:
- ✅ Session state tracking
- ✅ RP-initiated logout
- ✅ Check session iframe for logout coordination

Endpoints:
- `/check-session-iframe` - Session monitoring
- `/end-session` - Logout endpoint

---

## Discovery and Metadata

### OpenID Provider Configuration
**Endpoint:** `/.well-known/openid-configuration`

Returns:
- Authorization endpoint
- Token endpoint
- UserInfo endpoint
- JWKS endpoint
- Supported response types, grant types, algorithms
- Token endpoint authentication methods

### JSON Web Key Set (JWKS)
**Endpoint:** `/jwks`

Returns public keys for:
- RSA keys (RS*, PS* algorithms)
- EC keys (ES* algorithms)

---

## Token Introspection

**Endpoint:** `/introspect`

OAuth 2.0 Token Introspection (RFC 7662) support:
- Validate access tokens
- Check token status and metadata
- Get token claims and expiration

---

## Third-Party Application Integration

### As an Authorization Provider

1. **Register Client Application**
   - Create client in Django admin
   - Configure redirect URIs
   - Select appropriate response types
   - Choose signing algorithms
   - Configure scopes

2. **Client Configuration**
   ```python
   Client.objects.create(
       name='Third Party App',
       client_type='confidential',
       response_types=['code'],  # Authorization Code Flow
       redirect_uris=['https://third-party.com/callback'],
       jwt_alg='RS256',
       require_consent=True,  # Ask user for permission
       reuse_consent=True,    # Remember user choice
   )
   ```

3. **Scopes and Claims**
   - Define custom scopes for your API
   - Map scopes to user data/permissions
   - Configure in `OIDC_EXTRA_SCOPE_CLAIMS`

4. **User Consent**
   - Users see permission screen on first authorization
   - Can view and revoke permissions at `/consent/`
   - Granular scope-level control

---

## Testing Flows

### Test Authorization Code Flow
```bash
# 1. Authorization Request (in browser)
https://your-idp.com/authorize?
  response_type=code&
  client_id=test-client&
  redirect_uri=http://localhost:8000/callback&
  scope=openid profile email&
  state=test-state&
  code_challenge=CHALLENGE&
  code_challenge_method=S256

# 2. Token Request
curl -X POST https://your-idp.com/token \
  -d grant_type=authorization_code \
  -d code=AUTHORIZATION_CODE \
  -d redirect_uri=http://localhost:8000/callback \
  -d client_id=test-client \
  -d client_secret=test-secret \
  -d code_verifier=VERIFIER
```

### Test Client Credentials Flow
```bash
curl -X POST https://your-idp.com/token \
  -d grant_type=client_credentials \
  -d client_id=test-client \
  -d client_secret=test-secret \
  -d scope=api.read
```

---

## Migration from Other Providers

### From Auth0/Okta
- Similar flow support
- Compatible OIDC/OAuth2 standards
- Update discovery URL
- Update JWKS endpoint

### From Keycloak
- Full OIDC compatibility
- Realm → Client mapping
- User federation may need custom implementation

### From Firebase Auth
- Implement custom user claims
- Map Firebase scopes to OIDC scopes
- Update client SDKs

---

## Troubleshooting

### Common Issues

1. **"redirect_uri_mismatch" error**
   - Ensure redirect_uri matches exactly in client configuration
   - Include protocol, domain, and path

2. **"invalid_grant" error**
   - Authorization code expired (default 10 minutes)
   - Code already used
   - PKCE verifier mismatch

3. **"unsupported_response_type" error**
   - Response type not enabled for client
   - Check client's response_types configuration

4. **Token signature verification fails**
   - Wrong algorithm selected
   - Missing or expired keys
   - Check JWKS endpoint

---

## Standards Compliance

This implementation follows:
- ✅ [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- ✅ [OAuth 2.0 (RFC 6749)](https://tools.ietf.org/html/rfc6749)
- ✅ [OAuth 2.0 PKCE (RFC 7636)](https://tools.ietf.org/html/rfc7636)
- ✅ [OAuth 2.0 Token Introspection (RFC 7662)](https://tools.ietf.org/html/rfc7662)
- ✅ [OpenID Connect Session Management](https://openid.net/specs/openid-connect-session-1_0.html)
- ✅ [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)
