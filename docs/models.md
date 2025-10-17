# Models Reference

## Overview

Complete reference for all OIDC provider models.

## Core Models

### Client

OAuth2/OIDC client application.

**Fields:**
- `name` - Client name
- `client_id` - Unique client identifier
- `client_secret` - Client secret (for confidential clients)
- `client_type` - 'confidential' or 'public'
- `response_types` - Supported response types
- `redirect_uris` - Allowed redirect URIs
- `jwt_alg` - ID token signing algorithm
- `access_token_jwt_alg` - Access token algorithm
- `refresh_token_jwt_alg` - Refresh token algorithm
- `*_encrypted_response_alg` - Encryption algorithms
- `*_encrypted_response_enc` - Content encryption
- `allowed_origins` - Domain allowlist
- `strict_origin_validation` - Enable strict validation
- `require_consent` - Show consent screen
- `reuse_consent` - Remember consent

### Token

Access token and refresh token storage.

**Fields:**
- `user` - FK to User
- `client` - FK to Client
- `access_token` - Access token value
- `refresh_token` - Refresh token value
- `expires_at` - Expiration timestamp
- `scope` - Granted scopes
- `origin_domain` - Requesting domain

### Code

Authorization code storage.

**Fields:**
- `user` - FK to User
- `client` - FK to Client
- `code` - Authorization code value
- `expires_at` - Expiration timestamp
- `scope` - Requested scopes
- `nonce` - Nonce value
- `code_challenge` - PKCE challenge
- `code_challenge_method` - PKCE method
- `origin_domain` - Requesting domain

### UserConsent

User consent storage.

**Fields:**
- `user` - FK to User
- `client` - FK to Client
- `scope` - Granted scopes
- `expires_at` - Consent expiration
- `date_given` - Consent timestamp

## Key Models

### RSAKey

RSA key for RS*/PS* algorithms.

**Fields:**
- `key` - PEM format RSA key

**Properties:**
- `kid` - Key ID (MD5 hash)

### ECKey

Elliptic Curve key for ES* algorithms.

**Fields:**
- `key` - PEM format EC key
- `crv` - Curve (P-256, P-384, P-521)

**Properties:**
- `kid` - Key ID

## Passkey Models

### WebAuthnCredential

Passkey/FIDO2 credential storage.

**Fields:**
- `user` - FK to User
- `credential_id` - Unique credential ID
- `public_key` - COSE public key
- `sign_count` - Signature counter
- `authenticator_attachment` - platform/cross-platform
- `name` - User-given name
- `created_at` - Registration timestamp
- `last_used_at` - Last authentication
- `is_active` - Active status

### WebAuthnChallenge

Temporary challenge storage.

**Fields:**
- `challenge` - Base64 challenge
- `challenge_type` - registration/authentication
- `expires_at` - Challenge expiration
- `used` - Whether used

### PasskeyAuthenticationLog

Passkey audit log.

**Fields:**
- `user` - FK to User
- `credential` - FK to credential
- `success` - Success/failure
- `ip_address` - Request IP
- `timestamp` - Log timestamp

## Refresh Token Models

### RefreshTokenHistory

Refresh token rotation tracking.

**Fields:**
- `token` - FK to Token
- `jti` - JWT ID of old token
- `revoked` - Revocation status
- `created_at` - Rotation timestamp

## Model Methods

### Client Methods

```python
client.is_origin_allowed(origin)  # Check if origin allowed
client.allowed_origins_list  # Get list of origins
```

### WebAuthnCredential Methods

```python
credential.update_last_used(sign_count)  # Update usage
credential.credential_id_bytes  # Get as bytes
credential.public_key_bytes  # Get as bytes
```

### WebAuthnChallenge Methods

```python
challenge.is_valid()  # Check validity
challenge.mark_used()  # Mark as used
challenge.challenge_bytes  # Get as bytes
```

## Usage Examples

### Create Client

```python
from oidc_provider.models import Client, ResponseType

client = Client.objects.create(
    name='My App',
    client_type='confidential',
    jwt_alg='ES256',
    allowed_origins='https://app.example.com',
    strict_origin_validation=True,
)

code_type = ResponseType.objects.get(value='code')
client.response_types.add(code_type)
client.redirect_uris = ['https://app.example.com/callback']
client.save()
```

### Query Tokens

```python
from oidc_provider.models import Token

# Active tokens
active_tokens = Token.objects.filter(
    expires_at__gte=timezone.now()
)

# Tokens by origin
origin_tokens = Token.objects.filter(
    origin_domain='app.example.com'
)
```

### Query Passkeys

```python
from oidc_provider.models import WebAuthnCredential

# User's passkeys
user_passkeys = WebAuthnCredential.objects.filter(
    user=user,
    is_active=True
)

# Recently used
recent = WebAuthnCredential.objects.filter(
    last_used_at__gte=timezone.now() - timedelta(days=30)
)
```

## Summary

Complete model reference for OIDC provider. See [Customization Guide](customization.md) for extending models.
