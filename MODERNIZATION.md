# OIDC Provider Modernization - Token Algorithms and Encryption

This document describes the modernization updates to the OIDC provider that add support for modern JWT signing algorithms and token encryption.

## New Features

### 1. Extended JWT Signing Algorithm Support

The provider now supports the following signing algorithms:

#### HMAC-based (Symmetric)
- **HS256** - HMAC using SHA-256
- **HS384** - HMAC using SHA-384
- **HS512** - HMAC using SHA-512

#### RSA-based (Asymmetric)
- **RS256** - RSASSA-PKCS1-v1_5 using SHA-256
- **RS384** - RSASSA-PKCS1-v1_5 using SHA-384
- **RS512** - RSASSA-PKCS1-v1_5 using SHA-512
- **PS256** - RSASSA-PSS using SHA-256
- **PS384** - RSASSA-PSS using SHA-384
- **PS512** - RSASSA-PSS using SHA-512

#### Elliptic Curve-based (Asymmetric)
- **ES256** - ECDSA using P-256 and SHA-256
- **ES384** - ECDSA using P-384 and SHA-384
- **ES512** - ECDSA using P-521 and SHA-512

### 2. Separate Algorithm Configuration

You can now configure different algorithms for:
- **ID Tokens** - using `jwt_alg` field
- **Access Tokens** - using `access_token_jwt_alg` field (falls back to `jwt_alg` if not set)

### 3. JWT Encryption (JWE) Support

Both ID tokens and Access tokens can now be encrypted using JSON Web Encryption (JWE).

#### Encryption Key Management Algorithms (alg)
- **RSA-OAEP** - RSA with OAEP padding
- **RSA-OAEP-256** - RSA with OAEP-256 padding
- **A128KW** - AES Key Wrap with 128-bit key
- **A192KW** - AES Key Wrap with 192-bit key
- **A256KW** - AES Key Wrap with 256-bit key
- **dir** - Direct use of shared symmetric key
- **ECDH-ES** - Elliptic Curve Diffie-Hellman Ephemeral Static
- **ECDH-ES+A128KW** - ECDH-ES with AES-128 Key Wrap
- **ECDH-ES+A192KW** - ECDH-ES with AES-192 Key Wrap
- **ECDH-ES+A256KW** - ECDH-ES with AES-256 Key Wrap

#### Content Encryption Algorithms (enc)
- **A128CBC-HS256** - AES-128 CBC with HMAC-SHA-256
- **A192CBC-HS384** - AES-192 CBC with HMAC-SHA-384
- **A256CBC-HS512** - AES-256 CBC with HMAC-SHA-512
- **A128GCM** - AES-128 GCM
- **A192GCM** - AES-192 GCM
- **A256GCM** - AES-256 GCM

### 4. Elliptic Curve Key Management

A new `ECKey` model has been added to manage Elliptic Curve keys for ES256/ES384/ES512 algorithms.

## Usage Guide

### Creating Keys

#### RSA Keys (for RS*, PS* algorithms)
```bash
python manage.py creatersakey
```

#### EC Keys (for ES* algorithms)
```bash
# For ES256 (P-256 curve)
python manage.py createeckey --curve P-256

# For ES384 (P-384 curve)
python manage.py createeckey --curve P-384

# For ES512 (P-521 curve)
python manage.py createeckey --curve P-521
```

### Configuring Clients

#### Setting Signing Algorithms

In the Django admin or programmatically:

```python
from oidc_provider.models import Client

# Configure client with ES256 for ID tokens and RS256 for access tokens
client = Client.objects.get(client_id='your-client-id')
client.jwt_alg = 'ES256'  # ID token algorithm
client.access_token_jwt_alg = 'RS256'  # Access token algorithm
client.save()
```

#### Enabling Token Encryption

```python
# Enable ID token encryption with RSA-OAEP and AES-128-GCM
client.id_token_encrypted_response_alg = 'RSA-OAEP'
client.id_token_encrypted_response_enc = 'A128GCM'

# Enable access token encryption
client.access_token_encrypted_response_alg = 'RSA-OAEP'
client.access_token_encrypted_response_enc = 'A128GCM'

client.save()
```

### Discovery Endpoint Updates

The provider's discovery endpoint (`/.well-known/openid-configuration`) now advertises:

- `id_token_signing_alg_values_supported` - All supported signing algorithms
- `token_endpoint_auth_signing_alg_values_supported` - Token endpoint auth algorithms
- `id_token_encryption_alg_values_supported` - ID token encryption algorithms
- `id_token_encryption_enc_values_supported` - ID token content encryption algorithms

### JWK Endpoint Updates

The JWKS endpoint (`/jwks`) now includes:
- RSA public keys (for RS*, PS* algorithms)
- EC public keys (for ES* algorithms) with proper curve parameters

Example EC key in JWKS:
```json
{
  "keys": [
    {
      "kty": "EC",
      "alg": "ES256",
      "use": "sig",
      "kid": "abc123...",
      "crv": "P-256",
      "x": "base64url_encoded_x_coordinate",
      "y": "base64url_encoded_y_coordinate"
    }
  ]
}
```

## Migration

To apply these changes to an existing installation:

```bash
python manage.py migrate oidc_provider
```

This will:
1. Update the `Client` model with new algorithm and encryption fields
2. Create the `ECKey` model table
3. Expand algorithm choices for existing clients

## Security Considerations

1. **Algorithm Selection**: 
   - Use ES256/ES384/ES512 for better performance and smaller key sizes
   - Use RS256/RS384/RS512 for broader compatibility
   - Avoid HS* algorithms for public clients

2. **Encryption**:
   - Enable encryption when tokens contain sensitive information
   - Use RSA-OAEP-256 or ECDH-ES for key management when possible
   - Use GCM-based content encryption for better performance

3. **Key Management**:
   - Rotate keys periodically
   - Store private keys securely
   - Use separate keys for signing and encryption when possible

## Backward Compatibility

All changes are backward compatible:
- Existing clients continue to work with their configured algorithms
- Default algorithm remains RS256
- Encryption is optional and disabled by default
- Access token algorithm falls back to ID token algorithm if not specified

## Examples

### Example 1: High-Security Client with ES384 and Encryption

```python
client = Client.objects.create(
    name='High Security App',
    client_type='confidential',
    jwt_alg='ES384',
    access_token_jwt_alg='ES384',
    id_token_encrypted_response_alg='ECDH-ES+A256KW',
    id_token_encrypted_response_enc='A256GCM',
    access_token_encrypted_response_alg='ECDH-ES+A256KW',
    access_token_encrypted_response_enc='A256GCM',
)
```

### Example 2: Performance-Optimized Client with ES256

```python
client = Client.objects.create(
    name='Performance App',
    client_type='public',
    jwt_alg='ES256',
    access_token_jwt_alg='ES256',
    # No encryption for better performance
)
```

### Example 3: Legacy-Compatible Client with RS256

```python
client = Client.objects.create(
    name='Legacy App',
    client_type='confidential',
    jwt_alg='RS256',  # Widely supported
    access_token_jwt_alg='RS256',
)
```

## Testing

To verify the new features are working:

1. Create test keys:
```bash
python manage.py creatersakey
python manage.py createeckey --curve P-256
```

2. Configure a test client with modern algorithms

3. Request tokens and verify:
   - JWT headers contain the correct `alg` value
   - Encrypted tokens are in JWE compact serialization format
   - JWKS endpoint includes all key types

## Dependencies

The modernization uses existing dependencies:
- `pyjwkest>=1.3.0` - JWT/JWE handling
- `pycryptodomex` - Cryptographic operations for RSA and EC keys

No additional dependencies are required.

## Troubleshooting

### "You must add at least one EC Key" Error
- Create an EC key with the appropriate curve for your algorithm:
  - ES256 → P-256
  - ES384 → P-384
  - ES512 → P-521

### Encryption Not Working
- Verify both `alg` and `enc` fields are set
- Ensure appropriate keys exist for the encryption algorithm
- Check that encryption keys are properly formatted PEM

### JWKS Endpoint Issues
- Verify keys are properly imported
- Check key format (PEM for both RSA and EC)
- Review server logs for key export errors
