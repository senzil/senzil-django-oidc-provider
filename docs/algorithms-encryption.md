# Token Algorithms & Encryption

Complete guide to JWT signing algorithms and JWE token encryption.

## JWT Signing Algorithms

### Available Algorithms (12 total)

**Elliptic Curve (Best Performance):**
- `ES256` - ECDSA using P-256 and SHA-256 ⭐ Recommended
- `ES384` - ECDSA using P-384 and SHA-384
- `ES512` - ECDSA using P-521 and SHA-512

**RSA-PSS (Enhanced Security):**
- `PS256` - RSASSA-PSS using SHA-256
- `PS384` - RSASSA-PSS using SHA-384
- `PS512` - RSASSA-PSS using SHA-512

**RSA (Widely Supported):**
- `RS256` - RSASSA-PKCS1-v1_5 using SHA-256
- `RS384` - RSASSA-PKCS1-v1_5 using SHA-384
- `RS512` - RSASSA-PKCS1-v1_5 using SHA-512

**HMAC (Symmetric):**
- `HS256` - HMAC using SHA-256
- `HS384` - HMAC using SHA-384
- `HS512` - HMAC using SHA-512

### Choosing an Algorithm

**Recommended for production:**
- `ES256` - Best balance of security and performance
- `PS256` - If RSA required with better security
- `RS256` - Maximum compatibility

### Configuration

```python
client = Client.objects.create(
    jwt_alg='ES256',  # ID token algorithm
    access_token_jwt_alg='ES256',  # Access token
    refresh_token_jwt_alg='ES256',  # Refresh token
)
```

## Token Encryption (JWE)

### Encryption Algorithms (alg)

- `RSA-OAEP` - RSA with OAEP padding ⭐ Recommended
- `RSA-OAEP-256` - RSA-OAEP with SHA-256
- `A128KW` - AES Key Wrap with 128-bit key
- `A192KW` - AES Key Wrap with 192-bit key
- `A256KW` - AES Key Wrap with 256-bit key
- `dir` - Direct encryption
- `ECDH-ES` - Elliptic Curve Diffie-Hellman
- `ECDH-ES+A128KW` - ECDH-ES + AES128-KW
- `ECDH-ES+A192KW` - ECDH-ES + AES192-KW
- `ECDH-ES+A256KW` - ECDH-ES + AES256-KW

### Content Encryption (enc)

- `A128GCM` - AES-GCM with 128-bit key
- `A192GCM` - AES-GCM with 192-bit key
- `A256GCM` - AES-GCM with 256-bit key ⭐ Recommended
- `A128CBC-HS256` - AES-CBC + HMAC-SHA256
- `A192CBC-HS384` - AES-CBC + HMAC-SHA384
- `A256CBC-HS512` - AES-CBC + HMAC-SHA512

### Configuration

```python
client = Client.objects.create(
    # ID token encryption
    id_token_encrypted_response_alg='RSA-OAEP',
    id_token_encrypted_response_enc='A256GCM',
    
    # Access token encryption
    access_token_encrypted_response_alg='RSA-OAEP',
    access_token_encrypted_response_enc='A256GCM',
    
    # Refresh token encryption
    refresh_token_encrypted_response_alg='RSA-OAEP',
    refresh_token_encrypted_response_enc='A256GCM',
)
```

## Key Management

### Generate Keys

```bash
# RSA keys (2048-bit or 4096-bit)
python manage.py creatersakey

# EC keys
python manage.py createeckey --curve P-256  # For ES256
python manage.py createeckey --curve P-384  # For ES384
python manage.py createeckey --curve P-521  # For ES512
```

### Key Rotation

```python
# Generate new key
python manage.py creatersakey

# Old keys remain valid until tokens expire
# New tokens use new key
```

## Examples

### Basic Setup (ES256)

```python
client = Client.objects.create(
    jwt_alg='ES256',  # Fast, secure
)
```

### Maximum Security

```python
client = Client.objects.create(
    jwt_alg='ES384',  # Strong algorithm
    
    # Encrypt all tokens
    id_token_encrypted_response_alg='RSA-OAEP-256',
    id_token_encrypted_response_enc='A256GCM',
    access_token_encrypted_response_alg='RSA-OAEP-256',
    access_token_encrypted_response_enc='A256GCM',
    refresh_token_encrypted_response_alg='RSA-OAEP-256',
    refresh_token_encrypted_response_enc='A256GCM',
)
```

### Maximum Compatibility

```python
client = Client.objects.create(
    jwt_alg='RS256',  # Widely supported
    # No encryption (better compatibility)
)
```

## Summary

Choose the right combination for your needs:
- **Performance:** ES256 without encryption
- **Security:** ES384 or PS384 with A256GCM encryption
- **Compatibility:** RS256 without encryption

See [Configuration Guide](configuration.md) for complete settings.
