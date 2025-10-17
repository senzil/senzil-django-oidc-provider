# Security Configuration Guide

This guide covers security best practices and configuration for the OIDC provider.

## Table of Contents
- [Security Middleware](#security-middleware)
- [HTTPS Configuration](#https-configuration)
- [Client Security](#client-security)
- [Token Security](#token-security)
- [Rate Limiting](#rate-limiting)
- [CORS Configuration](#cors-configuration)
- [Security Headers](#security-headers)
- [Audit and Monitoring](#audit-and-monitoring)

---

## Security Middleware

### Enable Security Middleware

Add to your Django `settings.py`:

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    # ... other middleware ...
    'oidc_provider.middleware_security.OIDCSecurityHeadersMiddleware',
    'oidc_provider.middleware_security.OIDCCORSMiddleware',
    'oidc_provider.middleware_security.OIDCRateLimitMiddleware',  # Optional
]
```

### Security Headers Middleware
Automatically adds:
- `X-Frame-Options: DENY` - Prevents clickjacking
- `X-Content-Type-Options: nosniff` - Prevents MIME sniffing
- `X-XSS-Protection: 1; mode=block` - XSS protection
- `Strict-Transport-Security` - Forces HTTPS
- `Content-Security-Policy` - Restricts frame ancestors
- `Referrer-Policy` - Controls referrer information
- `Permissions-Policy` - Restricts browser features

---

## HTTPS Configuration

### Django HTTPS Settings

```python
# Force HTTPS in production
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# HSTS settings
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Cookie security
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'
```

### Web Server Configuration

#### Nginx
```nginx
server {
    listen 443 ssl http2;
    server_name your-idp.com;
    
    # SSL Configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    # Proxy to Django
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## Client Security

### Confidential Clients

For backend applications:

```python
from oidc_provider.models import Client

client = Client.objects.create(
    name='Backend App',
    client_type='confidential',
    # Strong, random client secret
    client_secret='<generated-secure-secret>',
    response_types=['code'],  # Authorization Code Flow only
    jwt_alg='RS256',  # Asymmetric signing
)
```

**Best Practices:**
- ✅ Use long, random client secrets (minimum 32 characters)
- ✅ Rotate client secrets regularly
- ✅ Store secrets securely (environment variables, secret managers)
- ✅ Use Authorization Code Flow
- ✅ Require PKCE even for confidential clients

### Public Clients

For SPAs and mobile apps:

```python
client = Client.objects.create(
    name='SPA App',
    client_type='public',
    # No client secret for public clients
    response_types=['code'],  # Authorization Code Flow with PKCE
    jwt_alg='RS256',
)
```

**Best Practices:**
- ✅ Always use PKCE
- ✅ Use Authorization Code Flow (not Implicit)
- ✅ Limit redirect URIs strictly
- ✅ Use refresh token rotation
- ✅ Short-lived access tokens

### Redirect URI Validation

```python
# Strict redirect URI configuration
client.redirect_uris = [
    'https://app.example.com/callback',
    'https://app.example.com/auth/callback',
    # No wildcards!
]
client.save()
```

**Security Rules:**
- ❌ Never use wildcards in redirect URIs
- ❌ Never allow http:// in production (except localhost for dev)
- ✅ Use exact URL matching
- ✅ Validate scheme, host, and path

---

## Token Security

### Token Lifetime Configuration

```python
# settings.py

# Authorization code (short-lived)
OIDC_CODE_EXPIRE = 600  # 10 minutes

# ID token (short to medium)
OIDC_IDTOKEN_EXPIRE = 3600  # 1 hour

# Access token (short-lived)
OIDC_TOKEN_EXPIRE = 3600  # 1 hour

# Refresh token handled by token rotation
```

### Token Encryption

Enable encryption for sensitive data:

```python
client = Client.objects.create(
    name='High Security App',
    # ID Token encryption
    id_token_encrypted_response_alg='RSA-OAEP',
    id_token_encrypted_response_enc='A256GCM',
    # Access Token encryption
    access_token_encrypted_response_alg='RSA-OAEP',
    access_token_encrypted_response_enc='A256GCM',
)
```

### Signing Algorithms

**Recommended Algorithm Hierarchy:**
1. **ES256/ES384** - Best security and performance
2. **RS256/RS384** - Good compatibility
3. **PS256/PS384** - Enhanced RSA security
4. **HS256** - Only for confidential clients

```python
# Recommended: Elliptic Curve
client.jwt_alg = 'ES256'
client.access_token_jwt_alg = 'ES256'

# Good: RSA
client.jwt_alg = 'RS256'

# Avoid: Symmetric (only for trusted scenarios)
client.jwt_alg = 'HS256'  # Requires secure client_secret
```

### Token Binding

Implement token binding to prevent token theft:

```python
# Custom token processing hook
def token_binding_hook(token_dict, user=None, token=None, request=None):
    if request:
        # Bind token to client IP or device fingerprint
        token_dict['client_ip'] = request.META.get('REMOTE_ADDR')
        # Add device fingerprint
        token_dict['device_id'] = request.META.get('HTTP_USER_AGENT', '')[:100]
    return token_dict

# settings.py
OIDC_IDTOKEN_PROCESSING_HOOK = 'path.to.token_binding_hook'
```

---

## Rate Limiting

### Basic Rate Limiting

Using the included middleware:

```python
# Enabled by default with OIDCRateLimitMiddleware
# Default: 60 requests per minute per client/IP
```

### Advanced Rate Limiting

Use Django Ratelimit:

```bash
pip install django-ratelimit
```

```python
from django_ratelimit.decorators import ratelimit

# In your views or create custom endpoint wrapper
@ratelimit(key='user_or_ip', rate='100/h', method='POST')
def rate_limited_token_endpoint(request):
    # Your token logic
    pass
```

### Per-Client Rate Limits

```python
# In settings.py
OIDC_RATE_LIMITS = {
    'authorize': '60/m',  # 60 per minute
    'token': '30/m',      # 30 per minute
    'userinfo': '100/m',  # 100 per minute
}
```

---

## CORS Configuration

### Configure Allowed Origins

```python
# settings.py

# For public discovery/JWKS endpoints
OIDC_CORS_ALLOWED_ORIGINS = ['*']  # Public endpoints

# For protected endpoints (token, userinfo)
OIDC_CORS_ALLOWED_ORIGINS = [
    'https://app1.example.com',
    'https://app2.example.com',
    # Don't use wildcard for protected endpoints
]
```

### CORS Middleware

The `OIDCCORSMiddleware` handles:
- Preflight requests (OPTIONS)
- CORS headers for allowed origins
- Credentials support for authenticated requests

---

## Security Headers

### Content Security Policy

```python
# settings.py
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_IMG_SRC = ("'self'", "data:", "https:")
CSP_FONT_SRC = ("'self'",)
CSP_CONNECT_SRC = ("'self'",)
CSP_FRAME_ANCESTORS = ("'none'",)  # Prevent clickjacking
```

### Additional Headers

```python
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin'
```

---

## Audit and Monitoring

### Logging Configuration

```python
# settings.py
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/oidc/security.log',
            'maxBytes': 1024 * 1024 * 10,  # 10MB
            'backupCount': 10,
        },
    },
    'loggers': {
        'oidc_provider': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}
```

### Audit Events to Log

Monitor these events:
- ✅ Failed authentication attempts
- ✅ Invalid token requests
- ✅ Client authentication failures
- ✅ Consent grants and revocations
- ✅ Token introspection requests
- ✅ Rate limit violations
- ✅ Invalid redirect URI attempts

### Security Signals

Use Django signals for audit:

```python
from oidc_provider import signals

@receiver(signals.user_accept_consent)
def log_consent_grant(sender, user, client, scope, **kwargs):
    logger.info(f'User {user.id} granted consent to {client.client_id}')

@receiver(signals.user_decline_consent)
def log_consent_decline(sender, user, client, scope, **kwargs):
    logger.warning(f'User {user.id} declined consent to {client.client_id}')
```

---

## Database Security

### Encrypt Sensitive Data

```python
# Use django-encrypted-model-fields
from encrypted_model_fields.fields import EncryptedCharField

class Client(models.Model):
    client_secret = EncryptedCharField(max_length=255)
```

### Secure Key Storage

```python
# Store RSA/EC keys encrypted
class RSAKey(models.Model):
    key = EncryptedTextField()  # Encrypt private keys
```

### Database Permissions

```sql
-- Principle of least privilege
GRANT SELECT, INSERT, UPDATE ON oidc_provider_* TO 'oidc_app'@'localhost';
-- Don't grant DELETE or DROP
```

---

## Key Management

### Key Rotation

```python
# Rotate keys regularly
from oidc_provider.models import RSAKey, ECKey

# Generate new key
new_key = RSAKey.objects.create(...)

# Keep old keys for verification (grace period)
# Delete old keys after grace period
old_keys = RSAKey.objects.filter(created__lt=grace_period_date)
old_keys.delete()
```

### Key Storage Best Practices

1. **Hardware Security Modules (HSM)** - For production
2. **Key Management Services** - AWS KMS, Azure Key Vault, GCP KMS
3. **Encrypted Storage** - Encrypt keys at rest
4. **Access Control** - Limit key access to OIDC service

---

## Checklist for Production

### Before Going Live

- [ ] HTTPS enabled and enforced
- [ ] Security middleware configured
- [ ] Rate limiting implemented
- [ ] CORS properly configured
- [ ] Client secrets are strong and secure
- [ ] Redirect URIs strictly validated
- [ ] Token lifetimes configured appropriately
- [ ] Keys properly managed and rotated
- [ ] Logging and monitoring enabled
- [ ] Security headers configured
- [ ] Database properly secured
- [ ] Regular security audits scheduled
- [ ] Incident response plan in place
- [ ] Backup and recovery tested

### Regular Security Maintenance

- [ ] Review and rotate keys quarterly
- [ ] Audit client configurations monthly
- [ ] Review access logs weekly
- [ ] Update dependencies regularly
- [ ] Security patch management
- [ ] Penetration testing annually
- [ ] Review and update security policies

---

## Vulnerability Reporting

If you discover a security vulnerability:

1. **Don't** open a public issue
2. Email security@example.com
3. Include detailed description
4. We'll respond within 48 hours
5. Coordinated disclosure after fix

---

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OAuth 2.0 Security Best Practices](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)
- [OpenID Connect Security Considerations](https://openid.net/specs/openid-connect-core-1_0.html#Security)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
