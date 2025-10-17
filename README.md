# Django OIDC Provider - Modernized

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Django](https://img.shields.io/badge/django-3.2+-green.svg)](https://www.djangoproject.com/)
[![OIDC](https://img.shields.io/badge/OIDC-Core%201.0-blue)](https://openid.net/specs/openid-connect-core-1_0.html)
[![OAuth2](https://img.shields.io/badge/OAuth2-RFC%206749-blue)](https://tools.ietf.org/html/rfc6749)

A complete, production-ready OpenID Connect Provider implementation for Django with modern security features.

## ✨ Features

- 🔐 **Passkeys (WebAuthn/FIDO2)** - Passwordless authentication like Google, Microsoft, Apple
- 🔒 **12 JWT Algorithms** - ES256/384/512, PS256/384/512, RS384/512, HS384/512
- 🔐 **Token Encryption** - Full JWE support for ID, access, and refresh tokens
- ✅ **All OIDC Flows** - Authorization Code, Implicit, Hybrid, Client Credentials, Password, Refresh
- 🌍 **Origin Security** - Domain allowlist, validation, and tracking
- 🔄 **Token Rotation** - Automatic refresh token rotation with reuse detection
- 👥 **Modern Consent UI** - Beautiful, responsive consent management
- ✅ **Standards Compliant** - OIDC Core 1.0, OAuth 2.0, WebAuthn Level 2
- 🧪 **Fully Tested** - 50+ comprehensive tests

## Quick Start

### Installation

```bash
pip install django-oidc-provider
```

### Setup

```bash
# Add to INSTALLED_APPS
INSTALLED_APPS = ['oidc_provider', ...]

# Run migrations
python manage.py migrate oidc_provider

# Generate keys
python manage.py creatersakey
python manage.py createeckey --curve P-256
```

### Configure

```python
# settings.py

MIDDLEWARE = [
    # ...
    'oidc_provider.middleware_origin.OriginTrackingMiddleware',
    'oidc_provider.middleware_origin.OriginValidationMiddleware',
]

# WebAuthn (for passkeys)
WEBAUTHN_RP_ID = 'your-domain.com'
WEBAUTHN_RP_NAME = 'Your App'
WEBAUTHN_RP_ORIGIN = 'https://your-domain.com'

# API Audience
def api_audience(client, request=None):
    return "https://api.your-domain.com"

OIDC_TOKEN_JWT_AUD = 'myapp.utils.api_audience'
```

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

## Documentation

**Complete documentation available in the [`docs/`](docs/) folder:**

- [Installation & Setup](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [Migration Guide](docs/migration.md)
- [All OIDC Flows](docs/oidc-flows.md)
- [Passkey Support](docs/passkeys.md)
- [Origin Security](docs/origin-security.md)
- [Security Guide](docs/security.md)
- [Customization](docs/customization.md)

## What's New

### Modern Security
- ✅ 12 JWT algorithms (ES*, PS*, RS*, HS*)
- ✅ Token encryption (JWE)
- ✅ Passkey/WebAuthn support
- ✅ Origin domain validation

### Enhanced Features
- ✅ Refresh token rotation
- ✅ Modern consent UI
- ✅ All OIDC flows tested
- ✅ Standards-compliant claims

### Developer Experience
- ✅ 50+ comprehensive tests
- ✅ 20+ documentation guides
- ✅ Real-world examples
- ✅ Easy customization

## Example: Authorization Code Flow

```python
# 1. Authorization Request
GET /oidc/authorize/?
  client_id=YOUR_CLIENT_ID
  &response_type=code
  &redirect_uri=https://yourapp.com/callback
  &scope=openid+profile+email
  &state=random_state

# 2. Token Exchange
POST /oidc/token/
  grant_type=authorization_code
  &code=CODE
  &client_id=YOUR_CLIENT_ID
  &client_secret=SECRET
  &redirect_uri=https://yourapp.com/callback

# Response:
{
  "access_token": "...",
  "id_token": "...",
  "refresh_token": "...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

## Testing

```bash
# Run all tests
python manage.py test oidc_provider

# Specific test suites
python manage.py test oidc_provider.tests.test_all_flows
python manage.py test oidc_provider.tests.test_passkey
python manage.py test oidc_provider.tests.test_origin_validation
```

## Standards Compliance

- ✅ **OIDC Core 1.0** - Full implementation
- ✅ **OAuth 2.0 (RFC 6749)** - All grant types
- ✅ **PKCE (RFC 7636)** - Security for public clients
- ✅ **WebAuthn Level 2** - Passkey support
- ✅ **JWT (RFC 7519)** - Proper claims
- ✅ **Resource Indicators (RFC 8707)** - Access token audience

## Security

- 🔒 Modern cryptography (ES256, PS256)
- 🔐 Token encryption (AES-256-GCM)
- 🔑 Passkey support (phishing-resistant)
- 🌍 Origin validation (domain allowlist)
- 🔄 Token rotation (prevent theft)
- 📊 Complete audit trail

## License

MIT License - See [LICENSE](LICENSE) file

## Contributing

Contributions welcome! Please see documentation for customization patterns.

## Support

- **Documentation:** [docs/](docs/)
- **Issues:** GitHub issues
- **Security:** See [Security Guide](docs/security.md)

## Credits

Built with ❤️ for the Django community.

Modernization includes passkey support, modern algorithms, token encryption, origin security, and comprehensive testing.

---

**Get started:** [Installation Guide](docs/installation.md)  
**Full changes:** [IMPLEMENTATION_CHANGES.md](IMPLEMENTATION_CHANGES.md)  
**Complete guide:** [MODERNIZATION.md](MODERNIZATION.md)
