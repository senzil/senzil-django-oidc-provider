# Django OIDC Provider - Complete Documentation

Welcome to the comprehensive documentation for the modernized Django OIDC Provider.

## 📚 Documentation Index

### Getting Started
- [Installation & Setup](installation.md) - Quick start guide
- [Configuration](configuration.md) - Complete configuration reference
- [Migration Guide](migration.md) - Upgrade from previous versions

### Core Features
- [Token Algorithms & Encryption](algorithms-encryption.md) - JWT algorithms and JWE
- [All OIDC Flows](oidc-flows.md) - Complete flow documentation
- [Passkey Authentication](passkeys.md) - WebAuthn/FIDO2 implementation
- [Origin Security](origin-security.md) - Domain validation and tracking
- [Refresh Tokens](refresh-tokens.md) - Advanced refresh token features
- [User Consent](consent.md) - Consent management system

### Security & Standards
- [Security Guide](security.md) - Security best practices
- [Standards Compliance](standards-compliance.md) - OIDC/OAuth2 compliance
- [JWT Claims](jwt-claims.md) - Required claims implementation

### Customization
- [Customization Guide](customization.md) - How to extend the provider
- [Real-World Examples](examples.md) - Multi-tenant, Enterprise, Healthcare

### API Reference
- [Settings Reference](settings.md) - All configuration options
- [Models Reference](models.md) - Database models
- [Endpoints Reference](endpoints.md) - API endpoints

## 🚀 Quick Links

**New to OIDC Provider?** Start with [Installation & Setup](installation.md)

**Upgrading?** See the [Migration Guide](migration.md)

**Need Examples?** Check [Real-World Examples](examples.md)

**Security Questions?** Read the [Security Guide](security.md)

## 🎯 What's New

This modernized version includes:

- ✅ **12 JWT Algorithms** - ES256/384/512, PS256/384/512, RS384/512, HS384/512
- ✅ **Token Encryption** - Full JWE support for ID, access, and refresh tokens
- ✅ **Passkey Support** - WebAuthn/FIDO2 passwordless authentication
- ✅ **Origin Security** - Domain allowlist and validation
- ✅ **Enhanced Refresh Tokens** - JWT format, rotation, encryption
- ✅ **Modern Consent UI** - Beautiful, responsive consent screens
- ✅ **All OIDC Flows** - Complete implementation and testing
- ✅ **Standards Compliance** - OIDC Core 1.0 and OAuth 2.0

## 📖 Documentation Structure

```
docs/
├── README.md (this file)
├── installation.md          # Setup guide
├── configuration.md         # Configuration reference
├── migration.md            # Upgrade guide
├── algorithms-encryption.md # JWT & JWE
├── oidc-flows.md           # All flows
├── passkeys.md             # Passkey implementation
├── origin-security.md      # Origin validation
├── refresh-tokens.md       # Refresh token features
├── consent.md              # Consent system
├── security.md             # Security guide
├── standards-compliance.md # OIDC/OAuth compliance
├── jwt-claims.md           # JWT claims
├── customization.md        # Extension guide
├── examples.md             # Real-world examples
├── settings.md             # Settings reference
├── models.md               # Models reference
└── endpoints.md            # API endpoints
```

## 🔍 Find What You Need

### By Role

**Developers:**
- [Installation](installation.md) → [Configuration](configuration.md) → [OIDC Flows](oidc-flows.md)

**Security Teams:**
- [Security Guide](security.md) → [Standards Compliance](standards-compliance.md) → [Origin Security](origin-security.md)

**System Architects:**
- [Customization Guide](customization.md) → [Examples](examples.md) → [Models Reference](models.md)

### By Task

**Setting Up:**
1. [Installation & Setup](installation.md)
2. [Configuration](configuration.md)
3. [Security Guide](security.md)

**Adding Passkeys:**
1. [Passkeys Guide](passkeys.md)
2. [Configuration](configuration.md)
3. [Security](security.md)

**Securing Your Provider:**
1. [Security Guide](security.md)
2. [Origin Security](origin-security.md)
3. [Standards Compliance](standards-compliance.md)

**Customizing:**
1. [Customization Guide](customization.md)
2. [Examples](examples.md)
3. [Settings Reference](settings.md)

## 💡 Key Concepts

### Authentication Methods
- **OAuth2/OIDC** - Standard flows (Authorization Code, Implicit, Hybrid, etc.)
- **Passkeys** - WebAuthn/FIDO2 passwordless authentication
- **Session Management** - RP-initiated logout

### Token Types
- **ID Tokens** - User identity information (`aud` = `client_id`)
- **Access Tokens** - API authorization (`aud` = resource server)
- **Refresh Tokens** - Long-lived token renewal

### Security Features
- **Origin Validation** - Domain allowlist
- **Token Encryption** - JWE for sensitive data
- **Token Rotation** - Automatic refresh token rotation
- **Reuse Detection** - Prevent token theft

## 🛠️ Common Tasks

### Configure a Client

```python
from oidc_provider.models import Client

client = Client.objects.create(
    name='My App',
    client_id='myapp',
    client_type='confidential',
    
    # Algorithms
    jwt_alg='ES256',
    access_token_jwt_alg='ES256',
    
    # Security
    allowed_origins='https://app.example.com',
    strict_origin_validation=True,
)
```

See: [Configuration Guide](configuration.md)

### Enable Passkeys

```python
# settings.py
WEBAUTHN_RP_ID = 'your-domain.com'
WEBAUTHN_RP_NAME = 'Your App'
WEBAUTHN_RP_ORIGIN = 'https://your-domain.com'
```

See: [Passkeys Guide](passkeys.md)

### Configure API Audience

```python
# settings.py
def api_audience(client, request=None):
    return "https://api.example.com"

OIDC_TOKEN_JWT_AUD = 'myapp.utils.api_audience'
```

See: [JWT Claims](jwt-claims.md)

## 🧪 Testing

```bash
# Run all tests
python manage.py test oidc_provider

# Specific test suites
python manage.py test oidc_provider.tests.test_all_flows
python manage.py test oidc_provider.tests.test_passkey
python manage.py test oidc_provider.tests.test_origin_validation
```

See: [Testing Guide](testing.md)

## 📞 Support

- **Documentation Issues:** Check the [Migration Guide](migration.md)
- **Security Concerns:** Read the [Security Guide](security.md)
- **Standards Questions:** See [Standards Compliance](standards-compliance.md)

## 🎉 Credits

This modernization includes contributions and improvements for:
- Modern JWT algorithms (ES*, PS*)
- Token encryption (JWE)
- Passkey/WebAuthn support
- Origin security and validation
- Enhanced refresh tokens
- Comprehensive testing

Built with ❤️ for the Django community.
