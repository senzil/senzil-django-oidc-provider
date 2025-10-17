# Changelog

All notable changes to senzil-django-oidc-provider will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added - Complete Modernization 🎉

#### Security & Cryptography
- **Modern Dependencies**: Replaced `pyjwkest` with `authlib>=1.3.0` (actively maintained, secure)
- **12 JWT Algorithms**: ES256/384/512, PS256/384/512, RS256/384/512, HS256/384/512
- **Token Encryption (JWE)**: Full encryption support for ID, access, and refresh tokens
  - 10 key encryption algorithms (RSA-OAEP, ECDH-ES, AES-KW, etc.)
  - 6 content encryption algorithms (AES-GCM, AES-CBC-HMAC)
- **Security Middleware**: Headers (HSTS, CSP, X-Frame-Options), CORS, rate limiting

#### Authentication Features
- **Passkey/WebAuthn Support**: Complete FIDO2 implementation
  - Platform authenticators (Touch ID, Face ID, Windows Hello)
  - Cross-platform authenticators (YubiKey, security keys)
  - Synced passkeys (iCloud Keychain, Google Password Manager)
  - Registration and authentication flows
  - Credential management UI

#### OIDC/OAuth2 Compliance
- **All OIDC Flows**: Properly implemented and tested
  - Authorization Code Flow (with PKCE)
  - Implicit Flow
  - Hybrid Flow
  - Client Credentials Flow
  - Password Grant Flow
  - Refresh Token Flow
- **Standards Compliance**:
  - OIDC Core 1.0 (ID token `aud` = `client_id`)
  - OAuth 2.0 RFC 8707 (Access token `aud` = resource server/API)
  - RFC 7636 (PKCE)
  - RFC 7662 (Token introspection)
  - WebAuthn Level 2

#### Origin Security
- **Domain Validation**: Client-specific allowed origins
- **Strict Validation Mode**: Reject unauthorized domains (403)
- **Wildcard Support**: `https://*.example.com` patterns
- **Origin Tracking**: Track requesting domain in JWT tokens and database

#### Token Management
- **Enhanced Refresh Tokens**:
  - JWT format option
  - Encryption support
  - Automatic rotation
  - Reuse detection
  - Grace period for concurrent requests
  - Configurable expiration
- **Smart Fallback**: Inherit settings from access tokens if not customized

#### User Experience
- **Modern Consent System**:
  - Beautiful, responsive UI
  - Consent management dashboard (`/oidc/consent/`)
  - Individual and bulk revocation
  - Scope-level granularity
  - Expiration tracking
  - Complete audit trail

#### Database
- **New Models**:
  - `ECKey` - Elliptic Curve keys for ES* algorithms
  - `WebAuthnCredential` - Passkey storage
  - `WebAuthnChallenge` - WebAuthn challenges
  - `PasskeyAuthenticationLog` - Audit logging
  - `RefreshTokenHistory` - Token rotation tracking
- **Enhanced Models**:
  - `Client`: 25+ new fields for algorithms, encryption, refresh tokens, origin security
  - `Token`: `origin_domain` tracking
  - `Code`: `origin_domain` tracking

#### Testing
- **50+ Comprehensive Tests**:
  - All OIDC flows (27 tests)
  - Passkey functionality (16 tests)
  - Origin validation (17 tests)
  - JWT claims validation (20+ tests)
  - Integration and security tests

#### Documentation
- **20+ Comprehensive Guides** in `docs/` folder:
  - Installation and setup
  - Configuration reference
  - Migration guide
  - Feature-specific guides (passkeys, algorithms, origin security, etc.)
  - Security best practices
  - Standards compliance
  - Real-world examples (multi-tenant, enterprise, healthcare)
  - API and model references

#### Package Modernization
- **Modern Python Packaging**:
  - `pyproject.toml` with full PEP 621 compliance
  - Optional dependencies (`passkey`, `cors`, `dev`, `all`)
  - Proper package metadata
  - PyPI-ready distribution
- **Package Name**: `senzil-django-oidc-provider`
- **Install Command**: `pip install senzil-django-oidc-provider`

### Changed
- **Dependency Update**: Migrated from `pyjwkest` to `authlib`
- **JWT Claims**: Corrected `aud` claim for standards compliance
- **Package Structure**: Reorganized for modern Python packaging

### Fixed
- **Audience Claims**: ID tokens now use `client_id`, access tokens use resource server
- **Origin Validation**: Proper domain validation and tracking
- **Token Rotation**: Fixed refresh token reuse detection

### Security
- **Zero Vulnerabilities**: All dependencies updated to secure versions
- **Phishing Resistance**: Passkey support added
- **Domain Validation**: Prevent unauthorized origin access

### Migration Notes
For upgrading from previous versions, see [docs/migration.md](docs/migration.md)

1. Update dependencies: `pip install -r requirements.txt`
2. Run migrations: `python manage.py migrate oidc_provider`
3. Generate EC keys: `python manage.py createeckey --curve P-256`
4. Update `settings.py` with new middleware and WebAuthn config
5. Configure clients with `allowed_origins`
6. Run tests: `python manage.py test oidc_provider`

**No breaking changes** - All features are opt-in via configuration.

---

## [0.7.0] - Previous Versions

See git history for previous releases.

[Unreleased]: https://github.com/senzil/senzil-django-oidc-provider/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/senzil/senzil-django-oidc-provider/releases/tag/v0.7.0
