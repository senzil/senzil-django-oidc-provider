# Quick Start - Senzil Django OIDC Provider

## 🚀 Installation

```bash
pip install senzil-django-oidc-provider
```

## 📦 Package Information

- **Name:** senzil-django-oidc-provider
- **Version:** 1.0.0
- **PyPI:** https://pypi.org/project/senzil-django-oidc-provider/
- **GitHub:** https://github.com/senzil/senzil-django-oidc-provider

## 🎯 Features

✅ **Modern Security**
- 12 JWT algorithms (ES256/384/512, PS256/384/512, RS256/384/512, HS256/384/512)
- Token encryption (JWE)
- Passkey/WebAuthn support
- Origin domain validation

✅ **Complete OIDC/OAuth2**
- All 6 flows (Authorization Code, Implicit, Hybrid, Client Credentials, Password, Refresh)
- Standards compliant (OIDC Core 1.0, OAuth 2.0)
- PKCE support
- Session management

✅ **Production Ready**
- 50+ comprehensive tests
- 18 documentation guides
- Django 3.2-4.2 support
- Python 3.8-3.12 support

## 📖 Documentation

All documentation is in the `docs/` folder:

- [Installation](docs/installation.md)
- [Configuration](docs/configuration.md)
- [Migration Guide](docs/migration.md)
- [All OIDC Flows](docs/oidc-flows.md)
- [Passkey Support](docs/passkeys.md)
- [Security Guide](docs/security.md)
- [And 12 more guides...](docs/README.md)

## 🔧 Building the Package

See [BUILD_INSTRUCTIONS.md](BUILD_INSTRUCTIONS.md) for complete guide.

```bash
# Install build tools
pip install build twine

# Build package
python -m build

# Check package
twine check dist/*

# Publish to PyPI
twine upload dist/*
```

## 📋 Key Files

- `pyproject.toml` - Modern packaging config
- `setup.py` - Setup script
- `setup.cfg` - Additional config
- `MANIFEST.in` - Package manifest
- `requirements.txt` - Dependencies
- `CHANGELOG.md` - Version history
- `CONTRIBUTING.md` - How to contribute

## 🎉 Ready!

Your package is ready for PyPI distribution!

**Install:** `pip install senzil-django-oidc-provider`
