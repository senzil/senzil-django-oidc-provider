# Upgrade Guide - Modern OIDC Provider

This guide walks you through upgrading your OIDC provider to use modern dependencies, enhanced security, and better user consent management.

## What's New

### 🔒 Security & Dependencies
- ✅ Replaced outdated `pyjwkest` with modern `authlib`
- ✅ Updated to Python 3.8+ and Django 3.2+
- ✅ Modern cryptography libraries with no known vulnerabilities
- ✅ Security headers middleware
- ✅ CORS configuration
- ✅ Rate limiting support

### 🔐 Token Algorithms & Encryption
- ✅ Extended JWT algorithms: ES256, ES384, ES512, PS256, PS384, PS512
- ✅ Full JWE (encryption) support for tokens
- ✅ Separate algorithms for ID and access tokens
- ✅ EC key support

### 👤 Enhanced User Consent
- ✅ Modern, beautiful consent UI
- ✅ Consent management dashboard
- ✅ Consent revocation
- ✅ Granular scope-level permissions
- ✅ Consent expiration tracking

### 🔄 OIDC Flow Support
- ✅ All flows properly implemented
- ✅ PKCE support
- ✅ Session management
- ✅ Third-party app integration ready

## Prerequisites

- Python 3.8 or higher
- Django 3.2 or higher
- PostgreSQL/MySQL (recommended) or SQLite

## Step-by-Step Upgrade

### 1. Backup Your Data

```bash
# Backup database
python manage.py dumpdata oidc_provider > oidc_backup.json

# Backup your keys
python manage.py dumpdata oidc_provider.RSAKey > keys_backup.json
```

### 2. Update Dependencies

```bash
# Install new dependencies
pip install -r requirements.txt

# Or manually
pip install Django>=3.2 authlib>=1.3.0 cryptography>=41.0.0 pycryptodomex>=3.19.0
```

### 3. Update Settings

Add to your `settings.py`:

```python
# OIDC Provider Settings
INSTALLED_APPS = [
    # ... your apps ...
    'oidc_provider',
]

# Security Middleware (add these)
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    # ... other middleware ...
    'oidc_provider.middleware_security.OIDCSecurityHeadersMiddleware',
    'oidc_provider.middleware_security.OIDCCORSMiddleware',
]

# HTTPS Settings (production)
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

# OIDC Configuration
OIDC_USERINFO = 'path.to.your.userinfo.function'
OIDC_IDTOKEN_SUB_GENERATOR = 'path.to.your.sub.generator'
OIDC_IDTOKEN_EXPIRE = 3600  # 1 hour
OIDC_TOKEN_EXPIRE = 3600    # 1 hour
OIDC_CODE_EXPIRE = 600      # 10 minutes

# Optional: Enable session management
OIDC_SESSION_MANAGEMENT_ENABLE = True

# Optional: CORS allowed origins
OIDC_CORS_ALLOWED_ORIGINS = [
    'https://your-app.com',
]
```

### 4. Run Migrations

```bash
# Apply new migrations
python manage.py migrate oidc_provider
```

This will:
- Add new algorithm choices
- Create EC key model
- Add encryption fields to Client model
- Add consent management fields

### 5. Update URL Configuration

Add consent management URLs (optional but recommended):

```python
# urls.py
from django.urls import path, include

urlpatterns = [
    # ... your URLs ...
    path('oidc/', include('oidc_provider.urls', namespace='oidc_provider')),
]
```

The consent management URLs will be available at:
- `/oidc/consent/` - List all consents
- `/oidc/consent/<id>/` - View consent details
- `/oidc/consent/<id>/revoke/` - Revoke consent

### 6. Update Templates (Optional)

Use the new modern consent template:

```python
# settings.py
OIDC_TEMPLATES = {
    'authorize': 'oidc_provider/consent.html',  # New modern UI
    'error': 'oidc_provider/error.html',
}
```

Or customize your own based on the new template.

### 7. Generate New Keys (Optional)

Generate EC keys for modern algorithms:

```bash
# For ES256
python manage.py createeckey --curve P-256

# For ES384
python manage.py createeckey --curve P-384

# For ES512
python manage.py createeckey --curve P-521
```

### 8. Update Client Configurations

Update your clients to use modern algorithms:

```python
from oidc_provider.models import Client

# Option 1: Via Django shell
client = Client.objects.get(client_id='your-client-id')
client.jwt_alg = 'ES256'  # Use EC algorithm
client.access_token_jwt_alg = 'ES256'
client.save()

# Option 2: Via Django admin
# Go to /admin/oidc_provider/client/ and update
```

### 9. Enable Token Encryption (Optional)

For sensitive data:

```python
client = Client.objects.get(client_id='your-client-id')

# ID Token encryption
client.id_token_encrypted_response_alg = 'RSA-OAEP'
client.id_token_encrypted_response_enc = 'A128GCM'

# Access Token encryption
client.access_token_encrypted_response_alg = 'RSA-OAEP'
client.access_token_encrypted_response_enc = 'A128GCM'

client.save()
```

## Migration Strategies

### Strategy 1: Gradual Migration (Recommended)

1. **Phase 1: Update Infrastructure**
   - Update dependencies
   - Run migrations
   - Keep existing algorithms

2. **Phase 2: Add New Keys**
   - Generate EC keys
   - Test with new test client

3. **Phase 3: Migrate Clients**
   - Update one client at a time
   - Monitor for issues
   - Rollback if needed

4. **Phase 4: Enable Advanced Features**
   - Enable encryption
   - Update consent UI
   - Add security middleware

### Strategy 2: Quick Migration

For new deployments or non-critical systems:

```bash
# Install, migrate, configure
pip install -r requirements.txt
python manage.py migrate
python manage.py createeckey --curve P-256
python manage.py creatersakey

# Update settings and deploy
```

## Compatibility Notes

### Backward Compatibility

✅ **Fully backward compatible:**
- Existing clients continue to work
- HS256, RS256 still supported
- No breaking changes to API
- Old tokens remain valid until expiration

### Breaking Changes

❌ **None** - All changes are additive

⚠️ **Deprecations to note:**
- `pyjwkest` replaced with `authlib` (internal change)
- Python 2.7 no longer supported
- Django < 3.2 not recommended

## Testing Your Upgrade

### 1. Test Authorization Flow

```bash
# Test authorization endpoint
curl "https://your-idp.com/authorize?response_type=code&client_id=test&redirect_uri=http://localhost/callback&scope=openid"
```

### 2. Test Token Endpoint

```bash
# Test token exchange
curl -X POST https://your-idp.com/token \
  -d grant_type=authorization_code \
  -d code=AUTH_CODE \
  -d client_id=test \
  -d client_secret=secret \
  -d redirect_uri=http://localhost/callback
```

### 3. Test JWKS Endpoint

```bash
# Verify JWKS includes all keys
curl https://your-idp.com/jwks
```

### 4. Test Consent Management

1. Visit `/oidc/consent/` as logged-in user
2. Verify consents are listed
3. Test consent revocation

### 5. Test New Algorithms

```python
# Create test client with ES256
from oidc_provider.models import Client

test_client = Client.objects.create(
    name='Test ES256',
    client_type='confidential',
    jwt_alg='ES256',
    response_types=['code'],
)

# Test token generation
# ... perform auth flow ...
# Verify JWT header contains: "alg": "ES256"
```

## Troubleshooting

### Issue: Migration Fails

```bash
# Check migration status
python manage.py showmigrations oidc_provider

# Fake migration if needed (only if you've manually applied changes)
python manage.py migrate oidc_provider 0029 --fake
```

### Issue: "No module named authlib"

```bash
# Install authlib
pip install authlib>=1.3.0
```

### Issue: Old Tokens Not Working

This is expected if:
- You changed client algorithm
- You deleted old keys

Solution:
- Keep old keys during migration
- Set grace period for key rotation
- Communicate token expiration to users

### Issue: Consent UI Not Loading

Check template configuration:

```python
# settings.py
OIDC_TEMPLATES = {
    'authorize': 'oidc_provider/consent.html',
    'error': 'oidc_provider/error.html',
}
```

Ensure templates are in the correct location.

### Issue: CORS Errors

```python
# settings.py
OIDC_CORS_ALLOWED_ORIGINS = [
    'https://your-frontend-app.com',
    # Add your origins
]

# Or use middleware
MIDDLEWARE = [
    # ...
    'oidc_provider.middleware_security.OIDCCORSMiddleware',
]
```

## Rollback Plan

If you need to rollback:

### 1. Restore Database

```bash
# Restore from backup
python manage.py loaddata oidc_backup.json
```

### 2. Revert Dependencies

```bash
# Reinstall old dependencies
pip install pyjwkest==1.4.2
```

### 3. Reverse Migrations

```bash
# Rollback migrations
python manage.py migrate oidc_provider 0028
```

### 4. Restart Services

```bash
# Restart your application
systemctl restart gunicorn
# or your deployment method
```

## Post-Upgrade Checklist

- [ ] All migrations applied successfully
- [ ] Dependencies updated
- [ ] Security middleware enabled
- [ ] Test client working with authorization flow
- [ ] JWKS endpoint returning all keys
- [ ] Consent management accessible
- [ ] Monitoring and logging configured
- [ ] Security headers present in responses
- [ ] HTTPS enforced in production
- [ ] Documentation updated for your team

## Next Steps

1. **Review Security Guide**: See `SECURITY_GUIDE.md`
2. **Configure Third-Party Apps**: See `OIDC_FLOWS_GUIDE.md`
3. **Optimize Performance**: Review caching and database indexes
4. **Set Up Monitoring**: Configure logging and alerts
5. **Plan Key Rotation**: Schedule regular key updates

## Support

For issues or questions:
- Check documentation: `MODERNIZATION.md`, `OIDC_FLOWS_GUIDE.md`, `SECURITY_GUIDE.md`
- Review examples in the repository
- Open an issue on GitHub

## Version History

### v2.0.0 (Current)
- Modern dependencies (authlib)
- Extended algorithms
- Token encryption
- Enhanced consent management
- Security improvements

### v1.x (Legacy)
- Basic OIDC support
- HS256, RS256 algorithms
- pyjwkest dependency

---

**Congratulations!** 🎉 Your OIDC provider is now modernized with state-of-the-art security and features.
