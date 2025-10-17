# Custom Client Model Merge Guide

## Summary

You want to apply ALL modernization changes from `cursor/update-oidc-provider-for-new-token-algorithms-b2d3` onto `feature/company_oidc_client` which has a custom client model pattern.

## Current Branch Status

**Branch:** `feature/custom-client-model-with-registration`  
**Base:** `origin/feature/company_oidc_client`  
**Target:** Merge all changes from `origin/cursor/update-oidc-provider-for-new-token-algorithms-b2d3`

## What feature/company_oidc_client Has

1. **Custom Client Model Pattern** (like Django's AUTH_USER_MODEL):
   - `AbstractClient` - Abstract base model
   - `Client` - Concrete model inheriting from AbstractClient
   - `get_client_model()` utility function
   - `OIDC_CLIENT_MODEL` setting support
   
2. **Modified Files**:
   - `oidc_provider/models.py` - AbstractClient/Client split
   - `oidc_provider/admin.py` - Uses `get_client_model()`
   - `oidc_provider/lib/utils/common.py` - Has `get_client_model()`

## What Needs to Be Merged

### From cursor branch (ALL modernization):
1. **60+ new/modified files**
2. **All new models**: ECKey, WebAuthnCredential, RefreshTokenHistory, etc.
3. **All new fields on Client/AbstractClient**:
   - Algorithm fields: `access_token_jwt_alg`, `refresh_token_jwt_alg`
   - Encryption fields: `*_encrypted_response_alg`, `*_encrypted_response_enc`
   - Refresh token fields: `refresh_token_format`, `enable_refresh_token_rotation`, etc.
   - Origin security fields: `allowed_origins`, `strict_origin_validation`, etc.
   - Passkey support fields
4. **New methods**: `is_origin_allowed()`, `allowed_origins_list`
5. **All migrations**: 0029, 0030, 0031, 0032
6. **All tests**: test_all_flows, test_passkey, test_origin_validation, etc.
7. **All documentation**: 20+ guides
8. **Dynamic Client Registration**: RFC 7591/7592 implementation
9. **Package modernization**: pyproject.toml, etc.

## Merge Strategy

### Option 1: Manual File-by-File Merge (Recommended)

#### Step 1: Prepare
```bash
git checkout feature/custom-client-model-with-registration
git fetch origin cursor/update-oidc-provider-for-new-token-algorithms-b2d3
```

#### Step 2: Copy All New Files
```bash
# Get list of new files from cursor branch
git diff --name-status origin/feature/company_oidc_client origin/cursor/update-oidc-provider-for-new-token-algorithms-b2d3 | grep "^A"

# Copy each new file
git checkout origin/cursor/update-oidc-provider-for-new-token-algorithms-b2d3 -- <new_file_path>
```

#### Step 3: Merge models.py

**Key principle**: Keep AbstractClient pattern, add all new fields

```python
# In oidc_provider/models.py

# 1. Keep JWT_ALGS extended list (12 algorithms)
JWT_ALGS = [
    ('HS256', 'HS256'), ('HS384', 'HS384'), ('HS512', 'HS512'),
    ('RS256', 'RS256'), ('RS384', 'RS384'), ('RS512', 'RS512'),
    ('ES256', 'ES256'), ('ES384', 'ES384'), ('ES512', 'ES512'),
    ('PS256', 'PS256'), ('PS384', 'PS384'), ('PS512', 'PS512'),
]

# 2. Keep AbstractClient as abstract, ADD new fields:
class AbstractClient(models.Model):
    # ... existing fields ...
    
    # ADD from cursor branch:
    access_token_jwt_alg = models.CharField(...)
    id_token_encrypted_response_alg = models.CharField(...)
    id_token_encrypted_response_enc = models.CharField(...)
    access_token_encrypted_response_alg = models.CharField(...)
    access_token_encrypted_response_enc = models.CharField(...)
    refresh_token_format = models.CharField(...)
    refresh_token_jwt_alg = models.CharField(...)
    refresh_token_encrypted_response_alg = models.CharField(...)
    refresh_token_encrypted_response_enc = models.CharField(...)
    enable_refresh_token_rotation = models.BooleanField(...)
    detect_refresh_token_reuse = models.BooleanField(...)
    refresh_token_grace_period_seconds = models.IntegerField(...)
    refresh_token_expire_seconds = models.IntegerField(...)
    allowed_origins = models.TextField(...)
    strict_origin_validation = models.BooleanField(...)
    include_origin_in_tokens = models.BooleanField(...)
    
    # ADD new methods:
    @property
    def allowed_origins_list(self):
        if not hasattr(self, 'allowed_origins') or not self.allowed_origins:
            return []
        return [origin.strip() for origin in self.allowed_origins.split('\n') if origin.strip()]
    
    def is_origin_allowed(self, origin):
        from oidc_provider.lib.utils.token_origin import validate_origin_for_client
        return validate_origin_for_client(origin, self)
    
    class Meta:
        abstract = True

# 3. Keep concrete Client model:
class Client(AbstractClient):
    # ... existing overrides ...
    
    class Meta:
        verbose_name = _('Client')
        verbose_name_plural = _('Clients')
        db_table = 'oidc_provider_client'
        # Can be swapped:
        swappable = 'OIDC_CLIENT_MODEL'

# 4. Update BaseCodeTokenModel to use get_client_model():
class BaseCodeTokenModel(models.Model):
    client = models.ForeignKey(
        'oidc_provider.Client',  # Or use get_client_model()
        verbose_name=_('Client'),
        on_delete=models.CASCADE
    )
    # ... rest ...

# 5. ADD all new models from cursor:
class ECKey(models.Model): ...
class WebAuthnCredential(models.Model): ...
class WebAuthnChallenge(models.Model): ...
class PasskeyAuthenticationLog(models.Model): ...
class RefreshTokenHistory(models.Model): ...
```

#### Step 4: Merge admin.py

```python
# In oidc_provider/admin.py

from oidc_provider.lib.utils.common import get_client_model
from oidc_provider.models import (
    Code, Token, RSAKey, ECKey, Scope,
    WebAuthnCredential, PasskeyAuthenticationLog  # Add new models
)

class ClientForm(ModelForm):
    class Meta:
        model = get_client_model()  # Use get_client_model()
        exclude = []

@admin.register(get_client_model())
class ClientAdmin(admin.ModelAdmin):
    # ... all fieldsets from cursor branch ...

# Register new models:
@admin.register(ECKey)
class ECKeyAdmin(admin.ModelAdmin): ...

@admin.register(WebAuthnCredential)
class WebAuthnCredentialAdmin(admin.ModelAdmin): ...
```

#### Step 5: Update Other Modified Files

- `oidc_provider/urls.py` - Add all new URL patterns
- `oidc_provider/views.py` - Merge changes
- `oidc_provider/version.py` - Set to 1.0.0
- `setup.py`, `pyproject.toml` - Take from cursor branch
- All other files - Take from cursor branch

#### Step 6: Add All Migrations

```bash
git checkout origin/cursor/update-oidc-provider-for-new-token-algorithms-b2d3 -- \
  oidc_provider/migrations/0029_add_modern_algorithms_and_encryption.py \
  oidc_provider/migrations/0030_add_refresh_token_customization.py \
  oidc_provider/migrations/0031_add_passkey_support.py \
  oidc_provider/migrations/0032_add_allowed_domains.py
```

**Note**: You'll need to adjust migration dependencies to work with your existing migrations.

#### Step 7: Add All Tests and Documentation

```bash
# Tests
git checkout origin/cursor/update-oidc-provider-for-new-token-algorithms-b2d3 -- \
  oidc_provider/tests/

# Documentation
git checkout origin/cursor/update-oidc-provider-for-new-token-algorithms-b2d3 -- \
  docs/ \
  README.md \
  CHANGELOG.md \
  BUILD_INSTRUCTIONS.md \
  CONTRIBUTING.md \
  pyproject.toml \
  setup.cfg \
  requirements.txt
```

### Option 2: Automated Merge Script

```bash
#!/bin/bash
# merge-custom-client.sh

set -e

echo "Merging cursor branch into custom client model branch..."

# 1. Get all new files
git diff --name-status origin/feature/company_oidc_client origin/cursor/update-oidc-provider-for-new-token-algorithms-b2d3 | \
  grep "^A" | cut -f2 | while read file; do
    git checkout origin/cursor/update-oidc-provider-for-new-token-algorithms-b2d3 -- "$file"
done

# 2. Handle modified files manually (listed above)
echo "Please manually merge: models.py, admin.py, urls.py, version.py"
echo "See CUSTOM_CLIENT_MODEL_MERGE_GUIDE.md for details"

# 3. Stage everything
git add .

# 4. Commit
git commit -m "feat: Merge all modernization features with custom client model support

Merged from cursor/update-oidc-provider-for-new-token-algorithms-b2d3

Features added:
- 12 JWT algorithms (ES*, PS*, RS*, HS*)
- Token encryption (JWE)
- Passkey/WebAuthn support
- Dynamic client registration (RFC 7591/7592)
- Origin security and validation
- Enhanced refresh tokens
- Modern consent system
- Complete documentation (20+ guides)
- Modern packaging (pyproject.toml)

Maintained:
- Custom client model pattern (AbstractClient/Client)
- get_client_model() utility
- OIDC_CLIENT_MODEL setting support
"
```

## Testing After Merge

```bash
# 1. Check migrations
python manage.py makemigrations --dry-run --check

# 2. Run tests
python manage.py test oidc_provider

# 3. Test custom client model
# Create a custom client model in your project:
# myapp/models.py
from oidc_provider.models import AbstractClient

class CompanyClient(AbstractClient):
    company = models.ForeignKey('Company', on_delete=models.CASCADE)
    
    class Meta:
        db_table = 'myapp_company_client'

# settings.py
OIDC_CLIENT_MODEL = 'myapp.CompanyClient'

# 4. Verify it works
python manage.py makemigrations
python manage.py migrate
python manage.py creatersakey
python manage.py createeckey --curve P-256
```

## Final Checklist

- [ ] All new files copied
- [ ] models.py merged (AbstractClient + Client pattern preserved)
- [ ] admin.py uses get_client_model()
- [ ] All migrations added and dependencies fixed
- [ ] All tests pass
- [ ] Custom client model can be defined
- [ ] Documentation updated
- [ ] Version set to 1.0.0
- [ ] Dynamic client registration works
- [ ] All OIDC flows work
- [ ] Passkey support works

## Key Files to Manually Merge

1. **oidc_provider/models.py** - Most critical (see details above)
2. **oidc_provider/admin.py** - Use get_client_model()
3. **oidc_provider/urls.py** - Add new URL patterns
4. **oidc_provider/version.py** - Update to 1.0.0

## Summary

The merge preserves the custom client model pattern while adding all modernization features. The key is to:

1. Keep `AbstractClient` as the abstract base with ALL fields
2. Keep `Client` as the concrete swappable model
3. Use `get_client_model()` everywhere instead of importing `Client` directly
4. Add all new models, views, tests, and documentation from cursor branch

This allows users to define custom client models (like `CompanyClient` with a `company` field) while having all the modern OIDC features.

---

**Next Steps**: Follow Option 1 (Manual Merge) step by step, or run the Option 2 script and manually fix the conflicts.
