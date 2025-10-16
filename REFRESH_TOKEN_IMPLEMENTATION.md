# Refresh Token Implementation - Quick Reference

## Summary

✅ **Refresh tokens now have full customization parity with access tokens!**

### Key Features Implemented

1. **JWT Format Support**
   - Opaque UUID (default, backward compatible)
   - JWT with claims (iss, sub, exp, jti, etc.)

2. **Encryption Support**
   - Same encryption options as access tokens
   - Inherits from access token if not specified

3. **Algorithm Customization**
   - Separate algorithm configuration
   - Fallback chain: refresh → access → id token

4. **Token Rotation**
   - Automatic rotation on use
   - Grace period for concurrency
   - Reuse detection

5. **Lifecycle Management**
   - Custom expiration times
   - Token family tracking
   - Automatic revocation

## Files Created

1. `oidc_provider/lib/utils/refresh_token.py` - Core utilities
2. `oidc_provider/migrations/0030_add_refresh_token_customization.py` - Database migration
3. `REFRESH_TOKEN_GUIDE.md` - Complete documentation

## Quick Start

### 1. Run Migration

```bash
python manage.py migrate oidc_provider
```

### 2. Configure Client

```python
from oidc_provider.models import Client

client = Client.objects.get(client_id='your-client')

# Option 1: Use same settings as access token (recommended)
client.refresh_token_format = 'jwt'
# Will automatically use access_token_jwt_alg and encryption

# Option 2: Separate configuration
client.refresh_token_format = 'jwt'
client.refresh_token_jwt_alg = 'ES256'
client.refresh_token_encrypted_response_alg = 'RSA-OAEP'
client.refresh_token_encrypted_response_enc = 'A256GCM'

# Enable rotation
client.enable_refresh_token_rotation = True
client.refresh_token_grace_period_seconds = 5
client.detect_refresh_token_reuse = True

# Custom expiration (30 days)
client.refresh_token_expire_seconds = 30 * 24 * 60 * 60

client.save()
```

### 3. Update Token Creation

The refresh token utilities are integrated into token creation:

```python
# In oidc_provider/lib/utils/token.py
from oidc_provider.lib.utils.refresh_token import create_refresh_token

def create_token(user, client, scope, id_token_dic=None, request=None):
    token = Token()
    token.user = user
    token.client = client
    token.access_token = uuid.uuid4().hex
    
    # Enhanced refresh token creation
    token.refresh_token = create_refresh_token(user, client, scope, token, request)
    
    # ... rest of the code
```

## Fallback Chain

When a setting is not specified, it falls back in this order:

### Algorithm Selection:
1. `client.refresh_token_jwt_alg` (if set)
2. `client.access_token_jwt_alg` (if set)
3. `client.jwt_alg` (always set)

### Encryption:
1. `client.refresh_token_encrypted_response_alg/enc` (if set)
2. `client.access_token_encrypted_response_alg/enc` (if set)
3. No encryption (if none set)

### Expiration:
1. `client.refresh_token_expire_seconds` (if set)
2. `OIDC_TOKEN_EXPIRE * 30` (default: 30x access token lifetime)

## Configuration Examples

### Example 1: Inherit Everything from Access Token

```python
client = Client.objects.create(
    name='App',
    # Access token settings
    access_token_jwt_alg='ES256',
    access_token_encrypted_response_alg='RSA-OAEP',
    access_token_encrypted_response_enc='A128GCM',
    
    # Refresh token - just enable JWT format
    refresh_token_format='jwt',
    # Everything else inherited automatically!
)
```

### Example 2: Override Specific Settings

```python
client = Client.objects.create(
    name='App',
    # Access tokens use ES256
    access_token_jwt_alg='ES256',
    
    # Refresh tokens use longer-lived RS256
    refresh_token_format='jwt',
    refresh_token_jwt_alg='RS256',
    refresh_token_expire_seconds=90 * 24 * 60 * 60,  # 90 days
)
```

### Example 3: Maximum Security

```python
client = Client.objects.create(
    name='High Security App',
    
    # JWT format with encryption
    refresh_token_format='jwt',
    refresh_token_jwt_alg='ES384',
    refresh_token_encrypted_response_alg='RSA-OAEP-256',
    refresh_token_encrypted_response_enc='A256GCM',
    
    # Rotation enabled
    enable_refresh_token_rotation=True,
    refresh_token_grace_period_seconds=10,
    detect_refresh_token_reuse=True,
    
    # Shorter lifetime
    refresh_token_expire_seconds=7 * 24 * 60 * 60,  # 7 days
)
```

## Testing

Test that refresh tokens work correctly:

```python
# Test basic refresh
response = client.post('/token', {
    'grant_type': 'refresh_token',
    'refresh_token': 'your-refresh-token',
    'client_id': 'client-id',
    'client_secret': 'secret',
})

assert response.status_code == 200
data = response.json()
assert 'access_token' in data
assert 'refresh_token' in data

# With rotation enabled, refresh token should be different
assert data['refresh_token'] != 'your-refresh-token'
```

## Admin Configuration

Update admin to show refresh token settings:

```python
# myapp/admin.py
from django.contrib import admin
from oidc_provider.admin import ClientAdmin
from oidc_provider.models import Client

admin.site.unregister(Client)

@admin.register(Client)
class EnhancedClientAdmin(ClientAdmin):
    fieldsets = ClientAdmin.fieldsets + [
        ('Refresh Token Settings', {
            'fields': (
                'refresh_token_format',
                ('refresh_token_jwt_alg', 'refresh_token_expire_seconds'),
                ('refresh_token_encrypted_response_alg', 'refresh_token_encrypted_response_enc'),
                'enable_refresh_token_rotation',
                ('refresh_token_grace_period_seconds', 'detect_refresh_token_reuse'),
            ),
            'classes': ('collapse',),
        }),
    ]
```

## Migration Notes

- ✅ **Backward Compatible**: Existing clients continue to use UUID refresh tokens
- ✅ **Gradual Migration**: Update clients one-by-one to JWT format
- ✅ **Zero Downtime**: No breaking changes
- ✅ **Automatic Fallback**: Inherits access token settings if not configured

## Security Benefits

1. **Rotation**: Limits exposure window
2. **Reuse Detection**: Catches token theft
3. **Encryption**: Protects token content
4. **Grace Period**: Handles network issues
5. **JWT Format**: Contains metadata and expiration

## Complete!

Your refresh tokens now have:
- ✅ Same algorithm options as access tokens
- ✅ Same encryption options as access tokens
- ✅ Automatic fallback to access token settings
- ✅ Enhanced security with rotation
- ✅ Backward compatibility
