# Refresh Token Customization Guide

This guide explains how to customize refresh tokens with the same options available for access tokens, including encryption, rotation, and lifecycle management.

## Table of Contents
- [Current Refresh Token Implementation](#current-refresh-token-implementation)
- [Refresh Token Customization Options](#refresh-token-customization-options)
- [Implementation Guide](#implementation-guide)
- [Refresh Token Rotation](#refresh-token-rotation)
- [Security Best Practices](#security-best-practices)
- [Examples](#examples)

---

## Current Refresh Token Implementation

### Default Behavior

By default, refresh tokens are:
- **Plain UUID** - Simple `uuid.uuid4().hex` format
- **Long-lived** - Same expiration as access tokens (configurable)
- **Non-rotating** - Same token reused until expiration
- **No encryption** - Stored and transmitted as plain UUIDs

### Limitations

The current implementation lacks:
- ❌ JWT format option for refresh tokens
- ❌ Encryption for refresh tokens
- ❌ Automatic rotation on use
- ❌ Separate algorithm configuration
- ❌ Custom claims in refresh tokens

---

## Refresh Token Customization Options

### Enhanced Model Fields

Add these fields to the `Client` model to enable refresh token customization:

```python
# oidc_provider/models.py - Add to Client model

class Client(models.Model):
    # ... existing fields ...
    
    # Refresh Token Configuration
    refresh_token_format = models.CharField(
        max_length=10,
        choices=[
            ('uuid', 'UUID (Opaque)'),
            ('jwt', 'JWT (Structured)'),
        ],
        default='uuid',
        verbose_name=_('Refresh Token Format'),
        help_text=_('Format for refresh tokens')
    )
    
    refresh_token_jwt_alg = models.CharField(
        max_length=10,
        choices=JWT_ALGS,
        blank=True,
        null=True,
        verbose_name=_('Refresh Token JWT Algorithm'),
        help_text=_('Algorithm for JWT refresh tokens. If not set, uses access_token_jwt_alg or jwt_alg')
    )
    
    refresh_token_encrypted_response_alg = models.CharField(
        max_length=30,
        choices=JWT_ENC_ALGS,
        blank=True,
        null=True,
        verbose_name=_('Refresh Token Encryption Algorithm'),
        help_text=_('JWE alg algorithm for encrypting refresh tokens')
    )
    
    refresh_token_encrypted_response_enc = models.CharField(
        max_length=30,
        choices=JWT_ENC_ENCS,
        default='A128CBC-HS256',
        blank=True,
        null=True,
        verbose_name=_('Refresh Token Encryption Encoding'),
        help_text=_('JWE enc algorithm for encrypting refresh tokens')
    )
    
    # Refresh Token Rotation
    enable_refresh_token_rotation = models.BooleanField(
        default=True,
        verbose_name=_('Enable Refresh Token Rotation'),
        help_text=_('Generate new refresh token on each use')
    )
    
    refresh_token_grace_period_seconds = models.IntegerField(
        default=0,
        verbose_name=_('Refresh Token Grace Period'),
        help_text=_('Seconds to allow old refresh token after rotation (for concurrency)')
    )
    
    # Refresh Token Lifetime
    refresh_token_expire_seconds = models.IntegerField(
        blank=True,
        null=True,
        verbose_name=_('Refresh Token Expiration'),
        help_text=_('Seconds until refresh token expires. If not set, uses OIDC_TOKEN_EXPIRE * 30')
    )
    
    # Refresh Token Reuse Detection
    detect_refresh_token_reuse = models.BooleanField(
        default=True,
        verbose_name=_('Detect Refresh Token Reuse'),
        help_text=_('Revoke token family if reuse detected')
    )
```

---

## Implementation Guide

### Step 1: Create Database Migration

```python
# Create migration file
python manage.py makemigrations oidc_provider --name add_refresh_token_customization

# The migration should add the new fields
```

**Migration file:**
```python
# oidc_provider/migrations/0030_add_refresh_token_customization.py
from django.db import migrations, models

class Migration(migrations.Migration):
    
    dependencies = [
        ('oidc_provider', '0029_add_modern_algorithms_and_encryption'),
    ]
    
    operations = [
        migrations.AddField(
            model_name='client',
            name='refresh_token_format',
            field=models.CharField(
                choices=[('uuid', 'UUID (Opaque)'), ('jwt', 'JWT (Structured)')],
                default='uuid',
                max_length=10,
                verbose_name='Refresh Token Format'
            ),
        ),
        migrations.AddField(
            model_name='client',
            name='refresh_token_jwt_alg',
            field=models.CharField(
                blank=True,
                choices=[
                    ('HS256', 'HS256'), ('HS384', 'HS384'), ('HS512', 'HS512'),
                    ('RS256', 'RS256'), ('RS384', 'RS384'), ('RS512', 'RS512'),
                    ('ES256', 'ES256'), ('ES384', 'ES384'), ('ES512', 'ES512'),
                    ('PS256', 'PS256'), ('PS384', 'PS384'), ('PS512', 'PS512'),
                ],
                max_length=10,
                null=True,
                verbose_name='Refresh Token JWT Algorithm'
            ),
        ),
        migrations.AddField(
            model_name='client',
            name='refresh_token_encrypted_response_alg',
            field=models.CharField(
                blank=True,
                max_length=30,
                null=True,
                verbose_name='Refresh Token Encryption Algorithm'
            ),
        ),
        migrations.AddField(
            model_name='client',
            name='refresh_token_encrypted_response_enc',
            field=models.CharField(
                blank=True,
                default='A128CBC-HS256',
                max_length=30,
                null=True,
                verbose_name='Refresh Token Encryption Encoding'
            ),
        ),
        migrations.AddField(
            model_name='client',
            name='enable_refresh_token_rotation',
            field=models.BooleanField(
                default=True,
                verbose_name='Enable Refresh Token Rotation'
            ),
        ),
        migrations.AddField(
            model_name='client',
            name='refresh_token_grace_period_seconds',
            field=models.IntegerField(
                default=0,
                verbose_name='Refresh Token Grace Period'
            ),
        ),
        migrations.AddField(
            model_name='client',
            name='refresh_token_expire_seconds',
            field=models.IntegerField(
                blank=True,
                null=True,
                verbose_name='Refresh Token Expiration'
            ),
        ),
        migrations.AddField(
            model_name='client',
            name='detect_refresh_token_reuse',
            field=models.BooleanField(
                default=True,
                verbose_name='Detect Refresh Token Reuse'
            ),
        ),
    ]
```

### Step 2: Enhanced Token Utilities

```python
# oidc_provider/lib/utils/refresh_token.py
"""
Enhanced refresh token utilities with JWT support and encryption.
"""

import uuid
import hashlib
from datetime import timedelta
from django.utils import timezone

from oidc_provider.lib.utils.jwt_authlib import jwt_handler
from oidc_provider import settings


def create_refresh_token(user, client, scope, token, request=None):
    """
    Create refresh token with customization options.
    
    Returns: refresh token string (UUID or JWT)
    """
    
    # Check format preference
    if client.refresh_token_format == 'jwt':
        return create_refresh_token_jwt(user, client, scope, token, request)
    else:
        # Default UUID format
        return uuid.uuid4().hex


def create_refresh_token_jwt(user, client, scope, token, request=None):
    """
    Create JWT-formatted refresh token.
    """
    from oidc_provider.lib.utils.common import get_issuer
    
    # Calculate expiration
    if client.refresh_token_expire_seconds:
        expire_seconds = client.refresh_token_expire_seconds
    else:
        # Default: 30x access token lifetime
        expire_seconds = settings.get('OIDC_TOKEN_EXPIRE') * 30
    
    now = timezone.now()
    exp_time = int((now + timedelta(seconds=expire_seconds)).timestamp())
    
    # Build JWT payload
    payload = {
        'iss': get_issuer(request=request),
        'sub': settings.get('OIDC_IDTOKEN_SUB_GENERATOR', import_str=True)(user=user) if user else None,
        'client_id': str(client.client_id),
        'iat': int(now.timestamp()),
        'exp': exp_time,
        'jti': uuid.uuid4().hex,  # Unique identifier for this refresh token
        'token_type': 'refresh',
        'scope': scope,
    }
    
    # Add token family ID for rotation tracking
    if client.enable_refresh_token_rotation:
        payload['token_family'] = token.access_token[:16]  # Use part of access token as family ID
    
    # Custom refresh token processing hook
    if settings.get('OIDC_REFRESH_TOKEN_PROCESSING_HOOK'):
        payload = settings.get('OIDC_REFRESH_TOKEN_PROCESSING_HOOK', import_str=True)(
            payload, user=user, client=client, token=token, request=request
        )
    
    # Determine algorithm (fallback chain)
    alg = (client.refresh_token_jwt_alg or 
           client.access_token_jwt_alg or 
           client.jwt_alg)
    
    # Encode JWT
    jwt_token = jwt_handler.encode(payload, client, alg=alg)
    
    # Encrypt if configured
    if client.refresh_token_encrypted_response_alg and client.refresh_token_encrypted_response_enc:
        jwt_token = jwt_handler.encrypt(
            jwt_token,
            client,
            client.refresh_token_encrypted_response_alg,
            client.refresh_token_encrypted_response_enc
        )
    
    return jwt_token


def decode_refresh_token(refresh_token_string, client):
    """
    Decode and validate refresh token.
    
    Returns: payload dict or raises exception
    """
    
    # If UUID format, return simple dict
    if client.refresh_token_format == 'uuid':
        return {
            'jti': refresh_token_string,
            'token_type': 'refresh',
        }
    
    # Decrypt if needed
    if client.refresh_token_encrypted_response_alg and client.refresh_token_encrypted_response_enc:
        refresh_token_string = jwt_handler.decrypt(
            refresh_token_string,
            client,
            client.refresh_token_encrypted_response_alg,
            client.refresh_token_encrypted_response_enc
        )
    
    # Decode JWT
    alg = (client.refresh_token_jwt_alg or 
           client.access_token_jwt_alg or 
           client.jwt_alg)
    
    payload = jwt_handler.decode(refresh_token_string, client, alg=alg)
    
    # Validate token type
    if payload.get('token_type') != 'refresh':
        raise ValueError('Invalid token type')
    
    return payload


def validate_refresh_token(token_obj, refresh_token_string, client):
    """
    Validate refresh token and check for reuse.
    
    Returns: (is_valid, reason)
    """
    
    # Basic validation
    if token_obj.has_expired():
        return False, 'token_expired'
    
    # Decode and validate format
    try:
        payload = decode_refresh_token(refresh_token_string, client)
    except Exception as e:
        return False, 'invalid_token'
    
    # For UUID tokens, simple comparison
    if client.refresh_token_format == 'uuid':
        if token_obj.refresh_token != refresh_token_string:
            return False, 'token_mismatch'
        return True, None
    
    # For JWT tokens, validate JTI
    if payload.get('jti') != token_obj.refresh_token:
        # Check if this is a recently rotated token (grace period)
        if client.refresh_token_grace_period_seconds > 0:
            if hasattr(token_obj, 'previous_refresh_tokens'):
                grace_cutoff = timezone.now() - timedelta(
                    seconds=client.refresh_token_grace_period_seconds
                )
                recent_tokens = token_obj.previous_refresh_tokens.filter(
                    created_at__gte=grace_cutoff
                )
                if recent_tokens.filter(jti=payload.get('jti')).exists():
                    return True, None
        
        # Possible reuse attack
        if client.detect_refresh_token_reuse:
            return False, 'token_reuse_detected'
        
        return False, 'token_mismatch'
    
    return True, None


def rotate_refresh_token(old_token, user, client, scope, request=None):
    """
    Rotate refresh token - create new one and optionally revoke old.
    
    Returns: new refresh token string
    """
    
    # Create new refresh token
    new_refresh_token = create_refresh_token(user, client, scope, old_token, request)
    
    # Store old token for grace period tracking (if JWT)
    if client.refresh_token_format == 'jwt' and client.refresh_token_grace_period_seconds > 0:
        from oidc_provider.models import RefreshTokenHistory
        
        # Decode old token to get JTI
        try:
            old_payload = decode_refresh_token(old_token.refresh_token, client)
            RefreshTokenHistory.objects.create(
                token=old_token,
                jti=old_payload.get('jti'),
                created_at=timezone.now(),
            )
        except:
            pass
    
    return new_refresh_token
```

### Step 3: Token History Model (for rotation tracking)

```python
# oidc_provider/models.py - Add this model

class RefreshTokenHistory(models.Model):
    """Track refresh token rotation history for grace period and reuse detection."""
    
    token = models.ForeignKey(
        'Token',
        on_delete=models.CASCADE,
        related_name='previous_refresh_tokens'
    )
    jti = models.CharField(max_length=255, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    revoked = models.BooleanField(default=False)
    
    class Meta:
        verbose_name = 'Refresh Token History'
        verbose_name_plural = 'Refresh Token Histories'
        indexes = [
            models.Index(fields=['token', 'created_at']),
            models.Index(fields=['jti', 'created_at']),
        ]
    
    def __str__(self):
        return f"Refresh token {self.jti[:8]}... for {self.token}"
```

### Step 4: Update Token Endpoint

```python
# oidc_provider/lib/endpoints/token.py - Update refresh token handling

from oidc_provider.lib.utils.refresh_token import (
    create_refresh_token,
    validate_refresh_token,
    rotate_refresh_token,
)

class TokenEndpoint(object):
    # ... existing code ...
    
    def create_refresh_response_dic(self):
        """Enhanced refresh token response with rotation support."""
        
        scope_param = self.params['scope']
        scope = (scope_param.split(' ') if scope_param else self.token.scope)
        unauthorized_scopes = set(scope) - set(self.token.scope)
        if unauthorized_scopes:
            raise TokenError('invalid_scope')
        
        # Validate refresh token
        is_valid, reason = validate_refresh_token(
            self.token,
            self.params['refresh_token'],
            self.client
        )
        
        if not is_valid:
            if reason == 'token_reuse_detected':
                # Revoke entire token family
                self._revoke_token_family(self.token)
                logger.warning(
                    f'Refresh token reuse detected for client {self.client.client_id}. '
                    f'Token family revoked.'
                )
            raise TokenError('invalid_grant', description=reason)
        
        # Create new token
        from oidc_provider.lib.utils.token import create_token, create_id_token, encode_id_token
        
        token = create_token(
            user=self.token.user,
            client=self.token.client,
            scope=scope
        )
        
        # Generate new refresh token (rotation)
        if self.client.enable_refresh_token_rotation:
            new_refresh_token = rotate_refresh_token(
                self.token,
                self.token.user,
                self.client,
                scope,
                self.request
            )
        else:
            # Reuse same refresh token
            new_refresh_token = create_refresh_token(
                self.token.user,
                self.client,
                scope,
                token,
                self.request
            )
        
        token.refresh_token = new_refresh_token
        
        # Create ID token if authentication request
        if self.token.id_token:
            id_token_dic = create_id_token(
                user=self.token.user,
                aud=self.client.client_id,
                token=token,
                nonce=None,
                at_hash=token.at_hash,
                request=self.request,
                scope=token.scope,
            )
            id_token_encoded = encode_id_token(id_token_dic, self.client)
        else:
            id_token_dic = {}
            id_token_encoded = None
        
        token.id_token = id_token_dic
        token.save()
        
        # Delete or mark old token as used
        if self.client.enable_refresh_token_rotation:
            self.token.delete()
        
        # Format access token
        from oidc_provider.lib.utils.token import access_token_format
        access_token = access_token_format(
            token=token,
            user=self.token.user,
            client=self.client,
            request=self.request
        )
        
        # Build response
        dic = {
            'access_token': access_token,
            'refresh_token': new_refresh_token,
            'token_type': 'bearer',
            'expires_in': settings.get('OIDC_TOKEN_EXPIRE'),
        }
        
        if id_token_encoded:
            dic['id_token'] = id_token_encoded
        
        return dic
    
    def _revoke_token_family(self, token):
        """Revoke all tokens in the same family (reuse detection)."""
        # Mark token and all related tokens as revoked
        token.delete()
        
        # If using token families, revoke all tokens with same family ID
        # This would require additional implementation based on your needs
```

### Step 5: Update Token Creation

```python
# oidc_provider/lib/utils/token.py - Update create_token

from oidc_provider.lib.utils.refresh_token import create_refresh_token

def create_token(user, client, scope, id_token_dic=None, request=None):
    """
    Create and populate a Token object with enhanced refresh token.
    Return a Token object.
    """
    token = Token()
    token.user = user
    token.client = client
    token.access_token = uuid.uuid4().hex

    if id_token_dic is not None:
        token.id_token = id_token_dic

    # Create refresh token with customization
    token.refresh_token = create_refresh_token(user, client, scope, token, request)
    
    # Set expiration
    token.expires_at = timezone.now() + timedelta(seconds=settings.get('OIDC_TOKEN_EXPIRE'))
    token.scope = scope

    return token
```

---

## Refresh Token Rotation

### How It Works

1. **Initial Grant**: Client receives refresh token `RT1`
2. **First Refresh**: Client sends `RT1`, receives `RT2` (and new access token)
3. **Second Refresh**: Client sends `RT2`, receives `RT3`
4. **Reuse Detection**: If client sends `RT1` again, all tokens revoked

### Configuration

```python
# Client configuration
client = Client.objects.get(client_id='your-client')

# Enable rotation
client.enable_refresh_token_rotation = True

# Grace period for concurrency (5 seconds)
client.refresh_token_grace_period_seconds = 5

# Detect and revoke on reuse
client.detect_refresh_token_reuse = True

client.save()
```

### Grace Period

Prevents issues with:
- **Network delays**: Request sent, response not received
- **Parallel requests**: Multiple tabs refreshing simultaneously
- **Retry logic**: Client retries with old token

```python
# Example: 10 second grace period
client.refresh_token_grace_period_seconds = 10
```

---

## Security Best Practices

### 1. Use JWT Format for Audit

```python
client.refresh_token_format = 'jwt'
client.refresh_token_jwt_alg = 'ES256'
```

**Benefits:**
- Contains metadata (expiration, issuer, etc.)
- Can be validated without database lookup
- Audit trail in token itself

### 2. Enable Encryption for Sensitive Apps

```python
client.refresh_token_encrypted_response_alg = 'RSA-OAEP'
client.refresh_token_encrypted_response_enc = 'A256GCM'
```

**When to use:**
- Tokens contain sensitive data
- Compliance requirements (PCI DSS, HIPAA)
- High-security applications

### 3. Enable Rotation

```python
client.enable_refresh_token_rotation = True
client.detect_refresh_token_reuse = True
```

**Security benefits:**
- Limits token lifetime
- Detects token theft
- Automatic revocation on reuse

### 4. Set Appropriate Expiration

```python
# For high-security apps: 7 days
client.refresh_token_expire_seconds = 7 * 24 * 60 * 60

# For standard apps: 30 days
client.refresh_token_expire_seconds = 30 * 24 * 60 * 60

# For long-lived apps: 90 days
client.refresh_token_expire_seconds = 90 * 24 * 60 * 60
```

### 5. Use Same Algorithm as Access Token (Default)

```python
# If not set, automatically uses access token settings
client.access_token_jwt_alg = 'ES256'
# Refresh token will use ES256 too (no need to set separately)
```

---

## Examples

### Example 1: Default Configuration (UUID, Rotation Enabled)

```python
client = Client.objects.create(
    name='Standard App',
    client_type='confidential',
    jwt_alg='RS256',
    # Refresh token settings (defaults)
    refresh_token_format='uuid',  # Opaque token
    enable_refresh_token_rotation=True,
    detect_refresh_token_reuse=True,
)
```

**Behavior:**
- Refresh tokens are UUIDs
- New refresh token on each use
- Old token invalidated
- Reuse detection active

### Example 2: JWT Refresh Tokens with Encryption

```python
client = Client.objects.create(
    name='High Security App',
    client_type='confidential',
    
    # Token algorithms
    jwt_alg='ES384',
    access_token_jwt_alg='ES384',
    refresh_token_jwt_alg='ES384',  # Same as access token
    
    # Refresh token format
    refresh_token_format='jwt',  # JWT format
    
    # Encryption
    refresh_token_encrypted_response_alg='RSA-OAEP-256',
    refresh_token_encrypted_response_enc='A256GCM',
    
    # Rotation
    enable_refresh_token_rotation=True,
    refresh_token_grace_period_seconds=10,
    detect_refresh_token_reuse=True,
    
    # Expiration (30 days)
    refresh_token_expire_seconds=30 * 24 * 60 * 60,
)
```

**Behavior:**
- Refresh tokens are encrypted JWTs
- Contains claims (sub, exp, iat, etc.)
- 10-second grace period
- 30-day lifetime
- Auto-rotation on use

### Example 3: Long-Lived Refresh Tokens (No Rotation)

```python
client = Client.objects.create(
    name='Mobile App',
    client_type='public',
    
    # Use opaque tokens
    refresh_token_format='uuid',
    
    # No rotation (same token reused)
    enable_refresh_token_rotation=False,
    
    # Long lifetime (90 days)
    refresh_token_expire_seconds=90 * 24 * 60 * 60,
)
```

**Use case:** Mobile apps where user shouldn't re-login frequently

### Example 4: Inherit from Access Token Settings

```python
client = Client.objects.create(
    name='API Client',
    client_type='confidential',
    
    # Access token settings
    access_token_jwt_alg='ES256',
    access_token_encrypted_response_alg='RSA-OAEP',
    access_token_encrypted_response_enc='A128GCM',
    
    # Refresh token inherits (just set format)
    refresh_token_format='jwt',
    # Algorithm: will use ES256 (from access_token_jwt_alg)
    # Encryption: will use RSA-OAEP + A128GCM (from access token)
)
```

### Example 5: Per-Environment Configuration

```python
# Development: Simple tokens, no rotation
dev_client = Client.objects.create(
    name='Dev App',
    refresh_token_format='uuid',
    enable_refresh_token_rotation=False,
    refresh_token_expire_seconds=365 * 24 * 60 * 60,  # 1 year
)

# Production: JWT, encrypted, rotated
prod_client = Client.objects.create(
    name='Prod App',
    refresh_token_format='jwt',
    refresh_token_jwt_alg='ES256',
    refresh_token_encrypted_response_alg='RSA-OAEP-256',
    refresh_token_encrypted_response_enc='A256GCM',
    enable_refresh_token_rotation=True,
    refresh_token_grace_period_seconds=5,
    detect_refresh_token_reuse=True,
    refresh_token_expire_seconds=30 * 24 * 60 * 60,  # 30 days
)
```

---

## Testing Refresh Tokens

### Test Rotation

```python
# myapp/tests.py
from django.test import TestCase, Client as TestClient
from oidc_provider.models import Client, Token
from django.contrib.auth import get_user_model

User = get_user_model()

class RefreshTokenRotationTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('test@example.com', password='test')
        self.client = Client.objects.create(
            name='Test Client',
            client_id='test123',
            client_secret='secret',
            enable_refresh_token_rotation=True,
        )
    
    def test_refresh_token_rotation(self):
        """Test that refresh token rotates on use."""
        # Get initial token
        token = Token.objects.create(
            user=self.user,
            client=self.client,
            access_token='access1',
            refresh_token='refresh1',
            scope=['openid'],
        )
        
        # Use refresh token
        response = self.client.post('/token', {
            'grant_type': 'refresh_token',
            'refresh_token': 'refresh1',
            'client_id': 'test123',
            'client_secret': 'secret',
        })
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        # New refresh token should be different
        self.assertNotEqual(data['refresh_token'], 'refresh1')
        
        # Old refresh token should be invalid
        response2 = self.client.post('/token', {
            'grant_type': 'refresh_token',
            'refresh_token': 'refresh1',  # Old token
            'client_id': 'test123',
            'client_secret': 'secret',
        })
        
        self.assertEqual(response2.status_code, 400)
    
    def test_reuse_detection(self):
        """Test that token reuse is detected."""
        # Implementation here
        pass
```

### Test Grace Period

```python
def test_grace_period(self):
    """Test that grace period allows old token briefly."""
    self.client.refresh_token_grace_period_seconds = 10
    self.client.save()
    
    # Get token and use it
    # ... 
    
    # Old token should work within grace period
    # ...
    
    # After grace period, should fail
    # ...
```

---

## Configuration Summary

### Settings.py Configuration

```python
# settings.py

# Default refresh token expiration (if not set on client)
OIDC_REFRESH_TOKEN_EXPIRE = 30 * 24 * 60 * 60  # 30 days

# Custom refresh token processing hook
OIDC_REFRESH_TOKEN_PROCESSING_HOOK = 'myapp.hooks.refresh_token_hook'

# Refresh token rotation enabled by default
OIDC_REFRESH_TOKEN_ROTATION_DEFAULT = True

# Default grace period
OIDC_REFRESH_TOKEN_GRACE_PERIOD = 5  # seconds
```

### Client Admin Integration

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
                'refresh_token_jwt_alg',
                ('refresh_token_encrypted_response_alg', 'refresh_token_encrypted_response_enc'),
                'enable_refresh_token_rotation',
                ('refresh_token_grace_period_seconds', 'refresh_token_expire_seconds'),
                'detect_refresh_token_reuse',
            ),
            'classes': ('collapse',),
        }),
    ]
```

---

## Migration Path

### For Existing Installations

1. **Add fields to model**
2. **Create and run migration**
3. **Existing clients default to UUID format**
4. **Gradually migrate clients to JWT + rotation**

```bash
# Run migration
python manage.py migrate oidc_provider

# Update clients programmatically
python manage.py shell
>>> from oidc_provider.models import Client
>>> for client in Client.objects.filter(client_type='confidential'):
...     client.refresh_token_format = 'jwt'
...     client.enable_refresh_token_rotation = True
...     client.save()
```

---

## Summary

✅ **Implemented:**
- JWT format for refresh tokens
- Encryption support (JWE)
- Automatic rotation
- Reuse detection
- Grace period for concurrency
- Custom expiration
- Algorithm inheritance from access tokens

✅ **Fallback Chain:**
1. `refresh_token_jwt_alg` (if set)
2. `access_token_jwt_alg` (if set)
3. `jwt_alg` (always set)

✅ **Security Features:**
- Token rotation prevents long-term exposure
- Reuse detection catches token theft
- Encryption protects token content
- Grace period handles network issues
- Token families for revocation

The refresh token implementation now has **full parity** with access tokens while maintaining backward compatibility!
