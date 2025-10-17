# User Consent System

Complete guide to the enhanced consent management system.

## Overview

The modernized consent system provides users with full control over their data and permissions with a beautiful, intuitive interface.

## Features

- ✅ Modern, responsive consent UI
- ✅ Consent management dashboard
- ✅ Individual and bulk revocation
- ✅ Scope-level granularity
- ✅ Expiration tracking
- ✅ Complete audit trail

## Consent Flow

### 1. Authorization Request

When a client requests authorization, users see a consent screen showing:
- Client information (name, logo, website)
- Requested permissions (scopes)
- What data will be shared
- Option to approve or deny

### 2. User Consent

User reviews and either:
- **Approves:** Grants requested permissions
- **Denies:** Rejects the authorization request

### 3. Consent Storage

If approved, consent is stored with:
- User
- Client
- Granted scopes
- Timestamp
- Expiration (optional)

## Consent Dashboard

Users can manage their consents at: `/oidc/consent/`

**Features:**
- View all granted consents
- See what data each app can access
- Revoke individual consents
- Revoke all consents at once
- View consent history

## Configuration

### Enable Consent

```python
client = Client.objects.create(
    name='My App',
    require_consent=True,  # Show consent screen
    reuse_consent=True,    # Remember consent
)
```

### Consent Expiration

```python
# settings.py

# Consent expires after 90 days
OIDC_CONSENT_EXPIRE_DAYS = 90
```

### Custom Consent Template

```python
# settings.py

OIDC_TEMPLATES = {
    'authorize': 'myapp/custom_consent.html',
}
```

## API Endpoints

### List Consents

```http
GET /oidc/consent/
```

Returns HTML dashboard.

### Revoke Consent

```http
POST /oidc/consent/<consent_id>/revoke/
```

### Revoke All

```http
POST /oidc/consent/revoke-all/
```

### API List (JSON)

```http
GET /oidc/api/consents/
Authorization: Bearer <access_token>
```

Response:
```json
[
  {
    "id": 123,
    "client": {
      "name": "My App",
      "logo": "https://..."
    },
    "scopes": ["openid", "profile", "email"],
    "date_given": "2025-01-15T10:30:00Z",
    "expires_at": "2025-04-15T10:30:00Z"
  }
]
```

## Customization

### Custom Scopes Display

```python
# In template
{% for scope in scopes %}
  <li>
    <strong>{{ scope.scope }}</strong>: {{ scope.description }}
  </li>
{% endfor %}
```

### Custom Consent Logic

```python
# myapp/consent.py

def custom_consent_logic(user, client, scopes):
    """Custom logic before showing consent."""
    # Auto-approve for trusted clients
    if client.is_trusted:
        return True  # Skip consent screen
    
    # Require explicit consent
    return False

# settings.py
OIDC_CONSENT_HANDLER = 'myapp.consent.custom_consent_logic'
```

## Summary

The enhanced consent system provides:
- Better user control
- Modern UI/UX
- Complete audit trail
- Easy management

See [Customization Guide](customization.md) for advanced patterns.
