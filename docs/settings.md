# Settings Reference

Complete reference for all OIDC provider settings.

## Core Settings

### OIDC_TOKEN_EXPIRE
- **Type:** Integer
- **Default:** 3600
- **Description:** Access token lifetime in seconds

### OIDC_IDTOKEN_EXPIRE
- **Type:** Integer
- **Default:** 600
- **Description:** ID token lifetime in seconds

### OIDC_CODE_EXPIRE
- **Type:** Integer
- **Default:** 600
- **Description:** Authorization code lifetime in seconds

### OIDC_IDTOKEN_SUB_GENERATOR
- **Type:** String (import path)
- **Default:** `'oidc_provider.lib.utils.common.default_sub_generator'`
- **Description:** Function to generate sub claim

### OIDC_ACCESS_TOKEN_JWT
- **Type:** Boolean
- **Default:** False
- **Description:** Use JWT format for access tokens

### OIDC_TOKEN_JWT_AUD
- **Type:** String (import path)
- **Default:** None
- **Description:** Function to generate aud claim for access tokens

## WebAuthn Settings

### WEBAUTHN_RP_ID
- **Type:** String
- **Required:** Yes (for passkeys)
- **Example:** `'your-domain.com'`
- **Description:** Relying Party ID (domain without https://)

### WEBAUTHN_RP_NAME
- **Type:** String
- **Required:** Yes
- **Example:** `'Your Application'`
- **Description:** Relying Party name

### WEBAUTHN_RP_ORIGIN
- **Type:** String
- **Required:** Yes
- **Example:** `'https://your-domain.com'`
- **Description:** Relying Party origin (full URL)

### WEBAUTHN_CHALLENGE_TIMEOUT
- **Type:** Integer
- **Default:** 300
- **Description:** Challenge validity in seconds

### WEBAUTHN_USER_VERIFICATION
- **Type:** String
- **Default:** `'preferred'`
- **Options:** `'required'`, `'preferred'`, `'discouraged'`
- **Description:** User verification requirement

## Security Settings

### SECURE_SSL_REDIRECT
- **Type:** Boolean
- **Default:** False
- **Production:** True
- **Description:** Redirect HTTP to HTTPS

### SECURE_HSTS_SECONDS
- **Type:** Integer
- **Default:** 0
- **Production:** 31536000
- **Description:** HSTS max-age in seconds

## Session Management

### OIDC_SESSION_MANAGEMENT_ENABLE
- **Type:** Boolean
- **Default:** False
- **Description:** Enable session management

### OIDC_CHECKSESSION_IFRAME_ENABLE
- **Type:** Boolean
- **Default:** True
- **Description:** Enable check session iframe

## Grant Types

### OIDC_GRANT_TYPE_PASSWORD_ENABLE
- **Type:** Boolean
- **Default:** False
- **Description:** Enable password grant

## Templates

### OIDC_TEMPLATES
- **Type:** Dictionary
- **Default:** Built-in templates
- **Example:**
```python
OIDC_TEMPLATES = {
    'authorize': 'myapp/consent.html',
    'error': 'myapp/error.html',
}
```

## Hooks

### OIDC_IDTOKEN_PROCESSING_HOOK
- **Type:** String (import path)
- **Description:** Process ID token before encoding

### OIDC_USERINFO
- **Type:** String (import path)
- **Description:** UserInfo response generator

## Summary

Complete settings reference. See [Configuration Guide](configuration.md) for usage examples.
