# API Endpoints Reference

## Standard OIDC Endpoints

### Discovery

**GET** `/.well-known/openid-configuration`

Returns provider configuration.

### Authorization

**GET/POST** `/oidc/authorize/`

Parameters:
- `client_id` - Client identifier
- `response_type` - code, token, id_token, etc.
- `redirect_uri` - Callback URL
- `scope` - Requested scopes
- `state` - CSRF protection
- `nonce` - Replay protection
- `code_challenge` - PKCE challenge
- `code_challenge_method` - PKCE method

### Token

**POST** `/oidc/token/`

Parameters:
- `grant_type` - authorization_code, refresh_token, client_credentials, password
- `code` - Authorization code
- `client_id` - Client ID
- `client_secret` - Client secret
- `redirect_uri` - Must match authorization
- `refresh_token` - For refresh grant
- `code_verifier` - PKCE verifier

### UserInfo

**GET** `/oidc/userinfo/`

Headers:
- `Authorization: Bearer <access_token>`

### JWKS

**GET** `/oidc/jwks/`

Returns JSON Web Key Set.

### Token Introspection

**POST** `/oidc/introspect/`

Parameters:
- `token` - Token to introspect
- `client_id` - Client ID
- `client_secret` - Client secret

## Passkey Endpoints

### Registration Options

**POST** `/oidc/passkey/register/options/`

Returns WebAuthn registration options.

### Registration Verify

**POST** `/oidc/passkey/register/verify/`

Verifies and stores passkey credential.

### Authentication Options

**POST** `/oidc/passkey/authenticate/options/`

Returns WebAuthn authentication options.

### Authentication Verify

**POST** `/oidc/passkey/authenticate/verify/`

Verifies passkey authentication.

### List Passkeys

**GET** `/oidc/passkey/list/`

Returns user's passkeys.

### Delete Passkey

**POST** `/oidc/passkey/delete/<credential_id>/`

Deletes passkey credential.

## Consent Endpoints

### Consent Dashboard

**GET** `/oidc/consent/`

User's consent management dashboard.

### Consent Detail

**GET** `/oidc/consent/<id>/`

Detailed consent view.

### Revoke Consent

**POST** `/oidc/consent/<id>/revoke/`

Revokes specific consent.

### Revoke All

**POST** `/oidc/consent/revoke-all/`

Revokes all consents.

### API Consent List

**GET** `/oidc/api/consents/`

Headers:
- `Authorization: Bearer <access_token>`

Returns JSON list of consents.

## Summary

Complete endpoint reference. See [OIDC Flows](oidc-flows.md) for usage examples.
