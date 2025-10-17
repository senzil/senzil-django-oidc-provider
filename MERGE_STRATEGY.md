# Merge Strategy: Custom Client Model + All Modernization Features

## Goal
Merge all modernization features from `cursor/update-oidc-provider-for-new-token-algorithms-b2d3` 
into `feature/company_oidc_client` while preserving the custom client model pattern.

## Key Differences

### feature/company_oidc_client Branch:
- Has `AbstractClient` (abstract model) with most fields
- Has `Client` (concrete model) inheriting from `AbstractClient`
- Supports custom client model via `OIDC_CLIENT_MODEL` setting
- Uses `get_client_model()` utility

### cursor Branch:
- Has `Client` as a non-abstract model directly
- Added many new fields (encryption, refresh token, origin security, passkey)
- Added new models (ECKey, WebAuthnCredential, etc.)
- Added utility methods (`is_origin_allowed`, `allowed_origins_list`)

## Merge Approach

### 1. Models (oidc_provider/models.py)
- Keep `AbstractClient` as abstract base
- Add ALL new fields from cursor's Client to AbstractClient:
  - `access_token_jwt_alg`
  - Encryption fields (`*_encrypted_response_alg`, `*_encrypted_response_enc`)
  - Refresh token fields
  - Origin security fields (`allowed_origins`, `strict_origin_validation`, etc.)
- Add new utility methods to AbstractClient:
  - `allowed_origins_list` property
  - `is_origin_allowed()` method
- Keep concrete `Client` model from feature branch
- Add all new models from cursor (ECKey, WebAuthnCredential, PasskeyAuthenticationLog, RefreshTokenHistory)
- Update `BaseCodeTokenModel` references to use `get_client_model()`

### 2. Admin (oidc_provider/admin.py)
- Use `get_client_model()` instead of importing `Client` directly
- Import new models (ECKey, WebAuthnCredential, etc.)
- Keep all fieldsets and admin configurations from cursor branch

### 3. Other Files
- Accept all new files from cursor branch
- Update URLs, views, tests as-is
- Update version to 1.0.0

## Implementation Steps

1. ✅ Create new branch from feature/company_oidc_client
2. ⏳ Manually merge models.py (preserve AbstractClient pattern, add all new fields)
3. ⏳ Fix admin.py to use get_client_model()
4. ⏳ Accept all other changes from cursor branch
5. ⏳ Test that custom client model still works
6. ⏳ Commit merged changes
