# Passkey (WebAuthn/FIDO2) Implementation Guide

This guide explains how to add passkey support to your OIDC provider for passwordless authentication, similar to Google, Microsoft, and Apple.

## Table of Contents
- [Overview](#overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Models](#models)
- [WebAuthn Flow](#webauthn-flow)
- [Integration with OIDC](#integration-with-oidc)
- [UI Components](#ui-components)
- [Security Considerations](#security-considerations)
- [Testing](#testing)

---

## Overview

### What are Passkeys?

Passkeys are a FIDO2/WebAuthn-based authentication method that:
- ✅ **Passwordless** - No passwords to remember
- ✅ **Phishing-resistant** - Cryptographically bound to domain
- ✅ **Multi-device** - Sync across devices (platform authenticators)
- ✅ **Biometric** - Uses fingerprint, face ID, or security keys
- ✅ **Standards-based** - FIDO2/WebAuthn specification

### How It Works

```
Registration Flow:
1. User initiates passkey creation
2. Server generates challenge
3. Browser/device creates key pair (private key never leaves device)
4. Public key sent to server
5. Server stores public key + credential ID

Authentication Flow:
1. User initiates login with passkey
2. Server sends challenge
3. Device signs challenge with private key
4. Server verifies signature with stored public key
5. User authenticated
```

---

## Architecture

### Components

```
┌─────────────────────────────────────────────┐
│           OIDC Provider (Server)            │
│                                             │
│  ┌─────────────────────────────────────┐  │
│  │  Passkey Models                     │  │
│  │  - WebAuthnCredential               │  │
│  │  - WebAuthnChallenge                │  │
│  └─────────────────────────────────────┘  │
│                                             │
│  ┌─────────────────────────────────────┐  │
│  │  WebAuthn Views                     │  │
│  │  - Registration (create passkey)    │  │
│  │  - Authentication (verify passkey)  │  │
│  └─────────────────────────────────────┘  │
│                                             │
│  ┌─────────────────────────────────────┐  │
│  │  OIDC Integration                   │  │
│  │  - Passkey-enabled authorize flow   │  │
│  │  - Conditional UI support           │  │
│  └─────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
                      ↕
┌─────────────────────────────────────────────┐
│          Browser (Client)                   │
│                                             │
│  ┌─────────────────────────────────────┐  │
│  │  WebAuthn JavaScript API            │  │
│  │  - navigator.credentials.create()   │  │
│  │  - navigator.credentials.get()      │  │
│  └─────────────────────────────────────┘  │
│                                             │
│  ┌─────────────────────────────────────┐  │
│  │  Authenticator                      │  │
│  │  - Platform (Face ID, Touch ID)    │  │
│  │  - Roaming (YubiKey, USB keys)     │  │
│  └─────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

---

## Installation

### 1. Install Dependencies

```bash
pip install webauthn>=2.0.0
pip install cbor2>=5.4.0
```

Add to `requirements.txt`:
```txt
# Passkey/WebAuthn support
webauthn>=2.0.0
cbor2>=5.4.0
```

### 2. Update Settings

```python
# settings.py

# WebAuthn Configuration
WEBAUTHN_RP_ID = 'your-domain.com'  # Relying Party ID (your domain)
WEBAUTHN_RP_NAME = 'Your OIDC Provider'  # Display name
WEBAUTHN_RP_ORIGIN = 'https://your-domain.com'  # Full origin URL

# Challenge timeout (5 minutes)
WEBAUTHN_CHALLENGE_TIMEOUT = 300

# Allowed authenticator types
WEBAUTHN_AUTHENTICATOR_ATTACHMENT = 'platform,cross-platform'  # or 'platform' only

# User verification requirement
WEBAUTHN_USER_VERIFICATION = 'preferred'  # 'required', 'preferred', 'discouraged'

# Attestation preference
WEBAUTHN_ATTESTATION = 'none'  # 'none', 'indirect', 'direct'

# Resident key requirement (for discoverable credentials)
WEBAUTHN_RESIDENT_KEY = 'preferred'  # 'required', 'preferred', 'discouraged'
```

---

## Models

### WebAuthn Models

```python
# oidc_provider/models.py

import base64
import json
from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta

User = get_user_model()


class WebAuthnCredential(models.Model):
    """Store WebAuthn/FIDO2 credentials (passkeys)."""
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='webauthn_credentials'
    )
    
    # Credential identification
    credential_id = models.TextField(
        unique=True,
        help_text='Base64-encoded credential ID'
    )
    
    # Cryptographic data
    public_key = models.TextField(
        help_text='Base64-encoded COSE public key'
    )
    
    # Metadata
    aaguid = models.CharField(
        max_length=36,
        blank=True,
        help_text='Authenticator AAGUID'
    )
    
    # Credential properties
    sign_count = models.IntegerField(
        default=0,
        help_text='Signature counter for cloned device detection'
    )
    
    transports = models.JSONField(
        default=list,
        help_text='Supported transports (usb, nfc, ble, internal)'
    )
    
    # Authenticator attachment
    authenticator_attachment = models.CharField(
        max_length=20,
        choices=[
            ('platform', 'Platform Authenticator'),
            ('cross-platform', 'Cross-Platform Authenticator'),
        ],
        null=True,
        blank=True,
        help_text='Platform (Touch ID) or Cross-platform (YubiKey)'
    )
    
    # User-friendly information
    name = models.CharField(
        max_length=200,
        blank=True,
        help_text='User-given name for this credential'
    )
    
    # Backup state (for synced passkeys)
    backup_eligible = models.BooleanField(
        default=False,
        help_text='Credential can be backed up'
    )
    
    backup_state = models.BooleanField(
        default=False,
        help_text='Credential is currently backed up'
    )
    
    # Attestation data
    attestation_format = models.CharField(
        max_length=50,
        blank=True
    )
    
    attestation_object = models.TextField(
        blank=True,
        help_text='Full attestation object (optional)'
    )
    
    # Tracking
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    
    # Security
    is_active = models.BooleanField(default=True)
    
    class Meta:
        verbose_name = 'WebAuthn Credential'
        verbose_name_plural = 'WebAuthn Credentials'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['credential_id']),
        ]
    
    def __str__(self):
        name = self.name or f'{self.authenticator_attachment} authenticator'
        return f'{self.user.username} - {name}'
    
    def update_last_used(self, sign_count=None):
        """Update last used timestamp and sign count."""
        self.last_used_at = timezone.now()
        if sign_count is not None:
            # Detect cloned credentials
            if sign_count != 0 and sign_count <= self.sign_count:
                # Possible cloned credential
                self.is_active = False
            self.sign_count = sign_count
        self.save()
    
    @property
    def credential_id_bytes(self):
        """Get credential ID as bytes."""
        return base64.b64decode(self.credential_id)
    
    @property
    def public_key_bytes(self):
        """Get public key as bytes."""
        return base64.b64decode(self.public_key)


class WebAuthnChallenge(models.Model):
    """Temporary challenge storage for WebAuthn registration/authentication."""
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='webauthn_challenges'
    )
    
    challenge = models.TextField(
        help_text='Base64-encoded challenge'
    )
    
    challenge_type = models.CharField(
        max_length=20,
        choices=[
            ('registration', 'Registration'),
            ('authentication', 'Authentication'),
        ]
    )
    
    # Session tracking
    session_key = models.CharField(
        max_length=40,
        db_index=True,
        help_text='Session key for anonymous users'
    )
    
    # Client data
    client_data_json = models.TextField(
        blank=True,
        help_text='Stored client data JSON for verification'
    )
    
    # Expiration
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    # Used flag
    used = models.BooleanField(default=False)
    
    class Meta:
        verbose_name = 'WebAuthn Challenge'
        verbose_name_plural = 'WebAuthn Challenges'
        indexes = [
            models.Index(fields=['session_key', 'challenge_type']),
            models.Index(fields=['expires_at']),
        ]
    
    def is_valid(self):
        """Check if challenge is still valid."""
        return not self.used and timezone.now() < self.expires_at
    
    def mark_used(self):
        """Mark challenge as used."""
        self.used = True
        self.save()
    
    @property
    def challenge_bytes(self):
        """Get challenge as bytes."""
        return base64.b64decode(self.challenge)


class PasskeyAuthenticationLog(models.Model):
    """Audit log for passkey authentication attempts."""
    
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='passkey_auth_logs'
    )
    
    credential = models.ForeignKey(
        WebAuthnCredential,
        on_delete=models.SET_NULL,
        null=True,
        related_name='auth_logs'
    )
    
    # Authentication details
    success = models.BooleanField()
    failure_reason = models.CharField(max_length=200, blank=True)
    
    # Context
    ip_address = models.GenericIPAddressField(null=True)
    user_agent = models.TextField(blank=True)
    
    # Client context
    client_id = models.CharField(max_length=255, blank=True)
    
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = 'Passkey Authentication Log'
        verbose_name_plural = 'Passkey Authentication Logs'
        ordering = ['-timestamp']
```

---

## WebAuthn Flow Implementation

### Registration Views

```python
# oidc_provider/views_passkey.py

import os
import json
import base64
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.utils import timezone
from datetime import timedelta

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    AttestationConveyancePreference,
    PublicKeyCredentialDescriptor,
)

from .models import WebAuthnCredential, WebAuthnChallenge, PasskeyAuthenticationLog


@login_required
@require_http_methods(['POST'])
def passkey_registration_options(request):
    """Generate WebAuthn registration options."""
    
    user = request.user
    
    # Get existing credentials to exclude
    existing_credentials = WebAuthnCredential.objects.filter(
        user=user,
        is_active=True
    )
    
    exclude_credentials = [
        PublicKeyCredentialDescriptor(id=base64.b64decode(cred.credential_id))
        for cred in existing_credentials
    ]
    
    # Generate registration options
    registration_options = generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        rp_name=settings.WEBAUTHN_RP_NAME,
        user_id=str(user.id).encode('utf-8'),
        user_name=user.username,
        user_display_name=user.get_full_name() or user.username,
        exclude_credentials=exclude_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM
            if settings.WEBAUTHN_AUTHENTICATOR_ATTACHMENT == 'platform'
            else None,
            resident_key=ResidentKeyRequirement(settings.WEBAUTHN_RESIDENT_KEY),
            user_verification=UserVerificationRequirement(settings.WEBAUTHN_USER_VERIFICATION),
        ),
        attestation=AttestationConveyancePreference(settings.WEBAUTHN_ATTESTATION),
    )
    
    # Store challenge
    challenge = WebAuthnChallenge.objects.create(
        user=user,
        challenge=base64.b64encode(registration_options.challenge).decode('utf-8'),
        challenge_type='registration',
        session_key=request.session.session_key,
        expires_at=timezone.now() + timedelta(seconds=settings.WEBAUTHN_CHALLENGE_TIMEOUT),
    )
    
    # Convert to JSON
    options_json = options_to_json(registration_options)
    
    return JsonResponse({
        'success': True,
        'options': json.loads(options_json),
    })


@login_required
@require_http_methods(['POST'])
def passkey_registration_verify(request):
    """Verify and store WebAuthn registration response."""
    
    user = request.user
    
    try:
        data = json.loads(request.body)
        credential = data.get('credential')
        credential_name = data.get('name', '')
        
        if not credential:
            return JsonResponse({
                'success': False,
                'error': 'No credential provided'
            }, status=400)
        
        # Get challenge
        challenge_obj = WebAuthnChallenge.objects.filter(
            user=user,
            challenge_type='registration',
            session_key=request.session.session_key,
            used=False,
        ).order_by('-created_at').first()
        
        if not challenge_obj or not challenge_obj.is_valid():
            return JsonResponse({
                'success': False,
                'error': 'Invalid or expired challenge'
            }, status=400)
        
        # Verify registration response
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge_obj.challenge_bytes,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_RP_ORIGIN,
        )
        
        # Store credential
        webauthn_credential = WebAuthnCredential.objects.create(
            user=user,
            credential_id=base64.b64encode(verification.credential_id).decode('utf-8'),
            public_key=base64.b64encode(verification.credential_public_key).decode('utf-8'),
            aaguid=str(verification.aaguid),
            sign_count=verification.sign_count,
            name=credential_name,
            backup_eligible=verification.credential_backup_eligible,
            backup_state=verification.credential_backed_up,
            attestation_format=verification.fmt,
        )
        
        # Mark challenge as used
        challenge_obj.mark_used()
        
        return JsonResponse({
            'success': True,
            'credential_id': webauthn_credential.credential_id,
            'message': 'Passkey registered successfully'
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=400)


@csrf_exempt
@require_http_methods(['POST'])
def passkey_authentication_options(request):
    """Generate WebAuthn authentication options."""
    
    data = json.loads(request.body) if request.body else {}
    username = data.get('username', '')
    
    # If username provided, get user's credentials
    allow_credentials = []
    user = None
    
    if username:
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            user = User.objects.get(username=username)
            credentials = WebAuthnCredential.objects.filter(
                user=user,
                is_active=True
            )
            
            allow_credentials = [
                PublicKeyCredentialDescriptor(
                    id=base64.b64decode(cred.credential_id),
                    transports=cred.transports if cred.transports else None,
                )
                for cred in credentials
            ]
        except User.DoesNotExist:
            pass
    
    # Generate authentication options
    authentication_options = generate_authentication_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement(settings.WEBAUTHN_USER_VERIFICATION),
    )
    
    # Store challenge
    challenge = WebAuthnChallenge.objects.create(
        user=user,
        challenge=base64.b64encode(authentication_options.challenge).decode('utf-8'),
        challenge_type='authentication',
        session_key=request.session.session_key,
        expires_at=timezone.now() + timedelta(seconds=settings.WEBAUTHN_CHALLENGE_TIMEOUT),
    )
    
    # Convert to JSON
    options_json = options_to_json(authentication_options)
    
    return JsonResponse({
        'success': True,
        'options': json.loads(options_json),
    })


@csrf_exempt
@require_http_methods(['POST'])
def passkey_authentication_verify(request):
    """Verify WebAuthn authentication response and log user in."""
    
    try:
        data = json.loads(request.body)
        credential = data.get('credential')
        
        if not credential:
            return JsonResponse({
                'success': False,
                'error': 'No credential provided'
            }, status=400)
        
        # Get credential ID
        credential_id_b64 = credential.get('id')
        
        # Find credential in database
        try:
            webauthn_cred = WebAuthnCredential.objects.get(
                credential_id=credential_id_b64,
                is_active=True
            )
        except WebAuthnCredential.DoesNotExist:
            PasskeyAuthenticationLog.objects.create(
                success=False,
                failure_reason='Credential not found',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
            )
            return JsonResponse({
                'success': False,
                'error': 'Invalid credential'
            }, status=400)
        
        # Get challenge
        challenge_obj = WebAuthnChallenge.objects.filter(
            challenge_type='authentication',
            session_key=request.session.session_key,
            used=False,
        ).order_by('-created_at').first()
        
        if not challenge_obj or not challenge_obj.is_valid():
            return JsonResponse({
                'success': False,
                'error': 'Invalid or expired challenge'
            }, status=400)
        
        # Verify authentication response
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge_obj.challenge_bytes,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_RP_ORIGIN,
            credential_public_key=webauthn_cred.public_key_bytes,
            credential_current_sign_count=webauthn_cred.sign_count,
        )
        
        # Update credential
        webauthn_cred.update_last_used(verification.new_sign_count)
        
        # Mark challenge as used
        challenge_obj.mark_used()
        
        # Log successful authentication
        PasskeyAuthenticationLog.objects.create(
            user=webauthn_cred.user,
            credential=webauthn_cred,
            success=True,
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )
        
        # Log user in
        from django.contrib.auth import login
        login(request, webauthn_cred.user, backend='django.contrib.auth.backends.ModelBackend')
        
        return JsonResponse({
            'success': True,
            'user': {
                'id': webauthn_cred.user.id,
                'username': webauthn_cred.user.username,
                'email': webauthn_cred.user.email,
            }
        })
        
    except Exception as e:
        PasskeyAuthenticationLog.objects.create(
            success=False,
            failure_reason=str(e),
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )
        
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=400)


def get_client_ip(request):
    """Extract client IP from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')


@login_required
@require_http_methods(['GET'])
def passkey_list(request):
    """List user's passkeys."""
    
    credentials = WebAuthnCredential.objects.filter(
        user=request.user,
        is_active=True
    )
    
    return JsonResponse({
        'passkeys': [
            {
                'id': cred.id,
                'name': cred.name or f'{cred.authenticator_attachment} authenticator',
                'authenticator_attachment': cred.authenticator_attachment,
                'created_at': cred.created_at.isoformat(),
                'last_used_at': cred.last_used_at.isoformat() if cred.last_used_at else None,
                'backup_state': cred.backup_state,
            }
            for cred in credentials
        ]
    })


@login_required
@require_http_methods(['DELETE'])
def passkey_delete(request, credential_id):
    """Delete a passkey."""
    
    try:
        credential = WebAuthnCredential.objects.get(
            id=credential_id,
            user=request.user
        )
        credential.is_active = False
        credential.save()
        
        return JsonResponse({
            'success': True,
            'message': 'Passkey deleted successfully'
        })
    except WebAuthnCredential.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Passkey not found'
        }, status=404)
```

---

## Integration with OIDC

### Updated Authorization View

```python
# oidc_provider/views_passkey_oidc.py

from django.shortcuts import render, redirect
from django.contrib.auth import login
from oidc_provider.views import AuthorizeView
from oidc_provider.lib.endpoints.authorize import AuthorizeEndpoint
from .models import WebAuthnCredential


class PasskeyAuthorizeView(AuthorizeView):
    """OIDC Authorization view with passkey support."""
    
    def get(self, request, *args, **kwargs):
        authorize = self.authorize_endpoint_class(request)
        
        try:
            authorize.validate_params()
            
            # Check if user is authenticated
            if request.user.is_authenticated:
                # Continue with normal flow
                return super().get(request, *args, **kwargs)
            
            # Check if user has passkeys (conditional UI)
            show_passkey_ui = self._should_show_passkey_ui(request, authorize)
            
            # Render login page with passkey option
            context = {
                'authorize_params': authorize.params,
                'client': authorize.client,
                'show_passkey': show_passkey_ui,
                'supports_passkey': self._check_passkey_support(),
            }
            
            return render(request, 'oidc_provider/login_with_passkey.html', context)
            
        except Exception as error:
            # Handle errors
            return super().get(request, *args, **kwargs)
    
    def _should_show_passkey_ui(self, request, authorize):
        """Check if passkey UI should be shown."""
        # Check if browser supports WebAuthn
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Most modern browsers support it
        # In production, you might want more sophisticated detection
        return True
    
    def _check_passkey_support(self):
        """Check if passkeys are enabled."""
        return hasattr(settings, 'WEBAUTHN_RP_ID')
```

---

## UI Components

### Login Page with Passkey

```html
<!-- oidc_provider/templates/oidc_provider/login_with_passkey.html -->
{% load static %}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In - {{ client.name }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .login-container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 420px;
            width: 100%;
            overflow: hidden;
        }
        
        .login-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 32px;
            text-align: center;
        }
        
        .login-header h1 {
            font-size: 24px;
            margin-bottom: 8px;
        }
        
        .login-header p {
            opacity: 0.9;
            font-size: 14px;
        }
        
        .login-body {
            padding: 32px;
        }
        
        .passkey-section {
            margin-bottom: 24px;
        }
        
        .passkey-button {
            width: 100%;
            padding: 16px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            transition: all 0.2s;
        }
        
        .passkey-button:hover {
            background: #5568d3;
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(102, 126, 234, 0.4);
        }
        
        .passkey-button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .passkey-icon {
            width: 24px;
            height: 24px;
        }
        
        .divider {
            display: flex;
            align-items: center;
            margin: 24px 0;
            color: #9ca3af;
            font-size: 14px;
        }
        
        .divider::before,
        .divider::after {
            content: '';
            flex: 1;
            height: 1px;
            background: #e5e7eb;
        }
        
        .divider span {
            padding: 0 16px;
        }
        
        .password-section {
            display: none;
        }
        
        .password-section.active {
            display: block;
        }
        
        .form-group {
            margin-bottom: 16px;
        }
        
        .form-label {
            display: block;
            margin-bottom: 8px;
            color: #374151;
            font-size: 14px;
            font-weight: 500;
        }
        
        .form-input {
            width: 100%;
            padding: 12px;
            border: 1px solid #d1d5db;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.2s;
        }
        
        .form-input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .submit-button {
            width: 100%;
            padding: 12px;
            background: #374151;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.2s;
        }
        
        .submit-button:hover {
            background: #1f2937;
        }
        
        .toggle-button {
            margin-top: 16px;
            width: 100%;
            padding: 8px;
            background: transparent;
            color: #667eea;
            border: none;
            font-size: 14px;
            cursor: pointer;
            text-decoration: underline;
        }
        
        .error-message {
            background: #fee2e2;
            color: #991b1b;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 16px;
            font-size: 14px;
        }
        
        .info-message {
            background: #dbeafe;
            color: #1e40af;
            padding: 12px;
            border-radius: 8px;
            margin-top: 16px;
            font-size: 13px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>Sign In</h1>
            <p>{{ client.name }}</p>
        </div>
        
        <div class="login-body">
            <div id="error-container"></div>
            
            {% if supports_passkey and show_passkey %}
            <div class="passkey-section">
                <button id="passkey-btn" class="passkey-button">
                    <svg class="passkey-icon" fill="currentColor" viewBox="0 0 24 24">
                        <path d="M12 2C9.243 2 7 4.243 7 7v3H6c-1.103 0-2 .897-2 2v8c0 1.103.897 2 2 2h12c1.103 0 2-.897 2-2v-8c0-1.103-.897-2-2-2h-1V7c0-2.757-2.243-5-5-5zM9 7c0-1.654 1.346-3 3-3s3 1.346 3 3v3H9V7zm4 10.723V20h-2v-2.277c-.595-.347-1-.984-1-1.723 0-1.103.897-2 2-2s2 .897 2 2c0 .738-.404 1.376-1 1.723z"/>
                    </svg>
                    Sign in with passkey
                </button>
                
                <div class="divider">
                    <span>or</span>
                </div>
            </div>
            {% endif %}
            
            <div class="password-section" id="password-section">
                <form method="post" action="{% url 'login' %}">
                    {% csrf_token %}
                    
                    <div class="form-group">
                        <label class="form-label" for="username">Username or Email</label>
                        <input type="text" id="username" name="username" class="form-input" required autofocus>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label" for="password">Password</label>
                        <input type="password" id="password" name="password" class="form-input" required>
                    </div>
                    
                    <input type="hidden" name="next" value="{{ request.get_full_path }}">
                    
                    <button type="submit" class="submit-button">Sign in with password</button>
                </form>
                
                {% if supports_passkey and show_passkey %}
                <button id="toggle-passkey" class="toggle-button">
                    Use passkey instead
                </button>
                {% endif %}
            </div>
            
            <div class="info-message">
                🔐 Passkeys are a secure way to sign in without a password using your fingerprint, face, or screen lock.
            </div>
        </div>
    </div>
    
    <script>
        // Check if WebAuthn is supported
        const supportsWebAuthn = window.PublicKeyCredential !== undefined;
        
        if (supportsWebAuthn && {{ show_passkey|yesno:"true,false" }}) {
            // Show passkey section by default
            document.querySelector('.passkey-section').style.display = 'block';
            
            const passkeyBtn = document.getElementById('passkey-btn');
            const passwordSection = document.getElementById('password-section');
            const toggleBtn = document.getElementById('toggle-passkey');
            
            // Toggle between passkey and password
            toggleBtn?.addEventListener('click', () => {
                document.querySelector('.passkey-section').style.display = 'block';
                passwordSection.classList.remove('active');
            });
            
            // Initially show password section if no passkey
            const urlParams = new URLSearchParams(window.location.search);
            if (urlParams.get('no_passkey') === '1') {
                document.querySelector('.passkey-section').style.display = 'none';
                passwordSection.classList.add('active');
            }
            
            // Passkey authentication
            passkeyBtn.addEventListener('click', async () => {
                try {
                    passkeyBtn.disabled = true;
                    passkeyBtn.textContent = 'Authenticating...';
                    
                    // Get authentication options
                    const optionsResponse = await fetch('{% url "passkey-auth-options" %}', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            username: document.getElementById('username')?.value || ''
                        })
                    });
                    
                    const { options } = await optionsResponse.json();
                    
                    // Convert base64 to ArrayBuffer
                    options.challenge = base64ToArrayBuffer(options.challenge);
                    if (options.allowCredentials) {
                        options.allowCredentials = options.allowCredentials.map(cred => ({
                            ...cred,
                            id: base64ToArrayBuffer(cred.id)
                        }));
                    }
                    
                    // Get credential from authenticator
                    const credential = await navigator.credentials.get({
                        publicKey: options
                    });
                    
                    // Prepare credential for server
                    const credentialJSON = {
                        id: credential.id,
                        rawId: arrayBufferToBase64(credential.rawId),
                        response: {
                            authenticatorData: arrayBufferToBase64(credential.response.authenticatorData),
                            clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
                            signature: arrayBufferToBase64(credential.response.signature),
                            userHandle: credential.response.userHandle ? arrayBufferToBase64(credential.response.userHandle) : null
                        },
                        type: credential.type
                    };
                    
                    // Verify with server
                    const verifyResponse = await fetch('{% url "passkey-auth-verify" %}', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            credential: credentialJSON
                        })
                    });
                    
                    const result = await verifyResponse.json();
                    
                    if (result.success) {
                        // Redirect to continue OIDC flow
                        window.location.href = '{{ request.get_full_path }}';
                    } else {
                        showError(result.error || 'Authentication failed');
                        passkeyBtn.disabled = false;
                        passkeyBtn.innerHTML = `
                            <svg class="passkey-icon" fill="currentColor" viewBox="0 0 24 24">
                                <path d="M12 2C9.243 2 7 4.243 7 7v3H6c-1.103 0-2 .897-2 2v8c0 1.103.897 2 2 2h12c1.103 0 2-.897 2-2v-8c0-1.103-.897-2-2-2h-1V7c0-2.757-2.243-5-5-5zM9 7c0-1.654 1.346-3 3-3s3 1.346 3 3v3H9V7zm4 10.723V20h-2v-2.277c-.595-.347-1-.984-1-1.723 0-1.103.897-2 2-2s2 .897 2 2c0 .738-.404 1.376-1 1.723z"/>
                            </svg>
                            Sign in with passkey
                        `;
                    }
                    
                } catch (error) {
                    console.error('Passkey error:', error);
                    if (error.name === 'NotAllowedError') {
                        showError('Authentication cancelled');
                    } else {
                        showError('Passkey authentication failed. Please try password instead.');
                    }
                    
                    passkeyBtn.disabled = false;
                    passkeyBtn.innerHTML = `
                        <svg class="passkey-icon" fill="currentColor" viewBox="0 0 24 24">
                            <path d="M12 2C9.243 2 7 4.243 7 7v3H6c-1.103 0-2 .897-2 2v8c0 1.103.897 2 2 2h12c1.103 0 2-.897 2-2v-8c0-1.103-.897-2-2-2h-1V7c0-2.757-2.243-5-5-5zM9 7c0-1.654 1.346-3 3-3s3 1.346 3 3v3H9V7zm4 10.723V20h-2v-2.277c-.595-.347-1-.984-1-1.723 0-1.103.897-2 2-2s2 .897 2 2c0 .738-.404 1.376-1 1.723z"/>
                        </svg>
                        Sign in with passkey
                    `;
                    
                    // Show password form as fallback
                    passwordSection.classList.add('active');
                }
            });
            
        } else {
            // WebAuthn not supported, show password form
            document.querySelector('.passkey-section').style.display = 'none';
            document.getElementById('password-section').classList.add('active');
        }
        
        // Helper functions
        function base64ToArrayBuffer(base64) {
            const binaryString = atob(base64.replace(/-/g, '+').replace(/_/g, '/'));
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes.buffer;
        }
        
        function arrayBufferToBase64(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }
        
        function showError(message) {
            const errorContainer = document.getElementById('error-container');
            errorContainer.innerHTML = `<div class="error-message">${message}</div>`;
            setTimeout(() => {
                errorContainer.innerHTML = '';
            }, 5000);
        }
    </script>
</body>
</html>
```

This is a comprehensive start to passkey implementation. Would you like me to continue with:

1. **Passkey Registration UI** - Settings page for users to register passkeys
2. **Conditional UI** - Autofill-based passkey authentication
3. **Admin Interface** - Manage passkeys in Django admin
4. **Complete Testing Suite** - Tests for all passkey flows
5. **Migration Files** - Database migrations for passkey models
6. **URL Configuration** - Complete URL routing

Let me know which parts you'd like me to complete next!