# OIDC Provider Customization Guide

This guide explains how to extend and customize the Client model, user consent system, and authentication flows in your Django OIDC provider.

## Table of Contents
- [Extending the Client Model](#extending-the-client-model)
- [Customizing User Consent](#customizing-user-consent)
- [Custom Scopes and Claims](#custom-scopes-and-claims)
- [Custom Authorization Logic](#custom-authorization-logic)
- [UI Customization](#ui-customization)
- [Advanced Patterns](#advanced-patterns)

---

## Extending the Client Model

### Method 1: Proxy Model (Simple Extensions)

Use proxy models when you only need to add methods or change behavior without new fields.

```python
# myapp/models.py
from oidc_provider.models import Client

class CustomClient(Client):
    """Extended client model with custom methods."""
    
    class Meta:
        proxy = True
    
    def is_trusted(self):
        """Check if client is a trusted first-party application."""
        return self.client_type == 'confidential' and self.owner is not None
    
    def get_allowed_redirect_hosts(self):
        """Get list of allowed hosts for redirect URIs."""
        from urllib.parse import urlparse
        hosts = []
        for uri in self.redirect_uris:
            parsed = urlparse(uri)
            if parsed.hostname:
                hosts.append(parsed.hostname)
        return hosts
    
    def requires_mfa(self):
        """Check if client requires MFA for authentication."""
        # Add custom logic
        return getattr(self, '_requires_mfa', False)
```

### Method 2: Model Inheritance (Add New Fields)

Create a custom client model with additional fields.

```python
# myapp/models.py
from django.db import models
from oidc_provider.models import Client as BaseClient

class ExtendedClient(BaseClient):
    """Extended client with additional fields."""
    
    # Additional metadata
    organization = models.CharField(max_length=200, blank=True)
    environment = models.CharField(
        max_length=20,
        choices=[
            ('development', 'Development'),
            ('staging', 'Staging'),
            ('production', 'Production'),
        ],
        default='development'
    )
    
    # Security settings
    require_mfa = models.BooleanField(
        default=False,
        help_text='Require multi-factor authentication for this client'
    )
    ip_whitelist = models.TextField(
        blank=True,
        help_text='Allowed IP addresses (one per line)'
    )
    
    # Rate limiting
    max_requests_per_hour = models.IntegerField(
        default=1000,
        help_text='Maximum API requests per hour'
    )
    
    # Notification settings
    notification_email = models.EmailField(
        blank=True,
        help_text='Email for security notifications'
    )
    webhook_url = models.URLField(
        blank=True,
        help_text='Webhook URL for events'
    )
    
    # Branding
    primary_color = models.CharField(
        max_length=7,
        default='#667eea',
        help_text='Primary brand color (hex)'
    )
    background_image = models.ImageField(
        upload_to='client_backgrounds/',
        blank=True,
        null=True
    )
    
    class Meta:
        verbose_name = 'Extended Client'
        verbose_name_plural = 'Extended Clients'
    
    @property
    def allowed_ips(self):
        """Get list of allowed IP addresses."""
        if not self.ip_whitelist:
            return []
        return [ip.strip() for ip in self.ip_whitelist.split('\n') if ip.strip()]
    
    def is_ip_allowed(self, ip_address):
        """Check if IP address is whitelisted."""
        if not self.ip_whitelist:
            return True  # No restriction
        return ip_address in self.allowed_ips
    
    def send_notification(self, subject, message):
        """Send notification to client admin."""
        if self.notification_email:
            from django.core.mail import send_mail
            send_mail(
                subject,
                message,
                'noreply@your-idp.com',
                [self.notification_email],
                fail_silently=True,
            )
```

**Create migration:**
```bash
python manage.py makemigrations
python manage.py migrate
```

### Method 3: OneToOne Relationship (Recommended)

Keep the base Client model intact and extend with a related model.

```python
# myapp/models.py
from django.db import models
from oidc_provider.models import Client

class ClientExtension(models.Model):
    """Additional fields for Client without modifying core model."""
    
    client = models.OneToOneField(
        Client,
        on_delete=models.CASCADE,
        related_name='extension'
    )
    
    # Organization info
    organization = models.CharField(max_length=200, blank=True)
    department = models.CharField(max_length=100, blank=True)
    cost_center = models.CharField(max_length=50, blank=True)
    
    # Security settings
    require_mfa = models.BooleanField(default=False)
    allowed_countries = models.TextField(
        blank=True,
        help_text='Allowed countries (ISO codes, one per line)'
    )
    session_timeout_minutes = models.IntegerField(default=30)
    
    # Compliance
    data_retention_days = models.IntegerField(default=90)
    gdpr_compliant = models.BooleanField(default=True)
    hipaa_compliant = models.BooleanField(default=False)
    
    # Analytics
    enable_analytics = models.BooleanField(default=False)
    analytics_webhook = models.URLField(blank=True)
    
    # Created/Updated tracking
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Client Extension'
        verbose_name_plural = 'Client Extensions'
    
    def __str__(self):
        return f"Extension for {self.client.name}"

# Access: client.extension.require_mfa
```

**Admin integration:**
```python
# myapp/admin.py
from django.contrib import admin
from oidc_provider.admin import ClientAdmin
from oidc_provider.models import Client
from .models import ClientExtension

class ClientExtensionInline(admin.StackedInline):
    model = ClientExtension
    can_delete = False
    verbose_name_plural = 'Extended Settings'
    fields = (
        ('organization', 'department'),
        ('require_mfa', 'session_timeout_minutes'),
        ('gdpr_compliant', 'hipaa_compliant'),
        'allowed_countries',
        'analytics_webhook',
    )

# Unregister original and re-register with inline
admin.site.unregister(Client)

@admin.register(Client)
class ExtendedClientAdmin(ClientAdmin):
    inlines = [ClientExtensionInline]
```

---

## Customizing User Consent

### 1. Custom Consent Model

Extend UserConsent with additional tracking:

```python
# myapp/models.py
from django.db import models
from oidc_provider.models import UserConsent as BaseUserConsent

class EnhancedUserConsent(models.Model):
    """Additional consent tracking."""
    
    consent = models.OneToOneField(
        BaseUserConsent,
        on_delete=models.CASCADE,
        related_name='enhanced'
    )
    
    # Granular scope consent
    individual_scopes = models.JSONField(
        default=dict,
        help_text='Individual scope consent with timestamps'
    )
    
    # Tracking
    ip_address = models.GenericIPAddressField(null=True)
    user_agent = models.TextField(blank=True)
    consent_method = models.CharField(
        max_length=20,
        choices=[
            ('explicit', 'Explicit Consent'),
            ('implicit', 'Implicit Consent'),
            ('renewed', 'Renewed Consent'),
        ],
        default='explicit'
    )
    
    # Audit trail
    consent_language = models.CharField(max_length=10, default='en')
    terms_version = models.CharField(max_length=20, blank=True)
    privacy_version = models.CharField(max_length=20, blank=True)
    
    # Revocation tracking
    revoked_at = models.DateTimeField(null=True, blank=True)
    revocation_reason = models.TextField(blank=True)
    
    def add_scope_consent(self, scope, timestamp=None):
        """Record consent for individual scope."""
        from django.utils import timezone
        timestamp = timestamp or timezone.now()
        self.individual_scopes[scope] = timestamp.isoformat()
        self.save()
    
    def has_scope_consent(self, scope):
        """Check if user has consented to specific scope."""
        return scope in self.individual_scopes
```

### 2. Custom Consent Logic

Override the authorize endpoint to customize consent behavior:

```python
# myapp/views.py
from oidc_provider.lib.endpoints.authorize import AuthorizeEndpoint as BaseAuthorizeEndpoint
from oidc_provider.models import UserConsent
from .models import EnhancedUserConsent

class CustomAuthorizeEndpoint(BaseAuthorizeEndpoint):
    """Custom authorization endpoint with enhanced consent."""
    
    def set_client_user_consent(self):
        """Save enhanced consent information."""
        # Call parent method
        super().set_client_user_consent()
        
        # Get the consent that was just created
        consent = UserConsent.objects.get(
            user=self.request.user,
            client=self.client
        )
        
        # Create or update enhanced consent
        enhanced, created = EnhancedUserConsent.objects.get_or_create(
            consent=consent
        )
        
        # Track metadata
        enhanced.ip_address = self._get_client_ip()
        enhanced.user_agent = self.request.META.get('HTTP_USER_AGENT', '')
        enhanced.consent_language = self.request.LANGUAGE_CODE
        enhanced.terms_version = self.client.terms_url  # Or version tracking
        
        # Record individual scope consent
        from django.utils import timezone
        now = timezone.now()
        for scope in self.params['scope']:
            enhanced.add_scope_consent(scope, now)
        
        enhanced.save()
        
        # Send notification if configured
        if hasattr(self.client, 'extension') and self.client.extension.analytics_webhook:
            self._send_consent_webhook(enhanced)
    
    def _get_client_ip(self):
        """Get client IP address."""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return self.request.META.get('REMOTE_ADDR')
    
    def _send_consent_webhook(self, enhanced_consent):
        """Send webhook notification about consent."""
        import requests
        import json
        
        webhook_url = self.client.extension.analytics_webhook
        payload = {
            'event': 'consent_granted',
            'user_id': str(self.request.user.id),
            'client_id': self.client.client_id,
            'scopes': self.params['scope'],
            'timestamp': enhanced_consent.consent.date_given.isoformat(),
            'ip_address': enhanced_consent.ip_address,
        }
        
        try:
            requests.post(webhook_url, json=payload, timeout=5)
        except:
            pass  # Don't fail consent if webhook fails

# Use custom endpoint in views
from oidc_provider.views import AuthorizeView

class CustomAuthorizeView(AuthorizeView):
    authorize_endpoint_class = CustomAuthorizeEndpoint
```

**Update URLs:**
```python
# myapp/urls.py
from django.urls import path
from .views import CustomAuthorizeView

urlpatterns = [
    path('authorize/', CustomAuthorizeView.as_view(), name='custom-authorize'),
]
```

### 3. Custom Consent Validation

Add custom consent requirements:

```python
# myapp/consent_validators.py
from django.core.exceptions import ValidationError

def validate_consent_requirements(user, client, scopes):
    """Validate that user meets requirements for consent."""
    
    # Check if user email is verified
    if not user.email_verified:
        raise ValidationError("Email must be verified before granting consent.")
    
    # Check age requirements
    if hasattr(client, 'extension') and client.extension.minimum_age:
        user_age = calculate_age(user.date_of_birth)
        if user_age < client.extension.minimum_age:
            raise ValidationError(f"You must be at least {client.extension.minimum_age} years old.")
    
    # Check geographic restrictions
    if hasattr(client, 'extension') and client.extension.allowed_countries:
        user_country = get_user_country(user)
        allowed = client.extension.allowed_countries.split('\n')
        if user_country not in allowed:
            raise ValidationError("This service is not available in your country.")
    
    # Check sensitive scopes
    sensitive_scopes = ['admin', 'write', 'delete']
    requested_sensitive = set(scopes) & set(sensitive_scopes)
    if requested_sensitive and not user.is_staff:
        raise ValidationError("You don't have permission for the requested access level.")
    
    return True

# Use in authorize endpoint
class CustomAuthorizeEndpoint(BaseAuthorizeEndpoint):
    def validate_params(self):
        super().validate_params()
        
        # Custom validation
        from .consent_validators import validate_consent_requirements
        try:
            validate_consent_requirements(
                self.request.user,
                self.client,
                self.params['scope']
            )
        except ValidationError as e:
            raise AuthorizeError(
                self.params['redirect_uri'],
                'access_denied',
                self.grant_type,
                description=str(e)
            )
```

---

## Custom Scopes and Claims

### 1. Define Custom Scopes

```python
# myapp/scopes.py
from oidc_provider.lib.claims import ScopeClaims

class CustomScopeClaims(ScopeClaims):
    """Custom scope claims for your application."""
    
    info_organization = (
        "Organization Information",
        "Access to your organization details"
    )
    
    info_billing = (
        "Billing Information",
        "Access to your billing and payment information"
    )
    
    info_analytics = (
        "Analytics Data",
        "Access to your usage analytics and reports"
    )
    
    write_profile = (
        "Update Profile",
        "Update your profile information"
    )
    
    admin_users = (
        "Manage Users",
        "Manage users in your organization"
    )
    
    def scope_organization(self):
        """Claims for organization scope."""
        if 'organization' not in self.scopes:
            return {}
        
        user = self.user
        dic = {}
        
        # Get user's organization
        if hasattr(user, 'organization'):
            dic['organization'] = {
                'id': user.organization.id,
                'name': user.organization.name,
                'role': user.organization_role,
            }
        
        return dic
    
    def scope_billing(self):
        """Claims for billing scope."""
        if 'billing' not in self.scopes:
            return {}
        
        user = self.user
        dic = {}
        
        # Only include if user has billing access
        if user.has_billing_access():
            dic['billing'] = {
                'customer_id': user.stripe_customer_id,
                'subscription_tier': user.subscription_tier,
            }
        
        return dic
    
    def scope_analytics(self):
        """Claims for analytics scope."""
        if 'analytics' not in self.scopes:
            return {}
        
        # Return analytics dashboard URL
        return {
            'analytics_url': f'https://analytics.example.com/user/{self.user.id}'
        }

# Configure in settings
OIDC_EXTRA_SCOPE_CLAIMS = 'myapp.scopes.CustomScopeClaims'
```

### 2. Dynamic Scopes Based on Client

```python
# myapp/scopes.py
class DynamicScopeClaims(ScopeClaims):
    """Dynamic scopes based on client configuration."""
    
    def get_scopes_info(cls, scopes):
        """Get scope information dynamically."""
        info = super().get_scopes_info(scopes)
        
        # Add client-specific scopes
        # This would need client context, shown as example
        custom_scopes = {
            'api_read': {
                'scope': 'api_read',
                'name': 'API Read Access',
                'description': 'Read-only access to the API'
            },
            'api_write': {
                'scope': 'api_write',
                'name': 'API Write Access',
                'description': 'Read and write access to the API'
            },
        }
        
        for scope in scopes:
            if scope in custom_scopes and scope not in [s['scope'] for s in info]:
                info.append(custom_scopes[scope])
        
        return info
```

### 3. Conditional Claims

```python
# myapp/claims.py
def custom_id_token_processing_hook(id_token, user=None, token=None, request=None):
    """Add custom claims to ID token based on conditions."""
    
    # Add user roles
    if hasattr(user, 'roles'):
        id_token['roles'] = [role.name for role in user.roles.all()]
    
    # Add client-specific claims
    if token and hasattr(token.client, 'extension'):
        extension = token.client.extension
        
        # Add organization context
        if extension.include_organization_context:
            id_token['org_id'] = user.organization_id
            id_token['org_name'] = user.organization.name
    
    # Add custom user attributes
    id_token['user_type'] = 'premium' if user.is_premium else 'standard'
    
    # Add metadata
    id_token['account_created'] = user.date_joined.isoformat()
    
    # Conditional claims based on scope
    if token and 'admin' in token.scope:
        id_token['admin_level'] = user.admin_level
        id_token['permissions'] = user.get_all_permissions()
    
    return id_token

# Configure in settings
OIDC_IDTOKEN_PROCESSING_HOOK = 'myapp.claims.custom_id_token_processing_hook'
```

---

## Custom Authorization Logic

### 1. Custom Client Validation

```python
# myapp/validators.py
def custom_client_validator(client, request):
    """Custom validation for client requests."""
    
    # IP whitelist check
    if hasattr(client, 'extension') and client.extension.ip_whitelist:
        client_ip = get_client_ip(request)
        if not client.extension.is_ip_allowed(client_ip):
            from oidc_provider.lib.errors import ClientIdError
            raise ClientIdError('IP address not allowed')
    
    # Time-based access
    if hasattr(client, 'extension'):
        from datetime import datetime
        current_hour = datetime.now().hour
        
        # Business hours only
        if client.extension.business_hours_only:
            if current_hour < 9 or current_hour > 17:
                raise ClientIdError('Access only allowed during business hours')
    
    # Environment check
    if hasattr(client, 'extension'):
        if client.extension.environment == 'development':
            # Additional dev environment restrictions
            if not request.META.get('HTTP_HOST', '').startswith('localhost'):
                raise ClientIdError('Development client can only be used on localhost')
    
    return True

def get_client_ip(request):
    """Extract client IP from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')
```

### 2. Custom User Authentication Hook

```python
# myapp/hooks.py
def custom_after_userlogin_hook(request, user, client):
    """Custom logic after user login."""
    
    # Check if MFA is required
    if hasattr(client, 'extension') and client.extension.require_mfa:
        if not user.mfa_verified:
            from django.shortcuts import redirect
            # Redirect to MFA verification
            return redirect('mfa-verify')
    
    # Log authentication
    from .models import AuthenticationLog
    AuthenticationLog.objects.create(
        user=user,
        client=client,
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        success=True
    )
    
    # Send notification for sensitive clients
    if hasattr(client, 'extension') and client.extension.notify_on_login:
        send_login_notification(user, client, request)
    
    # Check user status
    if user.account_locked:
        from django.http import HttpResponseForbidden
        return HttpResponseForbidden('Account is locked')
    
    # Continue normal flow
    return None

# Configure in settings
OIDC_AFTER_USERLOGIN_HOOK = 'myapp.hooks.custom_after_userlogin_hook'
```

### 3. Custom Token Generation

```python
# myapp/tokens.py
def custom_access_token_encoder(user, client, token, request):
    """Custom access token with additional claims."""
    from oidc_provider.lib.utils.token import encode_access_token_jwt
    
    # Generate standard JWT
    jwt_token = encode_access_token_jwt(user, client, token, request)
    
    # Add custom logic here if needed
    # For example, different token format for specific clients
    if hasattr(client, 'extension') and client.extension.use_opaque_tokens:
        # Return opaque token instead
        return token.access_token
    
    return jwt_token

# Configure in settings
OIDC_ACCESS_TOKEN_ENCODE = 'myapp.tokens.custom_access_token_encoder'
```

---

## UI Customization

### 1. Custom Consent Template

Create a completely custom consent template:

```html
<!-- myapp/templates/custom_consent.html -->
{% load static %}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorization - {{ client.name }}</title>
    <link rel="stylesheet" href="{% static 'myapp/consent.css' %}">
</head>
<body>
    <div class="consent-wrapper" {% if client.extension.primary_color %}
         style="--primary-color: {{ client.extension.primary_color }};"{% endif %}>
        
        <div class="consent-header">
            {% if client.extension.background_image %}
            <div class="background" style="background-image: url('{{ client.extension.background_image.url }}');"></div>
            {% endif %}
            
            <div class="header-content">
                {% if client.logo %}
                <img src="{{ client.logo.url }}" alt="{{ client.name }}" class="client-logo">
                {% endif %}
                <h1>{{ client.name }} wants to access your account</h1>
            </div>
        </div>
        
        <div class="consent-body">
            <div class="user-info">
                <p>Logged in as: <strong>{{ user.get_full_name|default:user.email }}</strong></p>
            </div>
            
            <div class="permissions">
                <h2>This app will be able to:</h2>
                <ul class="permission-list">
                    {% for scope in scopes %}
                    <li class="permission-item">
                        <svg class="permission-icon" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                        </svg>
                        <div class="permission-content">
                            <h3>{{ scope.name }}</h3>
                            <p>{{ scope.description }}</p>
                        </div>
                    </li>
                    {% endfor %}
                </ul>
            </div>
            
            {% if client.extension.show_data_retention %}
            <div class="info-box">
                <p><strong>Data retention:</strong> Your data will be retained for {{ client.extension.data_retention_days }} days.</p>
            </div>
            {% endif %}
            
            {% if client.extension.gdpr_compliant %}
            <div class="gdpr-notice">
                <p>✓ This application is GDPR compliant</p>
            </div>
            {% endif %}
        </div>
        
        <form method="post" action="{% url 'oidc_provider:authorize' %}" class="consent-form">
            {% csrf_token %}
            {{ hidden_inputs }}
            
            {% if client.reuse_consent %}
            <div class="remember-consent">
                <label>
                    <input type="checkbox" name="remember" checked>
                    <span>Don't ask again for this application</span>
                </label>
            </div>
            {% endif %}
            
            <div class="consent-actions">
                <button type="submit" class="btn-secondary">Cancel</button>
                <button type="submit" name="allow" class="btn-primary">Authorize</button>
            </div>
        </form>
        
        <div class="consent-footer">
            <p>
                By authorizing, you agree to {{ client.name }}'s 
                {% if client.terms_url %}
                <a href="{{ client.terms_url }}" target="_blank">Terms of Service</a>
                {% else %}
                terms of service
                {% endif %}
                and privacy policy.
            </p>
            {% if client.extension.organization %}
            <p class="organization">Operated by {{ client.extension.organization }}</p>
            {% endif %}
        </div>
    </div>
</body>
</html>
```

**Configure custom template:**
```python
# settings.py
OIDC_TEMPLATES = {
    'authorize': 'custom_consent.html',
    'error': 'oidc_provider/error.html',
}
```

### 2. Per-Client Template Selection

```python
# myapp/views.py
from oidc_provider.views import AuthorizeView as BaseAuthorizeView

class CustomAuthorizeView(BaseAuthorizeView):
    """Custom authorize view with per-client templates."""
    
    def get_template_names(self):
        """Select template based on client configuration."""
        authorize = self.authorize_endpoint_class(self.request)
        authorize.validate_params()
        
        client = authorize.client
        
        # Client-specific template
        if hasattr(client, 'extension') and client.extension.custom_consent_template:
            return [client.extension.custom_consent_template]
        
        # Environment-specific template
        if hasattr(client, 'extension'):
            env = client.extension.environment
            return [f'consent_{env}.html', 'oidc_provider/consent.html']
        
        # Default template
        return ['oidc_provider/consent.html']
```

---

## Advanced Patterns

### 1. Consent Expiration Policies

```python
# myapp/models.py
class ConsentPolicy(models.Model):
    """Flexible consent expiration policies."""
    
    client = models.OneToOneField(Client, on_delete=models.CASCADE, related_name='consent_policy')
    
    # Time-based expiration
    max_age_days = models.IntegerField(
        default=90,
        help_text='Maximum consent age in days'
    )
    
    # Event-based expiration
    expire_on_password_change = models.BooleanField(default=True)
    expire_on_permission_change = models.BooleanField(default=True)
    
    # Scope-based expiration
    sensitive_scopes_max_age_days = models.IntegerField(
        default=30,
        help_text='Max age for sensitive scopes'
    )
    
    # Re-consent requirements
    require_reconfirmation_after_days = models.IntegerField(
        null=True,
        blank=True,
        help_text='Require user to re-confirm consent after N days'
    )
    
    def is_consent_valid(self, consent):
        """Check if consent is still valid based on policy."""
        from datetime import timedelta
        from django.utils import timezone
        
        now = timezone.now()
        age = (now - consent.date_given).days
        
        # Check max age
        if age > self.max_age_days:
            return False
        
        # Check sensitive scopes
        sensitive_scopes = ['admin', 'write', 'delete', 'billing']
        has_sensitive = any(s in consent.scope for s in sensitive_scopes)
        if has_sensitive and age > self.sensitive_scopes_max_age_days:
            return False
        
        # Check re-confirmation
        if self.require_reconfirmation_after_days:
            if age > self.require_reconfirmation_after_days:
                # Check if user has re-confirmed
                if not hasattr(consent, 'last_confirmation'):
                    return False
        
        return True
```

### 2. Audit Trail

```python
# myapp/models.py
class ConsentAuditLog(models.Model):
    """Complete audit trail for consent actions."""
    
    ACTION_CHOICES = [
        ('granted', 'Consent Granted'),
        ('renewed', 'Consent Renewed'),
        ('modified', 'Consent Modified'),
        ('revoked', 'Consent Revoked'),
        ('expired', 'Consent Expired'),
    ]
    
    consent = models.ForeignKey(UserConsent, on_delete=models.CASCADE, related_name='audit_logs')
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # Context
    ip_address = models.GenericIPAddressField(null=True)
    user_agent = models.TextField(blank=True)
    scopes_before = models.JSONField(null=True)
    scopes_after = models.JSONField(null=True)
    
    # Actor
    actor = models.ForeignKey(
        'auth.User',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        help_text='User who performed the action (may differ from consent owner)'
    )
    
    # Reason
    reason = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['consent', '-timestamp']),
            models.Index(fields=['action', '-timestamp']),
        ]
    
    @classmethod
    def log_consent_action(cls, consent, action, request=None, actor=None, reason=''):
        """Log a consent action."""
        log = cls.objects.create(
            consent=consent,
            action=action,
            ip_address=get_client_ip(request) if request else None,
            user_agent=request.META.get('HTTP_USER_AGENT', '') if request else '',
            scopes_after=consent.scope,
            actor=actor or (request.user if request and request.user.is_authenticated else None),
            reason=reason,
        )
        return log
```

### 3. Consent Workflows

```python
# myapp/workflows.py
class ConsentWorkflow:
    """Manage complex consent workflows."""
    
    def __init__(self, user, client):
        self.user = user
        self.client = client
    
    def requires_legal_review(self, scopes):
        """Check if scopes require legal team review."""
        legal_review_scopes = ['financial', 'medical', 'legal']
        return any(scope in scopes for scope in legal_review_scopes)
    
    def requires_manager_approval(self, scopes):
        """Check if scopes require manager approval."""
        if hasattr(self.client, 'extension'):
            if self.client.extension.require_manager_approval:
                privileged_scopes = ['admin', 'delete', 'write']
                return any(scope in scopes for scope in privileged_scopes)
        return False
    
    def create_approval_request(self, scopes, requested_by):
        """Create approval request for consent."""
        from .models import ConsentApprovalRequest
        
        approval = ConsentApprovalRequest.objects.create(
            user=self.user,
            client=self.client,
            requested_scopes=scopes,
            requested_by=requested_by,
            requires_legal=self.requires_legal_review(scopes),
            requires_manager=self.requires_manager_approval(scopes),
        )
        
        # Send notifications
        if approval.requires_manager:
            self.notify_manager(approval)
        if approval.requires_legal:
            self.notify_legal_team(approval)
        
        return approval
    
    def approve_consent(self, approval, approved_by):
        """Approve and grant consent."""
        approval.approved_by = approved_by
        approval.approved_at = timezone.now()
        approval.status = 'approved'
        approval.save()
        
        # Grant consent
        from oidc_provider.models import UserConsent
        consent = UserConsent.objects.create(
            user=approval.user,
            client=approval.client,
            scope=approval.requested_scopes,
            # ... other fields
        )
        
        # Log the approval
        ConsentAuditLog.log_consent_action(
            consent,
            'granted',
            actor=approved_by,
            reason=f'Approved by {approved_by.get_full_name()}'
        )
        
        return consent
```

---

## Configuration Examples

### Complete Custom Setup Example

```python
# myapp/settings.py

# Custom scope claims
OIDC_EXTRA_SCOPE_CLAIMS = 'myapp.scopes.CustomScopeClaims'

# Custom hooks
OIDC_AFTER_USERLOGIN_HOOK = 'myapp.hooks.custom_after_userlogin_hook'
OIDC_IDTOKEN_PROCESSING_HOOK = 'myapp.claims.custom_id_token_processing_hook'
OIDC_INTROSPECTION_PROCESSING_HOOK = 'myapp.hooks.introspection_hook'

# Custom token handling
OIDC_ACCESS_TOKEN_ENCODE = 'myapp.tokens.custom_access_token_encoder'

# Templates
OIDC_TEMPLATES = {
    'authorize': 'myapp/custom_consent.html',
    'error': 'myapp/error.html',
}

# CORS for client extensions
OIDC_CORS_ALLOWED_ORIGINS = ['https://trusted-app.com']

# Session settings for extended clients
OIDC_SESSION_MANAGEMENT_ENABLE = True
```

### Admin Configuration

```python
# myapp/admin.py
from django.contrib import admin
from oidc_provider.models import Client, UserConsent
from oidc_provider.admin import ClientAdmin
from .models import ClientExtension, EnhancedUserConsent, ConsentAuditLog

# Extended Client Admin
class ClientExtensionInline(admin.StackedInline):
    model = ClientExtension
    can_delete = False

admin.site.unregister(Client)

@admin.register(Client)
class ExtendedClientAdmin(ClientAdmin):
    inlines = [ClientExtensionInline]
    list_display = ClientAdmin.list_display + ['environment', 'requires_mfa']
    list_filter = ClientAdmin.list_filter + [
        ('extension__environment', admin.AllValuesFieldListFilter),
        ('extension__require_mfa', admin.BooleanFieldListFilter),
    ]
    
    def environment(self, obj):
        return obj.extension.environment if hasattr(obj, 'extension') else '-'
    
    def requires_mfa(self, obj):
        return obj.extension.require_mfa if hasattr(obj, 'extension') else False
    requires_mfa.boolean = True

# Enhanced Consent Admin
class ConsentAuditLogInline(admin.TabularInline):
    model = ConsentAuditLog
    extra = 0
    readonly_fields = ['action', 'timestamp', 'ip_address', 'actor']
    can_delete = False

class EnhancedUserConsentInline(admin.StackedInline):
    model = EnhancedUserConsent
    can_delete = False
    readonly_fields = ['ip_address', 'user_agent', 'consent_method']

admin.site.unregister(UserConsent)

@admin.register(UserConsent)
class EnhancedUserConsentAdmin(admin.ModelAdmin):
    list_display = ['user', 'client', 'date_given', 'expires_at', 'consent_method', 'is_active']
    list_filter = ['date_given', 'client', 'enhanced__consent_method']
    search_fields = ['user__email', 'client__name']
    inlines = [EnhancedUserConsentInline, ConsentAuditLogInline]
    
    def consent_method(self, obj):
        return obj.enhanced.consent_method if hasattr(obj, 'enhanced') else '-'
    
    def is_active(self, obj):
        return not obj.has_expired()
    is_active.boolean = True
```

---

## Testing Your Customizations

```python
# myapp/tests.py
from django.test import TestCase, Client as TestClient
from django.contrib.auth import get_user_model
from oidc_provider.models import Client
from .models import ClientExtension, EnhancedUserConsent

User = get_user_model()

class ClientExtensionTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('test@example.com', password='test')
        self.client = Client.objects.create(
            name='Test Client',
            client_id='test123',
            client_type='confidential',
        )
        self.extension = ClientExtension.objects.create(
            client=self.client,
            require_mfa=True,
            organization='Test Org',
        )
    
    def test_mfa_requirement(self):
        """Test that MFA is enforced for clients that require it."""
        response = self.test_client.get('/authorize', {
            'client_id': 'test123',
            'response_type': 'code',
            'scope': 'openid',
        })
        # Assert MFA redirect
        self.assertRedirects(response, '/mfa-verify')
    
    def test_ip_whitelist(self):
        """Test IP whitelist functionality."""
        self.extension.ip_whitelist = '192.168.1.1\n10.0.0.1'
        self.extension.save()
        
        self.assertTrue(self.extension.is_ip_allowed('192.168.1.1'))
        self.assertFalse(self.extension.is_ip_allowed('1.2.3.4'))

class ConsentWorkflowTest(TestCase):
    def test_consent_audit_log(self):
        """Test that consent actions are logged."""
        # Create consent
        # ... 
        # Verify audit log entry created
        pass
```

---

## Best Practices

### 1. Always Extend, Never Modify Core
- Use OneToOne relationships for extensions
- Use hooks and signals instead of modifying core code
- Keep customizations in your app, not in oidc_provider

### 2. Security Considerations
- Validate all custom inputs
- Sanitize data before storing
- Use Django's security features (CSRF, XSS protection)
- Audit sensitive operations
- Don't expose sensitive data in tokens

### 3. Performance
- Index custom fields used in queries
- Cache expensive computations
- Use select_related/prefetch_related
- Async webhooks and notifications

### 4. Maintainability
- Document all customizations
- Write tests for custom logic
- Version your custom templates
- Keep migration files

---

## Summary

You can customize the OIDC provider by:

1. **Extending Client Model**
   - Proxy models for methods only
   - Model inheritance for new fields
   - OneToOne relationship (recommended)

2. **Customizing Consent**
   - Enhanced consent tracking
   - Custom validation logic
   - Audit trails
   - Workflow approvals

3. **Custom Scopes/Claims**
   - Define custom scopes
   - Add custom claims
   - Conditional claims based on client

4. **Custom Authorization**
   - IP whitelisting
   - Time-based access
   - Custom validation
   - MFA enforcement

5. **UI Customization**
   - Custom templates
   - Per-client branding
   - Dynamic styling

All customizations should be done in your own Django app, keeping the core OIDC provider code unchanged for easier updates.
