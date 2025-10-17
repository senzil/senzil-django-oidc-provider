# Practical Customization Examples

This document provides ready-to-use examples for common customization scenarios.

## Table of Contents
- [Example 1: Multi-tenant SaaS Platform](#example-1-multi-tenant-saas-platform)
- [Example 2: Enterprise SSO with Org Hierarchy](#example-2-enterprise-sso-with-org-hierarchy)
- [Example 3: Healthcare Application (HIPAA)](#example-3-healthcare-application-hipaa)
- [Example 4: Financial Services (PCI DSS)](#example-4-financial-services-pci-dss)
- [Example 5: API Marketplace](#example-5-api-marketplace)

---

## Example 1: Multi-tenant SaaS Platform

### Scenario
SaaS platform where each organization (tenant) has its own OAuth apps with isolated consent and branding.

### Implementation

**1. Extended Models:**
```python
# myapp/models.py
from django.db import models
from django.contrib.auth.models import User
from oidc_provider.models import Client

class Organization(models.Model):
    """Multi-tenant organization."""
    name = models.CharField(max_length=200)
    slug = models.SlugField(unique=True)
    domain = models.CharField(max_length=255, unique=True)
    
    # Branding
    logo = models.ImageField(upload_to='org_logos/', blank=True)
    primary_color = models.CharField(max_length=7, default='#667eea')
    custom_css = models.TextField(blank=True)
    
    # Settings
    max_apps_per_org = models.IntegerField(default=5)
    enable_sso = models.BooleanField(default=True)
    
    # Billing
    subscription_tier = models.CharField(
        max_length=20,
        choices=[
            ('free', 'Free'),
            ('pro', 'Pro'),
            ('enterprise', 'Enterprise'),
        ],
        default='free'
    )
    
    def __str__(self):
        return self.name

class OrganizationMember(models.Model):
    """Organization membership."""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='org_memberships')
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='members')
    role = models.CharField(
        max_length=20,
        choices=[
            ('owner', 'Owner'),
            ('admin', 'Admin'),
            ('developer', 'Developer'),
            ('member', 'Member'),
        ]
    )
    joined_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ('user', 'organization')

class TenantClient(models.Model):
    """Organization-specific OAuth client."""
    client = models.OneToOneField(Client, on_delete=models.CASCADE, related_name='tenant_info')
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='oauth_clients')
    
    # Tenant-specific settings
    environment = models.CharField(
        max_length=20,
        choices=[('dev', 'Development'), ('staging', 'Staging'), ('prod', 'Production')],
        default='dev'
    )
    
    # Resource limits based on subscription
    @property
    def max_users(self):
        tier_limits = {'free': 10, 'pro': 100, 'enterprise': -1}  # -1 = unlimited
        return tier_limits.get(self.organization.subscription_tier, 10)
    
    def can_create_client(self):
        """Check if org can create more clients."""
        current_count = self.organization.oauth_clients.count()
        return current_count < self.organization.max_apps_per_org
```

**2. Custom Authorization View:**
```python
# myapp/views.py
from django.shortcuts import render, redirect
from oidc_provider.views import AuthorizeView
from oidc_provider.lib.endpoints.authorize import AuthorizeEndpoint
from .models import TenantClient

class TenantAuthorizeEndpoint(AuthorizeEndpoint):
    """Multi-tenant authorization endpoint."""
    
    def validate_params(self):
        super().validate_params()
        
        # Verify client belongs to an organization
        if not hasattr(self.client, 'tenant_info'):
            raise AuthorizeError(
                self.params['redirect_uri'],
                'unauthorized_client',
                self.grant_type,
                description='Client not associated with an organization'
            )
        
        tenant = self.client.tenant_info
        
        # Verify user is member of organization
        user_orgs = self.request.user.org_memberships.values_list('organization_id', flat=True)
        if tenant.organization.id not in user_orgs:
            raise AuthorizeError(
                self.params['redirect_uri'],
                'access_denied',
                self.grant_type,
                description='User is not a member of this organization'
            )
        
        # Check subscription limits
        if tenant.organization.subscription_tier == 'free':
            # Free tier: limit scopes
            allowed_scopes = ['openid', 'profile', 'email']
            requested = set(self.params['scope'])
            if not requested.issubset(allowed_scopes):
                raise AuthorizeError(
                    self.params['redirect_uri'],
                    'invalid_scope',
                    self.grant_type,
                    description='Upgrade to Pro for additional scopes'
                )

class TenantAuthorizeView(AuthorizeView):
    authorize_endpoint_class = TenantAuthorizeEndpoint
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Add tenant branding
        client = context['client']
        if hasattr(client, 'tenant_info'):
            org = client.tenant_info.organization
            context['organization'] = org
            context['primary_color'] = org.primary_color
            context['org_logo'] = org.logo
        
        return context
```

**3. Tenant-specific Template:**
```html
<!-- myapp/templates/tenant_consent.html -->
{% load static %}
<!DOCTYPE html>
<html>
<head>
    <title>{{ organization.name }} - Authorization</title>
    <style>
        :root {
            --primary-color: {{ primary_color|default:"#667eea" }};
        }
        /* Organization custom CSS */
        {{ organization.custom_css|safe }}
    </style>
</head>
<body>
    <div class="tenant-consent">
        <div class="org-header">
            {% if org_logo %}
            <img src="{{ org_logo.url }}" alt="{{ organization.name }}">
            {% endif %}
            <h1>{{ organization.name }}</h1>
        </div>
        
        <div class="client-info">
            <h2>{{ client.name }} wants to access your account</h2>
            <p class="environment-badge">{{ client.tenant_info.environment|upper }}</p>
        </div>
        
        <!-- Rest of consent form -->
        <form method="post" action="{% url 'oidc_provider:authorize' %}">
            {% csrf_token %}
            {{ hidden_inputs }}
            
            <div class="scopes">
                {% for scope in scopes %}
                <div class="scope-item">
                    <strong>{{ scope.name }}</strong>
                    <p>{{ scope.description }}</p>
                </div>
                {% endfor %}
            </div>
            
            <div class="tier-notice">
                {% if organization.subscription_tier == 'free' %}
                <p>⚠️ Free tier - limited to basic scopes. <a href="/upgrade">Upgrade to Pro</a></p>
                {% endif %}
            </div>
            
            <button type="submit" name="allow">Authorize</button>
            <button type="submit">Cancel</button>
        </form>
    </div>
</body>
</html>
```

**4. Custom Scopes with Tenant Context:**
```python
# myapp/scopes.py
from oidc_provider.lib.claims import ScopeClaims

class TenantScopeClaims(ScopeClaims):
    """Tenant-aware scope claims."""
    
    info_organization = (
        "Organization Information",
        "Access to your organization profile and settings"
    )
    
    admin_organization = (
        "Manage Organization",
        "Manage organization members and settings"
    )
    
    def scope_organization(self):
        """Include organization context in token."""
        if 'organization' not in self.scopes:
            return {}
        
        user = self.user
        client = self.token.client
        
        # Get user's membership in client's organization
        if hasattr(client, 'tenant_info'):
            org = client.tenant_info.organization
            try:
                membership = user.org_memberships.get(organization=org)
                return {
                    'org_id': org.id,
                    'org_name': org.name,
                    'org_domain': org.domain,
                    'org_role': membership.role,
                    'org_subscription': org.subscription_tier,
                }
            except:
                pass
        
        return {}
    
    def scope_admin_organization(self):
        """Admin scope - only for org admins/owners."""
        if 'admin:organization' not in self.scopes:
            return {}
        
        user = self.user
        client = self.token.client
        
        if hasattr(client, 'tenant_info'):
            org = client.tenant_info.organization
            try:
                membership = user.org_memberships.get(organization=org)
                if membership.role in ['owner', 'admin']:
                    return {
                        'org_admin': True,
                        'can_manage_members': True,
                        'can_manage_apps': True,
                    }
            except:
                pass
        
        return {'org_admin': False}

# settings.py
OIDC_EXTRA_SCOPE_CLAIMS = 'myapp.scopes.TenantScopeClaims'
```

---

## Example 2: Enterprise SSO with Org Hierarchy

### Scenario
Enterprise with department hierarchy, role-based access control, and delegated administration.

### Implementation

**1. Models:**
```python
# myapp/models.py
from django.db import models
from django.contrib.auth.models import User
from oidc_provider.models import Client

class Enterprise(models.Model):
    """Top-level enterprise."""
    name = models.CharField(max_length=200)
    domain = models.CharField(max_length=255)
    saml_metadata_url = models.URLField(blank=True)
    
    # SSO Settings
    enforce_sso = models.BooleanField(default=False)
    allowed_auth_methods = models.JSONField(default=list)  # ['password', 'saml', 'ldap']
    
    # Security policies
    require_mfa = models.BooleanField(default=False)
    password_expiry_days = models.IntegerField(default=90)
    session_timeout_minutes = models.IntegerField(default=480)  # 8 hours

class Department(models.Model):
    """Department within enterprise."""
    enterprise = models.ForeignKey(Enterprise, on_delete=models.CASCADE, related_name='departments')
    name = models.CharField(max_length=200)
    parent = models.ForeignKey('self', null=True, blank=True, on_delete=models.CASCADE, related_name='subdepartments')
    
    # Department-specific policies
    data_classification = models.CharField(
        max_length=20,
        choices=[
            ('public', 'Public'),
            ('internal', 'Internal'),
            ('confidential', 'Confidential'),
            ('restricted', 'Restricted'),
        ],
        default='internal'
    )
    
    def get_ancestors(self):
        """Get all parent departments."""
        ancestors = []
        current = self.parent
        while current:
            ancestors.append(current)
            current = current.parent
        return ancestors
    
    def get_descendants(self):
        """Get all child departments."""
        descendants = list(self.subdepartments.all())
        for subdept in self.subdepartments.all():
            descendants.extend(subdept.get_descendants())
        return descendants

class EnterpriseUser(models.Model):
    """Enterprise user profile."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='enterprise_profile')
    enterprise = models.ForeignKey(Enterprise, on_delete=models.CASCADE, related_name='users')
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, related_name='users')
    
    # Employee info
    employee_id = models.CharField(max_length=50, unique=True)
    job_title = models.CharField(max_length=200)
    manager = models.ForeignKey('self', null=True, blank=True, on_delete=models.SET_NULL, related_name='direct_reports')
    
    # Access control
    security_clearance = models.CharField(
        max_length=20,
        choices=[
            ('basic', 'Basic'),
            ('elevated', 'Elevated'),
            ('privileged', 'Privileged'),
        ],
        default='basic'
    )
    
    # Compliance
    terms_accepted_at = models.DateTimeField(null=True)
    background_check_date = models.DateField(null=True)

class EnterpriseClient(models.Model):
    """Enterprise application."""
    client = models.OneToOneField(Client, on_delete=models.CASCADE, related_name='enterprise_info')
    enterprise = models.ForeignKey(Enterprise, on_delete=models.CASCADE, related_name='applications')
    departments = models.ManyToManyField(Department, blank=True, related_name='applications')
    
    # Access control
    min_security_clearance = models.CharField(
        max_length=20,
        choices=[('basic', 'Basic'), ('elevated', 'Elevated'), ('privileged', 'Privileged')],
        default='basic'
    )
    
    # Compliance
    requires_background_check = models.BooleanField(default=False)
    data_classification = models.CharField(
        max_length=20,
        choices=[('public', 'Public'), ('internal', 'Internal'), ('confidential', 'Confidential'), ('restricted', 'Restricted')],
        default='internal'
    )
```

**2. Custom Authorization with Hierarchy:**
```python
# myapp/authorization.py
from oidc_provider.lib.endpoints.authorize import AuthorizeEndpoint
from oidc_provider.lib.errors import AuthorizeError
from .models import EnterpriseUser, EnterpriseClient

class EnterpriseAuthorizeEndpoint(AuthorizeEndpoint):
    """Enterprise authorization with hierarchical access control."""
    
    def validate_params(self):
        super().validate_params()
        
        if not hasattr(self.client, 'enterprise_info'):
            return  # Not an enterprise client
        
        app = self.client.enterprise_info
        
        # Check if user has enterprise profile
        if not hasattr(self.request.user, 'enterprise_profile'):
            raise AuthorizeError(
                self.params['redirect_uri'],
                'access_denied',
                self.grant_type,
                description='Enterprise access required'
            )
        
        user_profile = self.request.user.enterprise_profile
        
        # 1. Enterprise membership check
        if user_profile.enterprise != app.enterprise:
            raise AuthorizeError(
                self.params['redirect_uri'],
                'access_denied',
                self.grant_type,
                description='Access denied: different enterprise'
            )
        
        # 2. Department access check
        if app.departments.exists():
            user_dept = user_profile.department
            allowed_depts = list(app.departments.all())
            
            # Include parent and child departments
            for dept in list(allowed_depts):
                allowed_depts.extend(dept.get_descendants())
                allowed_depts.extend(dept.get_ancestors())
            
            if user_dept not in allowed_depts:
                raise AuthorizeError(
                    self.params['redirect_uri'],
                    'access_denied',
                    self.grant_type,
                    description='Department access required'
                )
        
        # 3. Security clearance check
        clearance_levels = {'basic': 1, 'elevated': 2, 'privileged': 3}
        user_level = clearance_levels.get(user_profile.security_clearance, 0)
        required_level = clearance_levels.get(app.min_security_clearance, 0)
        
        if user_level < required_level:
            raise AuthorizeError(
                self.params['redirect_uri'],
                'access_denied',
                self.grant_type,
                description=f'Security clearance {app.min_security_clearance} required'
            )
        
        # 4. Background check requirement
        if app.requires_background_check and not user_profile.background_check_date:
            raise AuthorizeError(
                self.params['redirect_uri'],
                'access_denied',
                self.grant_type,
                description='Background check required'
            )
        
        # 5. MFA requirement
        if app.enterprise.require_mfa and not self.request.session.get('mfa_verified'):
            # Redirect to MFA
            from django.shortcuts import redirect
            self.request.session['pending_auth'] = self.params
            return redirect('mfa-verify')
        
        # 6. Data classification check
        user_dept_classification = user_profile.department.data_classification if user_profile.department else 'public'
        classifications = {'public': 0, 'internal': 1, 'confidential': 2, 'restricted': 3}
        
        user_class_level = classifications.get(user_dept_classification, 0)
        app_class_level = classifications.get(app.data_classification, 0)
        
        if user_class_level < app_class_level:
            raise AuthorizeError(
                self.params['redirect_uri'],
                'access_denied',
                self.grant_type,
                description='Insufficient data classification clearance'
            )
```

**3. Hierarchical Claims:**
```python
# myapp/claims.py
def enterprise_claims_hook(id_token, user=None, token=None, request=None):
    """Add enterprise hierarchy to ID token."""
    
    if not user or not hasattr(user, 'enterprise_profile'):
        return id_token
    
    profile = user.enterprise_profile
    
    # Basic enterprise info
    id_token['enterprise'] = {
        'id': profile.enterprise.id,
        'name': profile.enterprise.name,
        'domain': profile.enterprise.domain,
    }
    
    # Employee info
    id_token['employee_id'] = profile.employee_id
    id_token['job_title'] = profile.job_title
    id_token['security_clearance'] = profile.security_clearance
    
    # Department hierarchy
    if profile.department:
        dept_hierarchy = []
        for dept in [profile.department] + profile.department.get_ancestors():
            dept_hierarchy.append({
                'id': dept.id,
                'name': dept.name,
                'classification': dept.data_classification,
            })
        id_token['departments'] = dept_hierarchy
    
    # Manager chain
    if profile.manager:
        id_token['manager'] = {
            'employee_id': profile.manager.employee_id,
            'name': profile.manager.user.get_full_name(),
            'email': profile.manager.user.email,
        }
    
    # Role-based permissions
    id_token['permissions'] = get_user_permissions(user, token.client if token else None)
    
    return id_token

def get_user_permissions(user, client):
    """Calculate permissions based on role and app."""
    permissions = []
    
    if not hasattr(user, 'enterprise_profile'):
        return permissions
    
    profile = user.enterprise_profile
    
    # Base permissions
    permissions.append('read:profile')
    
    # Clearance-based permissions
    if profile.security_clearance in ['elevated', 'privileged']:
        permissions.append('read:reports')
    
    if profile.security_clearance == 'privileged':
        permissions.append('admin:users')
        permissions.append('write:config')
    
    # Department-based permissions
    if profile.department:
        permissions.append(f'access:dept:{profile.department.id}')
        
        # Access to child departments
        for subdept in profile.department.get_descendants():
            permissions.append(f'access:dept:{subdept.id}')
    
    # Manager permissions
    if profile.direct_reports.exists():
        permissions.append('manage:team')
    
    return permissions

# settings.py
OIDC_IDTOKEN_PROCESSING_HOOK = 'myapp.claims.enterprise_claims_hook'
```

---

## Example 3: Healthcare Application (HIPAA)

### Scenario
HIPAA-compliant healthcare application with patient consent, audit trails, and data access controls.

### Implementation

**1. Models:**
```python
# myapp/models.py
from django.db import models
from django.contrib.auth.models import User
from oidc_provider.models import Client, UserConsent

class HealthcareProvider(models.Model):
    """Healthcare organization."""
    name = models.CharField(max_length=200)
    npi_number = models.CharField(max_length=10, unique=True)  # National Provider Identifier
    
    # HIPAA compliance
    hipaa_certified = models.BooleanField(default=False)
    certification_date = models.DateField(null=True)
    baa_signed_date = models.DateField(null=True)  # Business Associate Agreement
    
    # Audit requirements
    audit_retention_years = models.IntegerField(default=6)
    enable_audit_trail = models.BooleanField(default=True)

class HealthcareClient(models.Model):
    """HIPAA-compliant OAuth client."""
    client = models.OneToOneField(Client, on_delete=models.CASCADE, related_name='healthcare_info')
    provider = models.ForeignKey(HealthcareProvider, on_delete=models.CASCADE, related_name='applications')
    
    # Compliance
    handles_phi = models.BooleanField(default=True, help_text='Handles Protected Health Information')
    encryption_required = models.BooleanField(default=True)
    
    # Access controls
    allowed_data_types = models.JSONField(default=list)  # ['demographics', 'diagnoses', 'medications', etc.]
    purpose_of_use = models.CharField(
        max_length=50,
        choices=[
            ('treatment', 'Treatment'),
            ('payment', 'Payment'),
            ('operations', 'Healthcare Operations'),
            ('research', 'Research'),
        ]
    )
    
    # Minimum necessary standard
    min_necessary_justification = models.TextField(
        help_text='Justification for data access under minimum necessary standard'
    )

class PatientConsent(models.Model):
    """HIPAA-compliant patient consent."""
    consent = models.OneToOneField(UserConsent, on_delete=models.CASCADE, related_name='patient_consent')
    
    # Patient information
    patient_id = models.CharField(max_length=50)
    
    # Consent specifics
    phi_types_authorized = models.JSONField(default=list)  # Specific PHI types
    purpose_disclosed = models.CharField(max_length=100)
    expiration_date = models.DateField()
    
    # Legal requirements
    consent_form_url = models.URLField()
    signature_method = models.CharField(
        max_length=20,
        choices=[
            ('electronic', 'Electronic Signature'),
            ('written', 'Written Signature'),
            ('verbal', 'Verbal (Documented)'),
        ]
    )
    witness = models.CharField(max_length=200, blank=True)
    
    # Right to revoke
    revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True)
    revocation_method = models.CharField(max_length=50, blank=True)
    
    # Audit
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    
    def revoke_consent(self, method='electronic', user=None):
        """Revoke patient consent."""
        from django.utils import timezone
        
        self.revoked = True
        self.revoked_at = timezone.now()
        self.revocation_method = method
        self.save()
        
        # Create audit log
        HIPAAAuditLog.objects.create(
            action='consent_revoked',
            patient_id=self.patient_id,
            client=self.consent.client,
            user=user or self.consent.user,
            details=f'Consent revoked via {method}',
            phi_accessed=False,
        )

class HIPAAAuditLog(models.Model):
    """HIPAA-required audit trail."""
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # Who
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    patient_id = models.CharField(max_length=50)
    
    # What
    action = models.CharField(
        max_length=50,
        choices=[
            ('consent_granted', 'Consent Granted'),
            ('consent_revoked', 'Consent Revoked'),
            ('phi_accessed', 'PHI Accessed'),
            ('phi_disclosed', 'PHI Disclosed'),
            ('phi_modified', 'PHI Modified'),
            ('access_denied', 'Access Denied'),
        ]
    )
    phi_accessed = models.BooleanField(default=False)
    phi_types = models.JSONField(default=list)
    
    # Where
    client = models.ForeignKey(Client, on_delete=models.SET_NULL, null=True)
    ip_address = models.GenericIPAddressField()
    
    # Why
    purpose = models.CharField(max_length=100)
    justification = models.TextField(blank=True)
    
    # Details
    details = models.JSONField(default=dict)
    
    # Outcome
    success = models.BooleanField(default=True)
    failure_reason = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['patient_id', '-timestamp']),
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['action', '-timestamp']),
        ]
```

**2. HIPAA-Compliant Authorization:**
```python
# myapp/authorization.py
from oidc_provider.lib.endpoints.authorize import AuthorizeEndpoint
from oidc_provider.lib.errors import AuthorizeError
from .models import HealthcareClient, PatientConsent, HIPAAAuditLog

class HIPAAAuthorizeEndpoint(AuthorizeEndpoint):
    """HIPAA-compliant authorization endpoint."""
    
    def validate_params(self):
        super().validate_params()
        
        if not hasattr(self.client, 'healthcare_info'):
            return
        
        healthcare_client = self.client.healthcare_info
        
        # 1. Provider HIPAA certification check
        if not healthcare_client.provider.hipaa_certified:
            self._log_access_denied('Provider not HIPAA certified')
            raise AuthorizeError(
                self.params['redirect_uri'],
                'access_denied',
                self.grant_type,
                description='Provider must be HIPAA certified'
            )
        
        # 2. BAA requirement
        if not healthcare_client.provider.baa_signed_date:
            self._log_access_denied('BAA not signed')
            raise AuthorizeError(
                self.params['redirect_uri'],
                'access_denied',
                self.grant_type,
                description='Business Associate Agreement required'
            )
        
        # 3. Encryption requirement
        if healthcare_client.encryption_required:
            if not self.client.id_token_encrypted_response_alg:
                self._log_access_denied('Encryption not configured')
                raise AuthorizeError(
                    self.params['redirect_uri'],
                    'access_denied',
                    self.grant_type,
                    description='Token encryption required for PHI access'
                )
        
        # 4. Purpose of use validation
        requested_purpose = self.request.GET.get('purpose_of_use')
        if healthcare_client.handles_phi and not requested_purpose:
            raise AuthorizeError(
                self.params['redirect_uri'],
                'invalid_request',
                self.grant_type,
                description='Purpose of use required for PHI access'
            )
        
        if requested_purpose != healthcare_client.purpose_of_use:
            self._log_access_denied(f'Invalid purpose: {requested_purpose}')
            raise AuthorizeError(
                self.params['redirect_uri'],
                'access_denied',
                self.grant_type,
                description=f'Application authorized for {healthcare_client.purpose_of_use} only'
            )
    
    def set_client_user_consent(self):
        """Create HIPAA-compliant consent."""
        # Standard consent
        super().set_client_user_consent()
        
        # Get created consent
        from oidc_provider.models import UserConsent
        consent = UserConsent.objects.get(
            user=self.request.user,
            client=self.client
        )
        
        # Create patient consent
        from datetime import timedelta
        from django.utils import timezone
        
        patient_consent = PatientConsent.objects.create(
            consent=consent,
            patient_id=self.request.user.username,  # Or actual patient ID
            phi_types_authorized=self._get_phi_types_from_scopes(),
            purpose_disclosed=self.request.GET.get('purpose_of_use', ''),
            expiration_date=timezone.now().date() + timedelta(days=365),
            consent_form_url=self._generate_consent_form_url(),
            signature_method='electronic',
            ip_address=self._get_client_ip(),
            user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
        )
        
        # Audit log
        HIPAAAuditLog.objects.create(
            action='consent_granted',
            user=self.request.user,
            patient_id=patient_consent.patient_id,
            client=self.client,
            purpose=patient_consent.purpose_disclosed,
            phi_accessed=False,
            phi_types=patient_consent.phi_types_authorized,
            ip_address=patient_consent.ip_address,
            details={
                'scopes': self.params['scope'],
                'consent_id': consent.id,
            },
            success=True,
        )
    
    def _get_phi_types_from_scopes(self):
        """Map scopes to PHI types."""
        scope_to_phi = {
            'patient:demographics': ['name', 'address', 'dob', 'ssn'],
            'patient:clinical': ['diagnoses', 'procedures', 'lab_results'],
            'patient:medications': ['medications', 'allergies'],
            'patient:billing': ['billing_info', 'insurance'],
        }
        
        phi_types = []
        for scope in self.params['scope']:
            if scope in scope_to_phi:
                phi_types.extend(scope_to_phi[scope])
        
        return list(set(phi_types))
    
    def _log_access_denied(self, reason):
        """Log access denial for audit."""
        HIPAAAuditLog.objects.create(
            action='access_denied',
            user=self.request.user,
            patient_id=self.request.user.username,
            client=self.client,
            purpose='',
            phi_accessed=False,
            ip_address=self._get_client_ip(),
            success=False,
            failure_reason=reason,
        )
    
    def _get_client_ip(self):
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return self.request.META.get('REMOTE_ADDR')
    
    def _generate_consent_form_url(self):
        """Generate URL to consent form PDF."""
        # Implementation to generate/store consent form
        return f'/consent-forms/{self.request.user.id}/{self.client.client_id}/'
```

**3. Audit Middleware:**
```python
# myapp/middleware.py
from .models import HIPAAAuditLog

class HIPAAAuditMiddleware:
    """Audit all PHI access."""
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        response = self.get_response(request)
        
        # Audit PHI access
        if self._is_phi_endpoint(request.path):
            self._log_phi_access(request, response)
        
        return response
    
    def _is_phi_endpoint(self, path):
        """Check if endpoint handles PHI."""
        phi_endpoints = ['/api/patient/', '/fhir/', '/hl7/']
        return any(path.startswith(endpoint) for endpoint in phi_endpoints)
    
    def _log_phi_access(self, request, response):
        """Log PHI access for HIPAA compliance."""
        if request.user.is_authenticated:
            HIPAAAuditLog.objects.create(
                action='phi_accessed',
                user=request.user,
                patient_id=request.GET.get('patient_id', ''),
                phi_accessed=True,
                ip_address=self._get_client_ip(request),
                purpose=request.META.get('HTTP_X_PURPOSE_OF_USE', ''),
                success=response.status_code < 400,
                details={
                    'method': request.method,
                    'path': request.path,
                    'status_code': response.status_code,
                },
            )
    
    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')
```

---

## Summary

These examples demonstrate:

1. **Multi-tenant SaaS**: Organization isolation, subscription tiers, tenant branding
2. **Enterprise SSO**: Hierarchical departments, role-based access, security clearances
3. **Healthcare (HIPAA)**: PHI protection, audit trails, patient consent

Each example shows:
- ✅ Model extensions
- ✅ Custom authorization logic
- ✅ Specialized consent handling
- ✅ Compliance requirements
- ✅ Audit logging

Use these as templates for your specific use case!
