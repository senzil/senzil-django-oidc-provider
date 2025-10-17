"""
Django admin configuration for WebAuthn/Passkey models.
"""

from django.contrib import admin
from django.utils.html import format_html
from django.utils import timezone

from .models import WebAuthnCredential, WebAuthnChallenge, PasskeyAuthenticationLog


@admin.register(WebAuthnCredential)
class WebAuthnCredentialAdmin(admin.ModelAdmin):
    list_display = [
        'user',
        'name_display',
        'authenticator_type',
        'backup_status',
        'created_at',
        'last_used_display',
        'is_active',
    ]
    list_filter = [
        'is_active',
        'authenticator_attachment',
        'backup_state',
        'created_at',
    ]
    search_fields = [
        'user__username',
        'user__email',
        'name',
        'credential_id',
    ]
    readonly_fields = [
        'user',
        'credential_id',
        'public_key',
        'aaguid',
        'sign_count',
        'transports',
        'authenticator_attachment',
        'backup_eligible',
        'backup_state',
        'attestation_format',
        'created_at',
        'last_used_at',
    ]
    fieldsets = [
        ('User Information', {
            'fields': ('user', 'name', 'is_active'),
        }),
        ('Credential Details', {
            'fields': (
                'credential_id',
                'public_key',
                'sign_count',
                'aaguid',
            ),
        }),
        ('Authenticator Properties', {
            'fields': (
                'authenticator_attachment',
                'transports',
                'backup_eligible',
                'backup_state',
            ),
        }),
        ('Attestation', {
            'fields': (
                'attestation_format',
                'attestation_object',
            ),
            'classes': ('collapse',),
        }),
        ('Timestamps', {
            'fields': (
                'created_at',
                'last_used_at',
            ),
        }),
    ]
    
    def name_display(self, obj):
        if obj.name:
            return obj.name
        return format_html('<em>Unnamed passkey</em>')
    name_display.short_description = 'Name'
    
    def authenticator_type(self, obj):
        if obj.authenticator_attachment == 'platform':
            return format_html('<span style="color: #2563eb;">🔐 Platform</span>')
        elif obj.authenticator_attachment == 'cross-platform':
            return format_html('<span style="color: #7c3aed;">🔑 Cross-platform</span>')
        return '-'
    authenticator_type.short_description = 'Type'
    
    def backup_status(self, obj):
        if obj.backup_state:
            return format_html('<span style="color: #059669;">☁️ Synced</span>')
        elif obj.backup_eligible:
            return format_html('<span style="color: #f59e0b;">☁️ Eligible</span>')
        return format_html('<span style="color: #6b7280;">Local only</span>')
    backup_status.short_description = 'Backup'
    
    def last_used_display(self, obj):
        if obj.last_used_at:
            delta = timezone.now() - obj.last_used_at
            if delta.days == 0:
                return 'Today'
            elif delta.days == 1:
                return 'Yesterday'
            elif delta.days < 7:
                return f'{delta.days} days ago'
            else:
                return obj.last_used_at.strftime('%Y-%m-%d')
        return format_html('<em>Never</em>')
    last_used_display.short_description = 'Last Used'
    
    def has_add_permission(self, request):
        # Passkeys can only be created via WebAuthn flow
        return False


@admin.register(WebAuthnChallenge)
class WebAuthnChallengeAdmin(admin.ModelAdmin):
    list_display = [
        'id',
        'user',
        'challenge_type',
        'created_at',
        'expires_at',
        'is_expired',
        'used',
    ]
    list_filter = [
        'challenge_type',
        'used',
        'created_at',
    ]
    search_fields = [
        'user__username',
        'session_key',
    ]
    readonly_fields = [
        'user',
        'challenge',
        'challenge_type',
        'session_key',
        'client_data_json',
        'expires_at',
        'created_at',
        'used',
    ]
    
    def is_expired(self, obj):
        if timezone.now() >= obj.expires_at:
            return format_html('<span style="color: #dc2626;">✗ Expired</span>')
        return format_html('<span style="color: #059669;">✓ Valid</span>')
    is_expired.short_description = 'Status'
    
    def has_add_permission(self, request):
        # Challenges are created automatically
        return False


@admin.register(PasskeyAuthenticationLog)
class PasskeyAuthenticationLogAdmin(admin.ModelAdmin):
    list_display = [
        'timestamp',
        'user',
        'credential_display',
        'success_display',
        'ip_address',
        'client_id',
    ]
    list_filter = [
        'success',
        'timestamp',
    ]
    search_fields = [
        'user__username',
        'user__email',
        'ip_address',
        'client_id',
    ]
    readonly_fields = [
        'user',
        'credential',
        'success',
        'failure_reason',
        'ip_address',
        'user_agent',
        'client_id',
        'timestamp',
    ]
    date_hierarchy = 'timestamp'
    
    def credential_display(self, obj):
        if obj.credential:
            return obj.credential.name or 'Unnamed passkey'
        return '-'
    credential_display.short_description = 'Passkey'
    
    def success_display(self, obj):
        if obj.success:
            return format_html('<span style="color: #059669;">✓ Success</span>')
        return format_html(
            '<span style="color: #dc2626;">✗ Failed</span><br><small>{}</small>',
            obj.failure_reason
        )
    success_display.short_description = 'Result'
    
    def has_add_permission(self, request):
        # Logs are created automatically
        return False
    
    def has_change_permission(self, request, obj=None):
        # Logs are read-only
        return False
