# -*- coding: utf-8 -*-
# Generated for WebAuthn/Passkey support

from django.db import migrations, models
import django.db.models.deletion
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('oidc_provider', '0030_add_refresh_token_customization'),
    ]

    operations = [
        # WebAuthn Credential model
        migrations.CreateModel(
            name='WebAuthnCredential',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('credential_id', models.TextField(help_text='Base64-encoded credential ID', unique=True)),
                ('public_key', models.TextField(help_text='Base64-encoded COSE public key')),
                ('aaguid', models.CharField(blank=True, help_text='Authenticator AAGUID', max_length=36)),
                ('sign_count', models.IntegerField(default=0, help_text='Signature counter for cloned device detection')),
                ('transports', models.JSONField(default=list, help_text='Supported transports (usb, nfc, ble, internal)')),
                ('authenticator_attachment', models.CharField(
                    blank=True,
                    choices=[('platform', 'Platform Authenticator'), ('cross-platform', 'Cross-Platform Authenticator')],
                    help_text='Platform (Touch ID) or Cross-platform (YubiKey)',
                    max_length=20,
                    null=True
                )),
                ('name', models.CharField(blank=True, help_text='User-given name for this credential', max_length=200)),
                ('backup_eligible', models.BooleanField(default=False, help_text='Credential can be backed up')),
                ('backup_state', models.BooleanField(default=False, help_text='Credential is currently backed up')),
                ('attestation_format', models.CharField(blank=True, max_length=50)),
                ('attestation_object', models.TextField(blank=True, help_text='Full attestation object (optional)')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('last_used_at', models.DateTimeField(blank=True, null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='webauthn_credentials', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'WebAuthn Credential',
                'verbose_name_plural': 'WebAuthn Credentials',
                'ordering': ['-created_at'],
            },
        ),
        
        # WebAuthn Challenge model
        migrations.CreateModel(
            name='WebAuthnChallenge',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('challenge', models.TextField(help_text='Base64-encoded challenge')),
                ('challenge_type', models.CharField(choices=[('registration', 'Registration'), ('authentication', 'Authentication')], max_length=20)),
                ('session_key', models.CharField(db_index=True, help_text='Session key for anonymous users', max_length=40)),
                ('client_data_json', models.TextField(blank=True, help_text='Stored client data JSON for verification')),
                ('expires_at', models.DateTimeField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('used', models.BooleanField(default=False)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='webauthn_challenges', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'WebAuthn Challenge',
                'verbose_name_plural': 'WebAuthn Challenges',
            },
        ),
        
        # Passkey Authentication Log model
        migrations.CreateModel(
            name='PasskeyAuthenticationLog',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('success', models.BooleanField()),
                ('failure_reason', models.CharField(blank=True, max_length=200)),
                ('ip_address', models.GenericIPAddressField(null=True)),
                ('user_agent', models.TextField(blank=True)),
                ('client_id', models.CharField(blank=True, max_length=255)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('credential', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='auth_logs', to='oidc_provider.webauthorncredential')),
                ('user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='passkey_auth_logs', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Passkey Authentication Log',
                'verbose_name_plural': 'Passkey Authentication Logs',
                'ordering': ['-timestamp'],
            },
        ),
        
        # Indexes
        migrations.AddIndex(
            model_name='webauthorncredential',
            index=models.Index(fields=['user', '-created_at'], name='oidc_webauthn_user_created_idx'),
        ),
        migrations.AddIndex(
            model_name='webauthorncredential',
            index=models.Index(fields=['credential_id'], name='oidc_webauthn_cred_id_idx'),
        ),
        migrations.AddIndex(
            model_name='webauthnchal lenge',
            index=models.Index(fields=['session_key', 'challenge_type'], name='oidc_challenge_session_idx'),
        ),
        migrations.AddIndex(
            model_name='webauthnchallenge',
            index=models.Index(fields=['expires_at'], name='oidc_challenge_expires_idx'),
        ),
    ]
