# -*- coding: utf-8 -*-
# Generated for allowed domains and origin tracking

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_provider', '0031_add_passkey_support'),
    ]

    operations = [
        # Add allowed domains to Client
        migrations.AddField(
            model_name='client',
            name='allowed_origins',
            field=models.TextField(
                blank=True,
                verbose_name='Allowed Origins',
                help_text='Allowed origin domains (one per line). If empty, all origins are allowed. Format: https://example.com'
            ),
        ),
        
        migrations.AddField(
            model_name='client',
            name='strict_origin_validation',
            field=models.BooleanField(
                default=False,
                verbose_name='Strict Origin Validation',
                help_text='Require origin header and validate against allowed origins'
            ),
        ),
        
        migrations.AddField(
            model_name='client',
            name='include_origin_in_tokens',
            field=models.BooleanField(
                default=True,
                verbose_name='Include Origin in Tokens',
                help_text='Include request origin domain as issuer/claim in JWT tokens'
            ),
        ),
        
        migrations.AddField(
            model_name='client',
            name='allowed_domains',
            field=models.TextField(
                blank=True,
                verbose_name='Allowed Domains (Legacy)',
                help_text='Comma-separated list of allowed domains. Use allowed_origins instead.'
            ),
        ),
        
        # Add origin tracking to Token
        migrations.AddField(
            model_name='token',
            name='origin_domain',
            field=models.CharField(
                max_length=255,
                blank=True,
                verbose_name='Origin Domain',
                help_text='Domain from which the token request originated'
            ),
        ),
        
        # Add origin tracking to Code
        migrations.AddField(
            model_name='code',
            name='origin_domain',
            field=models.CharField(
                max_length=255,
                blank=True,
                verbose_name='Origin Domain',
                help_text='Domain from which the authorization request originated'
            ),
        ),
        
        # Add index for origin domain queries
        migrations.AddIndex(
            model_name='token',
            index=models.Index(fields=['origin_domain'], name='oidc_token_origin_idx'),
        ),
        
        migrations.AddIndex(
            model_name='code',
            index=models.Index(fields=['origin_domain'], name='oidc_code_origin_idx'),
        ),
    ]
