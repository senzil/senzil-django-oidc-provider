# -*- coding: utf-8 -*-
# Generated for refresh token customization support

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_provider', '0029_add_modern_algorithms_and_encryption'),
    ]

    operations = [
        # Refresh token format
        migrations.AddField(
            model_name='client',
            name='refresh_token_format',
            field=models.CharField(
                choices=[('uuid', 'UUID (Opaque)'), ('jwt', 'JWT (Structured)')],
                default='uuid',
                help_text='Format for refresh tokens',
                max_length=10,
                verbose_name='Refresh Token Format'
            ),
        ),
        
        # Refresh token JWT algorithm
        migrations.AddField(
            model_name='client',
            name='refresh_token_jwt_alg',
            field=models.CharField(
                blank=True,
                choices=[
                    ('HS256', 'HS256'), ('HS384', 'HS384'), ('HS512', 'HS512'),
                    ('RS256', 'RS256'), ('RS384', 'RS384'), ('RS512', 'RS512'),
                    ('ES256', 'ES256'), ('ES384', 'ES384'), ('ES512', 'ES512'),
                    ('PS256', 'PS256'), ('PS384', 'PS384'), ('PS512', 'PS512'),
                ],
                help_text='Algorithm for JWT refresh tokens. If not set, uses access_token_jwt_alg or jwt_alg',
                max_length=10,
                null=True,
                verbose_name='Refresh Token JWT Algorithm'
            ),
        ),
        
        # Refresh token encryption algorithm
        migrations.AddField(
            model_name='client',
            name='refresh_token_encrypted_response_alg',
            field=models.CharField(
                blank=True,
                choices=[
                    ('RSA-OAEP', 'RSA-OAEP'), ('RSA-OAEP-256', 'RSA-OAEP-256'),
                    ('A128KW', 'A128KW'), ('A192KW', 'A192KW'), ('A256KW', 'A256KW'),
                    ('dir', 'dir'),
                    ('ECDH-ES', 'ECDH-ES'), ('ECDH-ES+A128KW', 'ECDH-ES+A128KW'),
                    ('ECDH-ES+A192KW', 'ECDH-ES+A192KW'), ('ECDH-ES+A256KW', 'ECDH-ES+A256KW'),
                ],
                help_text='JWE alg algorithm for encrypting refresh tokens',
                max_length=30,
                null=True,
                verbose_name='Refresh Token Encryption Algorithm'
            ),
        ),
        
        # Refresh token encryption encoding
        migrations.AddField(
            model_name='client',
            name='refresh_token_encrypted_response_enc',
            field=models.CharField(
                blank=True,
                choices=[
                    ('A128CBC-HS256', 'A128CBC-HS256'), ('A192CBC-HS384', 'A192CBC-HS384'),
                    ('A256CBC-HS512', 'A256CBC-HS512'),
                    ('A128GCM', 'A128GCM'), ('A192GCM', 'A192GCM'), ('A256GCM', 'A256GCM'),
                ],
                default='A128CBC-HS256',
                help_text='JWE enc algorithm for encrypting refresh tokens',
                max_length=30,
                null=True,
                verbose_name='Refresh Token Encryption Encoding'
            ),
        ),
        
        # Refresh token rotation
        migrations.AddField(
            model_name='client',
            name='enable_refresh_token_rotation',
            field=models.BooleanField(
                default=True,
                help_text='Generate new refresh token on each use',
                verbose_name='Enable Refresh Token Rotation'
            ),
        ),
        
        # Grace period for rotation
        migrations.AddField(
            model_name='client',
            name='refresh_token_grace_period_seconds',
            field=models.IntegerField(
                default=0,
                help_text='Seconds to allow old refresh token after rotation (for concurrency)',
                verbose_name='Refresh Token Grace Period'
            ),
        ),
        
        # Refresh token expiration
        migrations.AddField(
            model_name='client',
            name='refresh_token_expire_seconds',
            field=models.IntegerField(
                blank=True,
                help_text='Seconds until refresh token expires. If not set, uses OIDC_TOKEN_EXPIRE * 30',
                null=True,
                verbose_name='Refresh Token Expiration'
            ),
        ),
        
        # Reuse detection
        migrations.AddField(
            model_name='client',
            name='detect_refresh_token_reuse',
            field=models.BooleanField(
                default=True,
                help_text='Revoke token family if reuse detected',
                verbose_name='Detect Refresh Token Reuse'
            ),
        ),
        
        # Token history model for rotation tracking
        migrations.CreateModel(
            name='RefreshTokenHistory',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('jti', models.CharField(db_index=True, max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('revoked', models.BooleanField(default=False)),
                ('token', models.ForeignKey(
                    on_delete=models.CASCADE,
                    related_name='previous_refresh_tokens',
                    to='oidc_provider.Token'
                )),
            ],
            options={
                'verbose_name': 'Refresh Token History',
                'verbose_name_plural': 'Refresh Token Histories',
            },
        ),
        
        # Indexes for performance
        migrations.AddIndex(
            model_name='refreshtokenhistory',
            index=models.Index(fields=['token', 'created_at'], name='oidc_provider_token_created_idx'),
        ),
        migrations.AddIndex(
            model_name='refreshtokenhistory',
            index=models.Index(fields=['jti', 'created_at'], name='oidc_provider_jti_created_idx'),
        ),
    ]
