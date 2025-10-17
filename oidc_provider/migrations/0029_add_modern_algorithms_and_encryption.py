# -*- coding: utf-8 -*-
# Generated for modern algorithm and encryption support
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_provider', '0028_add_default_scope_20210503_1257'),
    ]

    operations = [
        # Update JWT_ALGS choices to include new algorithms
        migrations.AlterField(
            model_name='client',
            name='jwt_alg',
            field=models.CharField(
                choices=[
                    ('HS256', 'HS256'), ('HS384', 'HS384'), ('HS512', 'HS512'),
                    ('RS256', 'RS256'), ('RS384', 'RS384'), ('RS512', 'RS512'),
                    ('ES256', 'ES256'), ('ES384', 'ES384'), ('ES512', 'ES512'),
                    ('PS256', 'PS256'), ('PS384', 'PS384'), ('PS512', 'PS512'),
                ],
                default='RS256',
                help_text='Algorithm used to encode ID Tokens.',
                max_length=10,
                verbose_name='JWT Algorithm'
            ),
        ),
        # Add access token specific algorithm field
        migrations.AddField(
            model_name='client',
            name='access_token_jwt_alg',
            field=models.CharField(
                blank=True,
                choices=[
                    ('HS256', 'HS256'), ('HS384', 'HS384'), ('HS512', 'HS512'),
                    ('RS256', 'RS256'), ('RS384', 'RS384'), ('RS512', 'RS512'),
                    ('ES256', 'ES256'), ('ES384', 'ES384'), ('ES512', 'ES512'),
                    ('PS256', 'PS256'), ('PS384', 'PS384'), ('PS512', 'PS512'),
                ],
                default='RS256',
                help_text='Algorithm used to encode Access Tokens. If not set, uses jwt_alg.',
                max_length=10,
                null=True,
                verbose_name='Access Token JWT Algorithm'
            ),
        ),
        # Add ID token encryption fields
        migrations.AddField(
            model_name='client',
            name='id_token_encrypted_response_alg',
            field=models.CharField(
                blank=True,
                choices=[
                    ('RSA-OAEP', 'RSA-OAEP'), ('RSA-OAEP-256', 'RSA-OAEP-256'),
                    ('A128KW', 'A128KW'), ('A192KW', 'A192KW'), ('A256KW', 'A256KW'),
                    ('dir', 'dir'),
                    ('ECDH-ES', 'ECDH-ES'), ('ECDH-ES+A128KW', 'ECDH-ES+A128KW'),
                    ('ECDH-ES+A192KW', 'ECDH-ES+A192KW'), ('ECDH-ES+A256KW', 'ECDH-ES+A256KW'),
                ],
                help_text='JWE alg algorithm for encrypting ID Tokens.',
                max_length=30,
                null=True,
                verbose_name='ID Token Encryption Algorithm'
            ),
        ),
        migrations.AddField(
            model_name='client',
            name='id_token_encrypted_response_enc',
            field=models.CharField(
                blank=True,
                choices=[
                    ('A128CBC-HS256', 'A128CBC-HS256'), ('A192CBC-HS384', 'A192CBC-HS384'),
                    ('A256CBC-HS512', 'A256CBC-HS512'),
                    ('A128GCM', 'A128GCM'), ('A192GCM', 'A192GCM'), ('A256GCM', 'A256GCM'),
                ],
                default='A128CBC-HS256',
                help_text='JWE enc algorithm for encrypting ID Tokens.',
                max_length=30,
                null=True,
                verbose_name='ID Token Encryption Encoding'
            ),
        ),
        # Add access token encryption fields
        migrations.AddField(
            model_name='client',
            name='access_token_encrypted_response_alg',
            field=models.CharField(
                blank=True,
                choices=[
                    ('RSA-OAEP', 'RSA-OAEP'), ('RSA-OAEP-256', 'RSA-OAEP-256'),
                    ('A128KW', 'A128KW'), ('A192KW', 'A192KW'), ('A256KW', 'A256KW'),
                    ('dir', 'dir'),
                    ('ECDH-ES', 'ECDH-ES'), ('ECDH-ES+A128KW', 'ECDH-ES+A128KW'),
                    ('ECDH-ES+A192KW', 'ECDH-ES+A192KW'), ('ECDH-ES+A256KW', 'ECDH-ES+A256KW'),
                ],
                help_text='JWE alg algorithm for encrypting Access Tokens.',
                max_length=30,
                null=True,
                verbose_name='Access Token Encryption Algorithm'
            ),
        ),
        migrations.AddField(
            model_name='client',
            name='access_token_encrypted_response_enc',
            field=models.CharField(
                blank=True,
                choices=[
                    ('A128CBC-HS256', 'A128CBC-HS256'), ('A192CBC-HS384', 'A192CBC-HS384'),
                    ('A256CBC-HS512', 'A256CBC-HS512'),
                    ('A128GCM', 'A128GCM'), ('A192GCM', 'A192GCM'), ('A256GCM', 'A256GCM'),
                ],
                default='A128CBC-HS256',
                help_text='JWE enc algorithm for encrypting Access Tokens.',
                max_length=30,
                null=True,
                verbose_name='Access Token Encryption Encoding'
            ),
        ),
        # Create ECKey model
        migrations.CreateModel(
            name='ECKey',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('key', models.TextField(help_text='Paste your private EC Key here in PEM format.', verbose_name='Key')),
                ('crv', models.CharField(
                    choices=[('P-256', 'P-256'), ('P-384', 'P-384'), ('P-521', 'P-521')],
                    default='P-256',
                    help_text='Elliptic curve (P-256 for ES256, P-384 for ES384, P-521 for ES512)',
                    max_length=10,
                    verbose_name='Curve'
                )),
            ],
            options={
                'verbose_name': 'EC Key',
                'verbose_name_plural': 'EC Keys',
            },
        ),
    ]
