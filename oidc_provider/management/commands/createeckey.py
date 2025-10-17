from Cryptodome.PublicKey import ECC
from django.core.management.base import BaseCommand
from oidc_provider.models import ECKey


class Command(BaseCommand):
    help = 'Randomly generate a new EC key for the OpenID server'

    def add_arguments(self, parser):
        parser.add_argument(
            '--curve',
            type=str,
            default='P-256',
            choices=['P-256', 'P-384', 'P-521'],
            help='Elliptic curve to use (P-256 for ES256, P-384 for ES384, P-521 for ES512)'
        )

    def handle(self, *args, **options):
        try:
            curve = options['curve']
            key = ECC.generate(curve=curve)
            eckey = ECKey(
                key=key.export_key(format='PEM'),
                crv=curve
            )
            eckey.save()
            self.stdout.write(
                u'EC key successfully created with kid: {0}, curve: {1}'.format(
                    eckey.kid, eckey.crv
                )
            )
        except Exception as e:
            self.stdout.write('Something goes wrong: {0}'.format(e))
