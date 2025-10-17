from datetime import timedelta
import time
import uuid
import json

from Cryptodome.PublicKey.RSA import importKey
from Cryptodome.PublicKey import ECC
from django.utils import dateformat, timezone
from jwkest.jwk import RSAKey as jwk_RSAKey
from jwkest.jwk import ECKey as jwk_ECKey
from jwkest.jwk import SYMKey
from jwkest.jws import JWS
from jwkest.jwe import JWE
from jwkest.jwt import JWT

from oidc_provider.lib.utils.common import (
    get_issuer,
    run_processing_hook,
    decode_base64,
)
from oidc_provider.lib.claims import StandardScopeClaims
from oidc_provider.lib.errors import (
    ClientIdError, 
    BearerTokenError
)
from oidc_provider.models import (
    Code,
    RSAKey,
    ECKey,
    Token,
    Client,
)
from oidc_provider import settings


def create_id_token(token, user, aud, nonce='', at_hash='', request=None, scope=None):
    """
    Creates the id_token dictionary.
    See: http://openid.net/specs/openid-connect-core-1_0.html#IDToken
    Return a dic.
    
    Guarantees all required OIDC claims are present:
    - iss (issuer)
    - sub (subject)
    - aud (audience) - uses origin domain if available
    - exp (expiration)
    - iat (issued at)
    """
    if scope is None:
        scope = []
    sub = settings.get('OIDC_IDTOKEN_SUB_GENERATOR', import_str=True)(user=user)

    expires_in = settings.get('OIDC_IDTOKEN_EXPIRE')

    # Convert datetimes into timestamps.
    now = int(time.time())
    iat_time = now
    exp_time = int(now + expires_in)
    user_auth_time = user.last_login or user.date_joined
    auth_time = int(dateformat.format(user_auth_time, 'U'))

    # Determine audience - prefer origin domain over client_id
    from oidc_provider.lib.utils.audience import get_id_token_audience
    from oidc_provider.middleware_origin import get_request_origin
    
    # Use origin domain as audience if available
    audience = get_request_origin(request) if request else None
    if not audience:
        audience = str(aud)  # Fallback to provided aud (client_id)

    # Required OIDC claims - ALWAYS include these
    dic = {
        'iss': get_issuer(request=request),
        'sub': sub,
        'aud': audience,  # Now uses origin domain
        'exp': exp_time,
        'iat': iat_time,
        'auth_time': auth_time,
    }

    if nonce:
        dic['nonce'] = str(nonce)

    if at_hash:
        dic['at_hash'] = at_hash

    # Inlude (or not) user standard claims in the id_token.
    if settings.get('OIDC_IDTOKEN_INCLUDE_CLAIMS'):
        if settings.get('OIDC_EXTRA_SCOPE_CLAIMS'):
            custom_claims = settings.get('OIDC_EXTRA_SCOPE_CLAIMS', import_str=True)(token)
            claims = custom_claims.create_response_dic()
        else:
            claims = StandardScopeClaims(token).create_response_dic()
        dic.update(claims)

    dic = run_processing_hook(
        dic, 'OIDC_IDTOKEN_PROCESSING_HOOK',
        user=user, token=token, request=request)

    # Ensure all required claims are present (in case hook removed them)
    if 'iss' not in dic:
        dic['iss'] = get_issuer(request=request)
    if 'sub' not in dic:
        dic['sub'] = sub
    if 'aud' not in dic:
        dic['aud'] = audience
    if 'exp' not in dic:
        dic['exp'] = exp_time
    if 'iat' not in dic:
        dic['iat'] = iat_time

    return dic


def encode_jwt(payload, client, alg=None):
    """
    Represent payload as a JSON Web Token (JWT).
    Return a hash.
    """
    algorithm = alg or client.jwt_alg
    keys = get_client_alg_keys(client, algorithm)
    _jws = JWS(payload, alg=algorithm)
    jwt_token = _jws.sign_compact(keys)
    
    # Apply encryption if configured for ID tokens (backward compatible)
    if client.id_token_encrypted_response_alg and client.id_token_encrypted_response_enc:
        jwt_token = encrypt_jwt(
            jwt_token,
            client,
            client.id_token_encrypted_response_alg,
            client.id_token_encrypted_response_enc
        )
    
    return jwt_token


def encrypt_jwt(jwt_string, client, alg, enc):
    """
    Encrypt a JWT using JWE.
    Return encrypted JWT string.
    """
    if not alg or not enc:
        return jwt_string
    
    keys = get_client_encryption_keys(client, alg)
    if not keys:
        return jwt_string
    
    _jwe = JWE(jwt_string, alg=alg, enc=enc)
    return _jwe.serialize(keys[0])


def decode_jwt(jwt, client, alg=None):
    """
    Decode a JSON Web Token (JWT). If the signature doesn't match, raise BadSignature.
    Return a dict.
    """
    algorithm = alg or client.jwt_alg
    keys = get_client_alg_keys(client, algorithm)
    return JWS().verify_compact(jwt, keys=keys)


def decrypt_jwt(jwe_string, client, alg, enc):
    """
    Decrypt a JWE.
    Return decrypted JWT string.
    """
    if not alg or not enc:
        return jwe_string
    
    keys = get_client_encryption_keys(client, alg)
    if not keys:
        return jwe_string
    
    _jwe = JWE()
    return _jwe.decrypt(jwe_string, keys=keys)


def client_id_from_id_token(id_token):
    """
    Extracts the client id from a JSON Web Token (JWT).
    Returns a string or None.
    """
    payload = JWT().unpack(id_token).payload()
    aud = payload.get('aud', None)
    if aud is None:
        return None
    if isinstance(aud, list):
        return aud[0]
    return aud


def create_token(user, client, scope, id_token_dic=None, request=None):
    """
    Create and populate a Token object.
    Return a Token object.
    """
    token = Token()
    token.user = user
    token.client = client
    token.access_token = uuid.uuid4().hex

    if id_token_dic is not None:
        token.id_token = id_token_dic

    token.refresh_token = uuid.uuid4().hex
    token.expires_at = timezone.now() + timedelta(seconds=settings.get('OIDC_TOKEN_EXPIRE'))
    token.scope = scope

    return token


def access_token_format(token, client, request, user=None):
    if settings.get('OIDC_ACCESS_TOKEN_ENCODE') is None:
        return token.access_token

    return settings.get('OIDC_ACCESS_TOKEN_ENCODE', import_str=True)(
        user=user,
        client=client,
        token=token,
        request=request)


def encode_access_token_jwt(user, client, token, request):
    """
    Generate a JWT Access Token Response.
    Return JWT String object (return a hash).
    """
    # Required claims for access token
    payload = {
        'iss': get_issuer(request=request),
        'client_id': str(client.client_id),
        'exp': int(token.expires_at.timestamp()),
        'iat': int(timezone.now().timestamp()),
        'scope': token.scope,
        'jti': token.access_token,
    }

    # Subject - required if user context exists
    if user is not None:
        payload['sub'] = settings.get('OIDC_IDTOKEN_SUB_GENERATOR', import_str=True)(user=user)

    # Audience - use origin domain as the resource server
    from oidc_provider.lib.utils.audience import get_access_token_audience
    payload['aud'] = get_access_token_audience(client, request)

    if settings.get('OIDC_TOKEN_JWT_EXTRA_INFO'):
        extra_info = settings.get('OIDC_TOKEN_JWT_EXTRA_INFO', import_str=True)(token)
        payload.update(extra_info)

    # Use access token specific algorithm if set
    alg = client.access_token_jwt_alg or client.jwt_alg
    jwt_token = encode_jwt(payload, client, alg=alg)
    
    # Encrypt if encryption is configured
    if client.access_token_encrypted_response_alg and client.access_token_encrypted_response_enc:
        jwt_token = encrypt_jwt(
            jwt_token, 
            client, 
            client.access_token_encrypted_response_alg,
            client.access_token_encrypted_response_enc
        )
    
    return jwt_token


def wrapper_decode_jwt(access_token_jwt):
    try:
        not_verified_payload = decode_base64(access_token_jwt.split('.')[1])
    except Exception:
        raise BearerTokenError('invalid_token')

    try:
        payload_json = json.loads(not_verified_payload)
        client = Client.objects.get(client_id=payload_json['client_id'])
    except Client.DoesNotExist:
        raise ClientIdError()

    jwt_payload = decode_jwt(jwt=access_token_jwt, client=client)

    return jwt_payload


def decode_access_token_jwt(access_token_jwt):
    jwt_payload = wrapper_decode_jwt(access_token_jwt=access_token_jwt)
    return jwt_payload['jti']


def get_plain_access_token(access_token):
    if settings.get('OIDC_ACCESS_TOKEN_DECODE') is None:
        return access_token

    return settings.get('OIDC_ACCESS_TOKEN_DECODE', import_str=True)(
        access_token_jwt=access_token)


def create_code(user, client, scope, nonce, is_authentication,
                code_challenge=None, code_challenge_method=None):

    """
    Create and populate a Code object.
    Return a Code object.
    """

    code = Code()
    code.user = user
    code.client = client

    code.code = uuid.uuid4().hex

    if code_challenge and code_challenge_method:
        code.code_challenge = code_challenge
        code.code_challenge_method = code_challenge_method

    code.expires_at = timezone.now() + timedelta(
        seconds=settings.get('OIDC_CODE_EXPIRE'))
    code.scope = scope
    code.nonce = nonce
    code.is_authentication = is_authentication

    return code


def get_client_alg_keys(client, alg=None):
    """
    Takes a client and returns the set of keys associated with it.
    Returns a list of keys.
    """
    algorithm = alg or client.jwt_alg
    
    # RSA-based algorithms (RS256, RS384, RS512, PS256, PS384, PS512)
    if algorithm.startswith('RS') or algorithm.startswith('PS'):
        keys = []
        for rsakey in RSAKey.objects.all():
            keys.append(jwk_RSAKey(key=importKey(rsakey.key), kid=rsakey.kid))
        if not keys:
            raise Exception('You must add at least one RSA Key.')
    # HMAC-based algorithms (HS256, HS384, HS512)
    elif algorithm.startswith('HS'):
        keys = [SYMKey(key=client.client_secret, alg=algorithm)]
    # Elliptic Curve algorithms (ES256, ES384, ES512)
    elif algorithm.startswith('ES'):
        keys = []
        # Map algorithm to curve
        alg_to_crv = {
            'ES256': 'P-256',
            'ES384': 'P-384',
            'ES512': 'P-521',
        }
        expected_crv = alg_to_crv.get(algorithm)
        for eckey in ECKey.objects.filter(crv=expected_crv):
            try:
                ec_key = ECC.import_key(eckey.key)
                keys.append(jwk_ECKey(key=ec_key, kid=eckey.kid))
            except Exception as e:
                # Skip invalid keys
                pass
        if not keys:
            raise Exception(f'You must add at least one EC Key with curve {expected_crv} for {algorithm}.')
    else:
        raise Exception(f'Unsupported key algorithm: {algorithm}')

    return keys


def get_client_encryption_keys(client, alg):
    """
    Get keys for JWE encryption.
    Returns a list of keys suitable for encryption.
    """
    keys = []
    
    # RSA-based encryption
    if alg.startswith('RSA'):
        for rsakey in RSAKey.objects.all():
            keys.append(jwk_RSAKey(key=importKey(rsakey.key), kid=rsakey.kid))
    # ECDH-based encryption
    elif alg.startswith('ECDH'):
        for eckey in ECKey.objects.all():
            try:
                ec_key = ECC.import_key(eckey.key)
                keys.append(jwk_ECKey(key=ec_key, kid=eckey.kid))
            except Exception:
                pass
    # Symmetric key wrapping
    elif alg in ['A128KW', 'A192KW', 'A256KW', 'dir']:
        keys = [SYMKey(key=client.client_secret, alg=alg)]
    
    return keys
