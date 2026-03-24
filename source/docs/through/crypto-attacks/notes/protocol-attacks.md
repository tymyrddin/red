# Protocol-level cryptanalysis

Most real-world crypto failures happen at the protocol level, not in the algorithm itself.
AES is fine. The way people configure TLS, implement key exchange, handle padding, and
glue crypto primitives together is where things actually break.

## TLS misconfigurations

TLS is the most widely deployed cryptographic protocol. Its configuration surface is large
and its default settings have historically been too permissive. Common exploitable
misconfigurations:

Weak cipher suite support: many servers still accept cipher suites using RC4, DES, 3DES,
or export-grade cryptography. These can be forced by a downgrade attack.

```text
# enumerate supported cipher suites
nmap --script ssl-enum-ciphers -p 443 target.example.com
testssl.sh target.example.com
```

Any cipher suite rated D or F in testssl output is a potential downgrade target.

SSLv2/SSLv3/TLS 1.0/TLS 1.1 support: older protocol versions with known weaknesses.
DROWN (SSLv2) and POODLE (SSLv3) are exploitable on servers that still accept these
versions alongside modern ones.

Missing forward secrecy: RSA key exchange (as opposed to ephemeral ECDHE) means a session
captured today can be decrypted if the private key is later obtained. Relevant for
"harvest now decrypt later" threat models.

## Downgrade attacks

FREAK (2015): forced negotiation of export-grade RSA (512-bit). The client is tricked into
accepting a deliberately weak cipher suite; the server, if it still supports export ciphers,
completes the handshake. The 512-bit RSA can then be factored.

Logjam (2015): forced negotiation of 512-bit Diffie-Hellman for key exchange. The weak DH
parameters can be solved with precomputation. Affects any server that supports DHE_EXPORT.

Both require an active MITM position. `testssl.sh --drown --freak --logjam` checks for
these vulnerabilities.

## Padding oracle attacks

A padding oracle is any situation where the server's error response differs depending on
whether the padding of a decrypted message is valid. This difference, whether timing-based
or in the error message itself, allows an attacker to decrypt ciphertext byte by byte
without the key.

CBC padding oracle (Vaudenay, 2002): AES-CBC decryption removes PKCS#7 padding. If the
server reveals whether padding is valid (even through a timing difference), arbitrary
ciphertext blocks can be decrypted. The attack requires two chosen ciphertext queries per
byte: typically 128 * block_size * 8 total queries to decrypt one block.

```python
# padbuster automates CBC padding oracle exploitation
padbuster https://target.example.com/encrypted-param ENCRYPTED_VALUE 8 --encoding 0
```

ASP.NET padding oracle (POET): the default error page in some ASP.NET configurations
revealed padding validity. Widely exploited for ViewState decryption and authentication
bypass.

PKCS#1 v1.5 padding oracle (Bleichenbacher): RSA decryption with PKCS#1 v1.5 padding.
If the server signals whether decryption produced correctly padded output (even via timing),
the private key can be recovered with approximately 2^20 adaptive queries. The ROBOT
vulnerability (2018) found this still exploitable in major TLS stacks 20 years after
the original publication.

```text
# test for ROBOT vulnerability
git clone https://github.com/robotattackorg/robot-detect
python robot-detect.py target.example.com
```

## Hash length extension

Hash functions based on the Merkle-Damgard construction (MD5, SHA-1, SHA-256) are
vulnerable to length extension. Given `H(secret || message)` and the length of `secret`,
an attacker can compute `H(secret || message || padding || extension)` without knowing
`secret`.

This breaks MAC constructions of the form `H(secret || message)` used in custom
authentication schemes, signed URLs, and some API authentication implementations.

```text
# hash_extender automates this attack
hash_extender -d "original_message" -s KNOWN_HASH -a "appended_data" -l KEY_LENGTH --format sha256
```

The fix is HMAC: `H(secret XOR opad || H(secret XOR ipad || message))`. Length extension
does not apply to HMAC.

## Replay attacks

Any protocol that uses a nonce or timestamp to prevent replay but does not cryptographically
bind the nonce to the session is potentially vulnerable. Authentication tokens, session
cookies, and API signatures can sometimes be replayed outside their intended context if
the binding is missing or weak.

JWT (JSON Web Token) vulnerabilities have included algorithm confusion attacks: changing
the `alg` header from `RS256` to `HS256` and signing with the server's public key as the
HMAC secret causes the server to verify with the wrong key. Implementations that trust
the `alg` header from the token itself are vulnerable.

```text
# jwt_tool for JWT analysis and attack
pip install jwt_tool
jwt_tool TARGET_JWT -X a  # algorithm confusion attack
```

## Key exchange failures

Reused DH parameters: the logjam attack targets 512-bit DH. But many servers use the same
1024-bit DH parameters as other servers. The NSA's large-scale precomputation of discrete
logs for common 1024-bit parameters is documented. Servers using these parameters provide
weaker-than-advertised forward secrecy.

Missing authentication in DH: unauthenticated DH is vulnerable to active MITM. If the
DH exchange is not bound to a verified identity (certificate, PSK), an active attacker
can intercept both sides of the handshake and establish separate sessions.

Cross-protocol attacks: if the same key material or certificate is used across multiple
protocols, an attack on one protocol can affect another. Triple Handshake (2014) exploited
TLS renegotiation to inject data into an established TLS session using a different
protocol context.
