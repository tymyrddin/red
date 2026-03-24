# RNG quality assessment

Testing the randomness quality of a target's cryptographic material is a step in any
engagement involving embedded devices, custom applications, or IoT infrastructure.
Weak RNGs produce predictable keys, reused nonces, and factorable RSA moduli.

## Session token entropy analysis

Collect session tokens from a web application and measure their entropy:

```python
import requests, base64, math, collections, urllib3
urllib3.disable_warnings()

TARGET = 'https://target.example.com/login'
COOKIE_NAME = 'session'
SAMPLE_SIZE = 200

tokens = []
for _ in range(SAMPLE_SIZE):
    r = requests.get(TARGET, verify=False, allow_redirects=False, timeout=5)
    token = r.cookies.get(COOKIE_NAME)
    if token:
        try:
            tokens.append(base64.b64decode(token + '=='))
        except Exception:
            tokens.append(token.encode())

if not tokens:
    print('No tokens collected')
else:
    all_bytes = b''.join(tokens)
    counts = collections.Counter(all_bytes)
    total = len(all_bytes)
    entropy = -sum((c/total) * math.log2(c/total) for c in counts.values() if c > 0)
    print(f'Tokens collected: {len(tokens)}')
    print(f'Total bytes: {total}')
    print(f'Byte entropy: {entropy:.3f} bits (max 8.0)')
    if entropy < 7.0:
        print('LOW ENTROPY: likely weak or patterned generator')
    elif entropy < 7.5:
        print('MARGINAL: worth investigating further')
    else:
        print('Entropy looks reasonable')
```

Entropy below 7.0 bits per byte for what should be random session tokens indicates
either a weak generator or structural patterns worth analysing. Below 6.0 is
strongly predictable.

## Sequential or time-seeded token detection

Plot token values over time to detect sequential or time-seeded generation:

```python
import requests, base64, struct, time

tokens = []
timestamps = []
for _ in range(50):
    r = requests.get(TARGET, verify=False, allow_redirects=False, timeout=5)
    token = r.cookies.get(COOKIE_NAME)
    if token:
        tokens.append(base64.b64decode(token + '==')[:4])  # first 4 bytes
        timestamps.append(int(time.time()))
    time.sleep(0.1)

# check if token prefix increases monotonically (sequential counter)
values = [struct.unpack('>I', t)[0] for t in tokens]
diffs = [values[i+1] - values[i] for i in range(len(values)-1)]
print(f'Token prefix diffs: {diffs[:20]}')
if len(set(diffs)) == 1:
    print('SEQUENTIAL: tokens increment by a constant value')
```

## RSA public key GCD attack

Collect RSA public keys from embedded devices on the same network or firmware batch.
If multiple devices were provisioned with a low-entropy RNG, their keys may share
a prime factor.

```python
from math import gcd
import itertools

# collect public keys as integers (moduli)
# parse from PEM: openssl rsa -pubin -in key.pem -noout -modulus
moduli = [
    int("MODULUS_HEX_1", 16),
    int("MODULUS_HEX_2", 16),
    # ... add all collected moduli
]

for n1, n2 in itertools.combinations(moduli, 2):
    shared = gcd(n1, n2)
    if shared > 1:
        p = shared
        q1 = n1 // p
        q2 = n2 // p
        print(f'Shared prime found!')
        print(f'p = {p}')
        print(f'q (key 1) = {q1}')
        print(f'q (key 2) = {q2}')
```

For large key sets, batch the GCD computation. The naive O(n^2) approach is acceptable
for up to a few thousand keys; for larger sets use the batch GCD algorithm.

Collecting public keys from SSH host keys and HTTPS certificates on a subnet:

```text
# SSH host keys from network range
for ip in $(seq 1 254); do
    ssh-keyscan -t rsa 192.168.1.$ip 2>/dev/null >> host_keys.txt
done
ssh-keygen -l -f host_keys.txt

# extract RSA moduli from HTTPS certificates
for ip in $(seq 1 254); do
    echo | openssl s_client -connect 192.168.1.$ip:443 2>/dev/null | \
      openssl x509 -noout -modulus 2>/dev/null | \
      sed 's/Modulus=//' >> moduli.txt
done
```

## ECDSA nonce bias detection

If a target exposes many ECDSA signatures under the same key (TLS server, code signing,
JWT issuance), collect signatures and test for nonce bias. Even a single bit of
predictability allows private key recovery via lattice reduction.

```text
# collect TLS signatures (requires Wireshark + TLS 1.2 with non-PFS cipher)
# or collect JWT signatures
python3 -c "
import jwt, requests, json, base64

tokens = []
for _ in range(500):
    # collect signed JWTs or similar
    r = requests.get('https://target.example.com/api/token', verify=False)
    tokens.append(r.json()['token'])

# parse r and s values from EC signatures
for token in tokens:
    parts = token.split('.')
    sig = base64.urlsafe_b64decode(parts[2] + '==')
    # ES256 signature is r||s, each 32 bytes
    r = int.from_bytes(sig[:32], 'big')
    s = int.from_bytes(sig[32:], 'big')
    print(hex(r), hex(s))
"
```

Feed the (r, s, hash) tuples to a lattice attack tool if bias is suspected. Research
implementations exist for secp256r1 and secp256k1.

## Nonce reuse detection (AES-GCM)

AES-GCM nonce reuse is detectable from two ciphertexts: XOR of the ciphertexts gives
XOR of the plaintexts, which is a distinguishable pattern if any content is known.

```python
def detect_nonce_reuse(ciphertext_list):
    """Given a list of (nonce, ciphertext) pairs, find any repeated nonces."""
    seen = {}
    for i, (nonce, ct) in enumerate(ciphertext_list):
        nonce_hex = nonce.hex()
        if nonce_hex in seen:
            j = seen[nonce_hex]
            print(f'Nonce reuse: entries {j} and {i} share nonce {nonce_hex}')
            # XOR the ciphertexts (excluding tag) to get XOR of plaintexts
            xored = bytes(a ^ b for a, b in zip(ciphertext_list[j][1], ct))
            print(f'XOR of plaintexts: {xored.hex()}')
        else:
            seen[nonce_hex] = i
```

In a custom protocol capturing encrypted messages, collect (nonce, ciphertext) pairs
and run this check. Reused nonces reveal plaintext structure immediately.
