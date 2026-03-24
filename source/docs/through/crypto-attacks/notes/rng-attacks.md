# Randomness and RNG attacks

A surprisingly large proportion of real cryptographic failures trace back to a single root
cause: the random numbers were not random enough. Predictable keys, reused nonces, and
biased parameters turn a mathematically sound system into an open door.

## Why randomness matters so much

Symmetric keys, asymmetric key pairs, nonces, IVs, salts, session tokens, and DH
ephemeral values all require unpredictable random input. A cryptographic algorithm
processes whatever numbers it is given; it does not detect or compensate for weak input.
An AES key derived from a predictable seed is just as predictable as the seed itself.

## DUAL_EC_DRBG

The most famous RNG backdoor. DUAL_EC_DRBG (Dual Elliptic Curve Deterministic Random Bit
Generator) was standardised by NIST in 2006 and later shown (Bernstein et al., 2014, and
Snowden documents) to contain a likely backdoor: if you know the discrete logarithm
relating the two elliptic curve points in the standard, you can predict all future output
from 32 bytes of observed output.

This was the default PRNG in RSA Security's BSAFE library and was present in Juniper
ScreenOS firmware. It illustrates that the threat model for RNG attacks includes not
just poor implementations but also deliberate subversion of standards.

## Embedded and IoT devices

Embedded devices are the most common victim of RNG failures in practice. At boot time,
the entropy pool may be nearly empty: the system has been running for only seconds, the
hardware lacks dedicated entropy sources, and the seed file from the previous boot may
not exist (first boot, after a firmware flash, or on a device that does not persist state
across reboots).

Keys generated at first boot on devices with low-entropy RNGs are often weak. Research
(Heninger et al., 2012: "Mining Your Ps and Qs") scanned the internet's RSA and DSA
public keys and found that a significant fraction shared prime factors: the only
explanation is that the keys were generated with insufficient entropy, causing different
devices to draw from the same small pool of random state.

Two keys that share a prime factor can both be factored trivially:

```python
from math import gcd

n1 = int("RSA modulus 1 hex here", 16)
n2 = int("RSA modulus 2 hex here", 16)

shared = gcd(n1, n2)
if shared > 1:
    p = shared
    q1 = n1 // p
    q2 = n2 // p
    print(f"p={p}\nq1={q1}\nq2={q2}")
```

For red team engagements involving embedded devices, collecting the public keys and running
GCD checks across the set is a routine step. `factordb.com` and `RsaCtfTool` include
tools for this.

## Nonce reuse in stream ciphers and AEAD

Stream ciphers and AEAD modes (AES-GCM, ChaCha20-Poly1305) are catastrophically vulnerable
to nonce reuse. If the same nonce is used with the same key to encrypt two different
plaintexts, the keystream is the same for both. XORing the two ciphertexts gives the XOR
of the plaintexts, from which both can be recovered given any partial knowledge of either.

For AES-GCM, nonce reuse also allows forgery: an attacker who observes two encryptions
under the same nonce can compute the authentication key H and then forge arbitrary
authenticated ciphertext.

Finding nonce reuse requires observing many ciphertext blocks under the same key. In
protocols that increment or randomise nonces correctly this does not occur. In systems
that generate nonces from a poor RNG, or that reset nonce counters at reconnection, or
that have bugs in distributed systems where multiple nodes encrypt under the same key
without coordination, nonce reuse appears in practice.

## Predictable session tokens

Session tokens, CSRF tokens, and authentication cookies generated from weak RNGs are
predictable. PHP's `rand()` on older installations used a 32-bit seed; knowing the
approximate seed (system time at token generation) reduced the search space dramatically.

Test a target's session token entropy by collecting many tokens and checking their
randomness:

```python
import requests, base64, math, collections

tokens = []
for _ in range(100):
    r = requests.get('https://target.example.com/login')
    token = r.cookies.get('session')
    if token:
        tokens.append(base64.b64decode(token + '=='))

# check byte distribution across all collected tokens
all_bytes = b''.join(tokens)
counts = collections.Counter(all_bytes)
total = len(all_bytes)
entropy = -sum((c/total) * math.log2(c/total) for c in counts.values() if c > 0)
print(f'Byte entropy: {entropy:.2f} bits (max 8.0)')
```

Entropy below 7.5 bits per byte for what should be random tokens suggests a weak
generator or a pattern worth investigating.

## ML-assisted bias detection

Machine learning models trained to distinguish truly random sequences from PRNG output
can identify weak generators from their output, even when the bias is too subtle for
classical statistical tests (NIST SP 800-22).

For red team use, the practical application is: collect a large sample of values from
a target system (session tokens, nonces in a custom protocol, key material in a response),
train or apply a pre-trained classifier, and use a positive result to justify further
investigation. The ML model does not recover the seed; it flags the target for manual
follow-up.

## DSA/ECDSA nonce bias

DSA and ECDSA signature generation requires a fresh random nonce per signature. If the
nonce has even a small bias (one bit of predictability), collecting enough signatures
allows lattice-based private key recovery. The PlayStation 3 private key was recovered
this way in 2010 because Sony used a constant nonce.

For targets that expose many ECDSA signatures under the same key (TLS, code signing,
JWT with ES256), collecting signatures and running lattice reduction on the nonces is
a viable attack path if any bias is suspected.

```text
# lattice attack on biased ECDSA nonces
pip install ecdsa-nonce-attack  # or use research implementations
```
