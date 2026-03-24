# Attack chain: steganography and cryptanalysis combined

Steganography and cryptanalysis are not separate disciplines in practice. An operation that
uses steganographic covert channels also depends on cryptography for payload confidentiality,
and cryptographic weaknesses in the target environment create opportunities across the entire
kill chain. This page maps the interaction.

More detailed runbooks for each phase will follow. This is a planning overview.

## Initial compromise and foothold

Delivery uses the steganographic payload techniques: a malware bundle encoded inside an
AI-generated or neural-embedded image, bypassing AV detection because the carrier is
statistically normal. The image is delivered through phishing, a compromised download, or
a watering hole.

The cryptanalysis angle at this stage: if the initial payload is encrypted, key derivation
from a predictable RNG (common in dropper code) may allow recovery of the plaintext
before execution. Capturing a dropper and analysing its key derivation is a defensive
priority; offensively, the same analysis applies to a competitor's tooling.

## Establishing command and control

C2 communications use coverless steganographic channels: AI-generated images posted to
cloud storage or social media, each carrying encrypted instructions. The implant polls
and decodes.

The cryptanalysis angle: payload decryption keys may be derived from weak entropy sources.
If the key is derived from the timestamp of the C2 image, the process ID of the implant,
or another predictable value, the C2 channel can be decrypted by an analyst who observes
the traffic. Testing implant key derivation for entropy weakness is a standard reverse
engineering step.

Side-channel leakage from the implant's own crypto operations is also relevant in some
contexts: on hardware targets or in adversarial simulation scenarios where the implant
runs in a monitored environment.

## Lateral movement and escalation

Internal network exploration encounters the target organisation's cryptographic
infrastructure. Common attack surfaces:

TLS misconfigurations on internal services: many internal HTTPS services use self-signed
certificates, TLS 1.0, or weak cipher suites that would never be accepted on the public
internet. Protocol-level attacks (downgrade, padding oracle, BEAST on TLS 1.0) apply.

Kerberos and Windows authentication: AS-REP roasting targets accounts with
pre-authentication disabled; Kerberoasting targets service accounts with weak passwords
by requesting service tickets and cracking the RC4-encrypted material offline.

```text
# AS-REP roasting with impacket
GetNPUsers.py domain.local/ -no-pass -usersfile users.txt

# Kerberoasting
GetUserSPNs.py domain.local/user:password -request

# crack with hashcat
hashcat -m 18200 asrep_hashes.txt wordlist.txt   # AS-REP
hashcat -m 13100 kerberos_hashes.txt wordlist.txt # TGS
```

IoT and embedded devices on internal networks may use weak or default cryptographic
parameters, predictable keys, or vulnerable firmware crypto (see rng-attacks.md and
side-channels.md).

## Data exfiltration

Files are encrypted, chunked, and embedded into image sequences for upload via normal
web channels. The cryptanalysis angle for both attacker and defender:

If the encryption is implemented with a weak RNG or a hardcoded key (common in bespoke
exfiltration tools), the data can be decrypted by an analyst who captures the images and
can brute-force or predict the key. Testing exfiltration tool encryption quality is part
of red team tool development.

Multi-layer embedding (an image inside an image, or audio over a video channel) increases
exfiltration bandwidth while keeping individual uploads below alert thresholds. The
cryptographic layer wrapping each image ensures that capturing one image does not reveal
the payload schema.

## Ransomware and destructive payloads

After lateral spread and data exfiltration, ransomware activates. Payment instructions may
be embedded steganographically in communications to the victim.

Cryptanalysis angle: some ransomware implementations use poorly seeded symmetric keys.
If the key was derived from system time at infection with second-level precision, the
keyspace is small enough for brute force. Documented cases of ransomware key recovery
via this weakness exist (older Cerber variants, some GPCode variants).

For red team ransomware simulation, using correctly seeded, properly implemented
encryption is important: a simulated ransomware with a recoverable key undermines the
exercise unless recovery is specifically the test objective.

## Cross-cutting observations

Weak randomness appears at multiple stages and is always the highest-value target.
An operation that correctly implements AES but seeds it from a predictable source loses
at every stage: the C2 key is recoverable, the exfiltration key is recoverable, the
ransomware key is recoverable.

The covert channel and the encryption are mutually dependent. A steganographic channel
without encryption is trivially readable if discovered. Encryption without a covert
channel is still visible as encrypted traffic. The combination, properly implemented,
leaves little to attack on either axis.

Protocol-level weaknesses in the target's infrastructure (TLS misconfigurations,
Kerberos misuse, padding oracle vulnerabilities in web applications) are often faster
paths to privilege escalation than any cipher break, and require no novel cryptanalysis.
