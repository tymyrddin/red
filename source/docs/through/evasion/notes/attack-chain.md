# The low-noise intrusion model

Steganography hides communication. Cryptographic weaknesses expose or protect secrets.
Evasion techniques make everything look normal. Individually useful; together,
annoyingly effective.

This page maps how these disciplines combine into a coherent operational approach
built around one principle: staying boring.

## Entry: nothing fancy, just effective

The attacker does not start with cleverness. Phishing, credential reuse, token theft.
These work because they do not need to bypass anything technical: the front door is
open, so there is no need for a battering ram.

No exploits, no novel techniques, no detectable tooling at this stage. Entry via
identity abuse leaves the kind of log entries that look like a user authenticating.

## Foothold: establish quiet persistence

Once inside, the priority is persistence with minimal footprint:

- Fileless execution: payloads live in memory, not on disk
- LoLbin execution: system tools carry out the work
- In-memory .NET assembly loading for any tooling that needs to run

The first layer of steganographic C2 now activates. The implant fetches an image or
document from a legitimate platform. Hidden inside, encrypted, are the instructions
for the next phase. Extraction happens in memory. What is visible in network telemetry
is: a process requesting a file from a cloud storage service. Normal.

## Command and control: invisible conversation

Rather than beaconing to an attacker-controlled server, traffic goes to legitimate
platforms: image hosting, social media, cloud storage APIs. The content looks normal.

Instructions are hidden using modern steganography: coverless techniques produce AI-
generated images that carry no original to compare against. Each instruction image
is freshly generated. The payload is encrypted before embedding; even if the image
is recovered, the contents are ciphertext.

The C2 channel is therefore: normal HTTPS traffic to normal services, with a fully
functional control channel underneath. DNS-based fallback (instructions encoded in
subdomain queries) provides a secondary channel if the primary is disrupted.

## Internal movement: break what matters

Now the attacker encounters real boundaries: privilege restrictions, segmented networks,
hardened systems. This is where the noise budget matters most.

Protocol and cryptographic weaknesses: where internal services use weak TLS, padding
oracle vulnerabilities, or Kerberos configurations with crackable material, these
provide privilege escalation paths without requiring noisy exploitation.

Memory corruption where necessary: if a privilege boundary requires it, a short-lived
in-memory exploit (fileless, no disk artefact, executed in the context of a legitimate
process) bridges the gap. This is the only genuinely noisy part of the operation, and
even here execution is kept brief and the payload cleans up after itself.

BYOVD to disable EDR before the noisy step: load a vulnerable driver, remove kernel
callbacks, proceed.

## Persistence: become part of the system

The implant establishes persistence that mimics legitimate system activity:

- WMI event subscriptions triggered by normal system events
- Scheduled tasks with names matching the target organisation's naming conventions
- Cloud API keys and OAuth tokens stored in credential stores alongside legitimate ones
- Configuration changes that look like administrative decisions rather than implant
  behaviour

Behaviour from this point mimics the user whose credentials were used. Actions are
timed to business hours, use the expected tools, and leave log entries consistent with
that user's normal activity pattern.

## Exfiltration: slow, dull, effective

Data is encrypted, split into small chunks, and embedded into image sequences for
upload via normal web channels. No spike in volume. No suspicious destination. The
images are indistinguishable from the ambient traffic of a user uploading photos.

The specific steganographic method is selected based on the channel:

- JPEG images for social media (F5 or DCT-based embedding survives recompression)
- PNG images for cloud storage (lossless; LSB or neural embedding)
- Audio files where available (MP3Stego)

Volume is kept low. The exfiltration runs over days or weeks. The data trickles out
below the threshold at which any individual event looks suspicious.

## Where defenders can still win

Not by being clever, but by being disciplined:

Full logging and cross-system correlation: nothing in this model is suspicious in
isolation. The pattern only appears across multiple systems over time. High coverage
logging that is retained long enough to allow retrospective analysis is the primary
defence.

Identity and access control: the model depends on stolen credentials or tokens looking
legitimate. Short-lived tokens, strict MFA, and anomaly detection on credential use
raise the cost of the entry and persistence phases significantly.

Reduce cryptographic attack surface: removing padding oracle vulnerabilities, enforcing
TLS 1.3, and fixing Kerberos misconfigurations eliminate the lateral movement paths
that avoid noisy exploitation entirely.

Detect behaviour drift: not "is this malicious?" but "is this normal for this
user and this system?" is the right question. Subtle, hard to automate, but far more
effective than signature matching against a model designed to produce no signatures.
