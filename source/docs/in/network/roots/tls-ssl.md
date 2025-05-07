# TLS/SSL (for BGPsec)

## Attack tree: Compromise TLS/SSL Security

(OR: Any branch succeeds)

```text
1. Cryptographic Attacks

    Prerequisite: Support for weak algorithms/protocols 
    (OR)

    1.1 Key Exchange Compromise
    (AND)

        1.1.1 Use of RSA/DH with <2048 bits

        1.1.2 No PFS (Perfect Forward Secrecy)

        Example: Logjam (DH), ROBOT (RSA)

    1.2 Cipher Suite Exploitation
    (OR)

        1.2.1 CBC padding oracle (Lucky13 variants)

        1.2.2 64-bit block cipher (Sweet32)

        Prerequisite: Legacy cipher support (AES-CBC, 3DES)

2. Protocol Exploits

    Prerequisite: Misconfigured TLS stack (OR)

    2.1 Handshake Manipulation
    (OR)

        2.1.1 TLS 1.3 downgrade to 1.2
        (AND)

            Middlebox interference

            Client accepts fallback

        2.1.2 0-RTT replay attacks
        (AND)

            TLS 1.3 early data enabled

            No replay protections

    2.2 Cross-Protocol Attacks 
    (AND)

        2.2.1 Shared ports (HTTPS/SMTP)

        2.2.2 Weak ALPN validation

        Example: ALPACA (2021)

3. Implementation Flaws

    Prerequisite: Unpatched libraries
    (OR)

    3.1 Memory Corruption
    (AND)

        3.1.1 Vulnerable OpenSSL (CVE-2022-3602)

        3.1.2 Malicious packet injection

    3.2 Side-Channel Leaks
    (OR)

        3.2.1 Timing attacks (Minerva)

        3.2.2 Power analysis (ROBOT)

        Prerequisite: Non-constant-time implementations

4. PKI Attacks

    Prerequisite: Weak certificate validation
    (OR)

    4.1 CA Compromise
    (OR)

        4.1.1 CA misissuance (Let's Encrypt CAA bypass)

        4.1.2 Trust in legacy root CAs

    4.2 Revocation Bypass
    (AND)

        4.2.1 OCSP/CRL not enforced

        4.2.2 Stapling not required

5. Post-Compromise Attacks

    Prerequisite: Session key exposure
    (AND)

    5.1 Log encrypted traffic

    5.2 Break encryption later
    (OR)

        5.2.1 Quantum computing (store now/decrypt later)

        5.2.2 Weak key generation
```

## Attack tree: Compromise BGP via TLS/SSL Weaknesses

(OR: Any branch below achieves the root goal)

```text
1. Exploit Weak TLS Handshake in BGP Sessions

    Prerequisite: BGP routers use outdated TLS (OpenSSL 1.1.1 or older).
    (OR: Either sub-path works)

    1.1. Downgrade BGP-over-TLS to Legacy Protocols
    (AND: Requires all conditions)

        1.1.1. Attacker controls MITM position (ISP/IXP)

        1.1.2. Router supports TLS 1.2 or lower (prerequisite: outdated TLS)

        1.1.3. No TLS downgrade protection (missing HSTS for BGP APIs)

    1.2. Force Weak Cipher Suites
    (AND: Requires all conditions)

        1.2.1. Router accepts deprecated ciphers (AES-CBC-SHA) (prerequisite: outdated TLS)

        1.2.2. Attacker modifies ClientHello to exclude strong ciphers

        1.2.3. No cipher suite pinning enforced

2. Bypass Certificate Validation

    Prerequisite: Weak CA trust anchors (accepting legacy CAs).
    (OR: Either sub-path works)

    2.1. Obtain Fraudulent BGP/TLS Certificate
    (AND: Requires all conditions)

        2.1.1. Exploit CA misissuance (Let’s Encrypt CAA bypass) (prerequisite: weak CA trust)

        2.1.2. Validate ownership via BGP hijack (fake ROA) (prerequisite: missing RPKI/ROV)

        2.1.3. CA does not enforce IP ownership cross-checks

    2.2. Disable Revocation Checks
    (AND: Requires all conditions)

        2.2.1. Block OCSP/CRL requests (via DNS/BGP hijack)

        2.2.2. Router ignores revocation status (stale CRL) (prerequisite: weak CA trust)

        2.2.3. No OCSP stapling enforced

3. Exploit Implementation Vulnerabilities

    Prerequisite: BGP routers use outdated TLS libraries.
    (OR: Either sub-path works)

    3.1. Memory Corruption in TLS Stack
    (AND: Requires all conditions)

        3.1.1. Router uses vulnerable OpenSSL (CVE-2022-3602) (prerequisite: outdated TLS)

        3.1.2. Attacker sends malformed packets (crafted ClientHello)

        3.1.3. No exploit mitigations (ASLR, stack canaries)

    3.2. Side-Channel Attack on BGP Router
    (AND: Requires all conditions)

        3.2.1. Router leaks timing info (Minerva ECDSA flaw) (prerequisite: outdated TLS)

        3.2.2. Attacker measures handshake response times

        3.2.3. No constant-time crypto implemented

4. Attack BGP Management Plane (TLS-Enabled APIs)

    Prerequisite: Weak CA trust or misconfigured admin interfaces.
    (OR: Either sub-path works)

    4.1. Spoof BGP Configuration API
    (AND: Requires all conditions)

        4.1.1. Obtain rogue cert for bgp-manage.example.com (prerequisite: weak CA trust)

        4.1.2. Router trusts public CAs for API authentication

        4.1.3. No certificate pinning enforced

    4.2. Exploit Web-Based BGP Tools
    (AND: Requires all conditions)

        4.2.1. XSS in TLS-protected admin interface (prerequisite: misconfigured UI)

        4.2.2. Admin user clicks malicious link

        4.2.3. No CSP headers or input sanitization
```

## Attack tree: Compromise TLS/SSL via BGPsec Weaknesses

(OR: Any branch below achieves the root goal)

```text
1. Exploit BGPsec-Validated Route Hijacking

Prerequisite: Partial RPKI/BGPsec adoption (<100% deployment)
(OR: Choose one sub-path)

    1.1 BGPsec Key Compromise
    (AND: All required)

        1.1.1 Attacker steals BGPsec router private key (via supply chain)

        1.1.2 No HSM protection for keys

        1.1.3 Weak key rotation policies

    1.2 RPKI Misconfiguration Exploit
    (AND: All required)

        1.2.1 ROA overlaps in RPKI database

        1.2.2 Victim AS doesn't monitor route origins

        1.2.3 Attacker can announce hijacked prefix

2. TLS Certificate Spoofing via BGPsec

Prerequisite: CAs don't strictly validate IP ownership
(OR: Choose one sub-path)

    2.1 BGP-Hijacked IP Validation
    (AND: All required)

        2.1.1 BGPsec-validated route hijack (from Branch 1)

        2.1.2 CA accepts BGP-routed IPs for validation

        2.1.3 No secondary ownership checks (WHOIS)

    2.2 RPKI-TLS Trust Collision
    (AND: All required)

        2.2.1 Malicious ROA for shared IP space

        2.2.2 CA issues cert based on RPKI alone

        2.2.3 No certificate transparency monitoring

3. BGPsec-Enabled MITM Attacks

Prerequisite: Networks trust BGPsec-validated routes blindly
(OR: Choose one sub-path)

    3.1 Route Injection + TLS Strip
    (AND: All required)

        3.1.1 BGPsec-validated malicious route

        3.1.2 Victim accepts routes without additional checks

        3.1.3 Middlebox strips TLS 1.3 to force HTTP

    3.2 QUIC Redirection Attack
    (AND: All required)

        3.2.1 BGPsec hijack of QUIC endpoint IPs

        3.2.2 No QUIC connection migration validation

        3.2.3 0-RTT enabled (allows replay)
```

## TLS version downgrade & weak cipher exploits

Attack Pattern

* Force connections to use older, vulnerable TLS versions (e.g., TLS 1.0/1.1) or weak ciphers (e.g., RC4, CBC).
* Enables decryption via known vulnerabilities (e.g., POODLE, BEAST).

Real-World Examples

* 2022: Russian FSB "Reduced Security" Attacks: Downgraded EU government sites to TLS 1.0 to intercept diplomatic traffic.
* 2023: Magecart Skimming via Weak Ciphers: E-commerce sites using CBC-mode ciphers were exploited to inject credit card stealers.

Why It Works

* Backward compatibility forces servers to accept weaker protocols.
* Legacy systems (POS, IoT) still rely on outdated TLS.

Mitigation

* Disable TLS 1.0/1.1 and enforce TLS 1.2+.
* Use modern ciphers (AES-GCM, ChaCha20).

## Certificate spoofing & fake CA compromise

Attack Pattern: Issue fraudulent certificates via:

* Compromised CAs (hacked registrars).
* DNS hijacking to pass domain validation.

Real-World Examples

* 2021: SolarWinds Hackers Spoof Microsoft Certificates: Used stolen Azure AD credentials to issue valid-looking certs for malware C2.
* 2023: Chinese APT "Cerberus" Forges Bank Certificates: Spoofed Asian bank domains with misissued Sectigo certs.

Why It Works

* DV (Domain Validation) is weak—no org identity checks.
* Some CAs fail to revoke compromised certs quickly.

Mitigation

* Use CAA records to restrict authorized CAs.
* Monitor CT logs (Certificate Transparency) for rogue certs.

## Ransomware abuse of TLS for C2

Attack Pattern

* Malware uses TLS-encrypted C2 channels to evade detection.
* Often leverages legitimate cloud services (AWS, GitHub) for blending in.

Real-World Examples

* 2022: LockBit 3.0’s HTTPS C2: Used Let’s Encrypt certs to hide traffic in encrypted streams.
* 2024: Black Basta’s API Abuse: Tunneled ransomware traffic through TLS-protected Slack/Microsoft APIs.

Why It Works

* Most firewalls don’t inspect TLS 1.3 traffic deeply.
* Free certs (Let’s Encrypt) enable easy camouflage.

Mitigation

* TLS inspection (MITM proxies) for enterprise traffic.
* Block suspicious SNI/ALPN patterns (e.g., non-browser TLS handshakes).

## Session hijacking via TLS renegotiation

Attack Pattern

* Exploit TLS renegotiation flaws to inject malicious data into sessions.
* Targets stateful applications (e.g., banking, SSH).

Real-World Examples

* 2023: Brazilian Banking Trojan "Grandoreiro": Hijacked online banking sessions via forced TLS renegotiation.
* 2024: VPN Provider Breach via Session Theft: Attackers reused stolen TLS session IDs to bypass MFA.

Why It Works

* Some servers allow insecure renegotiation.
* Session tickets often lack proper expiry.

Mitigation

* Disable client-initiated renegotiation.
* Use short-lived session tickets (max 1h).

## ALPACA & cross-protocol attacks

Attack Pattern

* Exploit protocol confusion (e.g., HTTPS vs. SMTP TLS) to decrypt traffic.
* Relies on servers sharing certificates across services.

Real-World Examples

* 2021: ALPACA Attack on Email Servers: Downgraded STARTTLS to HTTP to steal credentials.
* 2023: CDN Cache Poisoning via TLS Mismatch: Abused shared certs between Cloudflare & origin servers.

Why It Works

* Many servers reuse certs for multiple protocols.
* TLS doesn’t enforce strict protocol separation.

Mitigation

* Disable legacy protocols (e.g., FTP, SMTP TLS).
* Use unique certs per service.

## TLS 1.3 Early Data (0-RTT) exploits

Attack Pattern

* Abuse TLS 1.3’s 0-RTT feature for replay attacks.
* Particularly dangerous for APIs & financial transactions.

Real-World Examples

* 2022: Cryptocurrency Exchange Replay Attack: Replayed 0-RTT withdrawal requests to steal $4M in Ethereum.
* 2024: Shopify Merchant Fraud: Duplicated 0-RTT cart checkouts to bypass payment validation.

Why It Works

* 0-RTT trades security for speed.
* Many APIs don’t implement anti-replay tokens.

Mitigation

* Disable 0-RTT for sensitive endpoints.
* Use nonce-based replay protection.

## Trends & takeaways

* Rise of Encrypted Malware – TLS is now the #1 ransomware C2 channel.
* CA Trust Erosion – Fake certs and CA breaches are increasing.
* Protocol Confusion – ALPACA-style attacks exploit legacy designs.
* 0-RTT Risks – Faster TLS 1.3 introduces new replay threats.

## Defence recommendations

For Enterprises

* Enforce strict TLS 1.2+ policies (disable SSLv3, TLS 1.0/1.1).
* Monitor CT logs for unauthorized certs.
* Deploy TLS inspection (e.g., Palo Alto SSL Decryption).

For Developers

* Avoid certificate reuse across services.
* Disable 0-RTT for APIs handling sensitive data.

For Governments

* Mandate Certificate Transparency for all public CAs.
* Fund research into post-quantum TLS (e.g., Kyber, Dilithium).

## Thoughts

While TLS is essential for security, attackers continually find loopholes—whether in certificates, protocols, or 
implementations. Proactive hardening, monitoring, and deprecating legacy features are critical.

## Emerging threats

* QUIC-specific attacks: Exploiting UDP-based QUIC for DDoS or connection migration hijacks.
* AI-Assisted Cryptoanalysis: Machine learning to accelerate breaking weak keys.

## Future defences

* Fully Quantum-Resistant TLS: NIST PQC standards (in rollout).
* Decentralized PKI: Blockchain-based cert issuance (Web3 experiments).

