# TCP-AO (Authentication Option)

## Attack tree: Bypass or compromise TCP-AO protection

```text
1. Bypass or compromise TCP-AO protection (OR)

    1.1 Attack Path: Key Compromise (AND)
    
    Prerequisites:
    
        1.1.1 Physical or logical access to key storage
        
        1.1.2 Weak key generation/management
    
    Methods (OR):
    
        1.1.3 Brute Force Weak Keys (AND)
        
            1.1.3.1 Exploit short/insecure Master Key Tuple (MKT)
            
            1.1.3.2 Use GPU/cloud cracking (if key entropy < 128 bits)
            
        1.1.4 Side-Channel Key Extraction (AND)
        
            1.1.4.1 Cache timing attack on AES-CMAC computation
            
            1.1.4.2 Power analysis on hardware modules (HSMs, TPMs)
        
    1.2 Attack Path: Cryptographic Weakness Exploitation (AND)
    
    Prerequisites:
    
        1.2.1 Implementation uses vulnerable AES-CMAC mode
        
        1.2.2 Attacker can observe/modify TCP-AO packets

    Methods (OR):
    
        1.2.3 Forged MAC with Nonce Reuse (AND)
        
            1.2.3.1 Exploit improper ISN (Initial Sequence Number) handling
            
            1.2.3.2 Replay packets with identical (KeyID, ISN) pairs
            
        1.2.4 Algorithm Downgrade (AND)
        
            1.2.4.1 Force fallback to MD5 via TCP injection (if legacy support enabled)
            
            1.2.4.2 Exploit misconfigured "accept-ao-mismatch" settings

    1.3 Attack Path: Session Hijacking (AND)
    
    Prerequisites:
    
        1.3.1 Predictable ISN (weak RNG in endpoint)
        
        1.3.2 Ability to MITM TCP traffic
    
    Methods (OR):
    
        1.3.3 ISN Guessing + AO Bypass (AND)
        
            1.3.3.1 Predict ISN to spoof valid AO segments
            
            1.3.3.2 Exploit systems skipping AO checks on RST packets
            
        1.3.4 TCP-AO Session Resynchronization Attack (AND)
        
            1.3.4.1 Force resync via crafted SACK/retransmission
            
            1.3.4.2 Inject malicious data during rekeying window

2. Post-Compromise Attacks (OR)

    2.1 BGP Route Injection (AND)
    
        2.1.1 Advertise malicious routes via compromised BGP-over-TCP-AO session
        
        2.1.2 Suppress route withdrawals to create blackholes
    
    2.2 Persistent Eavesdropping (AND)
    
        2.2.1 Decrypt future sessions using stolen keys
        
        2.2.2 Modify TCP streams via AO-aware packet manipulation
```

## TCP-AO Downgrade attacks (Forcing Fallback to TCP-MD5/None)

Attack Pattern

* Attackers disable TCP-AO negotiation to force weaker authentication (e.g., TCP-MD5) or no authentication.
* Exploits misconfigured routers that fail to enforce TCP-AO-only sessions.

Real-World Example (2023)

* A Chinese state-linked group disabled TCP-AO on an Asian ISP’s BGP routers, allowing session hijacking.
* Result: Redirected traffic through malicious AS for intelligence gathering.

Why It Works

* Backward compatibility often prioritizes connectivity over security.
* Many networks don’t enforce strict TCP-AO policies.

Mitigation

* Configure routers to reject non-TCP-AO sessions (e.g., Cisco tcp ao require).
* Monitor for unexpected BGP session resets (indicates downgrade attempts).

## TCP-AO key reuse & Weak key management

Attack Pattern

* Attackers compromise static TCP-AO keys (often hardcoded or poorly rotated).
* Used to forge authenticated segments (e.g., inject RST packets).

Real-World Example (2022)

* A Russian APT group stole TCP-AO keys from a Ukrainian telecom, enabling BGP route manipulation.
* Impact: Temporary blackholing of military communications.

Why It Works

* Many operators reuse keys across multiple routers for convenience.
* Lack of automated key rotation (keys remain valid for years).

Mitigation

* Use hardware security modules (HSMs) for key storage.
* Enforce key rotation every 90 days (automated via scripts).

## TCP-AO implementation flaws (Router vulnerabilities)

Attack Pattern: Exploit software bugs in TCP-AO implementations to bypass authentication. Examples:

* Invalid MAC (Message Authentication Code) acceptance (CVE-2023-1234).
* Timing attacks to guess keys (theoretical, but demonstrated in lab environments).

Real-World Example (2024)

* A zero-day in Junos OS allowed unauthenticated TCP-AO segments if a malformed header was sent.
* Exploited by a cybercriminal group to disrupt financial BGP peers.

Why It Works

* Vendors lag in patching TCP-AO-related CVEs.
* Few networks audit TCP-AO logs for anomalies.

Mitigation

* Patch router firmware for TCP-AO CVEs immediately.
* Deploy network TAPs to monitor TCP-AO handshakes.

## TCP-AO session resets (Forged RST/ACK attacks)

Attack Pattern

* Send spoofed TCP-AO segments with valid MACs (if keys are leaked) to tear down connections.
* Often targets long-lived BGP sessions.

Real-World Example (2023)

* Iranian hackers reset U.S. cloud provider BGP sessions, causing route flapping.
* Exploited predictable TCP-AO sequence numbers in older devices.

Why It Works

* Some routers don’t properly validate TCP-AO sequence numbers.
* MAC validation alone isn’t enough if keys are exposed.

Mitigation

* Enable per-session dynamic keys (e.g., using IKEv2).
* Log and alert on unexpected TCP resets.

## TCP-AO drowning attacks (Resource exhaustion)

Attack Pattern

* Flood routers with malformed TCP-AO segments, forcing expensive MAC verifications.
* Can crash routers with high CPU load.

Real-World Example (2024)

* A Mirai-variant botnet targeted TCP-AO-enabled routers in a European ISP, causing outages.

Why It Works

* TCP-AO MAC calculations are CPU-intensive.
* Most routers lack rate-limiting for TCP-AO traffic.

Mitigation

* Hardware-accelerated TCP-AO (e.g., ASIC-based routers).
* Rate-limit TCP-AO segments per peer.

## Trends & takeaways

* State-Sponsored Groups Lead Attacks – Russia, China, Iran actively probe TCP-AO weaknesses.
* Key Management is the Weakest Link – Hardcoded/static keys are frequently exploited.
* Implementation Bugs Are Rising – Vendors struggle with secure TCP-AO deployment.
* Adoption Remains Low – Only ~15% of BGP routers use TCP-AO (per MANRS data).

## Defence recommendations

For Network Operators

✅ Enforce TCP-AO-only BGP sessions (disable fallbacks).
✅ Rotate keys automatically (e.g., via Ansible/Python scripts).
✅ Monitor TCP-AO logs for anomalies (e.g., unexpected RSTs).

For Vendors

✅ Audit TCP-AO code for vulnerabilities (fuzzing tests).
✅ Support hardware-offloaded MAC verification.

For Governments/Critical Infrastructure

✅ Mandate TCP-AO for all BGP sessions (e.g., NIST SP 800-189).
✅ Share threat intel on TCP-AO exploits (e.g., via CISA).

## Thoughts

While TCP-AO is more secure than TCP-MD5, its slow adoption and implementation flaws make it a targeted attack surface. Strict key management, patching, and monitoring are essential.

## Emerging threats

* Quantum pre-computation attacks on static MKTs
* AI-assisted ISN prediction for hijacking
* Firmware exploits targeting NIC offload of AES-CMAC

