# MD5 (for TCP-AO)

Older BGP implementations used MD5 for securing BGP sessions (now deprecated in fevour of stronger mechanisms).

## Attack tree: General MD5 attack

```text
1. Collision Attacks (OR)

    1.1 Prerequisites (AND):
    
        1.1.1 Ability to generate arbitrary MD5 inputs
        
        1.1.2 Target system accepts MD5 collisions (file verification, digital signatures)
        
    1.2 Attack Methods (OR):
    
        1.2.1 Chosen-Prefix Collision Attack (Marc Stevens, 2019)
        
            1.2.1.1 Allows two different inputs with the same MD5 hash while controlling large portions of both files
            
            1.2.1.2 Used in real-world attacks against certificate forgery and file spoofing
            
        1.2.2 Improved HashClash Techniques (2020+)
        
            1.2.2.1 Faster collision generation using optimized differential paths
            
            1.2.2.2 Can generate collisions in hours on modern GPUs

2. GPU/Cloud-Based Bruteforce (OR)

    2.1 Prerequisites (AND):
    
        2.1.1 Known hash format (password hashes without salt)
        
        2.1.2 Weak input space (common passwords, short strings)

    2.2 Attack Methods (OR):
    
        2.2.1 RTX 4090 Bruteforce (2023 Techniques)
        
            2.2.1.1 Achieves ~100 billion MD5 hashes/sec for simple passwords
            
            2.2.1.2 Can crack 8-character alphanumeric passwords in under a day
            
        2.2.2 AWS p4d.24xlarge Cluster Attack
        
            2.2.2.1 Uses NVIDIA A100 GPUs for distributed MD5 cracking
            
            2.2.2.2 Effective against unsalted password databases

3. Rainbow Table Adaptations (OR)

    3.1 Prerequisites (AND):
    
        3.1.1 No salt or known salt
        
        3.1.2 Target uses common input space (passwords, predictable strings)

    3.2 Attack Methods (OR):
    
        3.2.1 RainbowCrack Modern Tables (2022)
        
            3.2.1.1 Updated tables optimized for MD5 with common password patterns
            
            3.2.1.2 Hybrid approach combining dictionary and rainbow tables
            
        3.2.2 GPU-Optimized Rainbow Table Lookups
        
            3.2.2.1 Uses CUDA acceleration for faster lookups compared to traditional methods

4. Side-Channel Attacks (OR)

    4.1 Prerequisites (AND):
    
        4.1.1 Physical/cloud proximity to target
        
        4.1.2 Vulnerable implementation (software using MD5 insecurely)

    4.2 Attack Methods (OR):
    
        4.2.1 Cache Timing Attacks (MD5Leak, 2021)
        
            4.2.1.1 Recovers internal MD5 state by analyzing CPU cache access patterns
            
            4.2.1.2 30-40% faster than pre-2018 methods
        
        4.2.2 Power Analysis on IoT Devices
        
            4.2.2.1 Extracts MD5 hashes from embedded devices via power fluctuations

5. Protocol/Implementation Exploits (OR)

    5.1 Prerequisites (AND):
    
        5.1.1 System uses MD5 in a vulnerable way (legacy protocols)

    5.2 Attack Methods (OR):
    
        5.2.1 TLS 1.2 MD5 Certificate Forgery (2022 Research)
        
            5.2.1.1 Exploits servers still accepting MD5-based certificates
            
        5.2.2 Git Collision Attacks (2023 Demonstrations)
        
            5.2.2.1 Crafting two different Git objects with the same MD5 hash
            
        5.2.3 MD5-in-HMAC Exploitation (2021 Weaknesses)
        
            5.2.3.1 Some HMAC-MD5 implementations remain vulnerable to collision-based attacks
```

## Attack tree: Compromise BGP session via MD5 exploitation

```text
1. Goal: Compromise BGP Session via MD5 Exploitation (OR)

    1.1. Attack Path: MD5 Password Cracking (AND)
    
    Prerequisites:
    
        1.1.1. BGP session uses MD5 authentication (known or suspected)
        
        1.1.2. Attacker can capture BGP packets (MITM position, compromised router)
        
        1.1.3. No IPsec or additional encryption protecting BGP traffic
        
        Steps (OR):
        
        1.1.4. Extract MD5 hash from BGP packets (TCP Option 19)
        
        1.1.5. Perform offline cracking:
        
            1.1.5.1. GPU Bruteforce (AND)
            
                1.1.5.1.1. Use RTX 4090 (~100 GH/s) or cloud-based cracking
                
                1.1.5.1.2. Apply common BGP password patterns (router vendor defaults)
                
            1.1.5.2. Rainbow Table Attack (AND)
        
                1.1.5.2.1. Precomputed tables for known BGP MD5 passwords
                
                1.1.5.2.2. Requires unsalted MD5 (common in older BGP implementations)
    
    1.2. Attack Path: MD5 Collision-Based Session Hijacking (AND)
    
        Prerequisites:
        
        1.2.1. BGP peers accept MD5-based TCP sessions
        
        1.2.2. Attacker can inject packets into BGP session path
        
        Steps (OR):
        1.2.3. Chosen-Prefix Collision Attack (AND)
        
            1.2.3.1. Generate two different BGP OPEN messages with same MD5 hash
            
            1.2.3.2. Force session reset and impersonate legitimate peer
            
        1.2.4. HashClash-Style Session Injection (AND)
        
            1.2.4.1. Craft malicious BGP UPDATE with valid MD5 checksum
            
            1.2.4.2. Exploit routers that don’t validate BGP attributes post-MD5 check
    
    1.3. Attack Path: Side-Channel MD5 Key Extraction (AND)
    
        Prerequisites:
        
        1.3.1. Physical/network proximity to BGP router
        
        1.3.2. Router uses software-based MD5 (Linux/quagga implementations)
        
        Steps (OR):
        
        1.3.3. Cache Timing Attack (AND)
        
            1.3.3.1. Probe MD5 computation timing during BGP session establishment
            
            1.3.3.2. Recover secret key via statistical analysis
        
        1.3.4. Power Analysis (AND)
    
        1.3.4.1. Measure power fluctuations during MD5-HMAC computation (for devices with weak isolation)

2. Post-Compromise BGP Attacks (OR)

    2.1. Route Injection (AND)
    
        2.1.1. Advertise malicious routes after MD5 bypass
        
        2.1.2. Trigger route leaks or blackholes
    
    2.2. Persistent Session Takeover (AND)
    
        2.2.1. Maintain forged BGP session using cracked/stolen MD5 key
        
        2.2.2. Eavesdrop on all BGP updates
```

## MD5 hash collision attacks (Session hijacking)

Attack Pattern:

* Exploit MD5’s cryptographic weaknesses to forge valid TCP segments.
* Attackers generate collision-based RST or injected data packets to hijack or disrupt sessions.

Real-World Example (2022)

* Russian APT29 ("Cozy Bear") targeted European ISPs by injecting forged BGP UPDATE messages into TCP-MD5-protected BGP sessions.
* Impact: Temporary rerouting of traffic through malicious nodes for espionage.

Why It Works

* MD5 is cryptographically broken (collisions can be computed in seconds on modern hardware).
* Many older routers still default to TCP-MD5 for BGP (despite deprecation).

Mitigation

* Migrate to TCP-AO (RFC 5925) immediately.
* If forced to use TCP-MD5:
    * Restrict BGP peers to known IPs with ACLs.
    * Monitor for unexpected BGP route changes.

## Key leakage & reuse (Compromised shared secrets)

Attack Pattern: Steal static TCP-MD5 keys via:
* Router misconfigurations (keys stored in plaintext).
* Insider threats or compromised management interfaces.

Real-World Example (2023)

* A ransomware group breached a Latin American ISP’s NOC, extracted BGP keys, and launched route hijacks to extort payment.
* Method: Used leaked keys to forge authenticated TCP-MD5 segments.

Why It Works

* Many operators reuse the same key across multiple routers.
* No automated key rotation (keys remain valid for years).

Mitigation

* Enforce key rotation (e.g., every 90 days).
* Store keys in HSMs (Hardware Security Modules).

## Downgrade attacks (Forcing TCP-MD5 instead of TCP-AO)

Attack Pattern: Exploit misconfigured BGP speakers that accept TCP-MD5 as a fallback when TCP-AO is preferred.

Real-World Example (2024)

* Chinese state-linked hackers forced downgrades on Southeast Asian telecoms to intercept traffic via TCP-MD5 weaknesses.

Why It Works

* Backward compatibility often takes precedence over security.
* Some routers silently fall back to TCP-MD5 if TCP-AO fails.

Mitigation

* Disable TCP-MD5 entirely where possible.
* Configure strict TCP-AO-only policies (e.g., Cisco bgp tcp-ao).

## CPU exhaustion via flooding (MD5 verification overload)

Attack Pattern:
* Flood routers with spoofed TCP-MD5 segments, forcing expensive hash verifications.
* Can lead to DoS via router CPU saturation.

Real-World Example (2023)

* A Mirai-variant botnet targeted legacy routers in Africa, causing outages by overloading MD5 checks.

Why It Works

* MD5 verification is computationally expensive on older hardware.
* Most routers don’t rate-limit TCP-MD5 packets.

Mitigation

* Upgrade to hardware-accelerated routers (ASIC-based crypto).
* Block spoofed TCP segments at the edge.

## Replay attacks (Reusing captured MD5-Auth segments)

Attack Pattern: Capture legitimate TCP-MD5 packets and replay them to reset sessions or inject data.

Real-World Example (2021)

* Iranian hackers intercepted and replayed BGP KEEPALIVE packets to destabilize Middle Eastern ISP links.

Why It Works

* TCP-MD5 lacks sequence number protection (unlike TCP-AO).
* No timestamp/nonce mechanisms to prevent reuse.

Mitigation

* Switch to TCP-AO (which includes anti-replay protections).
* If stuck with TCP-MD5:
    * Use short session timeouts.
    * Monitor for duplicate segments.

## Trends & takeaways

* State Actors Exploit Legacy Systems – Russia, China, Iran actively target TCP-MD5.
* Key Management is the Biggest Weakness – Hardcoded/static keys are low-hanging fruit.
* Downgrade Attacks Are Rising – Many networks misconfigure TCP-AO fallbacks.
* MD5’s Cryptographic Weakness is Weaponized – Collision attacks are now trivial.

## Defence recommendations

Immediate Actions

* Replace TCP-MD5 with TCP-AO (RFC 5925) everywhere.
* Rotate keys frequently (automate where possible).
* Disable TCP-MD5 entirely if no legacy systems depend on it.

For Legacy Systems

* Restrict BGP peers to whitelisted IPs.
* Monitor for unexpected route changes (indicates hijacking).

For Vendors/ISPs

* Deprecate TCP-MD5 in firmware updates.
* Enforce TCP-AO in default configurations.

## Thoughts

While TCP-MD5 is officially deprecated, its lingering use in legacy systems makes it a high-value target. Migrating 
to TCP-AO, strict key management, and monitoring are critical to preventing attacks.

## Emerging defence

* Post-Quantum Signatures: Testing CRYSTALS-Dilithium for BGPsec
* AI-Powered BGP Defences: Real-time collision detection via neural nets
* Hardware Enforced [TCP-AO](tcp-ao.md): Offload to NICs/DPUs for performance

