# Cryptographic attacks

## Attack pattern

IPsec relies heavily on cryptographic algorithms to provide confidentiality, integrity, and authentication for secure network communications. Weaknesses in these algorithms, their implementation, or their configuration can completely undermine the security of VPN tunnels and protected communications. Cryptographic attacks against IPsec target the fundamental trust mechanisms that secure the protocol, allowing attackers to decrypt traffic, impersonate peers, or establish unauthorized connections.

```text
1. Algorithm vulnerabilities [OR]

    1.1 Weak encryption algorithms (DES, 3DES) [OR]

        1.1.1 Brute-force attacks against 56-bit DES keys [AND]
            1.1.1.1 Exhaustive key search [AND]
                1.1.1.1.1 Generate all 2^56 candidate keys
                1.1.1.1.2 Test candidate keys using known plaintext/ciphertext
            1.1.1.2 Practical feasibility evidence [AND]
                1.1.1.2.1 Dedicated hardware demonstrations (e.g., Deep Crack)
                1.1.1.2.2 Distributed cracking campaigns validating timelines

        1.1.2 Sweet32 birthday attacks on 64-bit block ciphers (e.g., 3DES-CBC) [AND]
            1.1.2.1 Accumulate ≈ 2^32 cipher blocks in a single session
            1.1.2.2 Detect repeated block patterns [AND]
                1.1.2.2.1 Identify duplicate ciphertext blocks (birthday bound)
                1.1.2.2.2 Correlate repeats to recover/forge plaintext fragments
            1.1.2.3 Exploit protocol reuse of long-lived connections [AND]
                1.1.2.3.1 Target TLS/OpenVPN sessions that permit 3DES
                1.1.2.3.2 Bypass by enforcing AES/GCM or disabling 3DES

        1.1.3 Deprecated ECB mode misuse [OR]
            1.1.3.1 Block pattern leakage [AND]
                1.1.3.1.1 Recognise identical ciphertext blocks
                1.1.3.1.2 Infer repeated plaintext structure (image “penguin” effect)
            1.1.3.2 Message splicing and cut-and-paste [AND]
                1.1.3.2.1 Reorder ciphertext blocks without detection
                1.1.3.2.2 Cause predictable plaintext rearrangement on decryption

        1.1.4 CBC with predictable or reused IVs [OR]
            1.1.4.1 Chosen-plaintext manipulation [AND]
                1.1.4.1.1 Predict or control IV value
                1.1.4.1.2 Craft first-block plaintext via IV XOR properties
            1.1.4.2 Replay/nonce-misuse side effects [AND]
                1.1.4.2.1 Detect IV reuse enabling block equality tests
                1.1.4.2.2 Trigger protocol-level replays where anti-replay is absent

    1.2 Compromised or deprecated hash functions (MD5, SHA-1) [OR]

        1.2.1 MD5 chosen-prefix collisions enabling signature forgery [AND]
            1.2.1.1 Construct colliding messages with attacker-chosen prefixes
            1.2.1.2 Obtain signature on benign message and transfer to malicious twin
            1.2.1.3 Result: forged artefacts (e.g., certificates) where MD5 is accepted

        1.2.2 SHA-1 chosen-prefix collisions enabling forgery in legacy uses [AND]
            1.2.2.1 Generate chosen-prefix collision for two controlled inputs
            1.2.2.2 Get a legitimate signature on the benign input
            1.2.2.3 Reuse signature on the colliding malicious input

        1.2.3 Length-extension on Merkle–Damgård hashes used naively [AND]
            1.2.3.1 Obtain H(m) and |m| for MD5/SHA-1/SHA-256
            1.2.3.2 Append attacker-controlled suffix without key knowledge [AND]
                1.2.3.2.1 Compute correct MD padding for m ‖ pad ‖ suffix
                1.2.3.2.2 Produce valid H(m ‖ pad ‖ suffix)
            1.2.3.3 Note: does not apply to HMAC or SHA-3

        1.2.4 Reduced-round or non-standard variants collapse security margins [OR]
            1.2.4.1 Attacks outperform brute force on reduced-round MD5/SHA-1
            1.2.4.2 Implementation deviation (fewer rounds) ⇒ practical breaks [AND]
                1.2.4.2.1 Model reduced-round structure via differential techniques
                1.2.4.2.2 Derive collisions/forgeries far faster than full-round bounds

        1.2.5 HMAC-MD5 status in modern designs [OR]
            1.2.5.1 No practical break of HMAC-MD5 is known
            1.2.5.2 Nonetheless deprecated for new protocols; prefer HMAC-SHA-256

    1.3 Perfect forward secrecy (PFS) bypass paths [OR]

        1.3.1 Non-PFS ciphersuites: session decryption after long-term key compromise [AND]
            1.3.1.1 Recover static RSA or static DH key (via theft or side-channel)
            1.3.1.2 Decrypt previously recorded sessions that lacked PFS

        1.3.2 Downgrade to non-PFS or weak DH groups during negotiation [AND]
            1.3.2.1 Intercept and tamper with handshake parameters
            1.3.2.2 Force export-grade or static (non-ephemeral) groups [OR]
                1.3.2.2.1 512-bit export-grade finite-field DH (Logjam-style)
                1.3.2.2.2 Static DH/ECDH without ephemeral keys

        1.3.3 Ephemeral key reuse via RNG flaws [AND]
            1.3.3.1 Predict/observe nonce or ephemeral scalar reuse
            1.3.3.2 Recover session or long-term secrets from repeats [AND]
                1.3.3.2.1 Detect repeated ephemeral values across sessions
                1.3.3.2.2 Back-solve for secrets (ECDH/ECDSA analogues)

        1.3.4 Microarchitectural side-channels on elliptic-curve operations [AND]
            1.3.4.1 Measure timing/cache/EM characteristics of scalar mult. [AND]
                1.3.4.1.1 Repeated victim operations under observation
                1.3.4.1.2 Capture cache-timing/EM traces
            1.3.4.2 Infer private information from leakage [AND]
                1.3.4.2.1 Correlate traces with key-dependent behaviour
                1.3.4.2.2 Reconstruct partial/full private scalars

    1.4 Diffie–Hellman weak parameter exploitation [OR]

        1.4.1 Logjam against 512-bit export-grade DH [AND]
            1.4.1.1 Downgrade negotiation to 512-bit DH
            1.4.1.2 Solve discrete log with precomputation (NFS) [AND]
                1.4.1.2.1 Precompute for the target group once
                1.4.1.2.2 Derive session keys rapidly thereafter

        1.4.2 Small-subgroup confinement attacks [AND]
            1.4.2.1 Inject elements from a small subgroup (or invalid order)
            1.4.2.2 Extract key bits from victim responses [AND]
                1.4.2.2.1 Observe acceptance/rejection oracles
                1.4.2.2.2 Accumulate residues; reconstruct secret with CRT

        1.4.3 Invalid-curve attacks on ECDH implementations lacking checks [AND]
            1.4.3.1 Supply crafted points/parameters off the intended curve
            1.4.3.2 Use oracle behaviour to extract private key [AND]
                1.4.3.2.1 Collect accept/reject or finished-message signals
                1.4.3.2.2 Rebuild secret scalar via residues (CRT)

        1.4.4 Parameter injection during key exchange [OR]
            1.4.4.1 Substitute weak/attacker-chosen parameters [AND]
                1.4.4.1.1 Replace prime modulus or use non-safe groups
                1.4.4.1.2 Coerce peers into compromised/named groups
            1.4.4.2 Trigger DoS via malformed parameters [AND]
                1.4.4.2.1 Send invalid group elements or out-of-range exponents
                1.4.4.2.2 Force computation failure or excessive work
```

## Why it works

-   Cryptographic depreciation: Many IPsec implementations continue to support deprecated algorithms for backward compatibility, creating attack opportunities.
-   Implementation flaws: Even strong algorithms can be undermined by poor implementation choices, such as weak random number generation or side-channel vulnerabilities.
-   Configuration complexity: The numerous cryptographic options in IPsec make misconfigurations common, especially around PFS and algorithm prioritisation.
-   Computational advances: Increasing computational power makes previously secure algorithms vulnerable to brute-force attacks.
-   Standardisation lag: Formal deprecation of algorithms often occurs years after practical attacks become feasible.
-   Interoperability requirements: Enterprise environments often require support for weak algorithms to maintain compatibility with legacy systems.
-   DES brute-force attacks are feasible due to its 56-bit key length; dedicated hardware and distributed cracking campaigns have demonstrated practical timelines.  
-   3DES is vulnerable to Sweet32 birthday attacks on 64-bit block ciphers when long-lived connections accumulate ≈2^32 blocks, allowing plaintext recovery from repeated ciphertext patterns.  
-   ECB mode leaks structure because identical plaintext blocks produce identical ciphertext blocks, enabling pattern recognition and cut-and-paste manipulation.  
-   CBC with predictable or reused IVs allows attackers to manipulate first-block plaintext or trigger protocol-level replay attacks when anti-replay is absent.  
-   MD5 chosen-prefix collisions can forge signatures on artefacts like certificates by obtaining a legitimate signature on a benign message and transferring it to a malicious twin.  
-   SHA-1 chosen-prefix collisions remain practical in legacy systems, enabling forgery where SHA-1 is still accepted.  
-   Length-extension attacks exploit naive Merkle–Damgård hash usage; attackers can append controlled data and produce valid hashes without knowing secret keys, though HMAC-SHA-256 resists this.  
-   Reduced-round or non-standard hash implementations collapse security margins, allowing differential attacks to outperform brute force and derive collisions faster than full-round versions.  
-   HMAC-MD5 remains technically unbroken, but is deprecated for new protocols in favour of HMAC-SHA-256 due to theoretical weaknesses and widespread distrust.  
-   Non-PFS ciphersuites expose all past session data if long-term keys are compromised, making static RSA or DH keys a critical weakness.  
-   Downgrade attacks force negotiations to weak or non-ephemeral DH groups (e.g., 512-bit export-grade), undermining forward secrecy.  
-   RNG flaws causing ephemeral key reuse allow session or long-term secrets to be recovered when repeated ephemeral values are detected.  
-   Microarchitectural side-channels on elliptic-curve operations (timing, cache, EM) leak private scalars, letting attackers reconstruct partial or full keys through observation.  
-   Logjam attacks against 512-bit DH leverage precomputation to solve discrete logs rapidly, enabling decryption of session keys after negotiation downgrade.  
-   Small-subgroup confinement attacks extract key bits by injecting low-order elements and observing victim responses, reconstructing secrets using residues.  
-   Invalid-curve attacks exploit ECDH implementations lacking proper checks, feeding off-curve points and recovering private scalars via oracle behaviour.  
-   Parameter injection during key exchange can substitute weak or attacker-chosen group parameters, forcing peers to use compromised settings or triggering DoS through malformed elements.  
-   In general, these attacks succeed due to weak legacy algorithms, protocol shortcuts, predictable or misused cryptography, and insufficient validation of inputs and ephemeral material.

## Mitigation

### Algorithm selection and enforcement
-   Action: Implement strict cryptographic policies and disable weak algorithms
-   How:
    -   Disable DES, 3DES, MD5, and SHA-1 in IKE and ESP proposals
    -   Enforce AES-GCM with 128-bit or larger keys for encryption
    -   Require SHA-256 or stronger for integrity protection
    -   Implement algorithm prioritisation to prefer strongest available ciphers
-   Configuration example (Strong IKE proposal, cisco):

```text
crypto ikev2 proposal STRONG-PROPOSAL 
 encryption aes-gcm-256
 integrity sha512
 group 21
```

### Perfect forward secrecy enforcement
-   Action: Ensure ephemeral keys are used for all sessions
-   How:
    -   Require PFS for all IKE security associations
    -   Use modern Diffie-Hellman groups (≥ 2048-bit for DH, ≥ 256-bit for ECDH)
    -   Implement strict key lifetime policies for both IKE and IPsec SAs
    -   Regularly rotate pre-shared keys and certificate authority keys
-   Best practice: Use ECDH with P-384 or Curve25519 for optimal performance and security

### Cryptographic monitoring and testing
-   Action: Continuously monitor for cryptographic weaknesses and attacks
-   How:
    -   Implement IPsec session monitoring for anomalous parameters
    -   Use network testing tools to verify algorithm enforcement
    -   Conduct regular cryptographic audits of IPsec configurations
    -   Monitor for known vulnerable implementations and apply patches promptly
-   Tools: Custom scripts to parse IKE negotiations and flag weak algorithms

### Hardware security module integration
-   Action: Protect cryptographic keys using dedicated hardware
-   How:
    -   Use HSMs for private key storage and cryptographic operations
    -   Implement hardware-based random number generation
    -   Protect against side-channel attacks through physical security measures
    -   Use tamper-evident logging for cryptographic operations
-   Configuration example (HSM integration, junos):

```text
security {
    hsm {
        partition 1 {
            admin-password "$9$hsm-secure-password";
            crypto-package "ipsectunnel";
        }
    }
}
```

### Regular cryptographic assessment
-   Action: Conduct periodic reviews of cryptographic implementations
-   How:
    -   Test against known vulnerabilities (e.g., Sweet32, Logjam)
    -   Verify algorithm enforcement through penetration testing
    -   Review cryptographic policies against current best practices
    -   Assess computational feasibility of brute-force attacks against configured algorithms
-   Best practice: Quarterly cryptographic health checks and immediate response to new vulnerabilities

## Key insights from real-world implementations

-   Legacy system impact: Many organisations maintain support for weak algorithms due to legacy hardware, creating persistent vulnerabilities.
-   Performance trade-offs: The computational overhead of strong cryptography can lead to intentional weakening of security policies.
-   Configuration drift: Without automated enforcement, IPsec configurations tend to drift toward weaker settings over time.
-   Vendor inconsistencies: Different vendors implement cryptographic standards with varying rigor, leading to interoperability-driven weaknesses.

## Future trends and recommendations

-   Post-quantum preparation: Begin planning for migration to quantum-resistant algorithms as standards emerge.
-   Automated policy enforcement: Implement automated tools to continuously enforce cryptographic policies.
-   Hardware acceleration: Use modern cryptographic accelerators to eliminate performance excuses for weak algorithms.
-   Zero-trust cryptography: Implement continuous authentication and key rotation rather than long-lived sessions.

## Conclusion

Cryptographic attacks against IPsec remain highly effective due to the protocol's complexity, backward compatibility requirements, and implementation challenges. Protecting against these attacks requires rigorous algorithm management, strong forward secrecy enforcement, continuous monitoring, and regular cryptographic assessment. As computational capabilities advance and new attacks emerge, organisations must maintain vigilance in their IPsec cryptographic policies to ensure the continued security of their encrypted communications.