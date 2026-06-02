# Cryptographic attacks on routing protocols

## Attack pattern

Cryptographic attacks on routing protocols target the security mechanisms designed to protect the integrity, authenticity, and confidentiality of routing information exchanges. These attacks exploit vulnerabilities in cryptographic algorithms, key management practices, or protocol implementations to compromise routing infrastructure, facilitate traffic interception, or cause network disruption. As routing protocols increasingly incorporate cryptographic protections, attackers have developed sophisticated methods to undermine these security measures.

```text
1. Cryptographic attacks on routing protocols [OR]

    1.1 BGPsec exploitation [OR]
    
        1.1.1 Key compromise attacks
            1.1.1.1 Private key extraction from router hardware
            1.1.1.2 Key generation weakness exploitation
            1.1.1.3 Certificate signing request manipulation
            
        1.1.2 Signature validation bypass
            1.1.2.1 Algorithm downgrade attacks
            1.1.2.2 Signature verification logic flaws
            1.1.2.3 Path validation exploitation
            
        1.1.3 Protocol implementation attacks
            1.1.3.1 AS_PATH reconstruction vulnerabilities
            1.1.3.2 Secure_Path segment manipulation
            1.1.3.3 Confederation processing flaws
            
    1.2 TCP-AO cryptographic attacks [OR]
    
        1.2.1 Hash function exploitation
            1.2.1.1 HMAC-SHA-1-96 collision attacks
            1.2.1.2 AES-128-CMAC-96 pre-image attacks
            1.2.1.3 Key derivation function weaknesses
            
        1.2.2 Key management attacks
            1.2.2.1 Master key compromise
            1.2.2.2 Traffic key extraction
            1.2.2.3 Context manipulation attacks
            
        1.2.3 Protocol-specific exploitation
            1.2.3.1 TCP sequence number prediction
            1.2.3.2 Session hijacking through MAC bypass
            1.2.3.3 Replay attack exploitation
            
    1.3 RPKI infrastructure attacks [OR]
    
        1.3.1 Certificate chain exploitation
            1.3.1.1 Trust anchor compromise
            1.3.1.2 Intermediate CA manipulation
            1.3.1.3 Certificate revocation bypass
            
        1.3.2 Repository system attacks
            1.3.2.1 RPKI object manipulation
            1.3.2.2 Manifest forgery attacks
            1.3.2.3 Ghostbusters record exploitation
            
        1.3.3 Relying party software attacks
            1.3.3.1 Cache poisoning techniques
            1.3.3.2 Path traversal vulnerabilities
            1.3.3.3 Validation bypass attacks
            
    1.4 Algorithm-specific attacks [OR]
    
        1.4.1 Hash function collisions
            1.4.1.1 MD5 exploitation in legacy systems
            1.4.1.2 SHA-1 vulnerability targeting
            1.4.1.3 Birthday attack implementations
            
        1.4.2 Digital signature exploitation
            1.4.2.1 ECDSA nonce reuse attacks
            1.4.2.2 RSA key factor attempts
            1.4.2.3 Signature malleability exploitation
            
        1.4.3 Encryption algorithm attacks
            1.4.3.1 Block cipher mode weaknesses
            1.4.3.2 Initial vector manipulation
            1.4.3.3 Padding oracle exploitation
            
    1.5 Key management attacks [OR]
    
        1.5.1 Key generation weaknesses
            1.5.1.1 Pseudorandom number generator flaws
            1.5.1.2 Entropy source manipulation
            1.5.1.3 Key size exploitation
            
        1.5.2 Key distribution attacks
            1.5.2.1 Man-in-the-middle during key exchange
            1.5.2.2 Key injection attacks
            1.5.2.3 Key replication exploitation
            
        1.5.3 Key storage compromises
            1.5.3.1 Hardware security module attacks
            1.5.3.2 Memory scraping techniques
            1.5.3.3 Backup system targeting
            
    1.6 Implementation-specific attacks [OR]
    
        1.6.1 Side-channel attacks
            1.6.1.1 Timing analysis exploitation
            1.6.1.2 Power consumption monitoring
            1.6.1.3 Electromagnetic emission analysis
            
        1.6.2 Software vulnerability exploitation
            1.6.2.1 Buffer overflow attacks
            1.6.2.2 Memory corruption vulnerabilities
            1.6.2.3 Parser implementation flaws
            
        1.6.3 Configuration-based attacks
            1.6.3.1 Weak parameter exploitation
            1.6.3.2 Default configuration abuse
            1.6.3.3 Management interface targeting
            
    1.7 Protocol interaction attacks [OR]
    
        1.7.1 Cryptographic downgrade attacks
            1.7.1.1 Capability negotiation manipulation
            1.7.1.2 Algorithm selection influence
            1.7.1.3 Legacy protocol exploitation
            
        1.7.2 Mixed protocol exploitation
            1.7.2.1 Secure/insecure protocol interaction
            1.7.2.2 Validation inconsistency attacks
            1.7.2.3 Fallback mechanism exploitation
            
        1.7.3 Cross-protocol attacks
            1.7.3.1 BGP-OSPF interaction vulnerabilities
            1.7.3.2 RPKI-BGPsec validation conflicts
            1.7.3.3 TLS-RPKI integration flaws
            
    1.8 Resource exhaustion attacks [OR]
    
        1.8.1 Computational resource targeting
            1.8.1.1 Signature verification flooding
            1.8.1.2 Key generation overload
            1.8.1.3 Certificate validation saturation
            
        1.8.2 Memory exhaustion attacks
            1.8.2.1 Certificate chain amplification
            1.8.2.2 Key storage overflow
            1.8.2.3 Cache saturation techniques
            
        1.8.3 Network resource targeting
            1.8.3.1 Cryptographic protocol flooding
            1.8.3.2 Key exchange amplification
            1.8.3.3 Validation traffic multiplication
            
    1.9 Advanced persistent techniques [OR]
    
        1.9.1 State-sponsored exploitation
            1.9.1.1 Algorithm backdoor insertion
            1.9.1.2 Standards manipulation
            1.9.1.3 Implementation compromise
            
        1.9.2 Supply chain attacks
            1.9.2.1 Hardware implantation
            1.9.2.2 Software distribution compromise
            1.9.2.3 Library vulnerability insertion
            
        1.9.3 Zero-day exploitation
            1.9.3.1 Unknown algorithm vulnerabilities
            1.9.3.2 Implementation-specific zero-days
            1.9.3.3 Protocol interaction zero-days
            
    1.10 Defensive evasion techniques [OR]
    
        1.10.1 Cryptographic stealth methods
            1.10.1.1 Legitimate-looking malicious certificates
            1.10.1.2 Signature masking techniques
            1.10.1.3 Validation bypass camouflage
            
        1.10.2 Detection avoidance
            1.10.2.1 Low-and-slow attack patterns
            1.10.2.2 Anomaly evasion methods
            1.10.2.3 Log manipulation techniques
            
        1.10.3 Attribution obfuscation
            1.10.3.1 False flag cryptographic operations
            1.10.3.2 Intermediate system exploitation
            1.10.3.3 Cross-border attack obfuscation
```

## Why it works

-   Algorithm vulnerabilities: Many routing protocols initially deployed with weakened cryptographic algorithms like MD5 and SHA-1, which have known theoretical vulnerabilities that can be exploited despite protocol-level protections.
-   Implementation flaws: Cryptographic implementations often contain bugs, side-channel vulnerabilities, or incorrect usage of cryptographic primitives that attackers can exploit.
-   Key management challenges: Manual key distribution and the difficulty of regular key rotation in large networks create opportunities for key compromise and replay attacks.
-   Protocol complexity: The interaction between multiple cryptographic protocols (BGPsec, RPKI, TCP-AO) creates attack surfaces at integration points and validation boundaries.
-   Resource constraints: Network devices often have limited computational resources, making them vulnerable to resource exhaustion attacks against cryptographic operations.
-   Deployment inconsistencies: Partial deployment of cryptographic protections creates edge cases and validation gaps that attackers can exploit.

## Counter moves

Cryptographic attacks on routing protocols is the variant in play. RPKI origin validation and route monitoring are the levers. Defenders' notes on this are under [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
