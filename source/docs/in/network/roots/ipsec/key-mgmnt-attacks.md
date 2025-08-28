# Key management attacks

## Attack pattern

The Internet Key Exchange (IKE) protocol forms the foundation of IPsec security by establishing shared secret keys and authenticating peers. Flaws in key negotiation, weak authentication methods, or compromises in the supporting public key infrastructure can undermine the entire security association process. These attacks target the initial trust establishment phase, allowing adversaries to intercept, decrypt, or manipulate supposedly secure communications.

```text
1. Key management attacks [OR]

  1.1 IKEv1/IKEv2 key negotiation flaws [OR]

    1.1.1 IKEv1 Aggressive Mode weaknesses [OR]
      1.1.1.1 PSK exposure to offline attacks
        1.1.1.1.1 Capture of AM handshake for dictionary attack
        1.1.1.1.2 Identity (IDi) leakage aids selection of candidate PSKs
        1.1.1.1.3 Low-entropy PSKs enable rapid guessing
      1.1.1.2 Authentication bypass via legacy IKEv1 modes (rare edge cases)

    1.1.2 IKE state exhaustion / DoS [OR]
      1.1.2.1 Flood of half-open IKE_SA_INIT exchanges
      1.1.2.2 Retransmit amplification exploiting UDP-based IKE
      1.1.2.3 Mis-implemented cookies or puzzles abused for DoS

    1.1.3 Message/replay handling flaws [OR]
      1.1.3.1 Replay of IKEv2 Message IDs (including ID 0 in HA setups)
      1.1.3.2 Out-of-order or duplicate messages triggering SA inconsistencies

    1.1.4 Cryptographic / oracle-style negotiation flaws [OR]
      1.1.4.1 Bleichenbacher-style oracles in RSA-based IKEv1
      1.1.4.2 Distinct error/notify messages revealing validation state

    1.1.5 INITIAL_CONTACT and delete notifies [AND]
      1.1.5.1 Spoofing or injection requires bypassing cryptographic binding
      1.1.5.2 Potential for unauthenticated traffic to trigger SA changes if misused

  1.2 Pre-shared key brute-force attacks [OR]

    1.2.1 Offline PSK cracking from captured handshakes [OR]
      1.2.1.1 IKEv1 Aggressive Mode handshake capture
      1.2.1.2 Weak PSKs susceptible to GPU/cluster attacks

    1.2.2 Active-attacker oracles against PSK flows [OR]
      1.2.2.1 IKEv2 misconfiguration or legacy modes leak accept/reject
      1.2.2.2 Timing or response differences reveal PSK guesses

    1.2.3 Poor key derivation assumptions [OR]
      1.2.3.1 PRFs are not slow KDFs; entropy matters more than iteration
      1.2.3.2 Predictable or human-generated PSKs reduce effective strength

    1.2.4 Side-channel / implementation bugs [OR]
      1.2.4.1 Non-constant-time comparisons leak information
      1.2.4.2 Verbose notify messages reveal validation outcomes

  1.3 Certificate authority and trust-store compromise [OR]

    1.3.1 Rogue or compromised CA [OR]
      1.3.1.1 Issuance of fraudulent certificates
      1.3.1.2 Trusted certificate chain compromise

    1.3.2 Trust anchor manipulation on endpoints [OR]
      1.3.2.1 Malicious root or intermediate insertion
      1.3.2.2 Enterprise policy bypass / endpoint compromise

    1.3.3 Revocation weaknesses [OR]
      1.3.3.1 OCSP responder spoofing or unavailability
      1.3.3.2 CRL distribution tampering or unreachability

    1.3.4 Intermediate CA key compromise [OR]
      1.3.4.1 Valid-looking certificates issued until detection
      1.3.4.2 Ecosystem-wide impact until revocation

  1.4 Key lifetimes, rekeying, and time-source attacks [OR]

    1.4.1 SA lifetime misconfigurations [OR]
      1.4.1.1 Excessive lifetime → reduced forward secrecy
      1.4.1.2 Unsynchronised rekeying across peers

    1.4.2 Forged or skewed time affecting validation [OR]
      1.4.2.1 NTP time-shifting attacks impacting cert validation
      1.4.2.2 Log timestamp inconsistencies enabling replay or audit gaps

    1.4.3 Certificate validity window abuse [OR]
      1.4.3.1 Exploiting acceptance of out-of-window certificates
      1.4.3.2 Manipulating minor skew to bypass temporal checks

    1.4.4 Audit and logging attacks [OR]
      1.4.4.1 Unsynchronized clocks undermining non-repudiation
      1.4.4.2 Tampering or deletion of logs affecting incident reconstruction
```

## Why it works

-   Protocol complexity: IKE's multiple negotiation modes and options create a large attack surface for state machine manipulation.
-   PSK prevalence: Pre-shared keys remain widely used despite vulnerabilities, due to their simplicity over PKI deployment.
-   Trust propagation: Compromise of a single CA can affect all systems trusting that certificate authority.
-   Time dependency: Key lifetime mechanisms rely on accurate timekeeping, which can be manipulated.
-   Backward compatibility: Support for IKEv1 continues despite known vulnerabilities in its design.
-   Human factors: Weak PSK selection and poor certificate management practices are common.
-   IKEv1 Aggressive Mode enables offline PSK cracking; widely documented and formally analysed. 
-   Libreswan retransmit amplification DoS (CVE-2016-5361) and IKE cookie/puzzle DoS mitigation guidance. 
-   IKEv2 Message ID replay considerations for HA sync (Message ID 0) in RFC 6311.
-   Bleichenbacher-style oracles and auth bypass in IKE (academic).
-   `INITIAL_CONTACT` is a cryptographically protected notify; reliance should be paired with liveness checks. 
-   SA lifetimes are local policy (not negotiated); typical hours and rekey behaviour. 
-   Time shifting via NTP attacks can affect certificate validation/logging; RFC 5280 defines validity semantics; industry BRs cap certificate lifetimes. 
-   Rogue CA/trust-store manipulation and real-world CA compromises.

## Mitigation

### IKE protocol hardening

-   Action: Secure IKE negotiations through protocol restrictions and monitoring
-   How:
    -   Disable IKEv1 Aggressive Mode entirely
    -   Enforce Main Mode with strong authentication for IKEv1
    -   Implement IKEv2 with cryptographic binding of identities
    -   Enable replay protection and message ID verification
-   Configuration example (IKEv2 only enforcement, cisco):

```text
crypto ikev2 policy STRONG-POLICY
 encryption aes-gcm-256
 integrity sha512
 group 21
 prf sha512
 lifetime seconds 86400
```

### Pre-Shared key management

-   Action: Eliminate or strengthen pre-shared key usage
-   How:
    -   Replace PSK with certificate-based authentication where possible
    -   Enforce complex, randomly generated PSKs (20+ characters)
    -   Implement regular PSK rotation policies
    -   Use different PSKs for different security domains
-   Best practice: Use certificate authentication for site-to-site VPNs and reserve PSKs for mobile users with proper complexity requirements

### Certificate authority security

-   Action: Harden PKI infrastructure supporting IPsec authentication
-   How:
    -   Implement offline root CAs with online issuing intermediates
    -   Enforce strict certificate validation including CRL/OCSP checking
    -   Use certificate pinning for critical infrastructure
    -   Monitor certificate transparency logs for unauthorized issuance
-   Configuration example (Strict certificate validation, junos):

```text
security {
    ike {
        certificate {
            enforce-strict-crl-checking;
            ocsp enable;
            required-verify-depth 2;
        }
    }
}
```

### Key Lifetime Management
-   Action: Implement strict key lifetime controls and monitoring
-   How:
    -   Set conservative SA lifetimes (max 24 hours for IKE SA, 4 hours for Child SA)
    -   Enforce reauthentication during rekey operations
    --   Implement time synchronization via secure NTP sources
    -   Monitor for anomalous SA lifetime extension attempts
-   Configuration example (Short lifetimes with reauthentication):

```text
ikev2-rekey require-reauth: yes
ikev2-sa-lifetime: 8 hours
child-sa-lifetime: 2 hours
```

### Continuous monitoring and uuditing

-   Action: Monitor key management operations for anomalies
-   How:
    -   Log all IKE negotiation attempts and parameters
    -   Implement anomaly detection for unusual SA establishments
    -   Regularly audit trust stores and certificate validity
    -   Monitor for clock skew and time manipulation attempts
-   Tools: Security information and event management (SIEM) systems with IKE-specific correlation rules

## Key insights from real-world implementations

-   IKEv1 persistence: Many organisations maintain IKEv1 support for legacy compatibility, exposing them to known attacks.
-   PSK weakness: Pre-shared keys often reflect organisational naming conventions, making dictionary attacks effective.
-   Certificate management complexity: Poor PKI management leads to certificate validation being disabled or weakened.
-   Time synchronization neglect: Clock drift is common and can be exploited to extend key validity periods.

## Future trends and recommendations

-   Quantum-resistant key exchange: Prepare for adoption of post-quantum key exchange algorithms in IKEv2.
-   Automated key management: Implement automated certificate deployment and renewal systems.
-   Zero-trust key negotiation: Treat all IKE negotiations as untrusted until multiple factors are verified.
-   Hardware-backed key storage: Use TPMs or HSMs for all private key storage and cryptographic operations.

## Conclusion

Key management attacks against IPsec target the fundamental trust establishment mechanisms, making them particularly devastating to overall security. Mitigation requires protocol hardening, strong authentication methods, robust PKI management, and continuous monitoring. As attack techniques evolve, organisations must move beyond basic compliance and implement defence-in-depth strategies for their IPsec key management infrastructure. Regular auditing, automation of security controls, and adoption of modern authentication methods are essential for maintaining secure VPN communications.