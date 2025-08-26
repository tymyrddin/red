# IPsec key management attacks

## Attack pattern

The Internet Key Exchange (IKE) protocol forms the foundation of IPsec security by establishing shared secret keys and authenticating peers. Flaws in key negotiation, weak authentication methods, or compromises in the supporting public key infrastructure can undermine the entire security association process. These attacks target the initial trust establishment phase, allowing adversaries to intercept, decrypt, or manipulate supposedly secure communications.

```text
1. Key management attacks [OR]

  1.1 IKEv1/IKEv2 key negotiation flaws [OR]

    1.1.1 IKEv1 Aggressive Mode exposes PSKs to offline cracking [OR]
      1.1.1.1 Capture-based dictionary attacks against AM handshakes
      1.1.1.2 Identity leakage (IDi) helps candidate selection
      1.1.1.3 Low-entropy PSKs collapse effective security
      1.1.1.4 Mitigations: avoid IKEv1 AM; migrate to IKEv2; enforce strong PSKs; prefer EAP-TLS or certificates

    1.1.2 IKE state exhaustion and DoS during negotiation [OR]
      1.1.2.1 Libreswan retransmit amplification (CVE-2016-5361) enables remote DoS
      1.1.2.2 Half-open IKE_SA_INIT floods; enable/respond with stateless cookies
      1.1.2.3 Cookie/puzzle mis-implementation can itself be abused (client puzzles / RFC 8019 guidance)
      1.1.2.4 Operational hardening: rate-limit, prefer TCP/TLS encapsulation where appropriate, drop fragmented unauthenticated UDP

    1.1.3 Message/replay handling edge cases [OR]
      1.1.3.1 IKEv2 Message IDs normally prevent replay; HA sync messages using ID 0 are a replay DoS risk if not isolated
      1.1.3.2 Ensure anti-replay windows and strict ID monotonicity across failover/HA paths
      1.1.3.3 Prefer modern stacks with tested HA implementations

    1.1.4 Cryptographic/oracle-style negotiation flaws [OR]
      1.1.4.1 Bleichenbacher-style oracles feasible in some IKEv1 paths → auth bypass in practice
      1.1.4.2 Distinct error/notify behaviour can leak validation state and aid offline guessing
      1.1.4.3 Countermeasures: uniform error paths; constant-time checks; disable legacy RSA modes; favour IKEv2 with modern auth

    1.1.5 INITIAL_CONTACT and delete notifies are authenticated signals, not a generic spoofing vector [AND]
      1.1.5.1 Properly implemented, they must be cryptographically protected and bound to identity
      1.1.5.2 If you rely on them, also run liveness checks and DPD; treat unauthenticated traffic as untrusted

  1.2 Pre-shared key brute-force attacks [OR]

    1.2.1 Offline PSK cracking from captured handshakes [OR]
      1.2.1.1 IKEv1 Aggressive Mode enables straight offline cracking
      1.2.1.2 Weak PSKs fall quickly to GPU/cluster cracking
      1.2.1.3 Mitigations: kill AM; enforce high-entropy PSKs; or move to cert/EAP-TLS

    1.2.2 Active-attacker oracles against PSK flows [OR]
      1.2.2.1 IKEv2 misconfig/legacy modes can leak accept/reject signals useful for guesses
      1.2.2.2 Normalise error paths; throttle attempts; prefer mutual certificate auth

    1.2.3 Poor KDF/derivation assumptions [OR]
      1.2.3.1 IKE PRFs aren’t a “slow KDF”; security rests on PSK entropy, not iteration cost
      1.2.3.2 Policy: machine-generated PSKs only; rotate on leakage, not on a calendar

    1.2.4 Side-channel and implementation bugs in PSK validation [OR]
      1.2.4.1 Non-constant-time compares or verbose notifies leak information
      1.2.4.2 Require constant-time validation and uniform failure responses

  1.3 Certificate authority and trust-store compromise [OR]

    1.3.1 Rogue/compromised CA issues certificates [OR]
      1.3.1.1 Historical precedent (e.g., DigiNotar) shows ecosystem-wide impact
      1.3.1.2 Pinning/constraints and rapid revocation are essential

    1.3.2 Trust anchor manipulation on endpoints [OR]
      1.3.2.1 Malicious root insertion grants MITM/signing power
      1.3.2.2 Enterprise MDM/policy must lock trust stores; monitor for drift

    1.3.3 Revocation weaknesses [OR]
      1.3.3.1 OCSP responder spoofing/unavailability → soft-fail acceptance
      1.3.3.2 CRL distribution tampering/unreachability delays revocation
      1.3.3.3 Prefer OCSP stapling/must-staple where available; cache and audit revocation state

    1.3.4 Intermediate CA private-key compromise [OR]
      1.3.4.1 Allows valid-looking cert issuance until detected and revoked
      1.3.4.2 Require CT monitoring, key protection (HSM), and incident playbooks

  1.4 Key lifetimes, rekeying, and time-source attacks [OR]

    1.4.1 IKE/IPsec SA lifetime management errors [OR]
      1.4.1.1 Lifetimes are local policy (not negotiated) — misconfig leads to long-lived keys and reduced PFS in practice
      1.4.1.2 Enforce short SA lifetimes (hours), automatic rekey, and deletion on rekey success

    1.4.2 Forged time and skew affecting validation [OR]
      1.4.2.1 NTP time-shifting attacks can roll clocks, impacting cert validity checks and logs
      1.4.2.2 Use authenticated time (NTS/secure NTP), multiple sources, and tight skew windows

    1.4.3 Certificate validity windows and policy [OR]
      1.4.3.1 Adhere to current BR caps (≈398 days) and RFC 5280 validity semantics
      1.4.3.2 Use controlled “validity offset” only to absorb minor skew; log and alert on out-of-window acceptance

    1.4.4 Operational logging and audit integrity [OR]
      1.4.4.1 Unsynchronised clocks undermine non-repudiation and incident timelines
      1.4.4.2 Protect logs with signing/attestation; verify monotonicity against trusted time
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