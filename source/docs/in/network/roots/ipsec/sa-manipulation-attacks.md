# Security Association manipulation attacks

## Attack Pattern

Security Associations (SAs) form the core operational state of IPsec, defining the cryptographic parameters, keys, and policies for secure communication. Attacks targeting SAs aim to manipulate, exhaust, or corrupt these critical state elements to cause denial of service, bypass security policies, or force weaker cryptographic parameters. By attacking the SA management layer, adversaries can undermine active tunnels without necessarily breaking the underlying cryptography.

```text
1. Security association (SA) manipulation [OR]

    1.1 SA replay attacks [OR]

        1.1.1 Sequence number reset [AND]
            1.1.1.1 Reset ESP or IKE sequence counters
            1.1.1.2 Replay previously captured packets [AND]
                1.1.1.2.1 Inject encrypted payloads
                1.1.1.2.2 Observe victim acceptance/rejection

        1.1.2 Anti-replay window manipulation [AND]
            1.1.2.1 Burst traffic to advance window
            1.1.2.2 Force acceptance of delayed/replayed packets [AND]
                1.1.2.2.1 Exploit implementation tolerance
                1.1.2.2.2 Trigger replay or sequence gaps

        1.1.3 ESP sequence number cycle attacks [AND]
            1.1.3.1 Exploit 32-bit rollover
            1.1.3.2 Replay packets after rollover [AND]
                1.1.3.2.1 Predict sequence continuation
                1.1.3.2.2 Cause acceptance of repeated ciphertext

        1.1.4 IKE message replay [AND]
            1.1.4.1 Replay expired IKE_SA messages
            1.1.4.2 Recreate expired security associations [AND]
                1.1.4.2.1 Exploit session renegotiation behaviour
                1.1.4.2.2 Bypass replay protection if misconfigured

    1.2 SA parameter corruption [OR]

        1.2.1 SPI collision attacks [AND]
            1.2.1.1 Craft colliding SPI values
            1.2.1.2 Cause misrouting or misassociation of SAs [AND]
                1.2.1.2.1 Redirect traffic to attacker-controlled SA
                1.2.1.2.2 Exploit implementation lookup ambiguities

        1.2.2 Cryptographic algorithm parameter manipulation [AND]
            1.2.2.1 Alter negotiated algorithms
            1.2.2.2 Force weaker encryption or authentication [AND]
                1.2.2.2.1 Exploit victim’s algorithm preference logic
                1.2.2.2.2 Induce fallback to vulnerable cipher suites

        1.2.3 Key length downgrade [AND]
            1.2.3.1 Negotiate shorter keys than intended
            1.2.3.2 Exploit protocol negotiation gaps [AND]
                1.2.3.2.1 Use crafted SA proposals
                1.2.3.2.2 Trigger weak key acceptance in victim

        1.2.4 SA policy field corruption [AND]
            1.2.4.1 Modify policy attributes in SA messages
            1.2.4.2 Bypass filters or restrictions [AND]
                1.2.4.2.1 Exploit weak validation checks
                1.2.4.2.2 Force acceptance of otherwise blocked traffic

    1.3 SA lifetime exhaustion [OR]

        1.3.1 Rapid SA rekeying attacks [AND]
            1.3.1.1 Trigger frequent rekey events
            1.3.1.2 Exhaust cryptographic resources [AND]
                1.3.1.2.1 Force CPU-intensive key generation
                1.3.1.2.2 Cause service degradation

        1.3.2 Child SA flood attacks [AND]
            1.3.2.1 Create multiple simultaneous child SAs
            1.3.2.2 Overwhelm state tables [AND]
                1.3.2.2.1 Exploit maximum table capacity
                1.3.2.2.2 Induce SA management failures

        1.3.3 IKE_SA_INIT spoofed floods [AND]
            1.3.3.1 Send INIT messages with forged source addresses
            1.3.3.2 Consume SA allocation resources [AND]
                1.3.3.2.1 Prevent legitimate session establishment
                1.3.3.2.2 Trigger fallback or denial-of-service

        1.3.4 Persistent half-open SAs [AND]
            1.3.4.1 Maintain incomplete SA negotiations
            1.3.4.2 Exhaust state table entries [AND]
                1.3.4.2.1 Exploit timeout behaviour
                1.3.4.2.2 Reduce effective capacity for valid SAs

    1.4 SA selection algorithm abuse [OR]

        1.4.1 SPI selection attacks [AND]
            1.4.1.1 Predict or influence SPI assignment
            1.4.1.2 Force collisions or precomputed mapping [AND]
                1.4.1.2.1 Exploit deterministic SPI allocation
                1.4.1.2.2 Redirect traffic or confuse victim state

        1.4.2 Policy-based selection bypass [AND]
            1.4.2.1 Use crafted traffic patterns
            1.4.2.2 Circumvent policy-based SA selection [AND]
                1.4.2.2.1 Exploit implementation shortcuts
                1.4.2.2.2 Force weaker or unintended SA choice

        1.4.3 Multi-SA environment confusion [AND]
            1.4.3.1 Inject multiple SAs simultaneously
            1.4.3.2 Confuse victim selection logic [AND]
                1.4.3.2.1 Exploit priority resolution gaps
                1.4.3.2.2 Cause weaker SA to be used inadvertently

        1.4.4 SA priority manipulation [AND]
            1.4.4.1 Adjust negotiation or selection values
            1.4.4.2 Force weaker SA preference [AND]
                1.4.4.2.1 Exploit priority rules in multi-SA systems
                1.4.4.2.2 Reduce overall session security
```

## Why it works

-   Stateful complexity: SA management involves complex state machines that are vulnerable to manipulation and exhaustion attacks.
-   Limited resources: SA databases have finite size and processing capacity, making them susceptible to flooding attacks.
-   Sequence number limitations: 32-bit ESP sequence numbers can be exhausted or manipulated in high-throughput environments.
-   Interoperability requirements: Support for various SA parameters and negotiation options creates attack surface for parameter manipulation.
-   Silent state corruption: SA parameter manipulation may not trigger immediate errors, allowing stealthy degradation of security.
-   Implementation variability: Different vendors implement SA selection and management algorithms inconsistently.

## Mitigation

### Anti-replay protection strengthening
-   Action: Enhance replay detection and prevention mechanisms
-   How:
    -   Implement larger anti-replay windows (1024+ packets)
    -   Use strict sequence number enforcement without gaps
    -   Enable extended sequence numbers (ESN) where supported
    -   Implement time-based replay protection in addition to sequence numbers
-   Configuration example (Strong anti-replay settings, cisco):

```text
crypto ipsec profile SECURE-PROFILE
 set security-association lifetime kilobytes 256000
 set security-association lifetime seconds 3600
 set replay window-size 1024
 set esn enable
```

### SA parameter validation
-   Action: Implement strict validation of all SA parameters
-   How:
    -   Validate cryptographic parameters against security policy
    -   Reject SAs with inconsistent or invalid parameters
    -   Implement SPI randomness requirements
    -   Use SA parameter digital signatures where possible
-   Configuration example (Parameter validation, junos):

```text
security {
    ipsec {
        sa-param-validation {
            require-spi-randomness;
            min-key-length aes-256;
            reject-weak-algorithms;
            validate-lifetime-consistency;
        }
    }
}
```

### SA resource management
-   Action: Protect SA resources from exhaustion attacks
-   How:
    -   Implement SA rate limiting and quotas
    -   Use aggressive SA timeout for half-open connections
    -   Deploy SA state table protection mechanisms
    -   Implement SA garbage collection and cleanup
-   Configuration example (Resource protection):

```bash
# StrongSwan SA protection settings
charon {
    sa_limit = 10000
    sa_max_half_open = 100
    half_open_timeout = 30
    init_limit = 10
}
```

### SA Selection hardening
-   Action: Secure SA selection algorithms against manipulation
-   How:
    -   Implement deterministic SA selection policies
    -   Use cryptographically secure SPI generation
    -   Enforce consistent SA priority handling
    -   Log all SA selection decisions for audit purposes
-   Best practice: Use policy-based SA selection with explicit rules rather than automatic algorithms

### Monitoring and detection
-   Action: Monitor SA activity for signs of manipulation
-   How:
    -   Implement SA state monitoring and logging
    -   Detect abnormal SA creation rates
    -   Monitor for sequence number anomalies
    -   Alert on SA parameter changes
-   Configuration example (Monitoring setup):

```bash
# IPsec SA monitoring script
ipsec statusall | grep -E "(SA|bytes|packets)" 
ipsec listSAs --verbose
netstat -s | grep -i replay
```

## Key insights from real-world implementations

-   Resource constraints: Many devices have surprisingly small SA tables that can be exhausted with minimal effort.
-   Sequence number rollover: High-throughput VPNs can experience sequence number exhaustion, causing connectivity issues.
-   Interoperability issues: Different vendors handle SA parameters differently, leading to potential security gaps.
-   Monitoring gaps: Few organizations monitor SA state, allowing attacks to go undetected.

## Future trends and recommendations

-   Automated SA management: Implement AI-driven SA management that can detect and prevent manipulation attempts.
-   Quantum-resistant SAs: Prepare for larger key material and different SA requirements for post-quantum cryptography.
-   Hardware acceleration: Use hardware-assisted SA management to prevent resource exhaustion attacks.
-   Zero-trust SA establishment: Treat all SA establishment attempts as potentially malicious until validated.

## Conclusion

Security Association manipulation attacks represent a sophisticated threat to IPsec implementations, targeting the very foundation of secure communication state management. These attacks can bypass cryptographic protections, exhaust system resources, and degrade security without breaking encryption directly. Defence requires comprehensive SA management hardening, including strong anti-replay mechanisms, parameter validation, resource protection, and continuous monitoring. As network throughput increases and cryptographic requirements evolve, organizations must implement robust SA management practices that can withstand both current and emerging attack techniques. Regular security assessments should include specific testing for SA manipulation vulnerabilities to ensure the integrity of IPsec-protected communications.
