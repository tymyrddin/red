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
