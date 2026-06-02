# Resource exhaustion attacks

## Attack pattern

Resource exhaustion attacks against IPsec target the finite computational, memory, and state-tracking capabilities of implementations. By flooding systems with resource-intensive operations or crafting malicious inputs that consume disproportionate resources, attackers can cause denial of service, performance degradation, or bypass security controls. These attacks are particularly effective because they exploit the fundamental tension between cryptographic complexity and system resources.

```text
1. Resource exhaustion attacks [OR]

    1.1 SA table exhaustion attacks [OR]

        1.1.1 Rapid SA establishment from spoofed source addresses [AND]
            1.1.1.1 Generate multiple IKE_SA_INIT requests with forged IPs
            1.1.1.2 Force the IPsec stack to allocate SA entries [AND]
                1.1.1.2.1 Consume kernel or daemon memory
                1.1.1.2.2 Exhaust SA table capacity leading to denial-of-service

        1.1.2 Half-open SA state retention attacks [AND]
            1.1.2.1 Initiate SA setup without completing handshake
            1.1.2.2 Prevent proper garbage collection [AND]
                1.1.2.2.1 Keep ephemeral SAs alive in memory
                1.1.2.2.2 Exhaust resources and prevent new SA establishment

        1.1.3 SA rekeying storms to overwhelm state tables [AND]
            1.1.3.1 Trigger repeated rekey messages
            1.1.3.2 Exploit simultaneous child SA updates [AND]
                1.1.3.2.1 Saturate SA table processing
                1.1.3.2.2 Cause latency, failures, or crashes

        1.1.4 Persistent SA creation without proper teardown [AND]
            1.1.4.1 Exploit missing or delayed SA deletion
            1.1.4.2 Flood system with new SAs [AND]
                1.1.4.2.1 Consume memory and CPU
                1.1.4.2.2 Induce service denial

    1.2 IKE negotiation flood [OR]

        1.2.1 IKE_SA_INIT flooding with spoofed source IPs [AND]
            1.2.1.1 Send high-volume IKE_SA_INIT requests
            1.2.1.2 Force daemon to process incomplete negotiations [AND]
                1.2.1.2.1 Consume CPU cycles
                1.2.1.2.2 Prevent legitimate IKE establishment

        1.2.2 Resource-intensive transform attribute flooding [AND]
            1.2.2.1 Craft IKE messages with numerous transforms
            1.2.2.2 Force cryptographic processing [AND]
                1.2.2.2.1 Consume CPU for algorithm negotiation
                1.2.2.2.2 Increase memory allocation

        1.2.3 Large certificate payload attacks during IKE_AUTH [AND]
            1.2.3.1 Provide oversized or complex certificates
            1.2.3.2 Exploit certificate parsing routines [AND]
                1.2.3.2.1 Consume memory and processing resources
                1.2.3.2.2 Potentially trigger crashes

        1.2.4 Repeated failed negotiations to consume CPU cycles [AND]
            1.2.4.1 Send intentionally invalid IKE messages
            1.2.4.2 Force repeated validation/retry [AND]
                1.2.4.2.1 Exhaust CPU and memory
                1.2.4.2.2 Delay or block legitimate traffic

    1.3 CPU exhaustion through crypto processing [OR]

        1.3.1 Algorithm negotiation forcing computationally expensive ciphers [AND]
            1.3.1.1 Prioritise strong ciphers (AES-256, 3DES)
            1.3.1.2 Force repeated key schedule computations [AND]
                1.3.1.2.1 Consume CPU resources
                1.3.1.2.2 Slow legitimate sessions

        1.3.2 Large Diffie-Hellman group selection (groups 21, 24) [AND]
            1.3.2.1 Negotiate large modular exponentiations
            1.3.2.2 Force heavy math operations [AND]
                1.3.2.2.1 Consume CPU per handshake
                1.3.2.2.2 Amplify DoS potential via volume

        1.3.3 RSA encryption with large key sizes (4096-bit+) [AND]
            1.3.3.1 Negotiate large RSA keys during IKE/Auth
            1.3.3.2 Force CPU-intensive exponentiation [AND]
                1.3.3.2.1 Delay session setup
                1.3.3.2.2 Enable CPU-based DoS

        1.3.4 Perfect Forward Secrecy enforcement triggering frequent rekeying [AND]
            1.3.4.1 Initiate multiple ephemeral DH exchanges
            1.3.4.2 Exploit rekey policy frequency [AND]
                1.3.4.2.1 Consume CPU and entropy sources
                1.3.4.2.2 Slow or disrupt legitimate communications

    1.4 Memory exhaustion via large SAs [OR]

        1.4.1 Crafted SAs with excessive transform attributes [AND]
            1.4.1.1 Include many transforms in proposal
            1.4.1.2 Force allocation of large SA structures [AND]
                1.4.1.2.1 Consume kernel/daemon memory
                1.4.1.2.2 Reduce resources for legitimate SAs

        1.4.2 Large certificate chain consumption in IKE negotiations [AND]
            1.4.2.1 Supply multiple certificates per authentication
            1.4.2.2 Force parsing of oversized chains [AND]
                1.4.2.2.1 Exhaust memory
                1.4.2.2.2 Delay handshake completion

        1.4.3 Extended sequence number (ESN) state allocation attacks [AND]
            1.4.3.1 Trigger long sequence number tracking
            1.4.3.2 Allocate state for all possible windows [AND]
                1.4.3.2.1 Consume memory resources
                1.4.3.2.2 Prevent new SA establishment

        1.4.4 Anti-replay window expansion attacks [AND]
            1.4.4.1 Manipulate packet sequences to expand anti-replay buffers
            1.4.4.2 Force allocation of large sliding windows [AND]
                1.4.4.2.1 Exhaust memory
                1.4.4.2.2 Increase processing overhead
```

## Why it works

-   Finite resources: IPsec devices have limited SA tables, CPU capacity, and memory for cryptographic operations.
-   Asymmetric cost: IKE negotiation is computationally expensive for responders compared to initiators.
-   Stateful nature: SA maintenance requires persistent memory allocation and state tracking.
-   Cryptographic complexity: Modern algorithms (PFS, large DH groups) significantly increase computational load.
-   Interoperability requirements: Support for various algorithms and configurations expands attack surface.
-   Silent degradation: Resource exhaustion may cause performance issues before complete failure.

## Counter moves

Resource exhaustion attacks is what this page works through. Strong IKE configuration and pruning weak proposals are the fix. Seen from the other side, this sits in the blue notes on [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
