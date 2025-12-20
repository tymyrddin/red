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

## Mitigation

### SA resource management
-   Action: Implement strict SA quotas and state protection
-   How:
    -   Enforce maximum SA limits per peer and globally
    -   Implement aggressive half-open SA timeouts
    -   Use SA rate limiting and quotas
    -   Deploy SA garbage collection mechanisms
-   Configuration example (SA resource protection, cisco):

```text
crypto isakmp limit SA-LIMITS
 max-in-negotation-sa 100
 max-sa 5000
 percent 80
 queue-depth 1000
!
crypto ipsec sa limit 10000
```

### IKE flood protection
-   Action: Protect against IKE negotiation flooding
-   How:
    -   Implement IKE rate limiting per source IP
    -   Use puzzle mechanisms for IKE_SA_INIT requests
    -   Deploy SYN cookie-like techniques for half-open SAs
    -   Filter spoofed source addresses at network perimeter
-   Configuration example (IKE flood protection, junos):

```text
security {
    ike {
        traceoptions {
            flag flood;
        }
        flood-protection {
            threshold 100;
            source-limit 10;
            timeout 60;
        }
    }
}
```

### Computational load management
-   Action: Manage cryptographic processing loads
-   How:
    -   Implement algorithmic cost awareness in negotiations
    -   Use hardware crypto acceleration for expensive operations
    -   Deploy computational load shedding under stress
    -   Monitor CPU utilisation and throttle expensive operations
-   Configuration example (CPU protection, strongswan):

```text
charon {
    # Computational load management
    load_balancing = yes
    load_balance_factor = 2.0
    # Hardware acceleration
    openssl {
        engines = af_alg
    }
}
```

### Memory protection mechanisms
-   Action: Prevent memory exhaustion through SA manipulation
-   How:
    -   Implement maximum memory limits per SA
    -   Use memory pooling for SA state allocation
    -   Deploy memory pressure detection and mitigation
    -   Monitor SA memory usage and enforce limits
-   Configuration example (Memory protection):

```bash
# Systemd memory limits for IKE daemon
[Service]
MemoryMax=512M
MemoryHigh=384M
CPUQuota=75%
TasksMax=1000
```

### Monitoring and alerting
-   Action: Detect and respond to resource exhaustion attempts
-   How:
    -   Monitor SA table utilisation and growth rates
    -   Implement alerts for abnormal IKE negotiation rates
    -   Track cryptographic processing load patterns
    -   Monitor memory usage per SA and globally
-   Configuration example (Monitoring setup):

```bash
# IPsec resource monitoring script
watch -n 30 'ipsec statusall | grep -E "(SAs|memory|CPU)" \
&& cat /proc/net/xfrm_stat \
&& netstat -s | grep -i "retransmit\|timeout"'
```

## Key insights from real-world implementations

-   Scale limitations: Many commercial devices have surprisingly low SA capacity limits.
-   Asymmetric impact: Responders bear significantly higher computational loads than initiators.
-   Hardware dependencies: Performance varies dramatically based on crypto acceleration capabilities.
-   Configuration drift: Default settings often prioritize performance over security against exhaustion attacks.

## Future trends and recommendations

-   Adaptive resource management: AI-driven resource allocation that can detect and mitigate exhaustion attacks.
-   Hardware acceleration: Increased use of dedicated crypto processors to handle computational loads.
-   Cloud-scale architectures: Distributed SA state management across multiple nodes.
-   Zero-trust resource allocation: Treat all resource requests as potentially malicious until validated.

## Conclusion

Resource exhaustion attacks pose a significant threat to IPsec implementations by targeting the fundamental limitations of cryptographic processing and state management. These attacks can cause denial of service, performance degradation, and potentially bypass security controls by overwhelming system resources. Defence requires comprehensive resource management including strict quotas, rate limiting, computational load awareness, and continuous monitoring. As cryptographic requirements evolve toward more computationally intensive algorithms, organisations must implement robust resource protection mechanisms and ensure their IPsec infrastructure can withstand determined exhaustion attacks while maintaining legitimate service availability.
