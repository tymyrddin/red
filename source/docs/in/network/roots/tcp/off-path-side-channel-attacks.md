# Off-path & side-channel attacks

## Attack pattern

Off-path and side-channel attacks represent sophisticated techniques that exploit indirect information leakage and protocol behaviours to compromise BGP sessions without requiring direct network path interception. These attacks leverage subtle vulnerabilities in protocol implementations, timing characteristics, and information leakage to infer session state, manipulate communications, or extract sensitive information from seemingly protected channels.

```text
1. Off-path & side-channel attacks [AND]

    1.1 Blind in-window exploit [OR]
    
        1.1.1 NAT slipstreaming variants
            1.1.1.1 Protocol impersonation through packet injection
            1.1.1.2 HTTP header manipulation for session establishment
            1.1.1.3 SIP message injection for protocol bypass
            1.1.1.4 FTP PORT command abuse for connection manipulation
            
        1.1.2 Protocol downgrade attacks
            1.1.2.1 QUIC-to-TCP fallback exploitation
            1.1.2.2 TLS version downgrade manipulation
            1.1.2.3 Encryption protocol weakening attacks
            1.1.2.4 Forced protocol regression to vulnerable versions
            
    1.2 Side-channel data extraction [OR]
    
        1.2.1 TCP timestamp analysis
            1.2.1.1 Clock skew measurement for system identification
            1.2.1.2 Packet timing analysis for sequence prediction
            1.2.1.3 Throughput estimation for congestion inference
            1.2.1.4 Response timing for state detection
            
        1.2.2 Application data correlation
            1.2.2.1 BGP update timing correlation
            1.2.2.2 Route advertisement pattern analysis
            1.2.2.3 Session establishment timing attacks
            1.2.2.4 Protocol message size analysis
            
        1.2.3 Encrypted traffic classification
            1.2.3.1 Packet size distribution analysis
            1.2.3.2 Inter-packet timing characteristics
            1.2.3.3 Flow duration and behaviour patterns
            1.2.3.4 Machine learning-based traffic analysis
            
    1.3 Cache-based attacks [OR]
    
        1.3.1 CPU cache timing attacks
            1.3.1.1 Prime+probe techniques for memory access patterns
            1.3.1.2 Flush+reload for shared memory exploitation
            1.3.1.3 Evict+time for cryptographic operation detection
            1.3.1.4 Microarchitectural data sampling attacks
            
        1.3.2 Branch prediction exploitation
            1.3.2.1 Spectre-variant attacks on network stacks
            1.3.2.2 Indirect branch prediction manipulation
            1.3.2.3 Speculative execution side-channels
            1.3.2.4 Transient execution vulnerabilities
            
    1.4 Power analysis attacks [OR]
    
        1.4.1 Simple power analysis
            1.4.1.1 Direct power consumption measurement
            1.4.1.2 Cryptographic operation identification
            1.4.1.3 Key processing pattern recognition
            1.4.1.4 Operation timing through power signature
            
        1.4.2 Differential power analysis
            1.4.2.1 Statistical analysis of power variations
            1.4.2.2 Key extraction through correlation attacks
            1.4.2.3 Advanced signal processing techniques
            1.4.2.4 Multi-channel analysis combining power and EM
            
    1.5 Electromagnetic emanation attacks [OR]
    
        1.5.1 Tempest techniques
            1.5.1.1 Remote electromagnetic signal capture
            1.5.1.2 Video display reconstruction attacks
            1.5.1.3 Keyboard emanation interception
            1.5.1.4 Network device radiation analysis
            
        1.5.2 Near-field electromagnetic analysis
            1.5.2.1 Close-proximity device monitoring
            1.5.2.2 Chip-level electromagnetic measurement
            1.5.2.3 Circuit board signal extraction
            1.5.2.4 Power supply modulation analysis
            
    1.6 Acoustic cryptanalysis [OR]
    
        1.6.1 Keyboard acoustic emanations
            1.6.1.1 Keystroke recognition through sound analysis
            1.6.1.2 Mechanical keyboard acoustic signatures
            1.6.1.3 Touchscreen interaction sounds
            1.6.1.4 Device fan noise analysis
            
        1.6.2 Component acoustic signatures
            1.6.2.1 CPU operation frequency detection
            1.6.2.2 Disk access pattern analysis
            1.6.2.3 Cooling system acoustic monitoring
            1.6.2.4 Power supply whine analysis
```

## Why it works

-   Information leakage: Systems inevitably leak information through various channels despite encryption
-   Protocol complexities: Modern protocols contain numerous features that can be exploited indirectly
-   Physical properties: All electronic devices emit physical signals that can be measured and analysed
-   Implementation flaws: Software and hardware implementations often leave side-channels unaddressed
-   Performance optimisations: Hardware optimisations create predictable patterns that can be exploited
-   Resource sharing: Shared resources in cloud environments create cross-tenant information leakage
-   Measurement precision: Advanced equipment can detect extremely subtle signals and variations

## Mitigation

### Protocol hardening

-   Action: Strengthen protocols against blind attacks and downgrade attempts
-   How:
    -   Implement protocol version locking to prevent downgrades
    -   Use authenticated encryption with associated data (AEAD)
    -   Deploy strict protocol transition policies
    -   Enable protocol security extensions where available
-   Configuration example (Protocol security):

```text
crypto ipsec profile SECURE-PROFILE
 set security-association lifetime kilobytes 256000
 set security-association lifetime seconds 3600
 set replay window-size 1024
 set transform-set STRONG-TRANSFORM
 set pfs group14
```

### Side-channel protection

-   Action: Implement protections against information leakage through side-channels
-   How:
    -   Use constant-time cryptographic implementations
    -   Implement cache partitioning and flushing
    -   Deploy branch prediction hardening
    -   Enable memory access protection mechanisms
-   Best practices:
    -   Regular security audits for side-channel vulnerabilities
    -   Implementation of timing-safe comparison functions
    -   Use of hardware security features where available
    -   Continuous monitoring for anomalous behaviour patterns

### Physical security measures

-   Action: Protect against physical side-channel attacks
-   How:
    -   Implement tamper-evident enclosures for critical devices
    -   Use electromagnetic shielding for sensitive equipment
    -   Deploy acoustic damping measures in secure areas
    -   Implement power line filtering and conditioning
-   Physical security controls:
    -   Secure facility access controls
    -   Environmental monitoring systems
    -   RF shielding assessment and implementation
    -   Regular physical security audits

### Monitoring and detection

-   Action: Detect side-channel attack attempts and anomalous patterns
-   How:
    -   Monitor for unusual timing patterns in network traffic
    -   Implement anomaly detection for system behaviour
    -   Log and analyse cryptographic operation timing
    -   Deploy intrusion detection for side-channel indicators
-   Monitoring implementation:

```text
logging enable
logging timestamp
logging host 192.0.2.100
logging trap informational
logging source-interface GigabitEthernet0/0
logging rate-limit 1000
```

### Cryptographic protection enhancements

-   Action: Strengthen cryptographic implementations against side-channel attacks
-   How:
    -   Implement side-channel resistant algorithms
    -   Use hardware security modules for key operations
    -   Deploy white-box cryptography where appropriate
    -   Enable quantum-resistant algorithm preparation
-   Configuration guidelines:
    -   Regular cryptographic library updates
    -   Hardware acceleration for cryptographic operations
    -   Key rotation policies considering side-channel risks
    -   Multi-factor authentication for cryptographic operations

### Network architecture protections

-   Action: Design network architecture to mitigate off-path attacks
-   How:
    -   Implement strict network segmentation
    -   Deploy intrusion prevention systems with deep inspection
    -   Use encrypted communications throughout the network
    -   Implement zero-trust architecture principles
-   Architectural considerations:
    -   Defence-in-depth security layering
    -   Regular network security assessments
    -   Secure network device configuration
    -   Comprehensive access control policies

## Key insights from real-world implementations

-   Measurement sensitivity: Modern equipment can detect nanosecond-level timing differences
-   Cloud shared tenancy: Multi-tenant environments create additional side-channel risks
-   Hardware vulnerabilities: Many side-channel vulnerabilities exist at the hardware level
-   Protocol interactions: Complex protocol stacks create multiple potential leakage points
-   Detection challenges: Side-channel attacks are particularly difficult to detect and attribute

## Future trends and recommendations

-   Quantum resistance: Preparation for quantum computing impacts on side-channel security
-   Automated defence: Machine learning for side-channel attack detection
-   Hardware security: Development of side-channel resistant hardware architectures
-   Standardisation: Industry-wide standards for side-channel protection
-   Continuous monitoring: Advanced analytics for side-channel detection

## Conclusion

Off-path and side-channel attacks represent a sophisticated and evolving threat landscape that targets the fundamental properties of computing systems and network protocols. These attacks exploit subtle information leakage through timing, power consumption, electromagnetic emissions, and acoustic signatures to compromise systems that appear secure through conventional measures. Mitigation requires a comprehensive approach including protocol hardening, physical security measures, cryptographic enhancements, and continuous monitoring. As attack techniques continue to evolve, organisations must maintain vigilance through regular security assessments, implementation of latest protection mechanisms, and participation in industry-wide security initiatives. The defence against side-channel attacks necessitates ongoing research, development of new protection technologies, and collaboration across the security community to address these complex and subtle vulnerabilities.
