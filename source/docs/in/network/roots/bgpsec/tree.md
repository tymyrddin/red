# Attack overview DNS

## Attack tree

This attack tree explores the methods to undermine BGPsec, targeting its cryptographic core, trust infrastructure, and operational complexities. From exploiting algorithmic weaknesses and compromising key storage to leveraging partial adoption and AI-enhanced attacks, this framework reveals how the very mechanisms intended to secure global routing can be subverted to orchestrate sophisticated hijacks and undermine network trust at scale.

```text
1. Compromise BGPsec Validation [OR]

    1.1 Exploit Cryptographic Weaknesses [OR]
    
        1.1.1 Algorithm Vulnerabilities [OR]
            1.1.1.1 ECDSA with biased nonces (key recovery)
            1.1.1.2 RSA with weak key generation (ROBOT-style)
            1.1.1.3 Hash function collisions (SHA-1/256 issues)
            
        1.1.2 Implementation Flaws [OR]
            1.1.2.1 Non-constant-time implementations (timing attacks)
            1.1.2.2 Memory corruption in crypto libraries (CVE-2022-3602)
            1.1.2.3 Side-channel leaks (Minerva, Power analysis)
            
        1.1.3 Post-Quantum Threats [OR]
            1.1.3.1 Harvest now, decrypt later (quantum harvesting)
            1.1.3.2 Weak hybrid transition implementations
            1.1.3.3 Shor's algorithm preparation attacks

    1.2 Key Management Compromise [OR]
    
        1.2.1 Private Key Theft [OR]
            1.2.1.1 HSM vulnerabilities (CVE-2021-XXX)
            1.2.1.2 Supply chain backdoors in key generation
            1.2.1.3 Cloud HSM misconfigurations
            
        1.2.2 Key Rotation Failures [OR]
            1.2.2.1 Delayed key revocation propagation
            1.2.2.2 Weak key rotation policies
            1.2.2.3 Compromised key history retention
            
        1.2.3 Certificate Validation Bypass [OR]
            1.2.3.1 Rogue CA compromise for BGPsec certificates
            1.2.3.2 Certificate transparency log poisoning
            1.2.3.3 Trust anchor manipulation

    1.3 Protocol Implementation Attacks [OR]
    
        1.3.1 BGPsec Stack Vulnerabilities [OR]
            1.3.1.1 Memory corruption in BGPsec implementations
            1.3.1.2 Resource exhaustion attacks
            1.3.1.3 Parser differential attacks
            
        1.3.2 Validation Bypass [OR]
            1.3.2.1 Signature verification short-circuiting
            1.3.2.2 Cache poisoning attacks
            1.3.2.3 Time-of-check-time-of-use (TOCTOU) flaws
            
        1.3.3 Downgrade Attacks [OR]
            1.3.3.1 BGPsec capability negotiation manipulation
            1.3.3.2 Fallback to unsigned BGP sessions
            1.3.3.3 Version negotiation exploits

2. Attack BGPsec Infrastructure [OR]

    2.1 Trust Anchor Compromise [OR]
    
        2.1.1 Trust Distribution Attacks [OR]
            2.1.1.1 Malicious TAL (Trust Anchor Locator) distribution
            2.1.1.2 Package mirror compromise for validator software
            2.1.1.3 DNS poisoning for trust anchor retrieval
            
        2.1.2 Anchor Maintenance Exploits [OR]
            2.1.2.1 Delayed anchor revocation propagation
            2.1.2.2 Weak anchor rotation procedures
            2.1.2.3 Historical anchor abuse
            
        2.1.3 Cross-Protocol Trust Collisions [OR]
            2.1.3.1 RPKI-BGPsec trust chain conflicts
            2.1.3.2 TLS-BGPsec certificate trust confusion
            2.1.3.3 Shared HSM compromise across protocols

    2.2 Validator Infrastructure Attacks [OR]
    
        2.2.1 Software Vulnerabilities [OR]
            2.2.1.1 Memory safety issues in validators (Rust/C++)
            2.2.1.2 Logic flaws in path validation
            2.2.1.3 Denial-of-service through resource exhaustion
            
        2.2.2 Cache Poisoning [OR]
            2.2.2.1 Stale data attacks during sync intervals
            2.2.2.2 MITM attacks on validator-to-repository communication
            2.2.2.3 Repository compromise with malicious data
            
        2.2.3 Configuration Manipulation [OR]
            2.2.3.1 Admin interface compromises
            2.2.3.2 Misconfigured trust boundaries
            2.2.3.3 Weak access controls on validator systems

    2.3 Network Infrastructure Targeting [OR]
    
        2.3.1 Routing Table Poisoning [OR]
            2.3.1.1 Injection of malicious BGPsec paths
            2.3.1.2 Withdrawal of valid BGPsec routes
            2.3.1.3 Route flap attacks with signed updates
            
        2.3.2 Peer Session Compromise [OR]
            2.3.2.1 TCP-AO/MD5 bypass for BGP sessions
            2.3.2.2 Session reset attacks during key rotation
            2.3.2.3 MITM on BGPsec peer connections
            
        2.3.3 Resource Exhaustion [OR]
            2.3.3.1 CPU exhaustion through complex signature validation
            2.3.3.2 Memory exhaustion via large BGPsec updates
            2.3.3.3 Storage exhaustion from key history retention

3. Exploit Operational Weaknesses [OR]

    3.1 Partial Deployment Exploitation [OR]
    
        3.1.1 Validation Gap Attacks [OR]
            3.1.1.1 Route leaks through non-BGPsec ASes
            3.1.1.2 Mixed validation policy exploitation
            3.1.1.3 Border router misconfiguration
            
        3.1.2 Policy Inconsistency [OR]
            3.1.2.1 Differing local validation policies
            3.1.2.2 Conflict between RPKI and BGPsec validation
            3.1.2.3 Graceful restart compatibility issues
            
        3.1.3 Transition Period Attacks [OR]
            3.1.3.1 Exploitation during protocol migration
            3.1.3.2 Backward compatibility weaknesses
            3.1.3.3 Dual-stack (IPv4/IPv6) implementation gaps

    3.2 Human Factor Exploitation [OR]
    
        3.2.1 Social Engineering [OR]
            3.2.1.1 Operator credential theft
            3.2.1.2 Fake security alert social engineering
            3.2.1.3 Supply chain impersonation attacks
            
        3.2.2 Configuration Errors [OR]
            3.2.2.1 Weak signature policy configuration
            3.2.2.2 Incorrect trust anchor deployment
            3.2.2.3 Key management policy mistakes
            
        3.2.3 Monitoring Gaps [OR]
            3.2.3.1 Delayed attack detection
            3.2.3.2 False sense of security from partial deployment
            3.2.3.3 Lack of BGPsec-specific monitoring

    3.3 Economic and Coordination Attacks [OR]
    
        3.3.1 Resource Asymmetry Exploitation [OR]
            3.3.1.1 CPU-intensive signature attacks on smaller ASes
            3.3.1.2 Storage exhaustion through key history attacks
            3.3.1.3 Bandwidth consumption via BGPsec update floods
            
        3.3.2 Governance Attacks [OR]
            3.3.2.1 Policy registry manipulation
            3.3.2.2 Standards body influence operations
            3.3.2.3 Certification authority lobbying
            
        3.3.3 Timing and Persistence [OR]
            3.3.3.1 Long-term key compromise persistence
            3.3.3.2 Attack synchronization across multiple ASes
            3.3.3.3 Holiday/weekend attack timing

4. Cross-Protocol Attack Vectors [OR]

    4.1 RPKI-BGPsec Integration Attacks [OR]
    
        4.1.1 Validation Conflict Exploitation [OR]
            4.1.1.1 RPKI-valid but BGPsec-invalid route injection
            4.1.1.2 BGPsec-valid but RPKI-invalid path propagation
            4.1.1.3 Unknown state handling discrepancies
            
        4.1.2 Timing Attack Coordination [OR]
            4.1.2.1 Different cache TTL exploitation
            4.1.2.2 Revocation propagation timing gaps
            4.1.2.3 Validation frequency mismatches
            
        4.1.3 Trust Chain Collisions [OR]
            4.1.3.1 Shared CA compromise effects
            4.1.3.2 Different crypto algorithm support
            4.1.3.3 Protocol version compatibility issues

    4.2 TLS-BGPsec Attack Chains [OR]
    
        4.2.1 Certificate Trust Exploitation [OR]
            4.2.1.1 Cross-protocol certificate reuse attacks
            4.2.1.2 CA compromise affecting both TLS and BGPsec
            4.2.1.3 Validation policy conflict exploitation
            
        4.2.2 Session Handling Attacks [OR]
            4.2.2.1 TLS session compromise affecting BGPsec
            4.2.2.2 BGPsec key exposure affecting TLS sessions
            4.2.2.3 Cross-protocol side-channel attacks
            
        4.2.3 Implementation Shared Code [OR]
            4.2.3.1 Common crypto library vulnerabilities
            4.2.3.2 Shared memory safety issues
            4.2.3.3 Cross-protocol resource exhaustion

    4.3 Network Layer Integration Attacks [OR]
    
        4.3.1 IP Layer Exploitation [OR]
            4.3.1.1 Fragmentation attacks affecting BGPsec
            4.3.1.2 TTL-based attacks on validation
            4.3.1.3 DSCP priority manipulation
            
        4.3.2 Transport Layer Attacks [OR]
            4.3.2.1 TCP session manipulation affecting BGPsec
            4.3.2.2 QUIC protocol interaction issues
            4.3.2.3 UDP-based amplification attacks
            
        4.3.3 Application Layer Integration [OR]
            4.3.3.1 HTTP-based validator API attacks
            4.3.3.2 DNS dependencies for trust anchor resolution
            4.3.3.3 NTP timing attacks on signature validation

5. Advanced Persistent Threat Techniques [OR]

    5.1 Long-Term Key Compromise [OR]
    
        5.1.1 Supply Chain Attacks [OR]
            5.1.1.1 Hardware backdoors in crypto accelerators
            5.1.1.2 Compromised software distributions
            5.1.1.3 Malicious contributor code injections
            
        5.1.2 Key Generation Weaknesses [OR]
            5.1.2.1 Weak entropy sources during key generation
            5.1.2.2 Algorithm-specific bias introduction
            5.1.2.3 Compromised random number generators
            
        5.1.3 Key Storage Compromise [OR]
            5.1.3.1 Cold storage extraction techniques
            5.1.3.2 Cloud HSM configuration breaches
            5.1.3.3 Multi-party computation failures

    5.2 Stealthy Validation Manipulation [OR]
    
        5.2.1 Low-and-Slow Attacks [OR]
            5.2.1.1 Subtle signature validation corruption
            5.2.1.2 Gradual trust anchor manipulation
            5.2.1.3 Incremental policy modification
            
        5.2.2 False Flag Operations [OR]
            5.2.2.1 Attribution obfuscation through intermediate ASes
            5.2.2.2 Victim fingerprint spoofing
            5.2.2.3 Third-party tool exploitation
            
        5.2.3 Persistence Mechanisms [OR]
            5.2.3.1 Reinfection capabilities
            5.2.3.2 Multiple compromise vectors
            5.2.3.3 Anti-forensic techniques

    5.3 AI-Enhanced BGPsec Attacks [OR]
    
        5.3.1 Machine Learning Exploitation [OR]
            5.3.1.1 AI-generated optimal attack timing
            5.3.1.2 Neural network-based evasion patterns
            5.3.1.3 Reinforcement learning for policy exploitation
            
        5.3.2 Automated Vulnerability Discovery [OR]
            5.3.2.1 AI-assisted fuzz testing for BGPsec
            5.3.2.2 Machine learning for side-channel detection
            5.3.2.3 Automated exploit generation
            
        5.3.3 Adaptive Attack Systems [OR]
            5.3.3.1 Self-modifying attack code
            5.3.3.2 Dynamic protocol manipulation
            5.3.3.3 Intelligent countermeasure evasion
```

## Nitty gritty risk table

| Attack Path                                                | Technical Complexity | Resources Required | Risk Level | Notes                                                            |
|------------------------------------------------------------|----------------------|--------------------|------------|------------------------------------------------------------------|
| 1.1.1.1 ECDSA with biased nonces (key recovery)            | Very High            | High               | Very High  | Requires advanced crypto knowledge and access to signatures.     |
| 1.1.1.2 RSA with weak key generation (ROBOT-style)         | High                 | Medium             | High       | Exploit weakly generated keys; complex but feasible.             |
| 1.1.1.3 Hash function collisions (SHA-1/256 issues)        | Very High            | High               | Very High  | Requires computationally expensive collision attacks.            |
| 1.1.2.1 Non-constant-time implementations (timing attacks) | High                 | Medium             | High       | Side-channel exploitation; requires precision measurements.      |
| 1.1.2.2 Memory corruption in crypto libraries              | Very High            | Medium             | Very High  | Needs vulnerability discovery and exploitation skill.            |
| 1.1.2.3 Side-channel leaks (Minerva, Power analysis)       | Very High            | High               | Very High  | Requires lab-grade equipment and long-term analysis.             |
| 1.1.3.1 Harvest now, decrypt later (quantum harvesting)    | Very High            | High               | Very High  | Forward-looking threat; access to encrypted traffic over time.   |
| 1.1.3.2 Weak hybrid transition implementations             | High                 | Medium             | High       | Exploits transitional crypto; moderate resources.                |
| 1.1.3.3 Shor's algorithm preparation attacks               | Very High            | Very High          | Very High  | Future quantum attack; technically extreme.                      |
| 1.2.1.1 HSM vulnerabilities                                | Very High            | Medium             | Very High  | Attacks require specialized hardware and insider knowledge.      |
| 1.2.1.2 Supply chain backdoors in key generation           | Very High            | High               | Very High  | Sophisticated supply chain compromise; long-term planning.       |
| 1.2.1.3 Cloud HSM misconfigurations                        | High                 | Medium             | High       | Opportunistic but requires network/cloud access.                 |
| 1.2.2.1 Delayed key revocation propagation                 | Medium               | Low                | Medium     | Exploit time gaps; moderate impact.                              |
| 1.2.2.2 Weak key rotation policies                         | Medium               | Low                | Medium     | Policy misconfigurations; easy but detectable.                   |
| 1.2.2.3 Compromised key history retention                  | High                 | Medium             | High       | Requires access to historical keys or storage.                   |
| 1.2.3.1 Rogue CA compromise for BGPsec certificates        | Very High            | High               | Very High  | High-impact attack; targets trust infrastructure.                |
| 1.2.3.2 Certificate transparency log poisoning             | Very High            | Medium             | Very High  | Requires log manipulation; advanced.                             |
| 1.2.3.3 Trust anchor manipulation                          | High                 | Medium             | High       | Impacts BGPsec validation globally; technically advanced.        |
| 1.3.1.1 Memory corruption in BGPsec implementations        | Very High            | Medium             | Very High  | Exploit stack vulnerabilities; sophisticated.                    |
| 1.3.1.2 Resource exhaustion attacks                        | High                 | Medium             | High       | Denial-of-service via signature validation.                      |
| 1.3.1.3 Parser differential attacks                        | High                 | Medium             | High       | Requires protocol fuzzing and vulnerability discovery.           |
| 1.3.2.1 Signature verification short-circuiting            | Very High            | Medium             | Very High  | Bypasses core validation; highly technical.                      |
| 1.3.2.2 Cache poisoning attacks                            | High                 | Medium             | High       | Requires targeted injection; advanced skill.                     |
| 1.3.2.3 TOCTOU flaws                                       | High                 | Medium             | High       | Exploits timing between validation and use.                      |
| 1.3.3.1 Capability negotiation manipulation                | High                 | Medium             | High       | Needs session-level knowledge; moderate resources.               |
| 1.3.3.2 Fallback to unsigned BGP sessions                  | Medium               | Low                | Medium     | Opportunistic; relies on partial deployment.                     |
| 1.3.3.3 Version negotiation exploits                       | High                 | Medium             | High       | Targets protocol version logic; technical.                       |
| 2.1.1.1 Malicious TAL distribution                         | High                 | Medium             | High       | Affects trust distribution; requires access/control of channels. |
| 2.1.1.2 Package mirror compromise                          | High                 | Medium             | High       | Manipulates validator software; technical and targeted.          |
| 2.1.1.3 DNS poisoning for trust anchor retrieval           | Medium               | Low                | Medium     | Classic attack vector; moderate impact.                          |
| 2.1.2.1 Delayed anchor revocation propagation              | Medium               | Low                | Medium     | Timing attack; low resource.                                     |
| 2.1.2.2 Weak anchor rotation procedures                    | Medium               | Low                | Medium     | Policy misconfiguration; detectable.                             |
| 2.1.2.3 Historical anchor abuse                            | High                 | Medium             | High       | Requires access to old anchors; advanced.                        |
| 2.1.3.1 RPKI-BGPsec trust chain conflicts                  | High                 | Medium             | High       | Exploits protocol inconsistencies; technical skill needed.       |
| 2.1.3.2 TLS-BGPsec certificate trust confusion             | High                 | Medium             | High       | Cross-protocol attack; requires access to certs.                 |
| 2.1.3.3 Shared HSM compromise                              | Very High            | High               | Very High  | Infrastructure-level compromise; advanced.                       |
| 2.2.1.1 Memory safety issues in validators                 | Very High            | Medium             | Very High  | Vulnerability exploitation in validator software.                |
| 2.2.1.2 Logic flaws in path validation                     | High                 | Medium             | High       | Complex logic exploitation; advanced skill.                      |
| 2.2.1.3 DoS via resource exhaustion                        | High                 | Medium             | High       | Moderate-to-high impact; network load intensive.                 |
| 2.2.2.1 Stale data attacks during sync intervals           | Medium               | Low                | Medium     | Opportunistic; timing attack.                                    |
| 2.2.2.2 MITM attacks on validator-repo communication       | Very High            | Medium             | Very High  | Requires man-in-the-middle access; highly technical.             |
| 2.2.2.3 Repository compromise with malicious data          | Very High            | High               | Very High  | Supply chain-style attack; very impactful.                       |
| 2.2.3.1 Admin interface compromises                        | High                 | Medium             | High       | Requires privileged access; moderate complexity.                 |
| 2.2.3.2 Misconfigured trust boundaries                     | Medium               | Low                | Medium     | Policy misconfiguration; detectable.                             |
| 2.2.3.3 Weak access controls on validator systems          | Medium               | Low                | Medium     | Easy to exploit if present.                                      |
| 2.3.1.1 Injection of malicious BGPsec paths                | High                 | Medium             | High       | Network-level attack; needs protocol knowledge.                  |
| 2.3.1.2 Withdrawal of valid BGPsec routes                  | Medium               | Low                | Medium     | Opportunistic; moderate skill.                                   |
| 2.3.1.3 Route flap attacks with signed updates             | High                 | Medium             | High       | Requires careful timing; disruptive.                             |
| 2.3.2.1 TCP-AO/MD5 bypass for BGP sessions                 | Very High            | High               | Very High  | Requires privileged position or MITM.                            |
| 2.3.2.2 Session reset attacks during key rotation          | High                 | Medium             | High       | Timing-sensitive; requires control over sessions.                |
| 2.3.2.3 MITM on BGPsec peer connections                    | Very High            | High               | Very High  | Advanced network-level attack; very technical.                   |
| 2.3.3.1 CPU exhaustion through signature validation        | Medium               | Medium             | Medium     | Resource-heavy attack; detectable.                               |
| 2.3.3.2 Memory exhaustion via large updates                | Medium               | Medium             | Medium     | Moderate resource usage; network impact.                         |
| 2.3.3.3 Storage exhaustion from key history                | Medium               | Medium             | Medium     | Requires volume of historical keys; moderate skill.              |
| 3.1.1.1 Route leaks through non-BGPsec ASes                | Medium               | Low                | Medium     | Exploits partial deployment; opportunistic.                      |
| 3.1.1.2 Mixed validation policy exploitation               | Medium               | Low                | Medium     | Requires knowledge of adjacent AS policies.                      |
| 3.1.1.3 Border router misconfiguration                     | Low                  | Low                | Medium     | Easy to detect and fix; opportunistic.                           |
| 3.1.2.1 Differing local validation policies                | Medium               | Low                | Medium     | Exploits inconsistent policy; moderate impact.                   |
| 3.1.2.2 Conflict between RPKI and BGPsec validation        | Medium               | Low                | Medium     | Opportunistic misalignment exploitation.                         |
| 3.1.2.3 Graceful restart compatibility issues              | Medium               | Low                | Medium     | Exploits operational quirks; low-resource.                       |
| 3.1.3.1 Exploitation during protocol migration             | Medium               | Medium             | Medium     | Timing-dependent; requires some coordination.                    |
| 3.1.3.2 Backward compatibility weaknesses                  | Medium               | Medium             | Medium     | Moderate technical knowledge needed.                             |
| 3.1.3.3 Dual-stack implementation gaps                     | Medium               | Medium             | Medium     | IPv4/IPv6 gaps; moderately technical.                            |
| 3.2.1.1 Operator credential theft                          | Medium               | Low                | Medium     | Classic social engineering.                                      |
| 3.2.1.2 Fake security alert social engineering             | Medium               | Low                | Medium     | Phishing-style attack.                                           |
| 3.2.1.3 Supply chain impersonation attacks                 | High                 | Medium             | High       | Requires planning and insider knowledge.                         |
| 3.2.2.1 Weak signature policy configuration                | Medium               | Low                | Medium     | Misconfiguration; easy to exploit.                               |
| 3.2.2.2 Incorrect trust anchor deployment                  | Medium               | Low                | Medium     | Configuration error; moderate impact.                            |
| 3.2.2.3 Key management policy mistakes                     | Medium               | Low                | Medium     | Policy-based attack; detectable.                                 |
| 3.2.3.1 Delayed attack detection                           | Medium               | Low                | Medium     | Exploits monitoring gaps; low-resource.                          |
| 3.2.3.2 False sense of security from partial deployment    | Medium               | Low                | Medium     | Human factor; opportunistic.                                     |
| 3.2.3.3 Lack of BGPsec-specific monitoring                 | Medium               | Low                | Medium     | Detection gap exploitation.                                      |
| 3.3.1.1 CPU-intensive signature attacks on smaller ASes    | Medium               | Medium             | Medium     | Exploits resource asymmetry.                                     |
| 3.3.1.2 Storage exhaustion through key history attacks     | Medium               | Medium             | Medium     | Moderate resource attack.                                        |
| 3.3.1.3 Bandwidth consumption via update floods            | Medium               | Medium             | Medium     | Network-heavy attack; detectable.                                |
| 3.3.2.1 Policy registry manipulation                       | High                 | Medium             | High       | Governance-level attack; requires insider knowledge.             |
| 3.3.2.2 Standards body influence operations                | High                 | Medium             | High       | Long-term, low-technical but high-impact.                        |
| 3.3.2.3 Certification authority lobbying                   | High                 | Medium             | High       | Social/political attack vector.                                  |
| 3.3.3.1 Long-term key compromise persistence               | Very High            | High               | Very High  | Requires patience, access, and operational security.             |
| 3.3.3.2 Attack synchronization across multiple ASes        | High                 | High               | Very High  | Complex coordination; high technical skill.                      |
| 3.3.3.3 Holiday/weekend attack timing                      | Medium               | Low                | Medium     | Opportunistic; low-resource.                                     |
| 4.1.1.1 RPKI-valid but BGPsec-invalid route injection      | High                 | Medium             | High       | Exploits cross-protocol validation gaps.                         |
| 4.1.1.2 BGPsec-valid but RPKI-invalid path propagation     | High                 | Medium             | High       | Cross-protocol discrepancy; advanced.                            |
| 4.1.1.3 Unknown state handling discrepancies               | Medium               | Low                | Medium     | Opportunistic; low resource.                                     |
| 4.1.2.1 Different cache TTL exploitation                   | Medium               | Low                | Medium     | Timing attack on cache; low-resource.                            |
| 4.1.2.2 Revocation propagation timing gaps                 | Medium               | Low                | Medium     | Exploits operational timing; moderate impact.                    |
| 4.1.2.3 Validation frequency mismatches                    | Medium               | Low                | Medium     | Timing/monitoring mismatch exploitation.                         |
| 4.1.3.1 Shared CA compromise effects                       | Very High            | High               | Very High  | Infrastructure-level cross-protocol compromise.                  |
| 4.1.3.2 Different crypto algorithm support                 | Medium               | Low                | Medium     | Protocol mismatch exploitation; low-resource.                    |
| 4.1.3.3 Protocol version compatibility issues              | Medium               | Low                | Medium     | Operational gap exploitation.                                    |
| 4.2.1.1 Cross-protocol certificate reuse attacks           | Very High            | High               | Very High  | Affects TLS and BGPsec; high technical skill.                    |
| 4.2.1.2 CA compromise affecting both TLS and BGPsec        | Very High            | High               | Very High  | Infrastructure-level compromise.                                 |
| 4.2.1.3 Validation policy conflict exploitation            | High                 | Medium             | High       | Policy-based attack; technical.                                  |
| 4.2.2.1 TLS session compromise affecting BGPsec            | Very High            | High               | Very High  | Advanced network/crypto attack.                                  |
| 4.2.2.2 BGPsec key exposure affecting TLS sessions         | Very High            | High               | Very High  | High-impact cross-protocol attack.                               |
| 4.2.2.3 Cross-protocol side-channel attacks                | Very High            | High               | Very High  | Requires advanced analysis and monitoring.                       |
| 4.2.3.1 Common crypto library vulnerabilities              | High                 | Medium             | High       | Shared code; moderate difficulty.                                |
| 4.2.3.2 Shared memory safety issues                        | High                 | Medium             | High       | Complex exploitation; technical skill needed.                    |
| 4.2.3.3 Cross-protocol resource exhaustion                 | Medium               | Medium             | Medium     | Opportunistic; resource-heavy.                                   |
| 4.3.1.1 Fragmentation attacks affecting BGPsec             | Medium               | Medium             | Medium     | Network-layer attack; moderate impact.                           |
| 4.3.1.2 TTL-based attacks on validation                    | Medium               | Low                | Medium     | Opportunistic timing attack.                                     |
| 4.3.1.3 DSCP priority manipulation                         | Medium               | Low                | Medium     | Low-resource QoS manipulation.                                   |
| 4.3.2.1 TCP session manipulation affecting BGPsec          | High                 | Medium             | High       | Requires control over TCP flows.                                 |
| 4.3.2.2 QUIC protocol interaction issues                   | High                 | Medium             | High       | Advanced; experimental attack vector.                            |
| 4.3.2.3 UDP-based amplification attacks                    | Medium               | Medium             | Medium     | Opportunistic DoS.                                               |
| 4.3.3.1 HTTP-based validator API attacks                   | Medium               | Low                | Medium     | Exploits API exposure; moderate skill.                           |
| 4.3.3.2 DNS dependencies for trust anchor resolution       | Medium               | Low                | Medium     | Timing or poisoning attacks; low-resource.                       |
| 4.3.3.3 NTP timing attacks on signature validation         | Medium               | Low                | Medium     | Exploits timing assumptions; low-resource.                       |
| 5.1.1.1 Hardware backdoors in crypto accelerators          | Very High            | High               | Very High  | Supply chain compromise; advanced.                               |
| 5.1.1.2 Compromised software distributions                 | Very High            | High               | Very High  | High-impact supply chain attack.                                 |
| 5.1.1.3 Malicious contributor code injections              | Very High            | Medium             | Very High  | Insider threat; sophisticated.                                   |
| 5.1.2.1 Weak entropy sources during key generation         | High                 | Medium             | High       | Can produce weak keys; technical skill.                          |
| 5.1.2.2 Algorithm-specific bias introduction               | High                 | Medium             | High       | Cryptographic manipulation; advanced.                            |
| 5.1.2.3 Compromised random number generators               | High                 | Medium             | High       | Targets crypto core; advanced.                                   |
| 5.1.3.1 Cold storage extraction techniques                 | Very High            | High               | Very High  | Requires physical access; highly technical.                      |
| 5.1.3.2 Cloud HSM configuration breaches                   | High                 | Medium             | High       | Access to misconfigured cloud HSMs; technical.                   |
| 5.1.3.3 Multi-party computation failures                   | Very High            | High               | Very High  | Exploits collaborative crypto; highly complex.                   |
| 5.2.1.1 Subtle signature validation corruption             | Very High            | High               | Very High  | Stealthy, difficult to detect.                                   |
| 5.2.1.2 Gradual trust anchor manipulation                  | High                 | Medium             | High       | Low-and-slow attack; requires patience.                          |
| 5.2.1.3 Incremental policy modification                    | High                 | Medium             | High       | Operational-level subtle attack.                                 |
| 5.2.2.1 Attribution obfuscation through intermediate ASes  | High                 | Medium             | High       | Advanced false-flag operations.                                  |
| 5.2.2.2 Victim fingerprint spoofing                        | Medium               | Medium             | Medium     | Moderate technical skill; opportunistic.                         |
| 5.2.2.3 Third-party tool exploitation                      | Medium               | Medium             | Medium     | Exploits available tools; moderate complexity.                   |
| 5.2.3.1 Reinfection capabilities                           | Very High            | High               | Very High  | Persistence mechanism; highly advanced.                          |
| 5.2.3.2 Multiple compromise vectors                        | Very High            | High               | Very High  | Multi-pronged, complex attack.                                   |
| 5.2.3.3 Anti-forensic techniques                           | Very High            | High               | Very High  | Evades detection; high skill needed.                             |
| 5.3.1.1 AI-generated optimal attack timing                 | Very High            | High               | Very High  | Cutting-edge AI-assisted planning.                               |
| 5.3.1.2 Neural network-based evasion patterns              | Very High            | High               | Very High  | Adaptive attack techniques; advanced.                            |
| 5.3.1.3 Reinforcement learning for policy exploitation     | Very High            | High               | Very High  | Requires AI expertise; highly sophisticated.                     |
| 5.3.2.1 AI-assisted fuzz testing for BGPsec                | High                 | Medium             | High       | Speeds vulnerability discovery.                                  |
| 5.3.2.2 Machine learning for side-channel detection        | High                 | Medium             | High       | Advanced monitoring/attack synergy.                              |
| 5.3.2.3 Automated exploit generation                       | Very High            | High               | Very High  | AI-driven attack creation; highly technical.                     |
| 5.3.3.1 Self-modifying attack code                         | Very High            | High               | Very High  | Adaptive malware; extremely advanced.                            |
| 5.3.3.2 Dynamic protocol manipulation                      | Very High            | High               | Very High  | Changes attack vectors on the fly; complex.                      |
| 5.3.3.3 Intelligent countermeasure evasion                 | Very High            | High               | Very High  | Evades detection systems; cutting-edge threat.                   |

## BGPsec heatmap

<table>
  <thead>
    <tr>
      <th>Attack Category</th>
      <th>Example Attack Path</th>
      <th>Risk Level</th>
      <th>Likely Adversary</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Cryptography</td>
      <td>ECDSA with biased nonces, RSA weak keys</td>
      <td style="background-color:#ff4d4d;color:white;text-align:center;">Very High</td>
      <td>Nation-state / APT</td>
    </tr>
    <tr>
      <td>Key Management</td>
      <td>Private key theft, weak rotation policies</td>
      <td style="background-color:#ff944d;color:black;text-align:center;">High</td>
      <td>Nation-state / Cybercriminal</td>
    </tr>
    <tr>
      <td>Protocol Implementation</td>
      <td>Memory corruption, TOCTOU, downgrade attacks</td>
      <td style="background-color:#ff944d;color:black;text-align:center;">High</td>
      <td>Nation-state / Cybercriminal</td>
    </tr>
    <tr>
      <td>Trust Anchor</td>
      <td>Malicious TALs, anchor rotation flaws</td>
      <td style="background-color:#ffd11a;color:black;text-align:center;">Medium</td>
      <td>Cybercriminal / Opportunistic</td>
    </tr>
    <tr>
      <td>Validator Infrastructure</td>
      <td>Cache poisoning, validator misconfig</td>
      <td style="background-color:#ffd11a;color:black;text-align:center;">Medium</td>
      <td>Cybercriminal / Opportunistic</td>
    </tr>
    <tr>
      <td>Network Infrastructure</td>
      <td>Routing table poisoning, session compromise</td>
      <td style="background-color:#ff944d;color:black;text-align:center;">High</td>
      <td>Nation-state / Cybercriminal</td>
    </tr>
    <tr>
      <td>Partial Deployment</td>
      <td>Validation gaps, mixed policies</td>
      <td style="background-color:#ffff4d;color:black;text-align:center;">Low</td>
      <td>Opportunistic</td>
    </tr>
    <tr>
      <td>Human Factor</td>
      <td>Operator credential theft, social engineering</td>
      <td style="background-color:#ff944d;color:black;text-align:center;">High</td>
      <td>Nation-state / Cybercriminal</td>
    </tr>
    <tr>
      <td>Economic / Coordination</td>
      <td>Resource asymmetry, attack timing</td>
      <td style="background-color:#ffd11a;color:black;text-align:center;">Medium</td>
      <td>Nation-state / Cybercriminal</td>
    </tr>
    <tr>
      <td>Cross-Protocol</td>
      <td>RPKI/BGPsec conflicts, TLS integration</td>
      <td style="background-color:#ff944d;color:black;text-align:center;">High</td>
      <td>Nation-state / Cybercriminal</td>
    </tr>
    <tr>
      <td>APT / AI-Powered</td>
      <td>ML-generated attacks, adaptive persistence</td>
      <td style="background-color:#ff4d4d;color:white;text-align:center;">Very High</td>
      <td>Nation-state / APT</td>
    </tr>
  </tbody>
</table>

