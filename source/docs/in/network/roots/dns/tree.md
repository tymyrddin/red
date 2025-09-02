# Overview attacks on DNS

## Attack tree (DNS)

This attack tree outlines the methodologies for compromising DNS integrity, from classic cache poisoning and sophisticated DDoS amplification to AI-augmented phishing automation and the looming threat of cryptographic harvesting in the post-quantum era.

```text
1. Exploit Protocol Weaknesses [OR]

    1.1 Cache Poisoning [AND]
    
        1.1.1 Exploit weak TXID entropy in DoH/DoT/DoQ resolvers [OR]
            1.1.1.1 Birthday attack on 16-bit TXID space
            1.1.1.2 Timing attacks on resolver response handling
            1.1.1.3 Fragment-based poisoning attacks
            
        1.1.2 Side-channel attacks on encrypted DNS [OR]
            1.1.2.1 TLS padding oracle attacks on DoT
            1.1.2.2 QUIC protocol timing analysis on DoQ
            1.1.2.3 HTTP/2 stream correlation attacks on DoH
            
        1.1.3 DNSSEC Exploitation [OR]
            1.1.3.1 NSEC/NSEC3 walking for zone enumeration
            1.1.3.2 RRSIG timing attacks for key recovery
            1.1.3.3 Algorithm downgrade attacks (ECDSA to RSA)
            
        Prerequisite: AND (Attacker can intercept traffic AND resolver lacks full DNSSEC validation)

    1.2 DDoS Amplification [OR]
    
        1.2.1 Abuse misconfigured encrypted DNS resolvers [OR]
            1.2.1.1 DoQ reflection with large TXT records
            1.2.1.2 DoH POST request amplification
            1.2.1.3 DoT session resumption attacks
            
        1.2.2 DNSSEC-based amplification [OR]
            1.2.2.1 NSEC3 response amplification
            1.2.2.2 Large RRSIG reflection attacks
            1.2.2.3 DNAME chain exploitation
            
        Prerequisite: AND (Open resolver available AND vulnerable payload size > 1000 bytes)

    1.3 Protocol-Specific Vulnerabilities [OR]
    
        1.3.1 QUIC Protocol Exploitation (DoQ) [OR]
            1.3.1.1 Connection migration hijacking
            1.3.1.2 Stream priority manipulation
            1.3.1.3 QUIC spin bit side-channel
            
        1.3.2 HTTP/2 Exploitation (DoH) [OR]
            1.3.2.1 HPACK header compression attacks
            1.3.2.2 Server push cache poisoning
            1.3.2.3 Stream dependency manipulation
            
        1.3.3 TLS Session Attacks (DoT) [OR]
            1.3.3.1 Session ticket stealing
            1.3.3.2 Pre-shared key exhaustion
            1.3.3.3 Certificate transparency log poisoning

2. Attack Encrypted DNS [OR]

    2.1 Privacy Leaks [OR]
    
        2.1.1 Metadata Correlation [AND]
            2.1.1.1 IP + timestamp correlation across multiple resolvers
            2.1.1.2 Query size and timing analysis
            2.1.1.3 Server name indication (SNI) monitoring
            
        2.1.2 ML-based fingerprinting [OR]
            2.1.2.1 Neural network traffic analysis
            2.1.2.2 Query pattern recognition
            2.1.2.3 Encrypted traffic classification
            
        2.1.3 Protocol Identification [OR]
            2.1.3.1 DoH/DoT/DoQ protocol fingerprinting
            2.1.3.2 Application-level protocol detection
            2.1.3.3 Middlebox cooperation for traffic analysis

    2.2 Downgrade Attacks [AND]
    
        2.2.1 Force fallback to plaintext DNS [OR]
            2.2.1.1 TCP RST injection on port 853 (DoT)
            2.2.1.2 HTTP/2 GOAWAY frame injection (DoH)
            2.2.1.3 QUIC connection close spoofing (DoQ)
            
        2.2.2 Encryption Bypass [OR]
            2.2.2.1 Disable ECH (Encrypted Client Hello) in DoH
            2.2.2.2 TLS version downgrade attacks
            2.2.2.3 QUIC version negotiation manipulation
            
        2.2.3 Middlebox Interference [OR]
            2.2.3.1 ISP-level protocol blocking
            2.2.3.2 Enterprise firewall policy enforcement
            2.2.3.3 Government-mandated protocol filtering

    2.3 Certificate Attacks [OR]
    
        2.3.1 CA Compromise [OR]
            2.3.1.1 Rogue certificate issuance
            2.3.1.2 Intermediate CA exploitation
            2.3.1.3 Certificate transparency log poisoning
            
        2.3.2 Client Validation Bypass [OR]
            2.3.2.1 Self-signed certificate acceptance
            2.3.2.2 Certificate pinning bypass
            2.3.2.3 Trust store manipulation

3. Cloud/SaaS Exploits [OR]

    3.1 Kubernetes DNS Compromise [AND]
    
        3.1.1 CoreDNS/Etdncache Poisoning [OR]
            3.1.1.1 API server compromise
            3.1.1.2 ConfigMap manipulation
            3.1.1.3 Plugin vulnerability exploitation
            
        3.1.2 NetworkPolicy Bypass [OR]
            3.1.2.1 Privileged pod escape
            3.1.2.2 Node-level network access
            3.1.2.3 Cross-namespace traffic interception
            
        3.1.3 Service Mesh Exploitation [OR]
            3.1.3.1 Istio/Linkerd DNS redirection
            3.1.3.2 mTLS certificate theft
            3.1.3.3 Sidecar proxy manipulation

    3.2 Serverless Abuse [OR]
    
        3.2.1 DNS Tunneling [OR]
            3.2.1.1 Lambda TXT record exfiltration
            3.2.1.2 Cloud Functions DNS over HTTPS
            3.2.1.3 Azure Functions private resolver abuse
            
        3.2.2 Resource Exhaustion [OR]
            3.2.2.1 DNS query burst attacks
            3.2.2.2 Recursion depth exploitation
            3.2.2.3 Cache saturation attacks
            
        3.2.3 Cloud Integration Attacks [OR]
            3.2.3.1 AWS Route 53 resolver hijacking
            3.2.3.2 Google Cloud DNS API abuse
            3.2.3.3 Azure Private DNS zone poisoning

    3.3 Container Registry Attacks [OR]
    
        3.3.1 Image Pull Manipulation [OR]
            3.3.1.1 DNS spoofing for registry redirection
            3.3.1.2 MITM attacks on image downloads
            3.3.1.3 Cache poisoning for malicious images
            
        3.3.2 Supply Chain Compromise [OR]
            3.3.2.1 Malicious library injection via DNS
            3.3.2.2 Dependency confusion attacks
            3.3.2.3 Package manager DNS hijacking

4. Supply Chain Attacks [OR]

    4.1 Registrar Hijacking [AND]
    
        4.1.1 API Key Compromise [OR]
            4.1.1.1 Cloudflare token theft
            4.1.1.2 AWS Route 53 key leakage
            4.1.1.3 Google Domains API abuse
            
        4.1.2 Social Engineering [OR]
            4.1.2.1 Registrar support impersonation
            4.1.2.2 Post-GDPR WHOIS information gaps
            4.1.2.3 Phone number porting attacks
            
        4.1.3 Registry System Attacks [OR]
            4.1.3.1 EPP protocol exploitation
            4.1.3.2 Registry lock bypass
            4.1.3.3 Transfer process manipulation

    4.2 Subdomain Takeover [AND]
    
        4.2.1 Dangling Resource Identification [OR]
            4.2.1.1 CNAME mapping to unused cloud resources
            4.2.1.2 NS record pointing to decommissioned servers
            4.2.1.3 MX record targeting disabled services
            
        4.2.2 Malicious Content Deployment [OR]
            4.2.2.1 GitHub Pages site cloning
            4.2.2.2 S3 bucket takeover
            4.2.2.3 Azure Blob Storage hijacking
            
        4.2.3 Persistence Mechanisms [OR]
            4.2.3.1 SSL certificate procurement
            4.2.3.2 DNS record obfuscation
            4.2.3.3 Monitoring evasion techniques

    4.3 CDN Compromise [OR]
    
        4.3.1 DNS-Based CDN Manipulation [OR]
            4.3.1.1 Edge server cache poisoning
            4.3.1.2 Origin DNS spoofing
            4.3.1.3 GeoDNS manipulation
            
        4.3.2 Certificate Manipulation [OR]
            4.3.2.1 SAN certificate abuse
            4.3.2.2 CDN SSL termination bypass
            4.3.2.3 Multi-CDN configuration conflicts

5. AI/ML-Augmented Attacks [OR]

    5.1 Evasion Techniques [AND]
    
        5.1.1 Reputation System Poisoning [OR]
            5.1.1.1 DNS query pattern manipulation
            5.1.1.2 Behavioral model contamination
            5.1.1.3 Feedback loop exploitation
            
        5.1.2 Query Obfuscation [OR]
            5.1.2.1 GAN-generated benign-looking queries
            5.1.2.2 CDN traffic mimicry
            5.1.2.3 Legitimate domain spoofing
            
        5.1.3 Adaptive Attacks [OR]
            5.1.3.1 Reinforcement learning for evasion
            5.1.3.2 Genetic algorithm optimization
            5.1.3.3 Transfer learning across networks

    5.2 Phishing Automation [AND]
    
        5.2.1 Domain Generation [OR]
            5.2.1.1 LLM-generated homograph domains
            5.2.1.2 Context-aware typosquatting
            5.2.1.3 Cultural adaptation algorithms
            
        5.2.2 Infrastructure Management [OR]
            5.2.2.1 Dynamic DNS fast-flux networks
            5.2.2.2 Automated certificate procurement
            5.2.2.3 Multi-CDN abuse for resilience
            
        5.2.3 Target Identification [OR]
            5.2.3.1 NLP-based brand monitoring
            5.2.3.2 Social media sentiment analysis
            5.2.3.3 Employee behavior prediction

6. Post-Quantum Threats [OR]

    6.1 Cryptographic Harvesting [AND]
    
        6.1.1 DNSSEC Record Collection [OR]
            6.1.1.1 ECDSA-P256 signature harvesting
            6.1.1.2 RSA-2048 key storage
            6.1.1.3 NSEC3 chain enumeration
            
        6.1.2 Quantum Decryption Preparation [OR]
            6.1.2.1 Long-term encrypted data storage
            6.1.2.2 Future decryption capability planning
            6.1.2.3 Harvest-then-decrypt campaigns
            
        6.1.3 Transition Period Exploitation [OR]
            6.1.3.1 Algorithm confusion attacks
            6.1.3.2 Hybrid scheme weaknesses
            6.1.3.3 Backward compatibility exploitation

    6.2 Quantum Key Distribution Attacks [OR]
    
        6.2.1 QKD Protocol Exploitation [OR]
            6.2.1.1 Photon-splitting attacks
            6.2.1.2 Fake state attacks
            6.2.1.3 Trojans in QKD hardware
            
        6.2.2 Implementation Vulnerabilities [OR]
            6.2.2.1 Side-channel attacks on QKD systems
            6.2.2.2 Laser intensity manipulation
            6.2.2.3 Detector blinding attacks
            
        6.2.3 Integration Attacks [OR]
            6.2.3.1 Classical-quantum interface exploitation
            6.2.3.2 Key management system compromise
            6.2.3.3 Quantum network routing attacks

7. Data Exfiltration Techniques [OR]

    7.1 DNS Tunneling [AND]
    
        7.1.1 Protocol Selection [OR]
            7.1.1.1 Traditional DNS (TXT, NULL records)
            7.1.1.2 DoH/DoT/DoQ encrypted tunneling
            7.1.1.3 ICMP-based DNS manipulation
            
        7.1.2 Evasion Methods [OR]
            7.1.2.1 Query rate limiting bypass
            7.1.2.2 Legitimate traffic blending
            7.1.2.3 Multiple resolver rotation
            
        7.1.3 Data Encoding [OR]
            7.1.3.1 Base32/64 encoding variations
            7.1.3.2 Compression with error correction
            7.1.3.3 Fragmentation and reassembly

    7.2 Covert Channels [OR]
    
        7.2.1 Timing-Based Exfiltration [OR]
            7.2.1.1 Query response timing modulation
            7.2.1.2 DNS refresh interval exploitation
            7.2.1.3 TTL value manipulation
            
        7.2.2 Storage Channels [OR]
            7.2.2.1 DNS cache poisoning with data
            7.2.2.2 NSEC3 gap exploitation
            7.2.2.3 DNSSEC signature embedding
            
        7.2.3 Behavioral Patterns [OR]
            7.2.3.1 Query sequence encoding
            7.2.3.2 Resolver selection patterns
            7.2.3.3 Domain name generation algorithms

    7.3 Exfiltration Infrastructure [OR]
    
        7.3.1 Command and Control [OR]
            7.3.1.1 Dynamic domain generation
            7.3.1.2 DNS-based payload delivery
            7.3.1.3 Dead drop resolvers
            
        7.3.2 Data Processing [OR]
            7.3.2.1 Distributed exfiltration aggregation
            7.3.2.2 On-the-fly decoding services
            7.3.2.3 Cloud function data processing
            
        7.3.3 Persistence Mechanisms [OR]
            7.3.3.1 Multiple exfiltration pathways
            7.3.3.2 Fallback communication channels
            7.3.3.3 Anti-forensic techniques
```

## Nitty gritty risk table

| Attack Path                                                  | Technical Complexity | Resources Required | Risk Level | Notes                                                                                                |
| ------------------------------------------------------------ | -------------------- | ------------------ | ---------- | ---------------------------------------------------------------------------------------------------- |
| 1.1.1.1 Birthday attack on 16-bit TXID space                 | Medium               | Low                | Medium     | Feasible with traffic access and many queries; mitigated by DNSSEC and source port randomization.    |
| 1.1.1.2 Timing attacks on resolver response handling         | High                 | Medium             | High       | Requires precise measurements and traffic observation to bias/guess transactions.                    |
| 1.1.1.3 Fragment-based poisoning attacks                     | High                 | Medium             | High       | Exploits IP fragmentation behaviors; success depends on network middleboxes and resolver settings.   |
| 1.1.2.1 TLS padding oracle attacks on DoT                    | Very High            | Medium             | High       | Complex cryptographic side-channel; requires tailored interaction with target DoT stack.             |
| 1.1.2.2 QUIC protocol timing analysis on DoQ                 | High                 | Medium             | High       | Side-channel on QUIC recovery/timing; needs careful lab setup or privileged network vantage.         |
| 1.1.2.3 HTTP/2 stream correlation attacks on DoH             | High                 | Medium             | High       | Associates query streams via timing/priority; depends on client/server implementation quirks.        |
| 1.1.3.1 NSEC/NSEC3 walking for zone enumeration              | Medium               | Low                | Medium     | Information disclosure rather than integrity break; rate limits and opt-out reduce impact.           |
| 1.1.3.2 RRSIG timing attacks for key recovery                | Very High            | High               | Medium     | Academic-style side-channel; practical exploitation is difficult on hardened stacks.                 |
| 1.1.3.3 Algorithm downgrade attacks (ECDSA to RSA)           | High                 | Medium             | High       | Targets mismatched algorithm policies; hinges on fallback/misconfig.                                 |
| 1.2.1.1 DoQ reflection with large TXT records                | Medium               | Medium             | High       | Leverages path amplification via QUIC; requires open/misconfigured resolvers.                        |
| 1.2.1.2 DoH POST request amplification                       | Medium               | Medium             | High       | Uses HTTP request semantics for bandwidth multiplication; CDN/proxy behavior matters.                |
| 1.2.1.3 DoT session resumption attacks                       | High                 | Medium             | Medium     | Abuses TLS resumption tickets to cut cost per query; mitigations include rate and ticket controls.   |
| 1.2.2.1 NSEC3 response amplification                         | Medium               | Medium             | High       | DNSSEC negative responses can be large; filtering and minimization reduce effect.                    |
| 1.2.2.2 Large RRSIG reflection attacks                       | Medium               | Medium             | High       | Exploits oversised signed responses; best mitigated by response size limits and egress filtering.    |
| 1.2.2.3 DNAME chain exploitation                             | Medium               | Medium             | Medium     | Chained indirections inflate responses; effective mainly with weak ACLs.                             |
| 1.3.1.1 Connection migration hijacking                       | Very High            | High               | High       | Requires QUIC internals knowledge and network control to spoof migration paths.                      |
| 1.3.1.2 Stream priority manipulation                         | High                 | Medium             | Medium     | Exploits scheduler to starve/shape DNS streams; mainly service degradation.                          |
| 1.3.1.3 QUIC spin bit side-channel                           | Medium               | Low                | Medium     | Traffic analysis vector; limited by optional spin bit and padding.                                   |
| 1.3.2.1 HPACK header compression attacks                     | High                 | Medium             | High       | Compression side-channels (e.g., BREACH-style) adapted to DoH; requires precise control/measurement. |
| 1.3.2.2 Server push cache poisoning                          | High                 | Medium             | High       | Abuses HTTP/2 push semantics to seed caches with attacker-chosen artifacts.                          |
| 1.3.2.3 Stream dependency manipulation                       | Medium               | Low                | Medium     | QoS manipulation to infer/perturb query patterns.                                                    |
| 1.3.3.1 Session ticket stealing                              | High                 | Medium             | High       | Steals TLS/DoT tickets to resume as victim; needs endpoint compromise or MITM on storage.            |
| 1.3.3.2 Pre-shared key exhaustion                            | Medium               | Medium             | Medium     | Forces rotation/exhaustion of PSKs; primarily DoS on session setup.                                  |
| 1.3.3.3 Certificate transparency log poisoning               | Very High            | High               | Medium     | Requires ecosystem-level manipulation; detection and auditing make success difficult.                |
| 2.1.1.1 IP + timestamp correlation across multiple resolvers | Medium               | Low                | Medium     | Cross-correlation deanonymizes clients using multi-resolver setups.                                  |
| 2.1.1.2 Query size and timing analysis                       | Medium               | Low                | Medium     | Infers domains from packet sizes/timings even when encrypted.                                        |
| 2.1.1.3 Server name indication (SNI) monitoring              | Low                  | Low                | Medium     | Residual metadata (e.g., SNI when ECH disabled) leaks destinations.                                  |
| 2.1.2.1 Neural network traffic analysis                      | High                 | Medium             | High       | ML models classify encrypted flows; requires labeled data and training pipeline.                     |
| 2.1.2.2 Query pattern recognition                            | Medium               | Low                | Medium     | Identifies applications/users by request rhythms across sessions.                                    |
| 2.1.2.3 Encrypted traffic classification                     | High                 | Medium             | High       | Generic encrypted flow fingerprinting; scales with telemetry access.                                 |
| 2.1.3.1 DoH/DoT/DoQ protocol fingerprinting                  | Low                  | Low                | Medium     | Distinguishes protocols via handshake/behavior traits for policy enforcement or blocking.            |
| 2.1.3.2 Application-level protocol detection                 | Medium               | Low                | Medium     | Infers client apps from traffic patterns/URLs used by DoH endpoints.                                 |
| 2.1.3.3 Middlebox cooperation for traffic analysis           | Medium               | Medium             | High       | Correlated vantage points (ISP/CDN) increase deanonymization power.                                  |
| 2.2.1.1 TCP RST injection on port 853 (DoT)                  | Medium               | Low                | High       | Active interference to force plaintext fallback; mitigated by hard-fail policies.                    |
| 2.2.1.2 HTTP/2 GOAWAY frame injection (DoH)                  | High                 | Medium             | High       | Requires HTTP/2 manipulation capabilities; targets client fallback logic.                            |
| 2.2.1.3 QUIC connection close spoofing (DoQ)                 | High                 | Medium             | High       | Spoofs transport errors to trigger downgrade; path validation can help.                              |
| 2.2.2.1 Disable ECH (Encrypted Client Hello) in DoH          | Medium               | Low                | Medium     | Strips or blocks ECH to expose SNI; depends on network control.                                      |
| 2.2.2.2 TLS version downgrade attacks                        | High                 | Medium             | High       | Classical downgrade if endpoints permit weak versions/ciphers.                                       |
| 2.2.2.3 QUIC version negotiation manipulation                | High                 | Medium             | High       | Abuses version negotiation to weaker behavior/performance.                                           |
| 2.2.3.1 ISP-level protocol blocking                          | Low                  | Medium             | High       | Coarse-grained interference at scale; policy/legal environment dependent.                            |
| 2.2.3.2 Enterprise firewall policy enforcement               | Low                  | Low                | Medium     | Localised blocking/inspection; limited to enterprise boundaries.                                     |
| 2.2.3.3 Government-mandated protocol filtering               | Low                  | High               | High       | High-impact nation-scale filtering; requires regulatory authority.                                   |
| 2.3.1.1 Rogue certificate issuance                           | High                 | High               | High       | Compromised/abused CA issues certs for DoH/DoT endpoints.                                            |
| 2.3.1.2 Intermediate CA exploitation                         | High                 | High               | High       | Targeting subordinate CAs for lateral issuance capability.                                           |
| 2.3.1.3 Certificate transparency log poisoning               | Very High            | High               | Medium     | Attempts to corrupt ecosystem observability; hard to sustain covertly.                               |
| 2.3.2.1 Self-signed certificate acceptance                   | Low                  | Low                | Medium     | Misconfigured clients accept self-signed/invalid certs.                                              |
| 2.3.2.2 Certificate pinning bypass                           | High                 | Medium             | High       | Requires binary patching/hook or proxy control on client.                                            |
| 2.3.2.3 Trust store manipulation                             | Medium               | Medium             | High       | Installs rogue roots/intermediates on endpoints; persistent if unnoticed.                            |
| 3.1.1.1 API server compromise                                | High                 | High               | High       | Kubernetes control-plane breach enables CoreDNS poisoning.                                           |
| 3.1.1.2 ConfigMap manipulation                               | Medium               | Medium             | High       | Alters CoreDNS config/plugins to redirect/poison cluster DNS.                                        |
| 3.1.1.3 Plugin vulnerability exploitation                    | High                 | Medium             | High       | Targets CoreDNS/ETCD plugins for code execution or poisoning.                                        |
| 3.1.2.1 Privileged pod escape                                | High                 | Medium             | High       | Escape to node network namespace to intercept DNS flows.                                             |
| 3.1.2.2 Node-level network access                            | Medium               | Medium             | High       | DaemonSet/agent on nodes can observe/alter DNS traffic.                                              |
| 3.1.2.3 Cross-namespace traffic interception                 | High                 | Medium             | Medium     | Exploits policy gaps for lateral DNS observation within cluster.                                     |
| 3.1.3.1 Istio/Linkerd DNS redirection                        | High                 | Medium             | High       | Service mesh policies/proxies used to reroute DNS to attacker.                                       |
| 3.1.3.2 mTLS certificate theft                               | High                 | High               | High       | Theft of mesh certs enables decryption/impersonation of DNS sidecars.                                |
| 3.1.3.3 Sidecar proxy manipulation                           | Medium               | Medium             | High       | Misconfig or compromise of sidecars to tamper with DNS egress.                                       |
| 3.2.1.1 Lambda TXT record exfiltration                       | Medium               | Low                | Medium     | Uses serverless functions to encode data in DNS responses.                                           |
| 3.2.1.2 Cloud Functions DNS over HTTPS                       | Medium               | Low                | Medium     | DoH endpoints hosted on serverless for stealthy tunneling.                                           |
| 3.2.1.3 Azure Functions private resolver abuse               | Medium               | Medium             | Medium     | Misusing private resolver integrations for data movement.                                            |
| 3.2.2.1 DNS query burst attacks                              | Low                  | Low                | Medium     | Spiky invocation patterns drive resolver autoscaling/limits.                                         |
| 3.2.2.2 Recursion depth exploitation                         | Medium               | Low                | Medium     | Forces deep chains to inflate compute and latency.                                                   |
| 3.2.2.3 Cache saturation attacks                             | Medium               | Medium             | Medium     | Fills caches with low-TTL entries to evict hot data.                                                 |
| 3.2.3.1 AWS Route 53 resolver hijacking                      | High                 | High               | High       | IAM/API misuse to change resolver rules/forwarders.                                                  |
| 3.2.3.2 Google Cloud DNS API abuse                           | High                 | High               | High       | Abuse of project/service accounts to alter DNS configuration.                                        |
| 3.2.3.3 Azure Private DNS zone poisoning                     | High                 | High               | High       | Compromise of Azure DNS resources to redirect internal names.                                        |
| 3.3.1.1 DNS spoofing for registry redirection                | Medium               | Medium             | High       | Manipulates name resolution to pull images from attacker infra.                                      |
| 3.3.1.2 MITM attacks on image downloads                      | High                 | Medium             | High       | Intercepts registry traffic to inject malicious layers.                                              |
| 3.3.1.3 Cache poisoning for malicious images                 | Medium               | Medium             | High       | Seeds caching proxies with tampered image manifests.                                                 |
| 3.3.2.1 Malicious library injection via DNS                  | High                 | Medium             | High       | DNS redirection leading to malicious package sources.                                                |
| 3.3.2.2 Dependency confusion attacks                         | Medium               | Low                | High       | Public package names overshadow private ones using DNS hints.                                        |
| 3.3.2.3 Package manager DNS hijacking                        | High                 | Medium             | High       | Alters resolver path for package indexes to attacker-controlled hosts.                               |
| 4.1.1.1 Cloudflare token theft                               | Medium               | Medium             | High       | Stolen API tokens change DNS at registrar/hosted zones.                                              |
| 4.1.1.2 AWS Route 53 key leakage                             | High                 | Medium             | High       | Exposed access keys enable authoritative DNS manipulation.                                           |
| 4.1.1.3 Google Domains API abuse                             | Medium               | Medium             | High       | Misused API credentials alter domain/records.                                                        |
| 4.1.2.1 Registrar support impersonation                      | Low                  | Low                | High       | Social engineering resets ownership or enables transfers.                                            |
| 4.1.2.2 Post-GDPR WHOIS information gaps                     | Low                  | Low                | Medium     | Exploits limited contact visibility to facilitate impersonation.                                     |
| 4.1.2.3 Phone number porting attacks                         | Medium               | Low                | High       | SIM swap/port-out to intercept registrar 2FA challenges.                                             |
| 4.1.3.1 EPP protocol exploitation                            | High                 | Medium             | High       | Targets registrar-registry channel; requires ecosystem access.                                       |
| 4.1.3.2 Registry lock bypass                                 | High                 | Medium             | High       | Circumvents lock controls through process gaps or insider help.                                      |
| 4.1.3.3 Transfer process manipulation                        | Medium               | Medium             | High       | Abuses transfer windows/auth codes to seize domains.                                                 |
| 4.2.1.1 CNAME mapping to unused cloud resources              | Low                  | Low                | High       | Classic dangling CNAME takeover; easily automated discovery.                                         |
| 4.2.1.2 NS record pointing to decommissioned servers         | Medium               | Low                | High       | Orphaned NS enables zone control for subdomains.                                                     |
| 4.2.1.3 MX record targeting disabled services                | Medium               | Low                | Medium     | Mail path hijack for phishing/data collection.                                                       |
| 4.2.2.1 GitHub Pages site cloning                            | Low                  | Low                | Medium     | Rebind subdomain to attacker’s pages for brand abuse.                                                |
| 4.2.2.2 S3 bucket takeover                                   | Low                  | Low                | High       | Recreates deleted buckets to host attacker content.                                                  |
| 4.2.2.3 Azure Blob Storage hijacking                         | Low                  | Low                | High       | Claims unbound storage names referenced by CNAMEs.                                                   |
| 4.2.3.1 SSL certificate procurement                          | Medium               | Low                | High       | Validates control over taken subdomain to obtain certs.                                              |
| 4.2.3.2 DNS record obfuscation                               | Medium               | Low                | Medium     | Hides persistence with nested CNAMEs/TTL tricks.                                                     |
| 4.2.3.3 Monitoring evasion techniques                        | Medium               | Low                | Medium     | Low-and-slow changes and selective responses to evade detection.                                     |
| 4.3.1.1 Edge server cache poisoning                          | High                 | Medium             | High       | Poison CDN edge with malicious DNS/HTTP artifacts via control-path issues.                           |
| 4.3.1.2 Origin DNS spoofing                                  | High                 | Medium             | High       | Redirect CDN to attacker “origin” by DNS manipulation.                                               |
| 4.3.1.3 GeoDNS manipulation                                  | Medium               | Medium             | Medium     | Geographic split-horizon abuse to isolate victims.                                                   |
| 4.3.2.1 SAN certificate abuse                                | High                 | Medium             | High       | Misuses shared SAN certs for unintended hostnames.                                                   |
| 4.3.2.2 CDN SSL termination bypass                           | High                 | Medium             | High       | Forces traffic around expected TLS termination points.                                               |
| 4.3.2.3 Multi-CDN configuration conflicts                    | Medium               | Medium             | Medium     | Exploits inconsistent DNS/TLS between providers.                                                     |
| 5.1.1.1 DNS query pattern manipulation                       | Medium               | Medium             | Medium     | Pollutes reputation systems with crafted benign-looking query mixes.                                 |
| 5.1.1.2 Behavioral model contamination                       | High                 | Medium             | High       | Inserts poisoned samples into training/feedback loops.                                               |
| 5.1.1.3 Feedback loop exploitation                           | Medium               | Medium             | Medium     | Exploits automated block/allow updates to drift policies.                                            |
| 5.1.2.1 GAN-generated benign-looking queries                 | High                 | Medium             | High       | ML-generated traffic mimics normal distributions to evade filters.                                   |
| 5.1.2.2 CDN traffic mimicry                                  | Medium               | Low                | Medium     | Routes via popular CDNs to blend with noise and whitelists.                                          |
| 5.1.2.3 Legitimate domain spoofing                           | Medium               | Low                | Medium     | Uses typo/homograph names that resemble legitimate endpoints.                                        |
| 5.1.3.1 Reinforcement learning for evasion                   | Very High            | High               | High       | Trains agents to adapt queries against defenses; research-heavy.                                     |
| 5.1.3.2 Genetic algorithm optimization                       | High                 | Medium             | Medium     | Evolves traffic features to reduce detection scores.                                                 |
| 5.1.3.3 Transfer learning across networks                    | High                 | Medium             | Medium     | Reuses models between environments to shorten tuning time.                                           |
| 5.2.1.1 LLM-generated homograph domains                      | Low                  | Low                | High       | Automates convincing domain suggestions at scale.                                                    |
| 5.2.1.2 Context-aware typosquatting                          | Low                  | Low                | High       | Uses user/brand context to pick likely typos; increases click-through.                               |
| 5.2.1.3 Cultural adaptation algorithms                       | Medium               | Low                | Medium     | Localizes domain choices to regions/languages.                                                       |
| 5.2.2.1 Dynamic DNS fast-flux networks                       | Medium               | Medium             | High       | Rapidly changing DNS answers to resist takedown.                                                     |
| 5.2.2.2 Automated certificate procurement                    | Low                  | Low                | High       | Scripted DV issuance increases trust signals for phishing.                                           |
| 5.2.2.3 Multi-CDN abuse for resilience                       | Medium               | Medium             | Medium     | Spreads infrastructure across CDNs to survive blocking.                                              |
| 5.2.3.1 NLP-based brand monitoring                           | Medium               | Low                | Medium     | Identifies hot targets to register convincing domains.                                               |
| 5.2.3.2 Social media sentiment analysis                      | Medium               | Low                | Medium     | Times campaigns around trending events.                                                              |
| 5.2.3.3 Employee behavior prediction                         | High                 | Medium             | Medium     | Tailors lures using internal cadence/meeting patterns.                                               |
| 5.3.1.1 AI-generated optimal attack timing                   | High                 | Medium             | Medium     | Uses forecasting to time bursts/downgrades for max effect.                                           |
| 5.3.1.2 Neural network-based evasion patterns                | High                 | Medium             | High       | Learns feature sets that current detectors overlook.                                                 |
| 5.3.1.3 Reinforcement learning for policy exploitation       | Very High            | High               | High       | Probes defenses to discover blind spots automatically.                                               |
| 5.3.2.1 AI-assisted fuzz testing for BGPsec                  | High                 | Medium             | Medium     | (Cross-domain) automates fuzzing; limited direct impact on encrypted DNS.                            |
| 5.3.2.2 Machine learning for side-channel detection          | High                 | Medium             | Medium     | Enhances side-channel signal extraction; still constrained by noise.                                 |
| 5.3.2.3 Automated exploit generation                         | Very High            | High               | Medium     | Early-stage capability; high setup cost.                                                             |
| 5.3.3.1 Self-modifying attack code                           | High                 | Medium             | High       | Polymorphic tunneling/backdoor code hampers signatures.                                              |
| 5.3.3.2 Dynamic protocol manipulation                        | High                 | Medium             | High       | Switches among DoH/DoT/DoQ to evade static rules.                                                    |
| 5.3.3.3 Intelligent countermeasure evasion                   | High                 | Medium             | High       | Actively probes and adapts around rate limits and filters.                                           |
| 6.1.1.1 ECDSA-P256 signature harvesting                      | Low                  | Low                | Medium     | Collects public DNSSEC signatures for potential future attacks.                                      |
| 6.1.1.2 RSA-2048 key storage                                 | Low                  | Low                | Medium     | Archives RSA signatures/keys (public) for harvest-now-decrypt-later strategies.                      |
| 6.1.1.3 NSEC3 chain enumeration                              | Medium               | Low                | Medium     | Gathers structure of signed zones for later targeting.                                               |
| 6.1.2.1 Long-term encrypted data storage                     | Low                  | Medium             | Medium     | Warehouses captured encrypted DNS/DoH traffic for future decryption.                                 |
| 6.1.2.2 Future decryption capability planning                | Medium               | Medium             | Medium     | Organizes key materials and compute pipelines anticipating PQ-era.                                   |
| 6.1.2.3 Harvest-then-decrypt campaigns                       | Medium               | High               | High       | Strategic programs at scale to capture now and decrypt later.                                        |
| 6.1.3.1 Algorithm confusion attacks                          | High                 | Medium             | Medium     | Exploits transition periods where multiple DNSSEC algs coexist.                                      |
| 6.1.3.2 Hybrid scheme weaknesses                             | High                 | Medium             | Medium     | Attacks mis-implemented hybrid (classical+PQ) deployments.                                           |
| 6.1.3.3 Backward compatibility exploitation                  | Medium               | Medium             | Medium     | Forces fallback to pre-PQ algorithms/policies.                                                       |
| 6.2.1.1 Photon-splitting attacks                             | Very High            | Very High          | Medium     | Specialised QKD attack; requires physical access and lab gear.                                       |
| 6.2.1.2 Fake state attacks                                   | Very High            | Very High          | Medium     | Injects crafted quantum states to bias keys; niche, hardware-specific.                               |
| 6.2.1.3 Trojans in QKD hardware                              | Very High            | Very High          | Medium     | Supply-chain/hardware implants in QKD components.                                                    |
| 6.2.2.1 Side-channel attacks on QKD systems                  | Very High            | High               | Medium     | Exploits implementation leaks (detectors, timing).                                                   |
| 6.2.2.2 Laser intensity manipulation                         | Very High            | High               | Medium     | Alters device behavior; difficult to mount covertly.                                                 |
| 6.2.2.3 Detector blinding attacks                            | Very High            | High               | Medium     | Forces detectors into classical regimes; requires proximity.                                         |
| 6.2.3.1 Classical-quantum interface exploitation             | High                 | High               | Medium     | Targets key handoff between QKD and classical DNS/TLS systems.                                       |
| 6.2.3.2 Key management system compromise                     | High                 | High               | High       | Compromise of KMS integrating PQ/QKD undermines entire chain.                                        |
| 6.2.3.3 Quantum network routing attacks                      | Very High            | Very High          | Medium     | Attacks on early quantum network control planes; emerging risk.                                      |
| 7.1.1.1 Traditional DNS (TXT, NULL records)                  | Low                  | Low                | Medium     | Simple tunneling via classic records; widely detected by mature defenses.                            |
| 7.1.1.2 DoH/DoT/DoQ encrypted tunneling                      | Medium               | Low                | High       | Encrypts payloads to bypass middleboxes; harder to monitor.                                          |
| 7.1.1.3 ICMP-based DNS manipulation                          | Medium               | Low                | Medium     | Covert data over ICMP with DNS semantics; niche and noisy.                                           |
| 7.1.2.1 Query rate limiting bypass                           | Medium               | Low                | Medium     | Distributes queries to evade per-source throttling.                                                  |
| 7.1.2.2 Legitimate traffic blending                          | Medium               | Low                | High       | Shapes tunnels to match benign client/protocol patterns.                                             |
| 7.1.2.3 Multiple resolver rotation                           | Low                  | Low                | Medium     | Rotates upstreams to evade IP-based detection.                                                       |
| 7.1.3.1 Base32/64 encoding variations                        | Low                  | Low                | Medium     | Obfuscates payloads within label constraints.                                                        |
| 7.1.3.2 Compression with error correction                    | Medium               | Low                | Medium     | Balances throughput vs. reliability over lossy paths.                                                |
| 7.1.3.3 Fragmentation and reassembly                         | Medium               | Low                | Medium     | Splits payloads across queries to bypass size checks.                                                |
| 7.2.1.1 Query response timing modulation                     | Medium               | Low                | Medium     | Encodes bits in inter-arrival/latency; low bandwidth but stealthy.                                   |
| 7.2.1.2 DNS refresh interval exploitation                    | Medium               | Low                | Medium     | Uses refresh/probe timings as covert clock.                                                          |
| 7.2.1.3 TTL value manipulation                               | Medium               | Low                | Medium     | Encodes data in TTL fields; detectable via anomalies.                                                |
| 7.2.2.1 DNS cache poisoning with data                        | High                 | Medium             | High       | Seeds caches with attacker-controlled encodings for later retrieval.                                 |
| 7.2.2.2 NSEC3 gap exploitation                               | High                 | Medium             | Medium     | Stores bits via crafted non-existent name patterns.                                                  |
| 7.2.2.3 DNSSEC signature embedding                           | High                 | Medium             | Medium     | Hides data in optional fields/signature slack; raises validation risks.                              |
| 7.2.3.1 Query sequence encoding                              | Low                  | Low                | Medium     | Uses order of labels/queries to represent data.                                                      |
| 7.2.3.2 Resolver selection patterns                          | Low                  | Low                | Medium     | Chooses resolvers in specific sequences as a codebook.                                               |
| 7.2.3.3 Domain name generation algorithms                    | Medium               | Low                | Medium     | DGA-based channels for resilient command/data paths.                                                 |
| 7.3.1.1 Dynamic domain generation                            | Medium               | Medium             | High       | Rotates domains rapidly to evade blocklists.                                                         |
| 7.3.1.2 DNS-based payload delivery                           | Medium               | Low                | Medium     | Delivers stage payloads via TXT/NULL to reduce HTTP exposure.                                        |
| 7.3.1.3 Dead drop resolvers                                  | Medium               | Medium             | Medium     | Uses specific recursive resolvers as covert mailboxes.                                               |
| 7.3.2.1 Distributed exfiltration aggregation                 | Medium               | Medium             | Medium     | Fan-out/fan-in architecture to assemble data outside perimeter.                                      |
| 7.3.2.2 On-the-fly decoding services                         | Low                  | Low                | Medium     | Cloud functions decode/forward tunneled chunks in real time.                                         |
| 7.3.2.3 Cloud function data processing                       | Medium               | Low                | Medium     | Serverless transforms/filters exfil data before storage.                                             |
| 7.3.3.1 Multiple exfiltration pathways                       | Medium               | Medium             | Medium     | Redundant DNS + alt channels improve resilience.                                                     |
| 7.3.3.2 Fallback communication channels                      | Medium               | Low                | Medium     | Automatic switchover to new domains/resolvers/CDNs.                                                  |
| 7.3.3.3 Anti-forensic techniques                             | High                 | Medium             | High       | Deletes artifacts, pads timings, rotates keys to hinder IR.                                          |

## DNS heatmap

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
      <td>Exploit Protocol Weaknesses</td>
      <td>TXID birthday poisoning, HTTP/2 HPACK, QUIC migration spoof</td>
      <td style="background-color:#ff944d;color:black;text-align:center;">High</td>
      <td>Nation-state / Skilled cybercriminal</td>
    </tr>
    <tr>
      <td>Attack Encrypted DNS</td>
      <td>RST/GOAWAY/QUIC-close downgrades, ML traffic fingerprinting</td>
      <td style="background-color:#ff944d;color:black;text-align:center;">High</td>
      <td>Nation-state / ISP-level actor</td>
    </tr>
    <tr>
      <td>Cloud/SaaS Exploits</td>
      <td>CoreDNS ConfigMap poisoning, Route 53 rule hijack</td>
      <td style="background-color:#ff944d;color:black;text-align:center;">High</td>
      <td>Cloud-savvy attacker / APT</td>
    </tr>
    <tr>
      <td>Supply Chain Attacks</td>
      <td>Registrar API key theft, dangling CNAME takeover</td>
      <td style="background-color:#ff944d;color:black;text-align:center;">High</td>
      <td>Cybercriminal / APT</td>
    </tr>
    <tr>
      <td>AI/ML-Augmented Attacks</td>
      <td>GAN-shaped queries, RL-based evasion</td>
      <td style="background-color:#ffd11a;color:black;text-align:center;">Medium</td>
      <td>Well-resourced criminal / Research-grade actor</td>
    </tr>
    <tr>
      <td>Post-Quantum Threats</td>
      <td>Harvest-now-decrypt-later, transition-period confusion</td>
      <td style="background-color:#ffd11a;color:black;text-align:center;">Medium</td>
      <td>Nation-state / Strategic actor</td>
    </tr>
    <tr>
      <td>Data Exfiltration Techniques</td>
      <td>DoH/DoT/DoQ tunneling, cache-based storage channels</td>
      <td style="background-color:#ff944d;color:black;text-align:center;">High</td>
      <td>Cybercriminal / APT</td>
    </tr>
  </tbody>
</table>

