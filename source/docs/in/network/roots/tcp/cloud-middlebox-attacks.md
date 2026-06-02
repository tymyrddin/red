# Cloud/middlebox-specific attacks

## Attack pattern

Cloud and middlebox-specific attacks target the unique architectures and functionalities of modern network infrastructure components including cloud load balancers, stateful firewalls, and specialised monitoring systems. These attacks exploit the complex processing requirements, state management challenges, and performance optimisations inherent in these systems to bypass security controls, exhaust resources, or evade detection mechanisms.

```text
1. Cloud/middlebox-specific attacks [OR]

    1.1 Bypass cloud load balancers [AND]
    
        1.1.1 Crafted TCP segmentation evasion
            1.1.1.1 Overlapping TCP segment exploitation
            1.1.1.2 Out-of-order segment reassembly manipulation
            1.1.1.3 Maximum segment size (MSS) manipulation
            1.1.1.4 TCP option field abuse for evasion
            
        1.1.2 Instance resource exhaustion
            1.1.2.1 Connection pool exhaustion attacks
            1.1.2.2 Memory exhaustion through large requests
            1.1.2.3 CPU exhaustion via complex processing demands
            1.1.2.4 SSL/TLS handshake resource consumption
            
    1.2 Stateful firewall evasion [OR]
    
        1.2.1 TCP fast open cache poisoning
            1.2.1.1 TFO cookie theft or prediction
            1.2.1.2 Cache pollution through forged requests
            1.2.1.3 Race condition exploitation during TFO establishment
            1.2.1.4 Bypass of stateful inspection through TFO abuse
            
        1.2.2 Fragmentation overlap attacks
            1.2.2.1 IP fragment reassembly manipulation
            1.2.2.2 Overlapping fragment exploitation
            1.2.2.3 Time-to-live (TTL) based fragmentation attacks
            1.2.2.4 Protocol field manipulation in fragments
            
        1.2.3 Evade BGP monitoring systems
            1.2.3.1 Crafted BGP update timing attacks
            1.2.3.2 Route attribute manipulation for evasion
            1.2.3.3 Monitoring system resource exhaustion
            1.2.3.4 False positive induction in detection systems
            
    1.3 Application delivery controller exploitation [OR]
    
        1.3.1 SSL/TLS termination bypass
            1.3.1.1 Certificate validation evasion
            1.3.1.2 Encryption protocol downgrade attacks
            1.3.1.3 Cipher suite manipulation
            1.3.1.4 Session renegotiation attacks
            
        1.3.2 Content caching exploitation
            1.3.2.1 Cache poisoning through request smuggling
            1.3.2.2 Cache bypass techniques
            1.3.2.3 Cache timing attacks
            1.3.2.4 Cache-based side-channel attacks
            
    1.4 Cloud-native network function attacks [OR]
    
        1.4.1 Container networking exploitation
            1.4.1.1 Kubernetes network policy bypass
            1.4.1.2 Service mesh security control evasion
            1.4.1.3 Container escape to host network
            1.4.1.4 Cloud metadata service abuse
            
        1.4.2 Serverless function networking attacks
            1.4.2.1 Cold start timing attacks
            1.4.2.2 Function chain exploitation
            1.4.2.3 Event source manipulation
            1.4.2.4 Resource limit exhaustion
            
    1.5 Network function virtualisation attacks [OR]
    
        1.5.1 Virtual network function exploitation
            1.5.1.1 Hypervisor networking stack attacks
            1.5.1.2 Virtual switch security bypass
            1.5.1.3 SR-IOV configuration manipulation
            1.5.1.4 NFV infrastructure compromise
            
        1.5.2 Management and orchestration attacks
            1.5.2.1 MANO system compromise
            1.5.2.2 Network service descriptor manipulation
            1.5.2.3 Virtualised network function image tampering
            1.5.2.4 Orchestration API exploitation
            
    1.6 Content delivery network attacks [OR]
    
        1.6.1 CDN cache poisoning
            1.6.1.1 Request routing manipulation
            1.6.1.2 Cache key confusion attacks
            1.6.1.3 Domain fronting techniques
            1.6.1.4 Cache timing and race conditions
            
        1.6.2 CDN security feature bypass
            1.6.2.1 Web application firewall evasion
            1.6.2.2 DDoS protection bypass
            1.6.2.3 Bot detection evasion
            1.6.2.4 Rate limiting circumvention
```

## Why it works

-   Complexity of processing: Middleboxes perform complex packet inspection and modification that creates attack surface
-   State management challenges: Maintaining connection state across distributed systems introduces vulnerabilities
-   Performance optimisations: Optimisations for speed and efficiency often bypass security checks
-   Protocol complexity: Modern protocols have numerous edge cases that can be exploited
-   Resource sharing: Multi-tenant environments create opportunities for cross-customer attacks
-   Configuration complexity: Complex configuration requirements lead to misconfigurations and security gaps
-   Rapid deployment cycles: Fast deployment of new features may bypass security review processes

## Counter moves

Cloud/middlebox-specific attacks is the variant in play. Stateful filtering and anomaly detection on the handshake are the answer. The defensive counterpart is in the blue notes on [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
