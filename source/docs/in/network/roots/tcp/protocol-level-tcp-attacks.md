# Protocol-level TCP attacks

## Attack pattern

Protocol-level TCP attacks target the fundamental mechanisms of the Transmission Control Protocol (TCP) that underpin BGP sessions. These attacks exploit inherent vulnerabilities in TCP's design, implementation flaws in router operating systems, and weaknesses in how BGP utilises TCP for reliable communication. By manipulating TCP's core protocols, attackers can disrupt BGP sessions, inject malicious content, or exhaust router resources.

```text
1. Protocol-level TCP attacks [OR]

    1.1 Connection hijacking [AND]
    
        1.1.1 Off-path sequence number prediction
            1.1.1.1 Exploit poor initial sequence number generation
            1.1.1.2 Analyse timestamp-based sequence number leaks
            1.1.1.3 Predict sequence numbers through statistical analysis
            1.1.1.4 Capitalise on low entropy in random number generation
            
        1.1.2 Malicious packet injection
            1.1.2.1 RST spoofing to terminate BGP sessions
            1.1.2.2 FIN spoofing to gracefully close connections
            1.1.2.3 Data injection into established BGP sessions
            1.1.2.4 Crafted packet injection to corrupt BGP state
            
    1.2 Amplification/reflection attacks [OR]
    
        1.2.1 TCP middlebox reflection
            1.2.1.1 Exploit stateful firewall behaviour
            1.2.1.2 Abuse load balancer TCP handling
            1.2.1.3 Utilise proxy server amplification
            1.2.1.4 Reflect through misconfigured network devices
            
        1.2.2 ACK/PSH flood abuse
            1.2.2.1 Generate high-volume ACK storms
            1.2.2.2 Abuse push flag to force processing
            1.2.2.3 Consume router CPU with packet processing
            1.2.2.4 Trigger resource exhaustion on target systems
            
        1.2.3 BGP update reflection/amplification
            1.2.3.1 Spoof BGP update source addresses
            1.2.3.2 Amplify route advertisements through reflection
            1.2.3.3 Cause routing churn through reflected updates
            1.2.3.4 Exploit BGP's path vector protocol characteristics
            
    1.3 Resource exhaustion attacks [OR]
    
        1.3.1 TCP state table exhaustion
            1.3.1.1 Create numerous half-open connections
            1.3.1.2 Maintain persistent connection attempts
            1.3.1.3 Exploit maximum connection limits
            1.3.1.4 Target BGP session establishment resources
            
        1.3.2 Buffer manipulation attacks
            1.3.2.1 Force excessive buffer allocation
            1.3.2.2 Exploit TCP window size advertising
            1.3.2.3 Cause buffer bloat conditions
            1.3.2.4 Trigger memory exhaustion through crafted packets
            
    1.4 Protocol manipulation attacks [OR]
    
        1.4.1 TCP option exploitation
            1.4.1.1 Craft malicious TCP option fields
            1.4.1.2 Exploit option processing vulnerabilities
            1.4.1.3 Cause parser failures through invalid options
            1.4.1.4 Abuse timestamp options for sequence prediction
            
        1.4.2 Flow control mechanism abuse
            1.4.2.1 Manipulate window size advertisements
            1.4.2.2 Exploit congestion control algorithms
            1.4.2.3 Cause throughput degradation
            1.4.2.4 Trigger retransmission storms
            
    1.5 Timing and side-channel attacks [OR]
    
        1.5.1 Timing analysis attacks
            1.5.1.1 Measure packet processing times
            1.5.1.2 Infer network congestion state
            1.5.1.3 Detect sequence number validation timing
            1.5.1.4 Exploit timing differences in packet processing
            
        1.5.2 Side-channel information leakage
            1.5.2.1 Extract information through behavioural analysis
            1.5.2.2 Infer internal state through response patterns
            1.5.2.3 Exploit implementation-specific characteristics
            1.5.2.4 Gather intelligence for targeted attacks
```

## Why it works

-   Protocol design limitations: TCP's design includes inherent vulnerabilities that can be exploited
-   Implementation variability: Different TCP stack implementations have unique weaknesses
-   Predictable behaviour: TCP protocols often exhibit predictable patterns that attackers can analyse
-   Resource constraints: Network devices have limited resources for handling TCP connections
-   Stateful complexity: Maintaining TCP state requires significant resources and complex logic
-   Interoperability requirements: Support for various TCP extensions increases attack surface
-   Legacy compatibility: Backward compatibility requirements prevent removal of vulnerable features

## Counter moves

Protocol-level TCP attacks is what this page works through. Stateful filtering and anomaly detection on the handshake are the answer. The defensive counterpart is in the blue notes on [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
