# Transmission Control Protocol (TCP)

## Attack tree: Compromise a target via TCP vulnerabilities

```text
1. Exploit TCP Stack Vulnerabilities (OR)

    1.1. Remote Code Execution (RCE) via TCP/IP flaws
    
    1.2. Kernel memory corruption (SACK-based attacks)

2. Protocol-Level Attacks (OR)

    2.1. Connection Hijacking (AND)
    
        2.1.1. Off-path sequence number prediction
        
        2.1.2. Malicious packet injection (RST/FIN spoofing)
    
    2.2. Amplification/Reflection Attacks (OR)
    
        2.2.1. TCP middlebox reflection
        
        2.2.2. ACK/PSH flood abuse

3. Off-Path & Side-Channel Attacks (AND)

    3.1. Blind In-Window Exploit (OR)
    
        3.1.1. NAT Slipstreaming variants
        
        3.1.2. Protocol downgrade attacks (QUIC-to-TCP)
    
    3.2. Side-Channel Data Extraction (AND)
    
        3.2.1. TCP timestamp analysis
        
        3.2.2. Application data correlation

4. Cloud/Middlebox-Specific Attacks (OR)

    4.1. Bypass Cloud Load Balancers (AND)
    
        4.1.1. Crafted TCP segmentation evasion
        
        4.1.2. Instance resource exhaustion
    
    4.2. Stateful Firewall Evasion (OR)
    
        4.2.1. TCP Fast Open (TFO) cache poisoning
        
        4.2.2. Fragmentation overlap attacks

5. AI/ML-Enhanced Attacks (AND)

    5.1. Traffic Fingerprinting (OR)
    
        5.1.1. Encrypted traffic classification
        
        5.1.2. SCADA system detection via flow patterns
    
    5.2. Adversarial Traffic Generation (AND)
    
        5.2.1. GAN-based normal traffic modelling
        
        5.2.2. Stealthy DDoS payload synthesis
```

## Attack tree: Manipulate BGP routing by compromising TCP-based BGP sessions

BGP uses TCP (Transmission Control Protocol) as its transport layer protocol. TCP establishes a reliable, 
connection-oriented session between BGP peers (routers). BGP peers communicate default over TCP port 179.

```text
1. Disrupt BGP Session Establishment (OR)

    1.1. TCP SYN Flood Attack (Exhaust BGP Peer Resources)
    
    1.2. Exploit BGP’s MD5 Authentication Weaknesses (OR)
    
        1.2.1. Crack TCP-MD5 Hashes (if weak keys used)
        
        1.2.2. Bypass MD5 via TCP Session Hijacking

2. Hijack Active BGP Sessions (AND)

    2.1. Predict BGP TCP Sequence Numbers (OR)
    
        2.1.1. Off-Path ISN Prediction (using timestamp leaks)
        
        2.1.2. In-Window Guessing (due to poor ISN randomization)
    
    2.2. Inject Malicious BGP Updates (OR)
    
        2.2.1. Spoofed Route Advertisements
        
        2.2.2. Crafted AS_PATH Manipulation

3. Exploit TCP Stack Vulnerabilities on BGP Routers (OR)

    3.1. Trigger Kernel Crashes (DoS) (OR)
    
        3.1.1. Exploit TCP SACK Handling (Linux CVE-2019-11477)
        
        3.1.2. Abuse TCP Selective ACK (SACK) Resource Exhaustion
    
    3.2. Remote Code Execution (RCE) via TCP/IP Stack (AND)
    
        3.2.1. Exploit Router OS TCP Stack (JunOS, IOS XR flaws)
        
        3.2.2. Deploy Malicious BGP Configurations Post-Exploit

4. Man-in-the-Middle (MITM) BGP Sessions (AND)

    4.1. Intercept TCP Traffic (OR)
    
        4.1.1. ARP/DNS Spoofing to Redirect BGP Traffic
        
        4.1.2. BGP Peering Over Unencrypted Links (Internet Exchange Points)
    
    4.2. Decrypt or Modify BGP Messages (OR)
    
        4.2.1. Downgrade TCP-MD5 to Plaintext (if misconfigured)
        
        4.2.2. Exploit Missing TCP-AO (Authentication Option)

5. Abuse BGP Session Persistence (OR)

    5.1. Force BGP Session Resets via TCP Attacks (AND)
    
        5.1.1. Inject RST Packets (Precision Spoofing)
        
        5.1.2. Exploit TCP Keepalive Timeouts
    
    5.2. Subvert BGP Graceful Restart (OR)
    
        5.2.1. Spoof Graceful Restart Capabilities
        
        5.2.2. Exhaust Router Memory During Recovery
```

## TCP Reflection/Amplification attacks

Pattern: Attackers abuse TCP-based protocols (e.g., SYN-ACK reflection via middlebox misconfigurations) to amplify traffic.

Example: In 2022, attackers exploited misconfigured middleboxes (firewalls, load balancers) that responded to SYN packets with large SYN-ACK responses, enabling amplification.

Why It Works: Many network devices ignore RFC standards, allowing spoofed SYN packets to trigger disproportionate responses.

Mitigation: RFC 5358 (TCP Reflection Attacks) recommendations, such as filtering spoofed packets and disabling non-compliant middlebox behaviours.

## RST/FIN Floods (State-Exhaustion attacks)

Pattern: Attackers send spoofed RST or FIN packets to tear down legitimate TCP connections.

Example: In 2023, a cloud provider faced outages due to RST floods targeting critical services, forcing session resets and degrading performance.

Why It Works: Stateless firewalls often fail to validate RST/FIN sequence numbers, allowing blind connection resets.

Mitigation: TCP sequence number validation (e.g., SYN cookies) and stateful inspection.

## TCP Zero-Window attacks (Resource Starvation)

Pattern: Attackers advertise a zero receive window, forcing servers to hold connections open indefinitely.

Example: In 2021–2022, attackers targeted web servers (Apache/Nginx) by exhausting memory with zero-window stalls.

Why It Works: Servers retain buffers for stalled connections, leading to OOM (Out-of-Memory) crashes.

Mitigation: Aggressive timeouts for zero-window connections and dynamic window scaling adjustments.

## SYN Floods (Classic but Persistent)

Pattern: Still prevalent, using botnets to send high-volume SYN packets, exhausting server connection tables.

Example: In 2023, a gaming company faced a 3.5 Tbps SYN flood from a Mirai-variant botnet.

Why It Works: Default OS limits on half-open connections are easily overwhelmed.

Mitigation: SYN cookies, rate limiting, and cloud-based scrubbing (e.g., AWS Shield/Azure DDoS Protection).

## TCP Injection (In-Path adversaries)

Pattern: Attackers inject malicious packets (e.g., data segments with malicious payloads) into live TCP streams.

Example: In 2023, a nation-state actor hijacked BGP routes to inject TCP RSTs into VPN traffic (similar to the 2004 "NISCC TCP RST Attack" but modernized).

Why It Works: Weak TCP sequence number randomness or BGP hijacking enables in-path insertion.

Mitigation: Encryption (TLS), TCP-AO (Authentication Option), and BGP security (RPKI).

## TCP Middlebox exploits (Policing Evasion)

Pattern: Abuse of middlebox TCP optimizations (e.g., QoS prioritization) to evade rate limits.

Example: In 2022, attackers used TCP option fields (e.g., MP-TCP) to bypass traffic-shaping policies.

Why It Works: Middleboxes often prioritize certain TCP flags/options inconsistently.

Mitigation: Strict traffic normalization and deep packet inspection (DPI).

## Low-Rate TCP attacks (Partial DoS)

Pattern: Slowloris-like attacks sending periodic TCP segments to keep connections alive without completing handshakes.

Example: In 2024, API endpoints were targeted with low-rate TCP probes to evade traditional DDoS thresholds.

Why It Works: Traditional volumetric DDoS defences miss slow, persistent attacks.

Mitigation: AI-based anomaly detection and per-IP connection limits.

## Trends and takeaways

* Shift to Application-Layer: Attacks increasingly blend TCP flaws with HTTP/HTTPS exploits (e.g., Slowloris + HTTP/2 Zero-Length Headers).
* Cloud Targeting: Attacks focus on cloud infra (AWS, Azure) where auto-scaling can amplify costs.
* Protocol Abuse: Exploiting middleboxes and RFC non-compliance is now common.
* Defence Evasion: Attackers use low-and-slow techniques to bypass traditional rate-limiting.

## Defence recommendations

* For Networks: Deploy RFC-compliant middleboxes, enable TCP-AO, and use BGP monitoring.
* For Servers: Tune kernel TCP stack (e.g., net.ipv4.tcp_syncookies, tcp_max_syn_backlog).
* For Cloud: Leverage scalable DDoS protection (e.g., AWS Shield Advanced, Cloudflare Magic Transit).

## Thoughts

These patterns highlight the need for adaptive defences combining protocol hardening, behavioural analysis, and encryption. 

## Emerging threats

1. TCP Fast Open (TFO) Exploits: DDoS amplification & session hijacking via SYN-data injection; Example: Mirai botnets abusing TFO for 3x reflection attacks.
2. QUIC-over-TCP Bypass Attacks: Firewall evasion/data exfiltration via HTTP/3 fallback to TCP; Example: APT29 hiding C2 traffic in QUIC-TCP downgrades.
3. TCP Side-Channel Leaks: Encryption bypass via timing/padding oracles (e.g., inferring VPN activity); Example: Tor de-anonymization using TCP timestamp analysis.
4. TCP-AO Key Compromise: Session hijacking via weak key generation or replay attacks; Example: Chinese hackers exploiting Cisco TCP-AO bugs.
5. NAT Slipstreaming 2.0: Firewall bypass using TCP option manipulation (MSS/SACK); Example: IoT botnets piercing NATs to deploy ransomware.
6. Post-Quantum Harvesting: Adversaries storing encrypted TCP streams for future quantum decryption; Example: Nation-states hoarding VPN/SSH sessions.
7. Multipath TCP (MPTCP) Zero-Days: Subflow hijacking or CPU exhaustion via MPTCP reassembly; Example: iOS DoS (CVE-2024-23222).
8. RPKI/TCP-AO Downgrade Attacks: Forcing fallback to insecure TCP-MD5 or unsigned BGP; Example: Russian ISPs downgrading EU telecoms.
9. TCP Stack Fingerprinting: OS/device identification via ISN (Initial Sequence Number) patterns; Example: Targeted attacks against unpatched IoT devices.
10. Low-Rate TCP DoS (Partial Connection Starvation): Slow-drip attacks exhausting server resources (e.g., partial SYN floods); Example: Cloud API outages from "shrew" attacks.

## Emerging defence

* Shift to Memory-Safe Stacks: Reducing RCE risks (for example, Rust in Linux networking).
* Encryption Everywhere: QUIC and TCP-AO to prevent injection/hijacking.
* AI vs. AI Arms Race: Defenders use ML to detect adversarial TCP flows.
* Cloud-Native Protections: eBPF and Kubernetes policies for granular control.

