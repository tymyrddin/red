# Network Layer Protocol (IPv4 or IPv6)

BGP runs over IP (Internet Protocol). It can operate over both IPv4 (traditional BGP) and IPv6 (MP-BGP for 
multiprotocol support).

## Attack tree: Compromise Internet Protocol (IP)

```text
1. Initial Access [OR]

    1.1 Phishing & Social Engineering [OR]
    
        1.1.1 Spear Phishing (PDF/Excel malware)
        
        1.1.2 Business Email Compromise (BEC) with deepfake audio/video
        
        1.1.3 LinkedIn/Twitter impersonation for credential theft
        
    1.2 Exploiting Cloud Misconfigurations [OR]
    
        1.2.1 Exposed S3 buckets (AWS) or Azure Blob Storage
        
        1.2.2 Misconfigured GitHub/GitLab repos (API keys, credentials)
        
    1.3 Supply Chain Attacks [OR]
    
        1.3.1 Dependency confusion (malicious npm/PyPi packages) (2021)
        
        1.3.2 Compromised SaaS vendors (SolarWinds-style attacks)

2. Lateral Movement & Privilege Escalation [AND]

    2.1 Exploiting Zero-Day Vulnerabilities [OR]
    
        2.1.1 RCE in enterprise VPNs (Pulse Secure, Citrix CVE-2023-3519)
        
        2.1.2 Windows/Linux privilege escalation (Dirty Pipe, Log4Shell)
        
    2.2 Cloud Identity Attacks [OR]
    
        2.2.1 OAuth token hijacking (Microsoft/Azure AD)
        
        2.2.2 Shadow API abuse (undocumented cloud APIs)

3. Data Exfiltration [AND]

    3.1 Encrypted Exfiltration [OR]
    
        3.1.1 DNS tunneling (DoH/DoT for stealth)
        
        3.1.2 Legitimate cloud services (Dropbox, Google Drive, Slack)
        
    3.2 Insider Threats [OR]
    
        3.2.1 Rogue employees using USB exfiltration (Rubber Ducky attacks)
        
        3.2.2 Compromised contractors with excessive access

4. Persistence & Evasion [OR]

    4.1 Fileless Malware [OR]
    
        4.1.1 PowerShell/Cobalt Strike in-memory execution
        
        4.1.2 Linux rootkits (Symbiote, 2022)
        
    4.2 Cloud Backdoors [AND]
    
        4.2.1 Malicious Lambda functions (AWS)
        
        4.2.2 Hidden service accounts in Google Workspace

5. Counter-Forensics [OR]

    5.1 Log Manipulation [OR]
    
        5.1.1 SIEM poisoning (fake logs)
        
        5.1.2 Deleting AWS CloudTrail logs
        
    5.2 AI-Assisted Evasion [AND]
    
        5.2.1 AI-generated fake traffic (mimicking normal behaviour)
        
        5.2.2 Deepfake video calls to bypass MFA (2023+)
```

## IP spoofing & DDoS amplification

Attack Pattern: Attackers forge source IP addresses to launch reflection/amplification attacks (e.g., using UDP-based protocols like DNS, NTP, or even TCP middlebox abuse).

Example (2022): The "APT28 TCP Amplification DDoS" abused misconfigured firewalls and load balancers to reflect SYN-ACK packets, generating multi-Tbps attacks against Ukrainian and Western targets.

Why It Works: Many networks still allow source IP spoofing due to weak BCP38 (anti-spoofing) enforcement.

Mitigation

* Network-level filtering (BCP38/84) to block spoofed packets.
* Cloud-based DDoS scrubbing (AWS Shield, Cloudflare Magic Transit).

## BGP hijacking & route leaks

Attack Pattern: Attackers manipulate BGP routing to redirect traffic through malicious networks for interception or DoS.

Examples:

* 2021: Russian ISP "DDoS-Guard" hijacked Western financial traffic.
* 2023: A Chinese state-linked group rerouted US military traffic through China Telecom.

Why It Works: BGP lacks cryptographic authentication, making route manipulation easy.

Mitigation

* RPKI (Resource Public Key Infrastructure) for route origin validation.
* BGP monitoring (e.g., Cloudflare Radar, BGPMon).

## IP fragmentation attacks (Teardrop, Ping of Death Revisited)

Attack Pattern: Exploiting fragmentation reassembly flaws in network stacks to crash systems.

Example (2023): A variant of Ping of Death resurfaced in IoT devices, causing kernel panics in Linux-based systems.

Why It Works: Some devices still mishandle overlapping fragments or malformed packets.

Mitigation

* Patch systems (e.g., Linux net.ipv4.ipfrag_high_thresh tuning).
* Stateful firewalls to drop malicious fragments.

## ICMP ause (Smurf, flooding, covert channels)

Attack Pattern

* ICMP floods (e.g., Smurf attacks) or ICMP tunneling for data exfiltration.
* Example (2022): A Russian APT group used ICMP tunnels to bypass network monitoring in a cyber-espionage campaign.

Why It Works: Many networks allow unrestricted ICMP for diagnostics.

Mitigation

* Rate-limiting ICMP at network edges.
* Deep Packet Inspection (DPI) to detect tunneling.

## IPv6 exploitation (Flooding, SLAAC attacks)

Attack Pattern

* IPv6 DDoS: Attackers abuse large IPv6 neighbor discovery (ND) packets to overwhelm routers.
* SLAAC Attacks: Spoofing IPv6 router advertisements (RAs) to hijack traffic.

Example (2023): A Mirai-variant botnet launched IPv6-based floods against ISPs.

Why It Works: Many networks lack IPv6 security controls.

Mitigation

* RA Guard to block rogue IPv6 advertisements.
* IPv6-specific DDoS protections (e.g., AWS Shield Advanced).

## TTL expiry attacks (Resource exhaustion)

Attack Pattern: Attackers send packets with low TTL values, forcing routers to generate ICMP Time Exceeded messages, overwhelming infrastructure.

Example (2024): A cryptocurrency exchange was hit by a TTL-based attack, disrupting API services.

Why It Works: Many networks don’t rate-limit ICMP responses.

Mitigation

* Rate-limiting ICMP Time Exceeded messages.
* Filtering packets with TTL=1 at the edge.

## Geolocation spoofing (Evasion & Censorship bypass)

Attack Pattern: Attackers fake IP geolocation to bypass geo-blocks or evade detection.

Example (2023): A ransomware group used cloud proxies to mask origins as legitimate US IPs.

Why It Works: Many geo-IP databases are outdated.

Mitigation

* Strict ASN-based filtering (e.g., only allow traffic from known cloud providers).
* Behavioral analysis (unusual traffic patterns from "legit" IPs).

## Trends & takeaways

* BGP Hijacking Remains Critical: State-sponsored groups abuse BGP for espionage.
* IPv6 Attacks Rising: As adoption grows, so do IPv6-specific exploits.
* Cloud & IoT Are Prime Targets: Attackers exploit weak default configurations.
* Low-TTL & ICMP Attacks Resurging: Old tricks are being modernized.

## Defence recommendations

For Networks:

* Deploy RPKI + BGP monitoring.
* Enforce strict anti-spoofing (BCP38).
* Rate-limit ICMP & TTL expiry packets.

For Enterprises:

* Use DDoS-protected cloud services.
* Patch IP stack vulnerabilities (e.g., Linux kernel updates).

For Governments/Critical Infra: Mandate BGP security (MANRS compliance).

## Emerging tech

* Confidential Computing (for example Intel SGX, Azure Confidential VMs) to protect IP in use.
* Post-Quantum Cryptography Prep (NIST’s CRYSTALS-Kyber for future-proofing).

