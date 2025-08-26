# Attack tree (IPv4 and IPv6)

```text
1. Compromise Internet Protocol (IP) [OR]

    1.1 Initial Access [OR]
    
        1.1.1 Phishing & Social Engineering [OR]
        
            1.1.1.1 Spear Phishing (PDF/Excel malware)
            1.1.1.2 Business Email Compromise (BEC) with deepfake audio/video
            1.1.1.3 LinkedIn/Twitter impersonation for credential theft
            
        1.1.2 Exploiting Cloud Misconfigurations [OR]
        
            1.1.2.1 Exposed S3 buckets (AWS) or Azure Blob Storage
            1.1.2.2 Misconfigured GitHub/GitLab repos (API keys, credentials)
            1.1.2.3 Publicly exposed Kubernetes API servers
            
        1.1.3 Supply Chain Attacks [OR]
        
            1.1.3.1 Dependency confusion (malicious npm/PyPi packages)
            1.1.3.2 Compromised SaaS vendors (SolarWinds-style attacks)
            1.1.3.3 Compromised software update mechanisms
            
    1.2 Lateral Movement & Privilege Escalation [OR]
    
        1.2.1 Exploiting Zero-Day Vulnerabilities [OR]
        
            1.2.1.1 RCE in enterprise VPNs (Pulse Secure, Citrix CVE-2023-3519)
            1.2.1.2 Windows/Linux privilege escalation (Dirty Pipe, Log4Shell)
            1.2.1.3 Exploiting IPv6 NDP or SLAAC flaws
            
        1.2.2 Cloud Identity Attacks [OR]
        
            1.2.2.1 OAuth token hijacking (Microsoft/Azure AD)
            1.2.2.2 Shadow API abuse (undocumented cloud APIs)
            1.2.2.3 Privileged role assignment abuse
            
    1.3 Data Exfiltration [OR]
    
        1.3.1 Encrypted Exfiltration [OR]
        
            1.3.1.1 DNS tunneling (DoH/DoT for stealth)
            1.3.1.2 Legitimate cloud services (Dropbox, Google Drive, Slack)
            1.3.1.3 ICMPv6 or IPv6 Extension Header Tunneling
            
        1.3.2 Insider Threats [OR]
        
            1.3.2.1 Rogue employees using USB exfiltration (Rubber Ducky)
            1.3.2.2 Compromised contractors with excessive access
            1.3.2.3 Abusing approved data transfer tools
            
    1.4 Persistence & Evasion [OR]
    
        1.4.1 Fileless Malware [OR]
        
            1.4.1.1 PowerShell/Cobalt Strike in-memory execution
            1.4.1.2 Linux rootkits (Symbiote, 2022)
            1.4.1.3 Abusing legitimate admin tools (LOLBins)
            
        1.4.2 Cloud Backdoors [OR]
        
            1.4.2.1 Malicious Lambda functions (AWS)
            1.4.2.2 Hidden service accounts in Google Workspace
            1.4.2.3 Persistent VNC/RDP via cloud instances
            
    1.5 Counter-Forensics [OR]
    
        1.5.1 Log Manipulation [OR]
        
            1.5.1.1 SIEM poisoning (injecting fake logs)
            1.5.1.2 Deleting AWS CloudTrail or Azure Activity Logs
            1.5.1.3 Using cloud API keys with excessive permissions
            
        1.5.2 AI-Assisted Evasion [OR]
        
            1.5.2.1 AI-generated fake traffic (mimicking normal behaviour)
            1.5.2.2 Deepfake video calls to bypass MFA
            1.5.2.3 AI-powered password spraying attacks
            
2. Protocol-Specific Attacks [OR]

    2.1 IPv4-Specific Attacks [OR]
    
        2.1.1 IP Fragmentation Attacks [OR]
        
            2.1.1.1 Teardrop attacks causing kernel panics
            2.1.1.2 Overlapping fragment firewall evasion
            
        2.1.2 ICMP Abuse [OR]
        
            2.1.2.1 Smurf attacks (amplification via broadcast)
            2.1.2.2 ICMP tunneling for data exfiltration
            
        2.1.3 ARP Spoofing/Poisoning [OR]
        
            2.1.3.1 Gratuitous ARP for Man-in-the-Middle
            2.1.3.2 ARP cache poisoning for DoS
            
        2.1.4 NAT Abuse [OR]
        
            2.1.4.1 NAT state table exhaustion attacks
            2.1.4.2 NAT traversal techniques for unauthorized access
            
    2.2 IPv6-Specific Attacks [OR]
    
        2.2.1 SLAAC & RA Attacks [OR]
        
            2.2.1.1 Rogue Router Advertisements (MitM)
            2.2.1.2 RA flooding for DoS
            
        2.2.2 NDP Exploitation [OR]
        
            2.2.2.1 Neighbor Advertisement spoofing
            2.2.2.2 Duplicate Address Detection (DAD) DoS
                    
        2.2.3 Extension Header Abuse [OR]
            
            2.2.3.1 Firewall evasion using Hop-by-Hop options
            2.2.3.2 Resource exhaustion via complex header chains
            2.2.3.3 Covert channel via Traffic Class / Flow Label (exfiltrate information in unused header fields)
      
        2.2.4 Dual-Stack Attacks [OR]
        
            2.2.4.1 Bypassing IPv4 security via unmonitored IPv6
            2.2.4.2 Tunneling IPv4 over IPv6 for evasion
            
    2.3 Protocol-Agnostic Attacks [OR]
    
        2.3.1 IP Spoofing & DDoS Amplification [OR]
        
            2.3.1.1 DNS/NTP reflection attacks
            2.3.1.2 TCP middlebox amplification (SYN-ACK)
            
        2.3.2 BGP Hijacking & Route Leaks [OR]
        
            2.3.2.1 Prefix hijacking for traffic interception
            2.3.2.2 Route leaks causing traffic blackholes
            
        2.3.3 TTL Expiry Attacks [OR]
        
            2.3.3.1 ICMP Time Exceeded flooding
            2.3.3.2 TTL-based resource exhaustion
            
        2.3.4 Geolocation Spoofing [OR]
        
            2.3.4.1 Proxy/VPN evasion of geo-blocks
            2.3.4.2 ASN spoofing for trust exploitation
```

## Risk table

| Attack Path                                             | Technical Complexity | Resources Required | Risk Level | Notes                                                                                         |
|---------------------------------------------------------|----------------------|--------------------|------------|-----------------------------------------------------------------------------------------------|
| 1.1.1.1 Spear Phishing (PDF/Excel malware)              | Medium               | Low                | Medium     | Requires some social engineering skills; low cost but can bypass antivirus if well-crafted.   |
| 1.1.1.2 BEC with deepfake audio/video                   | High                 | Medium             | High       | AI tools needed for realistic deepfakes; targeted attacks on executives.                      |
| 1.1.1.3 LinkedIn/Twitter impersonation                  | Medium               | Low                | Medium     | Relatively simple, relies on human error; can harvest credentials for further attacks.        |
| 1.1.2.1 Exposed S3/Azure buckets                        | Low                  | Low                | Medium     | Exploitable if public misconfigurations exist; low effort but impact varies.                  |
| 1.1.2.2 Misconfigured GitHub/GitLab repos               | Medium               | Low                | Medium     | Requires reconnaissance and some automation; easy to detect if logging exists.                |
| 1.1.2.3 Publicly exposed Kubernetes API servers         | High                 | Medium             | High       | Needs knowledge of Kubernetes; can lead to cluster compromise.                                |
| 1.1.3.1 Dependency confusion                            | High                 | Medium             | High       | Requires control over package repos; can scale to multiple victims.                           |
| 1.1.3.2 Compromised SaaS vendors                        | High                 | High               | High       | Complex supply chain attack; hard to execute but high payoff.                                 |
| 1.1.3.3 Compromised software update mechanisms          | Very High            | High               | Very High  | Extremely difficult, but can compromise all users of software.                                |
| 1.2.1.1 RCE in enterprise VPNs                          | Very High            | Medium             | High       | Exploiting zero-days requires research; potentially devastating.                              |
| 1.2.1.2 Windows/Linux privilege escalation              | High                 | Low                | High       | Commonly automated; requires some OS-level knowledge.                                         |
| 1.2.1.3 Exploiting IPv6 NDP/SLAAC flaws                 | High                 | Medium             | High       | Requires IPv6-enabled networks; less common but impactful.                                    |
| 1.2.2.1 OAuth token hijacking                           | High                 | Medium             | High       | Needs phishing or token capture; cloud credentials can grant full access.                     |
| 1.2.2.2 Shadow API abuse                                | Very High            | High               | Very High  | Undocumented APIs are tricky to discover; potential for serious cloud compromise.             |
| 1.2.2.3 Privileged role assignment abuse                | Medium               | Medium             | Medium     | Relies on misconfigured permissions; often simple to escalate privileges if misconfig exists. |
| 1.3.1.1 DNS tunneling (DoH/DoT)                         | Medium               | Low                | Medium     | Can bypass network monitoring; low resource cost.                                             |
| 1.3.1.2 Legitimate cloud services exfiltration          | Low                  | Low                | Medium     | Easy to blend in; detection depends on monitoring.                                            |
| 1.3.1.3 ICMPv6/IPv6 extension header tunneling          | High                 | Medium             | High       | Requires advanced networking knowledge; stealthy.                                             |
| 1.3.2.1 Rogue employees using USB                       | Low                  | Low                | Medium     | Hard to prevent; physical controls required.                                                  |
| 1.3.2.2 Compromised contractors                         | Medium               | Medium             | Medium     | Insider risk; depends on trust model.                                                         |
| 1.3.2.3 Abusing approved data transfer tools            | Medium               | Low                | Medium     | Often overlooked; requires user credentials.                                                  |
| 1.4.1.1 PowerShell/Cobalt Strike in-memory execution    | High                 | Medium             | High       | Requires endpoint access; evades most AV.                                                     |
| 1.4.1.2 Linux rootkits (Symbiote)                       | Very High            | Medium             | High       | Hard to detect/remove; requires admin access.                                                 |
| 1.4.1.3 Abusing admin tools (LOLBins)                   | Medium               | Low                | Medium     | Simple but effective; depends on monitoring.                                                  |
| 1.4.2.1 Malicious Lambda functions                      | High                 | Medium             | High       | Cloud-specific persistence; needs developer access.                                           |
| 1.4.2.2 Hidden service accounts in Google Workspace     | Medium               | Low                | Medium     | Persistent access; easy to hide without monitoring.                                           |
| 1.4.2.3 Persistent VNC/RDP via cloud instances          | Medium               | Medium             | Medium     | Maintains access; requires cloud resources.                                                   |
| 1.5.1.1 SIEM poisoning                                  | High                 | Medium             | High       | Manipulates logs; requires access to logging infrastructure.                                  |
| 1.5.1.2 Deleting CloudTrail/Activity Logs               | Medium               | Medium             | Medium     | Simple if permissions exist; detection risk high.                                             |
| 1.5.1.3 Using cloud API keys with excessive permissions | Medium               | Low                | Medium     | Opportunistic; can lead to privilege abuse.                                                   |
| 1.5.2.1 AI-generated fake traffic                       | Very High            | Medium             | High       | Needs AI modelling; evades anomaly detection.                                                 |
| 1.5.2.2 Deepfake video calls to bypass MFA              | Very High            | High               | Very High  | Sophisticated attack; requires real-time AI.                                                  |
| 1.5.2.3 AI-powered password spraying                    | Medium               | Medium             | Medium     | Automates common attacks; detection depends on rate limits.                                   |
| 2.1.1.1 Teardrop attacks                                | Medium               | Low                | Medium     | Classic DoS; mitigated on modern OSes.                                                        |
| 2.1.1.2 Overlapping fragment firewall evasion           | High                 | Medium             | High       | Needs careful crafting; firewall-specific.                                                    |
| 2.1.2.1 Smurf attacks                                   | Low                  | Medium             | Medium     | Low complexity, needs broadcast network.                                                      |
| 2.1.2.2 ICMP tunneling                                  | Medium               | Medium             | Medium     | For data exfiltration; requires stealth.                                                      |
| 2.1.3.1 Gratuitous ARP (MitM)                           | Medium               | Low                | Medium     | Effective on LANs; physical access often required.                                            |
| 2.1.3.2 ARP cache poisoning (DoS)                       | Low                  | Low                | Low        | Limited scope; easily detectable.                                                             |
| 2.1.4.1 NAT table exhaustion                            | Medium               | Medium             | Medium     | Targets network devices; resource-limited.                                                    |
| 2.1.4.2 NAT traversal for unauthorized access           | Medium               | Medium             | Medium     | Exploits existing NAT behaviour; technical knowledge required.                                |
| 2.2.1.1 Rogue RA (MitM)                                 | High                 | Medium             | High       | Requires IPv6 knowledge; can intercept traffic.                                               |
| 2.2.1.2 RA flooding for DoS                             | Medium               | Medium             | Medium     | Localised impact; network resources needed.                                                   |
| 2.2.2.1 Neighbor Advertisement spoofing                 | High                 | Medium             | High       | Network-level attack; stealth varies.                                                         |
| 2.2.2.2 DAD DoS                                         | Medium               | Medium             | Medium     | Can disrupt IPv6 address assignment; requires network access.                                 |
| 2.2.3.1 Hop-by-Hop firewall evasion                     | High                 | Medium             | High       | Sophisticated; requires deep packet crafting.                                                 |
| 2.2.3.2 Complex header resource exhaustion              | High                 | Medium             | High       | Can cause device/network failure; technical expertise needed.                                 |
| 2.2.4.1 Bypassing IPv4 security via unmonitored IPv6    | Medium               | Medium             | Medium     | Exploits misconfiguration; easier in dual-stack networks.                                     |
| 2.2.4.2 Tunneling IPv4 over IPv6                        | Medium               | Medium             | Medium     | Requires network skill; detection depends on monitoring.                                      |
| 2.3.1.1 DNS/NTP reflection attacks                      | Medium               | Medium             | Medium     | Classic DDoS; amplification multiplies effect.                                                |
| 2.3.1.2 TCP middlebox amplification                     | High                 | Medium             | High       | Needs specific network targets; effective but targeted.                                       |
| 2.3.2.1 BGP prefix hijacking                            | Very High            | High               | Very High  | Requires access to routing infrastructure; high impact.                                       |
| 2.3.2.2 Route leaks causing blackholes                  | High                 | Medium             | High       | Misconfig-driven; limited but disruptive.                                                     |
| 2.3.3.1 ICMP Time Exceeded flooding                     | Medium               | Medium             | Medium     | Can congest network; limited to TTL expiry.                                                   |
| 2.3.3.2 TTL-based resource exhaustion                   | Medium               | Medium             | Medium     | Needs high packet rates; detectable.                                                          |
| 2.3.4.1 Proxy/VPN geo evasion                           | Low                  | Low                | Low        | Simple; mainly circumvents restrictions.                                                      |
| 2.3.4.2 ASN spoofing                                    | High                 | Medium             | High       | Requires BGP knowledge; trickier than geo-spoofing.                                           |

