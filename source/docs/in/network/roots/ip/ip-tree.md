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