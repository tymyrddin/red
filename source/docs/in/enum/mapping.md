# Mapping the lay of the land

Before launching any attack, you need to understand the battlefield. Enumeration is the process of systematically 
probing a network to identify hosts, services, users, and vulnerabilities, like a digital cartographer sketching out 
enemy territory.

1. Network Reconnaissance
    * Scan hosts with Zenmap (Nmap’s GUI) to map the network topology.
    * Identify live systems, open ports, and running services (nmap -sV).
    * Enumerate SMB shares (smbclient -L //target or nmap --script smb-enum-shares).
2. User & Service Discovery
    * Extract user/group lists (e.g., enum4linux for Windows, ldapsearch for AD).
    * Crack weak credentials (Ncrack, Hydra) to escalate access.
    * Dump process lists (if you gain creds, use ps (Linux) or tasklist (Windows)).
3. Web & App Enumeration
    * Spider URLs (Burp Suite, gobuster) to find hidden pages.
    * Scrape social media (recon-ng, Maltego) for user-IP correlations.
    * Check for exposed APIs (Postman, curl).
4. Vulnerability Scanning
    * Run aggressive scans (Nessus, OpenVAS) to flag weak SMTP/SNMP configs, unpatched services, and misconfigurations.
    * Stealthier approaches (for red teams):
        * Slow, randomised scans (nmap -T2 --randomize-hosts).
        * Spoofed/scattered IP sources.
        * Avoid sequential port sweeps.
5. Compliance & Depth Testing
* Test as different users:
    * Anonymous/non-creds: What’s visible to outsiders?
    * Low-privilege creds: Can you pivot?
    * Admin access: Hunt password policies, excessive group rights, and missing patches.
* PCI-DSS rules: Quarterly ASV scans, post-change validation, and critical-fix verification.