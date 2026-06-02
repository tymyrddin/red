# Internet Protocol version 4 (IPv4)

## Advantages of IPv4

- Universality: supported by every network device and application globally.
- Simplicity: mature and well-understood, with extensive troubleshooting tools.
- NAT (Network Address Translation): conserves public addresses and adds a layer of privacy.
- Broadcast Support: built-in mechanism for network-wide announcements.

## Writing IPv4 addresses

- Dotted-Decimal Notation: four 8-bit octets separated by dots (e.g., `192.168.1.1`).
- CIDR Notation: always include prefix length (e.g., `192.168.1.0/24`).
- Private Address Ranges:
  - `10.0.0.0/8`
  - `172.16.0.0/12`
  - `192.168.0.0/16`
- Avoid Leading Zeros: write `192.168.1.1`, not `192.168.001.001`.

## IPv4 address types and scopes

| Type      | Range                 | Scope             | Use Case                                         |
|-----------|-----------------------|-------------------|--------------------------------------------------|
| Public    | Except private ranges | Global (internet) | Routable on the internet.                        |
| Private   | `10.0.0.0/8`          | Site-local        | Internal networks, NATed for internet.           |
|           | `172.16.0.0/12`       |                   |                                                  |
|           | `192.168.0.0/16`      |                   |                                                  |
| APIPA     | `169.254.0.0/16`      | Link-local        | Auto-configured when DHCP fails.                 |
| Loopback  | `127.0.0.0/8`         | Node-local        | Localhost (typically `127.0.0.1`).               |
| Broadcast | Subnet-specific       | Subnet-local      | Send to all hosts on the subnet.                 |
| Multicast | `224.0.0.0/4`         | Defined by TTL    | Group communication (e.g., `224.0.0.9` for RIP). |

## Calculating IPv4 subnets

- Subnetting borrows bits from the host portion to create subnets.
- Formula: Number of subnets = `2^(borrowed_bits)`
- Hosts per subnet = `2^(remaining_host_bits) - 2` (subtract network and broadcast).
- Example: subnet `192.168.1.0/24` into four `/26` subnets:
  - Borrowed bits: `26 - 24 = 2` → `2^2 = 4` subnets.
  - Subnets: `192.168.1.0/26`, `.64/26`, `.128/26`, `.192/26`.
  - Hosts per subnet: `2^(6) - 2 = 62`.

## Key IPv4-related protocols

- ARP (Address Resolution Protocol): maps IP addresses to MAC addresses.
- DHCP (Dynamic Host Configuration): assigns IP addresses and configs to hosts.
- ICMP (Internet Control Message Protocol): error reporting and diagnostics (e.g., `ping`).
- NAT (Network Address Translation): translates private IPs to public IPs.
- DNS (Domain Name System): resolves domain names to IP addresses.

## Characteristics and security concerns

- Characteristics:
  - Uses broadcast for network-wide communication.
  - Relies on NAT for address conservation.
  - Header includes checksum for error detection.
- Security Concerns:
  - NAT Limitations: breaks end-to-end connectivity, complicating applications like VoIP.
  - ARP Spoofing: attackers poison ARP tables to intercept traffic.
  - Broadcast Storms: misconfigurations can lead to network congestion.
  - Address Exhaustion: limited address space (4.3 billion addresses) has been depleted.
  - Fragmentation Attacks: maliciously crafted packets can evade security controls.

## IPv4 transition mechanisms to IPv6

- Dual Stack: devices run both IPv4 and IPv6 simultaneously.
- Tunnelling: encapsulate IPv6 in IPv4 packets (e.g., 6to4, Teredo).
- Translation: convert IPv4 to IPv6 (e.g., NAT64 with DNS64).
- Proxying: use a proxy to mediate between IPv4 and IPv6 hosts.

## Quick Reference

- /24: common subnet mask for small networks (254 hosts).
- /30: typical for point-to-point links (2 hosts).
- Private Ranges: use `10.0.0.0/8` for large networks, `192.168.0.0/16` for home networks.
- NAT: essential for connecting private networks to the internet.

## Counter moves

Internet Protocol version 4 (IPv4) is the variant in play. Segmentation, egress filtering, and flow baselining are the durable answers. Seen from the other side, this sits in the blue notes on [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
