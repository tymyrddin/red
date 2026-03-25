# IP-level attacks

The Internet Protocol operates at Layer 3, routing datagrams between networks based on destination address. The fundamental design of IP prioritises scalability and interoperability over authentication: a packet's source address is declared by the sender with no cryptographic verification, and routing decisions are based on prefix reachability information that any network can announce. These design choices, reasonable for a research network in the 1970s, have consequences for security that remain relevant today.

## IP address spoofing

IP spoofing means sending packets with a source address other than the true origin. It is used most effectively in attack scenarios where the attacker does not need to receive the response, because replies will be routed to the spoofed address rather than to the attacker.

Amplification attacks exploit this: the attacker sends a small request with a spoofed source set to the victim's address to a service that returns a large response. The service sends its large response to the victim. DNS, NTP, Memcached, and SSDP have all been used as amplifiers. Amplification factors of 10x to 50,000x have been demonstrated, converting modest bandwidth into massive floods directed at the victim.

Spoofing a source address from within the target network is harder to do remotely, because most ISPs implement BCP 38 egress filtering, dropping packets with source addresses that do not belong to the originating network. However, BCP 38 is not universally deployed, particularly at smaller ISPs and within organisational networks, and any position inside the target network eliminates the need to spoof across provider boundaries.

## Reflection and amplification

A reflection attack routes attack traffic through third parties, obscuring the attacker's address and multiplying the traffic volume. The amplification factor depends on the ratio of response size to request size for the chosen protocol. UDP-based protocols are preferred because they do not require a handshake, allowing spoofed requests to be sent without establishing a connection.

The impact of amplification attacks is primarily denial-of-service against the victim. In some scenarios, sustained amplification can also serve as a cover operation: a defender dealing with a volumetric DDoS is less likely to notice concurrent activity against other targets or within the network.

## Routing as an attack surface

The Border Gateway Protocol determines which path traffic takes between autonomous systems. BGP is based on trust between neighbouring peers, and the announcements a router accepts from its peers are applied to its routing table without cryptographic verification in most deployments. BGP route hijacking occurs when an autonomous system announces a more specific or equivalent prefix that it does not legitimately originate, causing traffic for that prefix to be routed to the attacker's network instead of the destination.

BGP hijacking has been used for traffic interception, SSL certificate validation abuse, and cryptocurrency theft. The attacker can inspect traffic that routes through their network, modify it, or selectively forward it to the legitimate destination after inspection. The feasibility of a BGP hijack depends on whether the target prefix's legitimate origin has a more specific or equivalent announcement; Route Origin Authorisation records published in the RPKI system allow receivers to reject announcements from unauthorised ASes, but RPKI adoption is still incomplete.

## ICMP-based attacks

ICMP carries control messages for IP, including echo requests and replies (ping), destination unreachable, time exceeded, and redirect messages. ICMP redirect messages instruct a host to update its routing table to use a different gateway for a destination. These are legitimate network management messages but can be injected by an attacker on the local segment to redirect traffic through a controlled host.

ICMP tunnelling encodes data in the payload of ICMP echo requests and replies. Because ICMP is frequently permitted through firewalls that block TCP and UDP, it provides a covert channel that can be used for data exfiltration or command-and-control. Detection requires inspecting ICMP payload sizes and patterns; a stream of large-payload ICMP echo requests to a single destination is anomalous.
