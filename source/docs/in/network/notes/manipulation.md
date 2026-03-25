# Traffic analysis and packet crafting

Understanding what traverses a network is foundational to attacking it. Traffic analysis reveals protocol behaviour, authentication exchanges, and timing patterns that are invisible from a host-level perspective. Packet crafting goes the other direction: it allows an attacker to construct arbitrary frames and datagrams, test protocol edge cases, and inject data into live sessions.

## Passive capture

Placing a capture interface on a network segment in promiscuous mode records everything the network card sees. On shared media this includes all traffic on the segment; on switched networks it captures broadcast and multicast traffic plus traffic addressed to the local interface. ARP cache poisoning or a rogue spanning tree root bridge position can extend this to unicast traffic between other hosts.

Wireshark and tcpdump are the standard capture tools. Wireshark's display filter language allows real-time filtering by protocol, address, and content. For capture files that need scripted processing, `tshark` exposes the same dissection engine from the command line.

```bash
tcpdump -i eth0 -w capture.pcap -s 0 'not port 22'
tshark -r capture.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
```

Even in environments where application traffic is encrypted, metadata remains. Source and destination addresses, timing patterns, packet sizes, and connection durations can identify protocol types, user behaviour, and sometimes authentication exchanges. TLS ClientHello messages expose the SNI field in plaintext, revealing the hostname being contacted even when the session content is encrypted.

## Packet crafting with Scapy

Scapy is a Python library and interactive shell for constructing packets at any layer, sending them, and analysing responses. It treats each protocol layer as a composable object:

```python
from scapy.all import *

# Craft an ICMP echo request
pkt = IP(dst="192.168.1.1")/ICMP()
response = sr1(pkt, timeout=2)
response.show()

# Craft a TCP SYN with a specific sequence number
pkt = IP(dst="192.168.1.1")/TCP(dport=80, flags="S", seq=1000)
response = sr1(pkt, timeout=2)
```

This composability is useful for testing protocol implementations, probing firewall rules by crafting packets that should or should not be permitted, and injecting crafted frames into a network segment.

## Network-level fingerprinting

Operating systems implement TCP/IP stacks differently. Initial TTL values, TCP window sizes, options fields, and the order of TCP options in a SYN packet form a fingerprint that identifies the OS with reasonable confidence even without any application-layer interaction. Tools such as `p0f` perform this analysis passively against captured traffic; nmap's OS detection (`-O`) performs it actively.

Protocol timing behaviour is also distinctive. The interval between a TCP SYN and the first data packet, the retransmission timing, and the window scaling negotiation all contribute to fingerprints that can distinguish device types on a segment without sending a single application request.

## Traffic as intelligence

PCAP files from network captures are operational intelligence when they contain authentication exchanges. NTLM challenge-response hashes captured from SMB or HTTP authentication can be submitted to hashcat for offline cracking. Kerberos AS-REQ and TGS-REQ packets contain ticket material that similarly yields to offline attack. NTLMv2 hashes captured through LLMNR or NBT-NS poisoning follow the same path.

Traffic analysis identifies which hosts communicate with which others, which protocols are in use, and which services are actively being accessed. That picture guides subsequent attack decisions about where to position further access and what trust relationships exist across the network.
