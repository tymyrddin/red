# Packet manipulation

Sniffing, analysing and inspecting packets, and forging and decoding packets.

An `nmap` port scan may show a host as down or all of the ports as `filtered`. Analysing and inspecting packets over the network can help provide some insight as to what is going on with the connection attempts.

## PCAP files

Packet Capture or PCAP (also known as libpcap) is an application programming interface (API) that captures live network packet data from OSI model Layers 2-7. Network analysers like [Wireshark](https://nta.tymyrddin.dev/docs/wireshark/readme) create `.pcap` files to collect and record packet data from a network. 

1. Capture packets  with tcpdump or Wireshark
2. Analyse packets (packet tracing)

## Example

```text
# tcpdump -i <interface> -w <file-name>
# wireshark <filename>
```

## Sniffing

Depending on the network topology, there are many ways of gaining read-access to a network to conduct passive attacks. The most common method compromises a general purpose operating system on the segment and installs sniffer software that puts a network interface card in promiscuous mode and captures traffic. ARP/MAC spoofing may be necessary to sniff traffic on switched networks.

1. Get into a good spot and gain local network access to a segment, tap a physical medium, or redirect traffic through a compromised host    
2. Sniff information (if possible, email traffic, FTP passwords, Web traffic, Telnet passwords, Router configuration, Chat sessions, DNS traffic)

## Forging and decoding packets

Scapy is a Python program that can assist with packet manipulation by forging and decoding packets. Scapy supports 
many use cases.

## Resources

* [The Art of Packet Crafting with Scapy!](https://0xbharath.github.io/art-of-packet-crafting-with-scapy/index.html)

