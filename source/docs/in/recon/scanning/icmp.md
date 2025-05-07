# Host discovery with ICMP

The easiest and fastest way to discover if a host is up or not is by trying to send some ICMP packets.

Send an echo request using a simple `ping` or `fping` (for ranges). If pinging a single host works, try a ping-sweep: Send out ICMP echo requests to every system on a particular network 
or subset of a network to determine which hosts are up.

ICMP error messages can be used to mask the source of a Distributed Denial of Service attack, and with such attacks 
being common, ICMP error rate limiting is often applied. To avoid filters to common ICMP echo request-response, use 
`nmap` to send other types of ICMP packets. If scans still take incredibly long, try discovering hosts with a 
[SYN scan](tcp.md) or [UDP scan](udp.md) instead.

## Examples

Send a single echo request
```text
# ping -c 1 192.168.122.10
```

Send echo requests to ranges:
```text
# fping -g 192.168.122.0/24
```

Using nmap, send echo, timestamp requests and subnet mask requests:
```text
# nmap -PEPM -sP -n 192.168.122.0/24
```

