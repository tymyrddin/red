# Diving deeper in discovery

1. Identify live networks between source and already identified subnets
    * Traceroute to the gateway or DNS server for each network 
    * Add newly identified networks to the list of subnets
2. Discover the IP addresses of servers behind a DNS 
3. Discover how long a server has been up 
4. Where is a server's physical location 
5. ...

## Under the hood

Traceroutes work by manipulating the Time-To-Live (TTL) field in an IP packet. This field tells a device a packet is passing through how many more systems (or hops) a packet can pass through before being dropped. This is to ensure that lost packets do not just simply hop around the Internet forever and eventually, with enough lost packets clogs it up. The field is decremented as it passes through each network hop. When it reaches zero, a router will drop the packet being sent through it and send an ICMP Time-To-Live exceeded message back to the source.

This can be used to determine the route to a host or network, the time it takes for a message to be sent and a response to be received by using a traceroute, which service provider the target is using
There is an ICMP traceroute (tracert.exe, Windows) and a UDP traceroute (traceroute -l, all other OSs).
       
* ICMP traceroute expects all intermediary routers to respond with an ICMP TTL Exceeded message. Most do not (RFC 792)
* UDP traceroute is not so great where filtering is in place. 
* Most Unix traceroute implementations now support TCP static port traceroutes out of the box.

## Mapping out DMZ and internal networks

Because all traceroutes work using ICMP TTL Exceeded messages, which protocol is used is not important as long as there 
is a known response. Use a TCP traceroute with a `SYN` flag set, and commonly open ports such as 25, 80 or 443 for which 
you can get a reliable response back once the target is reached. 

## Uptime

Each time a server is patched or updated, it must also be rebooted. If a server has been up for a long time, we know it 
has not been patched or updated in that time, and that it will be vulnerable to all vulnerabilities discovered during 
that timeframe.

## Examples

Traceroute in `nmap` with Geo resolving:
```text
nmap --traceroute --script traceroute-geolocation.nse -p 80 [ip_or_hostname]
```

The default packet which `hping3` will create is a TCP packet:

```text
# hping3 -T -V --tr-stop -S -p 80 [ip_or_hostname]
```

Specify the source and destination ports of the packet to help it bypass the firewall. Send three packets out (`-c`) to 
destination port 53 (`-p`) and set the SYN flag in the packet, so it looks like the first phase of the three-way 
handshake (`-S`):

```text
hping3 -c 3 -p 53 -S [ip_or_hostname]
```

Traceroute in `hping3` using a TCP scan to a specific destination port:

```text
# hping3 --traceroute --verbose --syn --destport [80] [ip_or_hostname]
```

Discover the IP addresses of servers behind a DNS:

```text
# hping3 [big site hostname] -S -p 80 -T –ttl 13 –tr-keep-ttl -n
```

Uptime of a server:
```text
# hping3 [ip_or_hostname] -p 80 –tcp-timestamp -S -c 4
```

