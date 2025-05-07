# Host discovery with UDP

Split port scans by port number

1. Low UDP port scans
2. Remaining UDP port scans

## Relationship with ICMP

UDP is a stateless protocol. It was designed for applications that do not care whether a packet is received. This could 
saturate a link, and ICMP is used in its congestion control. Because UDP is stateless, it is easy to spoof using ICMP error messages to mask the source of a Distributed Denial of 
Service attack, and with such attacks common, UDP scans are considered bad and ICMP error rate limiting good. 
With 65,535 ports to scan and error rate limits of 1 ICMP message per second, it can take 9+ hours to scan some hosts. 

Solutions are scanning multiple hosts in parallel, scanning popular ports first, and ignoring ports that require 
specific protocols and scanning those separately. Older versions of Windows (and some configurations of current Windows systems) do not implement ICMP error rate 
limiting. Knowing beforehand which are Windows systems, these can be put on a separate IP list.

## Not responding

UDP services are highly unlikely to respond to a regular empty UDP probe datagaram because the underlying 
application does not receive a packet that causes it to respond. The solution is to send a packet related to the 
most likely service (based on port number) running under it. For example, brute forcing SNMP on port 161 could be 
worthwhile and sending a correctly formed DNS query datagram to UDP port 53 will likely give a useful response.

## Interpreting portscan outputs

`nmap` will report a lot of closed ports, and some as `open|filtered`. The latter means that `nmap` did not receive a 
response. Use a combination of ICMP and IP to whittle things down:

* An open port will respond to a correctly formed application message if the service is supposed to respond to that message
* A closed port will lead to an ICMP port unreachable from the device (or a similar destination unreachable message from a nearby device)
* A filtered port will occasionally result in a message, but more often than not, nothing
* If a packet’s TTL expires an ICMP TTL Expired In Transit message is sent from the router the datagram is currently passing through to the packet’s source

## Examples

Low UDP port scans:
```text
# nmap -sU -PN -n -iL $TARGETFILE -p 0-1024 -oA nmap/udp-lo -sV
```

Expect to find 53, 111 and 137 open.

Remaining UDP port scans:
```text
# nmap -sU -PN -n -iL $TARGETFILE -p 1025-65535 -oA nmap/udp-full -sV
```

Expect to find Sun RPC services or DCE RPC services, 3rd-party backup utilities, and application services with SAP 
deployments.
