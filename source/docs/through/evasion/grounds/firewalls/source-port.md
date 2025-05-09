# Evasion via controlling the source MAC/IP/Port

When scanning a host behind a firewall, the firewall will usually detect and block port scans. This situation would 
require adaptation of network and port scan to evade the firewall. A network scanner like Nmap provides features to 
help with such a task:

* Evasion via controlling the source MAC/IP/Port
* Evasion via fragmentation, MTU, and data length
* Evasion through modifying header fields

Nmap allows for hiding or spoofing the source with:

* Decoy(s)
* Proxy
* Spoofed MAC Address
* Spoofed Source IP Address
* Fixed Source Port Number

## Decoy(s)

Using decoys mixes the source IP address with other "decoy" IP addresses, making it difficult for the firewall and 
target host to know where the port scan is coming from. This can exhaust the blue team investigating each source 
IP address.

To add decoy source IP addresses use the `-D` option to confuse the target:

    nmap -sS -Pn -D 10.10.10.1,10.10.10.2,ME -F MACHINE_IP

To set Nmap to use random source IP addresses instead of explicitly specifying them: 

    nmap -sS -Pn -D RND,RND,ME -F MACHINE_IP

## Proxy

Relaying the port scan via a proxy helps keep a source IP address unknown to the target host. This technique allows 
for keeping an IP address hidden while the target logs to the IP address of the proxy server. 

To send all packets via a specified proxy server:

    nmap -sS -Pn --proxies PROXY_URL -F MACHINE_IP

Note that you can chain proxies using a comma-separated list.

## Spoofed MAC address

Nmap allows for spoofing MAC addresses using the option `--spoof-mac MAC_ADDRESS`. This technique is tricky; spoofing 
the MAC address works only if the attacking host is on the same network segment as the target host. The target system 
is going to reply to a spoofed MAC address. If not on the same network segment, sharing the same Ethernet, it
would not be possible to capture and read the responses. 

It allows for exploiting any trust relationship based on MAC addresses. This technique can be used to hide scanning 
activities on the network. For example, by making scans appear as if coming from a network printer.

## Spoofed IP address

Nmap allows for spoofing IP addresses using `-S IP_ADDRESS`. Spoofing the IP address is useful if the attacking system 
is on the same subnetwork as the target host; otherwise, the replies sent back can not be read. 
Another use for spoofing IP address is when controlling the system that has that particular IP address. If noticing 
the target starts to block the spoofed IP address, switch to a different spoofed IP address that belongs to another 
controlled system. 

This scanning technique can help maintain a stealthy existence and with exploiting trust 
relationships on the network based on IP addresses.

## Fixed Source Port Number

Scanning from one particular source port number can be helpful when discovering the firewalls allows incoming packets 
from particular source port numbers, such as port 53 or 80. Without inspecting the packet contents, packets from 
source TCP port 80 or 443 look like packets from a web server, while packets from UDP port 53 look like responses 
to DNS queries. Set a port number using `-g` or `--source-port` options.

## Resources

* [OUI Lookup Tool](https://rst.im/oui/00:02:DC)
