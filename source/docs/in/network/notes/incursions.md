# Internet incursions

Hacking the heart of the Internet.

## IP spoofing

In an IP spoofing attack an external or internal adversary pretends to be using a trusted device by using the address of that device. This can be either an IP address within a range of trusted internal addresses for a network or an authorised external address that is trusted and allowed access to specified network resources. Spoofing an address might enable data to be sent through a router interface with filtering based on that address.

IP address spoofing can be used to mask botnet device locations in DDoS attacks and to stage DrDoS attacks, and IP spoofing can also be used to bypass IP address-based authentication.

1. Non-blind spoofing attack by gaining local network access to a segment and sniffing sequence numbers
2. Blind spoofing attack which require calculating sequence numbers.

## Denial of Service (DoS)

The two most devastating variations of Denial of Service attacks are the distributed denial of service (DDoS) and the distributed deflection denial of service (DrDoS). Both types enlist the assistance of others, voluntary or not, to assist in the attack. This significantly increases the size of the attack, shields the source, and makes defending from it harder.

```text
1 Physical destruction of machine (OR)
2 Link layer attacks (OR)
    2.1 Protocol attack using link layer protocol (OR)
    2.2 Physical link attack
3 ARP attacks (OR)
4 IP attacks (OR)
    4.1 ICMP Message (OR)
        4.1.1 Ping O' Death: Send one or more oversized ping packets (larger than 65,536 bytes) (OR)
        4.1.2 Malformed
    4.2 IP Fragmentation Attack
5 UDP attacks (OR)
6 TCP attacks (OR)
    6.1 TCP SYN Flood: Trick target into thinking a session is being established by creating half-open connections (OR)
    6.2 Connect() (OR)
    6.3 LAST_ACK (OR)
    6.4 New/undiscovered DoS against TCP
7 Application-Layer DoS (OR)
    7.1 Telnet (OR)
    7.2 SSH (OR)
    7.3 SNMP (OR)
    7.4 HTTP (OR)
        7.4.1 HTTP Flood (OR)
        7.4.2 Long form field submission through POST method (OR)
        7.4.3 Partial requests (OR)
        7.4.4 Junk HTTP GET and POST requests
    7.5 Other application layer protocol
```

## Distributed Denial of Service (DDoS)

A DoS is distributed from only one starting point, whereas a DDoS implies several computers or servers. Amplification is dependent on the amount of zombies in the botnet used. In UDP spoofing the IP address of the packet (where it comes from) is replaced by the IP address of the target. The answers to the sent packets will thus come back to the target, and not to the attacker. Amplification is dependent on the number of zombies in the botnet and the used protocol (attack vector). Everything that works on UDP presents a good amplification factor and allows spoofing are prime candidates, such as game servers, timeservers (NTP) or Domain Name Servers.

```text
1 UDP (User Datagram Protocol) spoofing
2 Create zombies
    2.1 Voluntary “botnet”
    2.2 Create a botnet
3 Launch DoS vector
    3.1 UDP Flood (OR)
    3.2 TCP SYN Flood (OR)
    3.3 ICMP echo request Flood (OR)
    3.4 ICMP directed broadcast (like smurf)
    3.5 NTP Flood
    3.6 Another UDP based protocol whose answers are longer than the questions
```

## Distributed Deflection Denial of Service (DrDoS)

In a DrDoS attack, the requests meant for a target are sent using systems earlier compromised.

```text
1 IP spoofing of machines and servers (AND)
2 Attack
    2.1 Call a large number of servers (DNS, NTP, Game servers) using a legitimate UDP request (amplification coefficient of between 20 and 50) (OR)
    2.2 Call a large number of servers using a TCP SYN request (amplification coefficient of 10)
```

## On-path attack (alias MitM)

A Man-in-the-Middle (MitM) attack is a general term for when an adversary positions herself in the middle of a conversation (usually between a user and an application on the application or cryptograhic layer). A MitM attack allow an adversary to proxy communication between two parties allowing any data to either be read or altered. For example to eavesdrop or to steal personal information such as login credentials, account details, tokens and credit card numbers. This information can then further be used for unapproved fund transfers, password changes, impersonation, complete identity theft and for gaining a foothold during the infiltration stage of a structured hack.

The adversary first subverts the address infrastructure (intercepts traffic). In passive interception forms, an adversary makes, for example, an infected Wi-Fi hotspot available to the public. Active forms use some sort of spoofing. After subverting the address infrastructure, any two-way encrypted traffic needs to be decrypted. This can be done by, for example, SSL spoofing(does not attack SSL itself, but the transition from non-encrypted to encrypted communications), spoofing HTTPS, an SSL BEAST attack, or hijacking SSL. Session replay and hijacking attacks can be used to bypass authentication. If a root certificate can be installed on the target, the adversary can replace it and maintain a secure connection.
 
NetBIOS is outdated but still lives on in some older systems, sometimes for backward compatability. It is the equivalent of broadcasting names to look for each other but is not routable. It is local network only. If no one on the other network can use it for your network, then no one there can access your NetBIOS shared folders and printers, unless one has gained access to your local network. You can also access NetBIOS machines with a WINS server. That is the NetBIOS equivalent of a DNS server.

```text
1 Subvert address infrastructure (AND)
    1.1 L2 Spoofing 
        1.1.1 ARP/MAC spoofing (OR)
        1.1.2 VLAN hopping (OR)
        1.1.3 STP (RSTP, PVSTP, MSTP) spoofing 
    1.2 L3 Spoofing 
        1.2.1 SLAAC attack (OR)
        1.2.2 Hijacking HSRP (VRRP, CARP) (OR)
        1.2.3 Hijacking BGP (OR)
        1.2.4 Routing table poisoning (OR)
        1.2.5 Redirecting ICMP 
    1.3 L4+ Spoofing
        1.3.1 NetBIOS (LLMNR) spoofing (OR)
        1.3.2 DHCP spoofing (OR)
        1.3.3 Rogue Access Point (OR)
        1.3.4 IP spoofing (OR)
        1.3.5 DNS spoofing 
2 Decrypt (AND)
    2.2 SSL BEAST (OR)
    2.3 Hijack SSL (OR)
    2.4 Strip SSL
3 Do whatever 
```



