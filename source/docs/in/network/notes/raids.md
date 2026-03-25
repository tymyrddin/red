# Transport layer attacks

TCP provides the reliable, ordered, connection-oriented transport that most application protocols depend on. Its reliability mechanisms, the sequence number space, the acknowledgement window, and the connection state machine, are the same properties that create attack surfaces. An attacker who can observe or predict the state of a TCP connection can inject data, terminate the session, or replay captured packets.

## TCP sequence prediction and session hijacking

Every TCP connection uses a 32-bit sequence number to order segments. The initial sequence number (ISN) is supposed to be unpredictable; early TCP implementations used sequential ISNs, and the first practical TCP hijacking attacks exploited this predictability. Current operating systems use cryptographically random ISNs, but the attack surface shifts to connections where the attacker can observe traffic.

On a network segment where traffic is visible, an attacker can inject a TCP segment into an existing session by using the correct sequence number. If the victim is communicating over an unencrypted protocol such as Telnet or early versions of rsh/rlogin, injected commands will be executed by the session. The attacker must also prevent the legitimate client from receiving the server's responses to the injected commands, which typically requires ARP poisoning or otherwise desynchronising the client's TCP state.

## TCP reset injection

TCP RST injection terminates an existing connection. A correctly sequenced RST segment causes the receiving TCP stack to abort the connection. Applications may or may not retry, and the visibility of the termination depends on whether the application exposes connection-level errors to the user.

RST injection is used by some network middleboxes as a policy enforcement mechanism, and has been used for censorship of specific protocols or destinations. From an attacker's perspective, RST injection can be used to force reconnection (which may trigger credential re-exchange in a position suitable for capture), to terminate monitoring connections, or to disrupt services.

## BGP hijacking and traffic interception

BGP session hijacking targets the BGP peering session itself rather than the routing table. BGP peers communicate over TCP port 179 using MD5 authentication in most deployments. An attacker who can inject a TCP RST into the BGP session tears down the peering relationship and causes a route flap. More ambitiously, an attacker able to predict or observe the sequence numbers of a BGP TCP session can inject BGP UPDATE messages, injecting or withdrawing routes.

This is distinct from BGP route hijacking (covered in the IP-level notes), which exploits the routing protocol's trust model by participating as a legitimate peer. TCP-level BGP attacks require proximity or existing man-in-the-middle positioning on the path between two BGP peers.

## Protocol tunnelling and C2 over network protocols

Living-off-the-land networking uses legitimate network protocols as communication channels. DNS, ICMP, and HTTP/HTTPS are permitted across most network boundaries and monitored with less granularity than proprietary or unusual protocols. Tunnelling C2 traffic inside these protocols allows communication through firewalls that would block direct connections.

DNS tunnelling encodes data in subdomain queries. A host with a foothold inside the network queries `<base64-data>.c2.attacker.com`, which resolves to the attacker's authoritative DNS server. The server extracts the data from the query label and responds with encoded data in the DNS answer. Tools like `iodine` and `dnscat2` implement this; detection relies on anomaly detection against query rate, query length distributions, and the entropy of queried hostnames.

ICMP tunnelling and HTTP/HTTPS C2 follow the same logic. The key property they share is that the carrier protocol is generally trusted and permitted, so the security control problem shifts from blocking the protocol to distinguishing legitimate use from tunnelling. For TLS-encrypted C2 over HTTPS, certificate inspection and SNI analysis are the primary detection mechanisms available without breaking the encryption.
