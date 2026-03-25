# Name resolution attacks

Name resolution is the mechanism that converts human-readable names into routable addresses. Every application that makes a network connection starts with a name resolution request, and the trust model for most network communication depends on that resolution returning the correct address. Attacks against name resolution therefore affect the entire protocol stack above, regardless of whether the target application uses TLS, SMB, HTTP, or any other protocol.

## LLMNR and NBT-NS poisoning

Link-Local Multicast Name Resolution and NetBIOS Name Service are fallback resolution mechanisms used by Windows when DNS fails to resolve a name. When a Windows host cannot resolve a name through DNS, it broadcasts an LLMNR or NBT-NS query to the local subnet asking any host that knows the answer to respond. Any host on the segment can respond, and Windows will trust the first response it receives.

Responder listens for these broadcasts and responds to all of them, claiming to be the authoritative host for whatever name was queried. The requesting host then attempts to authenticate to Responder using NTLM, delivering the NTLMv2 challenge-response hash. Responder captures these hashes and writes them to a file.

```bash
responder -I eth0 -rdw
```

The captured NTLMv2 hashes can be cracked offline with hashcat using a dictionary attack:

```bash
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```

The frequency of LLMNR and NBT-NS queries in any Windows environment is high: mistyped hostnames, failed DNS lookups, and service discovery all generate them. Responder typically captures multiple hashes within minutes of being started on an active network segment.

## NTLM relay

Rather than cracking the captured hash, relay attacks forward it to another service in real time. When a victim attempts to authenticate to Responder, Responder simultaneously authenticates to a target service using the victim's credentials. The victim's authentication succeeds, the session with the target service is established, and the attacker has an authenticated session without knowing the password.

ntlmrelayx from Impacket automates this:

```bash
# Disable SMB and HTTP responders so they don't capture but don't relay
responder -I eth0 -rdw --disable-ess

# Relay to a list of targets
ntlmrelayx.py -tf targets.txt -smb2support
```

The most impactful relay targets are machines where the victim has local administrator rights, allowing ntlmrelayx to dump SAM hashes or execute commands. Domain controllers are high-value relay targets when the relayed user is a domain admin. SMB signing, which authenticates every SMB message, prevents relay against hosts where it is enforced; LDAP signing and LDAP channel binding similarly prevent relay to domain controllers for LDAP operations in current configurations.

## DNS attacks

DNS cache poisoning injects forged records into a resolver's cache, causing subsequent queries for a domain to return attacker-controlled addresses. Modern resolvers are substantially more resistant to classic Kaminsky-style poisoning than older implementations, due to source port randomisation and DNSSEC. However, DNSSEC adoption remains incomplete, and many internal DNS servers do not randomise source ports or implement other mitigations.

DNS is also a reliable command-and-control channel. Queries and responses traverse almost every network without inspection, and the high volume of legitimate DNS traffic makes malicious queries difficult to distinguish. DNS tunnelling tools encode data in subdomain labels, transmitting it to an attacker-controlled authoritative server. Detection requires anomaly detection on query volume, query length, and the ratio of unique queried domains per source.

## Multicast DNS and mDNS

mDNS operates similarly to LLMNR but is used primarily by Apple and Linux systems rather than Windows. It queries the multicast address `224.0.0.251` and is used for Bonjour service discovery and `.local` domain resolution. The same class of poisoning attack applies: an attacker can respond to mDNS queries before the legitimate host and redirect connections. Cross-platform environments running both Windows and macOS or Linux present multiple resolution protocols as an attack surface simultaneously.
