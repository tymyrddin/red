# Detecting network attacks

Network attack detection requires visibility at multiple layers: packet-level data from network taps or span ports, flow data from routers and switches, authentication logs from directory services, and DNS query logs from resolvers. No single source is sufficient because the attacks span multiple protocol layers.

## ARP anomaly detection

Gratuitous ARP replies that change a known IP-to-MAC mapping should generate alerts. The detection logic is straightforward: maintain a table of IP-to-MAC mappings observed via DHCP snooping or ARP inspection, and alert when an ARP reply contradicts the known mapping without a preceding DHCP lease event.

Signs of active ARP poisoning:

- ARP replies from a host that did not send the corresponding ARP request.
- The same MAC address claiming multiple IP addresses on the same segment.
- High volume of ARP replies from a single source.

## LLMNR and NBT-NS poisoning detection

Detecting Responder activity requires monitoring LLMNR and NBT-NS query responses. A host that responds to LLMNR queries for names that do not belong to it is behaving anomalously. The baseline for comparison is which hosts legitimately respond to name resolution on each segment.

Alert when:

- A host responds to an LLMNR or NBT-NS query for a name that is not its own hostname.
- Multiple different hosts respond to the same LLMNR query.
- A new host begins responding to name resolution queries without a corresponding new DHCP lease.

## Authentication anomaly detection

NTLM relay attacks generate authentication events at relay targets that do not correspond to interactive logon activity from the victim. Correlating successful SMB authentication events with LLMNR and NBT-NS query activity on the same segment identifies relay chains.

Kerberoasting generates a spike in TGS-REQ requests with RC4 encryption type (etype 23) from a single source. Modern Kerberos clients prefer AES encryption; a sudden increase in RC4 ticket requests, particularly for multiple different service accounts within a short window, is a strong indicator.

AS-REP roasting generates AS-REQ requests without pre-authentication. These are visible in Kerberos event logs (Event ID 4768 with pre-authentication type 0).

```
Event ID 4769 (TGS request): filter for Ticket Encryption Type = 0x17 (RC4)
  Alert on: >5 requests with RC4 encryption within 10 minutes from single source
Event ID 4768 (AS request): filter for Pre-Authentication Type = 0
  Alert on: any occurrence for non-service accounts
```

## DNS anomaly detection

C2 tunnelling over DNS generates characteristic patterns:

- High query rate to a single authoritative domain from a single source.
- Long subdomain labels (DNS tunnelling encodes data in subdomain names; legitimate subdomains are short).
- High entropy in queried subdomain names.
- Consistent query intervals with jitter (automated beaconing).
- TXT or NULL record queries (used by some DNS tunnelling tools).

Baseline DNS query volumes per host and alert on deviations. The ratio of unique domain labels queried per host per hour is a useful metric: legitimate browsing generates queries across many domains; DNS tunnelling concentrates queries to one or a few domains.

## Network scanning detection

Internal host discovery and port scanning generate connection patterns that are rare in normal traffic: a single source attempting connections to dozens of hosts across many ports within a short window. Firewall and flow logs with connection state tracking identify scanners through their ratio of SYN packets to established connections.

Alert on:

- A host generating TCP SYN packets to more than 20 distinct destinations within 60 seconds.
- A host generating TCP SYN packets to the same destination on more than 10 distinct ports within 30 seconds.
- ICMP echo requests to more than 50 hosts within 60 seconds.

## Lateral movement detection

Pass-the-hash and pass-the-ticket movement leaves authentication logs at both source and destination. Characteristics that distinguish lateral movement from normal administrative access:

- Successful authentication using NTLMv2 or Kerberos to a host that the user does not normally access.
- Administrative access to a host at a time or from a source outside the user's normal pattern.
- New service installations or scheduled tasks created by non-standard accounts.
- LSASS access events from processes that are not credential managers (Event ID 10 in Sysmon: process access to LSASS).

The most reliable lateral movement detection correlates authentication success events with the network path: if a user authenticates to a server but no interactive session exists on the workstation attributed to that user at the time, the authentication is likely automated or relayed.
