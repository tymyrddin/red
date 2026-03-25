# Network surface discovery

Network reconnaissance establishes what exists before anything is touched. The difference between a careful engagement and a noisy one is largely determined here: passive enumeration reveals topology, ownership, and technology choices without generating a single packet to the target, while active scanning confirms what passive sources suggest and fills the gaps.

## Passive enumeration

Autonomous System lookups are the starting point for any external target. BGP routing tables, available through route collectors such as RIPE's RIS and RouteViews, reveal which IP prefixes an organisation announces, which upstream providers it uses, and whether it peers directly at any internet exchange points. This topology is structural context: it identifies which prefixes are in scope, which are hosted externally, and which provider relationships might be exploitable for later routing manipulation.

Certificate transparency logs contain a near-complete record of TLS certificates issued for an organisation's domains. Querying crt.sh or using tools like `subfinder` with passive CT sources produces subdomain lists without any DNS queries to the target. These lists frequently surface internal-facing services, staging environments, API gateways, and VPN endpoints that do not appear in marketing material.

WHOIS and RDAP records link IP ranges to organisations and provide registration dates, abuse contacts, and sometimes internal contact names. Shodan and Censys maintain snapshots of banner information from Internet-facing services, often including software versions, certificate chains, and open port inventories. These snapshots age quickly but provide orientation before any active work.

Job postings and technical documentation often describe the internal network architecture in detail sufficient for planning. Infrastructure vendors, specific hardware models, and internal naming conventions frequently appear in public job descriptions.

## Active scanning

Host discovery should precede port scanning. Sending ICMP echo requests and TCP SYN probes to the gateway addresses for each identified prefix confirms which ranges are live before committing to a full port scan. Many hosts block ICMP but respond to TCP; combining both improves coverage.

Port scanning with nmap against confirmed live hosts should use timing carefully. The default T3 timing is appropriate for most engagements; T4 trades some stealth for speed on low-latency segments. Service version detection (`-sV`) and default script scanning (`-sC`) add significant value for each open port but increase scan duration and detectability.

```bash
nmap -sS -sV -sC -T3 -p- --open -oA network-scan <target-range>
```

Service fingerprinting from the results determines which hosts warrant further attention. Web interfaces on non-standard ports, management protocols such as SNMP and SSH on unusual hosts, and unauthenticated services warrant immediate investigation.

DNS enumeration through zone transfer attempts, brute-force subdomain enumeration, and reverse DNS lookups against identified ranges builds a name-to-address mapping that complements the IP-level picture.

## Internal networks

Inside a network segment, the enumeration changes character. ARP scanning with `netdiscover` or `arp-scan` reveals all hosts on the local segment without generating routable traffic. NetBIOS and LLMNR responses identify Windows hosts before any direct probing.

SMB signing and version enumeration identifies hosts susceptible to relay attacks. LDAP enumeration against any domain controller, even unauthenticated, returns naming context information that confirms the domain name and structure. With any domain credentials, LDAP enumeration with `ldapdomaindump` or BloodHound collection reveals the full identity graph.

The goal of internal recon is not just a host list but a map of trust relationships: which hosts authenticate against which domain controllers, which service accounts have elevated privileges, and which network segments can reach which others. That map is what converts a foothold into a path to the objective.
