# Playbook: Network entry and lateral movement chain

This playbook connects the network runbooks into an operational sequence. It covers the full chain from passive external reconnaissance through to domain-level compromise, with decision points that reflect the most common network configurations encountered in enterprise targets.

## Objective

Obtain a persistent foothold inside the target network and progress to domain-level access, using the network as both the entry path and the lateral movement medium.

## Prerequisites

- Scope definition covering IP ranges, domains, and permitted techniques.
- Rules of engagement confirmation for active techniques including deauthentication frames, ARP poisoning, and Kerberos ticket requests.
- Attacker infrastructure: a C2 server with a valid domain and TLS certificate, DNS authoritative access for a subdomain, and a Cobalt Strike, Sliver, or Havoc listener configured with a clean profile.

## Passive surface mapping

Spend at least an hour on passive sources before sending any packets to the target. BGP routing tables reveal the full announced prefix range. Certificate transparency logs yield subdomain inventory. Shodan and Censys provide service banners for all Internet-facing hosts in the identified ranges.

Record the technology stack for every externally accessible service. VPN concentrators, email gateways, web application firewalls, and remote access portals are the highest-priority targets because they authenticate against the internal directory service and are reachable from outside.

## External access path selection

The most common external entry paths, in order of reliability:

Exposed VPN or remote access portals that authenticate against Active Directory are susceptible to password spraying. Even a single set of valid credentials provides authenticated access to the internal network. The threshold for lockout varies; spraying a single password across all discovered usernames with a four-hour gap between rounds avoids most lockout policies.

Externally accessible web applications may be in scope and may run on servers that are domain-joined. A web application compromise that yields command execution provides a beachhead on a domain-joined host.

Wireless access from the car park or building perimeter provides Layer 2 access without touching the Internet-facing perimeter at all.

## Internal foothold establishment

From the first internal host, deploy a C2 agent using the HTTPS channel as the primary beacon and DNS as the fallback. The agent should beacon with jitter of 20 to 50 percent at a base interval appropriate to the engagement's operational tempo.

Immediately assess the foothold host's domain membership, local admin rights, logged-in users, and network connectivity. Check LSASS for cached credentials and tickets before the session ages out.

## Name resolution poisoning

With access to an internal Windows network segment, start Responder with SMB and HTTP disabled, and ntlmrelayx targeting unsigned SMB hosts. LLMNR and NBT-NS poisoning in an active Windows environment yields hashes within minutes; relay delivers SAM dumps or command execution on hosts where the captured user has local admin.

This phase produces either cracked domain credentials or a second foothold on a higher-value host.

## Domain enumeration and path planning

With any domain credentials, collect BloodHound data. Upload the collection to BloodHound and run the built-in queries: Shortest Path to Domain Admins, All Kerberoastable Users, Principals with DCSync Rights, and Users with Foreign Domain Group Membership.

These queries identify the specific attack paths available from the current position. The next phase depends entirely on what BloodHound reveals.

## Privilege escalation within the domain

The most common paths from a low-privileged domain user to domain admin:

Kerberoasting recovers service account passwords through offline cracking. Any service account that is a member of a privileged group or has administrative access to a domain controller provides direct escalation.

ACE-based privilege chains, visible in BloodHound, allow privilege escalation through a sequence of individually limited operations: password reset, group membership modification, or constrained delegation abuse.

DCSync rights on any account allow replication of the entire NTDS.dit, recovering all domain password hashes. Accounts with DCSync rights appear in BloodHound under the `GetChangesAll` edge.

## Domain compromise and persistence

Once domain admin or equivalent access is obtained:

```bash
# Dump all domain hashes via DCSync
secretsdump.py -just-dc domain/admin@<DC-IP>
```

The krbtgt hash allows creation of Golden Tickets, which remain valid for the lifetime of the krbtgt account even if all user passwords are changed. Golden Ticket access persists through password resets.

## Evidence collection

For each phase, capture the specific commands executed, responses received, and credentials or access obtained. The final evidence package should demonstrate the complete path from the initial passive reconnaissance observation to domain admin, with each step documented as reproducible.

## Runbooks

- [Network reconnaissance](../runbooks/network-recon.md)
- [Wireless attacks](../runbooks/wireless.md)
- [Layer 2 attacks](../runbooks/layer2.md)
- [Name resolution attacks](../runbooks/name-resolution.md)
- [C2 and tunnelling](../runbooks/c2-tunneling.md)
- [Lateral movement](../runbooks/lateral-movement.md)
