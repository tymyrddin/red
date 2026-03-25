# Active Directory and domain trust attacks

Active Directory is the identity and authorisation infrastructure for the vast majority of enterprise Windows environments. It controls authentication, policy, resource access, and group membership across every domain-joined system. Compromising domain-level identity infrastructure is therefore not one step in a chain but the end state that converts a foothold into persistent, organisation-wide access. AD attacks have become the dominant technique for converting initial access into complete domain compromise because the attack surface is large, the tooling is mature, and many defensive controls remain misconfigured or absent.

## The identity graph

BloodHound models Active Directory as a graph where nodes are users, computers, groups, and organisational units, and edges are the relationships between them: membership, delegation, ACE permissions, session presence, and trust paths. The value of BloodHound is that it makes visible attack paths that are individually innocuous but collectively lead from a low-privileged user to domain admin.

Collecting BloodHound data requires domain credentials but not elevated privileges. The SharpHound collector, run as any authenticated domain user, queries LDAP for group memberships, ACEs, and GPO links, and queries the domain controllers for session and local admin information.

```bash
# From a domain-joined Windows host
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -ZipFileName loot.zip

# From Linux with Impacket
bloodhound-python -u user -p password -d domain.local -ns <DC-IP> -c All
```

## Kerberoasting

Service accounts in Active Directory are identified by Service Principal Names. Any authenticated domain user can request a Kerberos service ticket for any SPN. The ticket is encrypted with the service account's NTLM hash. Kerberoasting extracts these tickets and submits them to offline cracking.

Service accounts with SPNs and weak passwords are extremely common in legacy AD environments. They frequently have elevated privileges because they need them for the services they run, and their passwords are often not rotated because rotation requires updating the service configuration. A Kerberoastable account that is a member of Domain Admins, Backup Operators, or any other sensitive group can translate directly into domain compromise if the password falls to a dictionary attack.

```bash
# Impacket
GetUserSPNs.py domain/user:password -request -outputfile hashes.txt

# Crack the hashes
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
```

## AS-REP roasting

If a domain account has Kerberos pre-authentication disabled, the domain controller will return an AS-REP encrypted with the account's password hash to any unauthenticated requestor who knows the username. This AS-REP material can be cracked offline without ever authenticating to the domain.

The `DONT_REQ_PREAUTH` flag should never be set on administrative accounts, but it appears on service accounts and legacy accounts in many environments.

```bash
GetNPUsers.py domain/ -usersfile users.txt -format hashcat -no-pass
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

## Pass-the-hash and pass-the-ticket

Once NTLM hashes are obtained from any source, whether from SAM dumps, LSASS dumps via Mimikatz, or from captured NTLMv2 hashes that have been cracked, they can be used directly for authentication without knowing the plaintext password. NTLM authentication accepts the hash itself as the authentication credential; the protocol challenge-response only requires possession of the hash.

```bash
# Pass-the-hash with Impacket
smbexec.py -hashes :<NTLM-hash> domain/administrator@target
psexec.py -hashes :<NTLM-hash> domain/administrator@target
```

Kerberos tickets, once obtained from memory with Mimikatz or Rubeus, can be imported into the current session and used for authentication as the ticket's owner. A TGT extracted from LSASS memory provides the same access as the user's credentials for the duration of the ticket's validity.

## Domain escalation paths

The ACE-based privilege model in Active Directory means that many domain objects have extended rights that translate into credential recovery or privilege escalation. ForceChangePassword on a user account allows password reset without knowing the current password. GenericAll or GenericWrite on a computer object allows resource-based constrained delegation abuse. WriteOwner or WriteDACL on a group allows modification of its membership.

These paths are nearly invisible without BloodHound analysis and are the main reason that graph-based enumeration has replaced manual enumeration for AD assessments. The attacker's objective is not to find a single vulnerability but to traverse the identity graph from their current node to a node with the target level of access.

## Lateral movement through trust

Domain trusts extend authentication across forest boundaries. A user in a trusted domain can be granted access to resources in the trusting domain. The Golden Ticket attack, which requires the krbtgt hash, allows creation of forged Kerberos tickets with arbitrary group membership, including membership in groups from trusted forests. The attack chain from single DC compromise to cross-forest privilege escalation depends on the trust configuration and the group memberships present in each forest's PAC validation logic.
