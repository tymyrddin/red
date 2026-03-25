# Runbook: Network reconnaissance

## Objective

Build a complete map of the target network: live hosts, open services, OS fingerprints, domain structure, and trust relationships. Passive before active; external before internal.

## Phase 1: Passive external enumeration

Query BGP routing tables for the target organisation's ASN and announced prefixes:

```bash
# Look up ASN by organisation name
whois -h whois.radb.net -- '-i origin AS12345'
# Or use the RIPE database
curl 'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS12345'
```

Enumerate subdomains from certificate transparency logs:

```bash
subfinder -d target.com -silent -o subdomains.txt
# Or query crt.sh directly
curl -s 'https://crt.sh/?q=%25.target.com&output=json' | jq -r '.[].name_value' | sort -u
```

Check Shodan for all IPs in the announced prefix range:

```bash
shodan search 'net:203.0.113.0/24' --fields ip_str,port,org,hostname
```

## Phase 2: Active external scanning

Confirm live hosts before port scanning:

```bash
nmap -sn 203.0.113.0/24 -oG - | grep Up | awk '{print $2}' > live-hosts.txt
```

Port scan live hosts:

```bash
nmap -sS -sV -sC -T3 -p- --open -iL live-hosts.txt -oA external-scan
```

Enumerate DNS:

```bash
# Zone transfer attempt
dig axfr @ns1.target.com target.com

# Subdomain brute-force
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r 8.8.8.8
```

## Phase 3: Internal host discovery

From a foothold inside the network:

```bash
# ARP scan of local segment
arp-scan -I eth0 --localnet

# NetBIOS discovery
nbtscan 192.168.1.0/24

# Ping sweep of target range
nmap -sn 192.168.0.0/16 -oG - | grep Up | awk '{print $2}' > internal-hosts.txt
```

## Phase 4: Service enumeration

For each live host, enumerate key services:

```bash
# SMB enumeration
nmap -p 445 --script smb-security-mode,smb2-security-mode,smb-enum-shares -iL internal-hosts.txt

# SNMP enumeration
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt -i internal-hosts.txt
snmpwalk -v2c -c public <target-ip> 1.3.6.1.2.1.1

# LDAP enumeration (unauthenticated)
ldapsearch -x -H ldap://<DC-IP> -b "" -s base namingContexts
```

## Phase 5: Domain enumeration (with credentials)

With any domain user credentials:

```bash
# Dump domain info
ldapdomaindump -u 'domain\user' -p password <DC-IP>

# Collect BloodHound data
bloodhound-python -u user -p password -d domain.local -ns <DC-IP> -c All

# Enumerate SPNs for Kerberoasting
GetUserSPNs.py domain/user:password -dc-ip <DC-IP>

# Check for AS-REP roastable accounts
GetNPUsers.py domain/ -usersfile users.txt -format hashcat -no-pass -dc-ip <DC-IP>
```

## Evidence collection

For each phase, record:

- All live hosts with IP and hostname mappings.
- Open ports and service banners for each host.
- Domain name, domain controllers, and naming context.
- Any unauthenticated access to services or shares.
- SPNs found and any hashes obtained.
