# Runbook: OT reconnaissance

## Objective

Build a picture of the OT environment without generating traffic that could disrupt process control. Passive enumeration first; active scanning only where explicitly permitted and against non-critical segments.

## Prerequisites

- Explicit written confirmation that OT recon is in scope.
- Confirmation of which segments can be actively scanned and at what timing and rate.
- A designated safe-to-scan OT segment, separate from live production control systems, if active scanning is required.

## Phase 1: Passive external discovery

Before touching the OT network:

```bash
# Shodan: find exposed OT devices on the organisation's IP ranges
shodan search 'org:"Target" port:502'       # Modbus
shodan search 'org:"Target" port:44818'     # EtherNet/IP
shodan search 'org:"Target" port:47808'     # BACnet
shodan search 'org:"Target" port:102'       # Siemens S7
shodan search 'org:"Target" port:4840'      # OPC UA

# Censys: similar coverage, different indexing
censys search 'ip:"203.0.113.0/24" and protocols.102'

# Certificate transparency: find OT-adjacent hostnames
subfinder -d target.com -silent | grep -i 'scada\|hist\|hmi\|ics\|control\|plc'
```

Note every exposed OT device: IP, port, product banner, and vendor. Each is a direct attack surface if credentials are weak or authentication is absent.

## Phase 2: Passive capture on accessible OT segment

From a foothold in the IT/OT boundary:

```bash
# Passive capture of OT protocol traffic (no packets sent)
tcpdump -i eth0 -n 'port 502 or port 20000 or port 44818 or port 47808 or port 102 or port 4840' \
  -w ot-passive.pcap -s 0

# Identify communication pairs and protocols
tshark -r ot-passive.pcap -T fields -e ip.src -e ip.dst -e tcp.dstport -e udp.dstport \
  | sort | uniq -c | sort -rn
```

From the capture, extract:
- Which hosts communicate on OT protocol ports (SCADA masters, PLCs, RTUs, historians).
- The register addresses that are polled and the values observed.
- The timing and frequency of polling cycles.
- Any write operations and the values written.

## Phase 3: OPC UA and historian enumeration

OPC UA servers expose a browse interface that returns the full tag database without requiring writes:

```bash
# Using opcua-client-cli or python-opcua
pip install opcua
python3 -c "
from opcua import Client
c = Client('opc.tcp://<historian-ip>:4840')
c.connect()
root = c.get_root_node()
print(root.get_children())
"
```

For OSIsoft PI historian:

```bash
# PI Web API (if exposed)
curl -k -u 'domain\user:password' \
  'https://<historian>:443/piwebapi/assetservers'

# PI OLEDB provider: enumerate tags via SQL
# SELECT * FROM PIPoint WHERE Tag LIKE '%flow%'
```

## Phase 4: Asset mapping

Build a table of all discovered assets:

| IP | Hostname | Protocol | Vendor/Model | Firmware | Notes |
|---|---|---|---|---|---|
| 10.20.1.10 | plc-west-01 | EtherNet/IP | Rockwell 1756-L85E | v34 | Writable tags |
| 10.20.1.20 | hist-01 | OPC UA | AVEVA PI | 3.4.390 | No auth |

This inventory drives every subsequent decision about targeting, protocol selection, and the scope of the demonstration.
