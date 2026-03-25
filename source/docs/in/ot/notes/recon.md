# OT surface discovery

OT reconnaissance is different in character from IT reconnaissance. Sending a SYN scan to a PLC is not equivalent to scanning a web server; the consequences of an unexpected packet flood on a process controller can range from disrupted communication to a crashed device. Passive reconnaissance is not just preferable, it is often mandatory.

## Passive external discovery

Shodan indexes Modbus, DNP3, BACnet, and other industrial protocols on Internet-facing addresses. Queries against the organisation's IP ranges and ASN frequently reveal exposed HMI servers, SCADA web interfaces, remote access gateways, and historian databases. Many OT environments were connected to the internet for remote monitoring without the security review that would accompany equivalent IT infrastructure.

```bash
# Shodan queries for common OT protocols
shodan search 'org:"Target Corp" port:502'       # Modbus
shodan search 'org:"Target Corp" port:47808'     # BACnet
shodan search 'org:"Target Corp" port:4840'      # OPC UA
shodan search 'org:"Target Corp" product:Siemens'
shodan search 'org:"Target Corp" product:"GE SCADA"'
```

Certificate transparency logs reveal VPN gateways and remote access portals labelled with OT-indicative hostnames such as `scada.`, `historian.`, `hmi.`, `ics.`, and `control.`. These are frequently separate from the IT estate and less heavily monitored.

Job postings and vendor documentation for OT environments often describe the specific PLC model, SCADA software version, and communication protocols in use. This intelligence is available passively and informs the entire subsequent engagement.

## Network topology inference

OT networks tend to follow the Purdue model with varying degrees of rigour: Level 0 (field devices), Level 1 (PLCs and RTUs), Level 2 (supervisory control and HMI), Level 3 (operations management), and the IT/OT boundary at the DMZ. Understanding which level a foothold sits on determines what can be reached.

From a foothold in the corporate IT network, the OT DMZ is usually reachable and contains historian servers (OSIsoft PI, Aspentech IP.21), remote desktop jump hosts, and sometimes direct connectivity to Level 2 networks. Scanning the 10.x.x.x and 192.168.x.x ranges for hostnames containing `hist`, `scada`, `hmi`, `ics`, or `control` identifies candidate targets.

## Passive protocol identification

Once inside a network segment that carries OT traffic, passive capture identifies protocols without generating any queries:

```bash
# Capture and display OT protocol traffic
tcpdump -i eth0 -n 'port 502 or port 20000 or port 47808 or port 4840' -w ot-capture.pcap

# Parse with Wireshark OT protocol dissectors
# Filter: modbus or dnp3 or bacnet or opcua
```

Modbus TCP (port 502) is unencrypted and carries all register read and write operations in cleartext. A passive capture reveals the SCADA server's IP, the PLC addresses, the specific registers being polled, and the frequency of polling. This inventory of register addresses is operationally significant: it identifies which addresses correspond to which process values, enabling targeted manipulation.

## Asset enumeration inside the OT network

Where active enumeration is permitted in the engagement scope:

```bash
# Nmap with reduced aggression (-T2 or lower) against OT targets
nmap -sV -T2 -p 102,502,2222,4840,20000,44818,47808 <ot-range>
# Port 102 = S7comm (Siemens), 44818 = EtherNet/IP, 2222 = EtherNet/IP

# plcscan for Siemens S7 devices
python plcscan.py <target-ip>
```

Time scans appropriately and confirm with the client that active scanning of OT segments is within scope and acceptable. A default nmap T3 or T4 scan against a process controller should never be run without explicit approval.
