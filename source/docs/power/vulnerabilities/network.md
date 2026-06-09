# Network security assessment: Discovering what is listening

*Or: How Ponder Mapped The Attack Surface*

## The Network as It Actually Exists

Network diagrams, Ponder had learnt, were aspirational documents. They showed how networks were meant to be configured, with neat segmentation, carefully labelled VLANs, and firewalls drawn as impenetrable walls. Reality was invariably messier.

The UU P&L simulator represented a simplified but realistic industrial network: multiple PLCs on various ports, a SCADA server providing supervisory control, and no meaningful network segmentation whatsoever. Everything was on localhost, port 127.0.0.1, which meant everything could talk to everything else.

This wasn't a simulator limitation. This was representative of many actual industrial facilities, where "network segmentation" meant different port numbers and the earnest hope that attackers wouldn't notice.

## Reconnaissance: What is actually listening?

The first step in any network assessment is determining what's actually there. Theory and documentation are useful, but port scanning provides truth.

### Port scanning the simulator

```bash
# Basic TCP port scan
nmap -sT 127.0.0.1 -p 1-65535

# Results:
# 502/tcp    open  Modbus TCP (turbine PLC, relays, actuators)
# 2404/tcp   open  IEC-104 (turbine PLC, substation RTU)
# 20000/tcp  open  DNP3 (turbine PLC)
# 4840/tcp   open  OPC UA (turbine sidecar, DMZ gateways)
# 1883/tcp   open  MQTT (broker)
# 161/udp    open  SNMP (turbine PLC)
```

Several ports and protocols across the control estate. Each port represented an attack surface. Each protocol had its own characteristics and vulnerabilities.

### Protocol fingerprinting

Simply knowing ports were open wasn't sufficient. Confirming what protocols were actually running required protocol-specific probing:

IEC-104 (Port 2404):
```bash
# Interrogate the RTU's datapoints with an IEC-104 client (c104)
python iec104_interrogate.py 127.0.0.1
```

Result: Confirmed IEC-104, no authentication, datapoints readable and writable.

Modbus TCP (Port 502):
```bash
# Using nmap's modbus-discover script
nmap -p 10502 --script modbus-discover 127.0.0.1

# Or using testing scripts
python scripts/vulns/modbus_coil_register_snapshot.py
```

Result: Confirmed Modbus TCP, unit IDs 1, 2, and 10, complete read access.

OPC UA (Ports 4840, 4841):
```bash
# Using testing script
python scripts/vulns/opcua_readonly_probe.py
```

Result: Port 4840 allows anonymous access, port 4841 requires certificates.

DNP3 (Port 20000):
```bash
nmap -p 20000 --script dnp3-info 127.0.0.1
```

Result: Confirmed DNP3 on the turbine PLC, no authentication.

## Network architecture discoveries

Testing the simulator revealed several architectural patterns common in industrial networks:

### No authentication at the network layer

None of the protocols required network-level authentication. If you could reach the port, you could interact with the protocol. There were no:
- VPN requirements
- Certificate-based network access
- 802.1X port authentication
- Network admission control

The security model was "physical access to the network provides logical access to everything".

### Multiple protocols per device

Several devices supported multiple protocols simultaneously:
- Turbine PLC: Modbus (502), DNP3 (20000), IEC-104 (2404), and an OPC-UA sidecar (4840)
- Substation RTU: IEC-104 (2404) and a no-auth REST API (8080)

This wasn't redundancy for security. This was integration necessity. Different systems needed different protocols, so devices supported multiple protocols simultaneously. Each protocol was another attack surface.

### Standard ports, in the open

The services sit on their standard ports: Modbus on 502, IEC-104 on 2404, DNP3 on 20000, OPC-UA on 4840. Nothing is
hidden behind a non-standard port, and nothing needs to be. A full port scan finds the whole control estate in
seconds, because there is no authentication waiting behind any of them.

### Everything on localhost

The simulator ran everything on 127.0.0.1, which meant:
- No actual network segmentation
- No firewall rules between services
- Complete connectivity between all components

This represented the worst case: an attacker who had gained access to a system on the OT network could reach everything. In a properly segmented network, the turbine PLC and field devices would be separate from the relay and actuator network, which would be separate from the SCADA server network.

But "properly segmented" networks were rarer than network diagrams suggested.

## What the network layout reveals

The reconnaissance scripts (in `scripts/recon/` and `scripts/vulns/`) demonstrated what an attacker could learn:

### Device inventory
- A turbine PLC, two protective relays, and four Modbus actuators
- A SCADA server and a process historian
- Several protocols: Modbus, DNP3, IEC-104, OPC UA, MQTT

### Protocol capabilities
- Modbus: full register and coil access, no authentication
- DNP3 and IEC-104: datapoint read and write on the turbine PLC and the RTU
- OPC UA: anonymous browsing and method calls on the sidecar and the DMZ gateways
- MQTT: anonymous publish and subscribe on the broker

### Attack surface
Every open port was a potential entry point. Every protocol that lacked authentication was exploitable. The reconnaissance revealed:
- Every control port unauthenticated (Modbus, DNP3, IEC-104, OPC UA, MQTT, SNMP)
- The only friction anywhere is the stunnel-fronted Modbus path to the PLC
- Complete visibility into all protocols

## Network reconnaissance

Several reconnaissance approaches apply on this segment, each read-only and aimed at learning what is exposed before
anything is touched:

- Raw TCP probing to confirm which ports answer and stay responsive.
- Modbus identity queries (Function Code 43) to fingerprint devices.
- Modbus register and coil reads to map a controller's memory.
- OPC UA connection tests against the supervisory layer and the DMZ gateways.

The lab's per-component documentation lists each device's exposed ports and protocols, which is where enumeration
tends to start. None of these approaches change state; they show what is visible without authentication.

## The security model (lack thereof)

The network architecture demonstrated several security anti-patterns:

### Trust through obscurity
"Nobody knows these devices are here, so they're secure." Except port scanning reveals everything in seconds.

### Protocol diversity as security
"We use multiple protocols, so it's harder to attack." Except each protocol is well-documented, and tools exist for all of them.

### Network access equals authorisation
"If you're on the network, you're trusted." This worked when networks were physically isolated. It fails catastrophically when networks are interconnected.

## The realistic assessment

Testing the simulator's network provided several uncomfortable insights:

Industrial networks are flat: Devices can typically reach each other. Segmentation exists in diagrams more than in practice.

Protocols lack authentication: Most industrial protocols were designed assuming network access was controlled through other means. Those means often don't exist.

Everything is discoverable: Port scanning, protocol fingerprinting, and service enumeration reveal the complete attack surface in minutes.

Defence in depth doesn't exist: There's usually one layer of defence (network access), and once breached, everything is accessible.

The only realistic security measures are:
- Proper network segmentation (actually enforced, not just diagrammed)
- Firewall rules restricting protocol access
- Network monitoring to detect reconnaissance
- Accepting that protocols themselves provide no security

Ponder's final note in his testing journal: "The network is the security boundary. Unfortunately, the network boundary is porous, poorly defined, and often non-existent. Once you're on the OT network, you're effectively trusted by everything. This is not a technology problem that can be patched. This is an architectural reality that must be defended around."

Related runbooks (in the ICS Access SimLab, to be linked once migrated into this repository):

- ARP poisoning and Modbus MITM runbook: on-path interception of control traffic on the OT segment
- STP root takeover runbook: seizing the spanning-tree root with a superior BPDU
- OSPF attacks runbook: route injection and authentication denial of service
- iBGP route hijack runbook: redirecting traffic through FRR
- FRR vtysh takeover runbook: router compromise via default credentials
- SNMP default community runbook: read and write access through unchanged community strings
- DNS reconnaissance and poisoning runbook: enumeration and on-path response poisoning
