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
# 102/tcp   open  S7 (Reactor PLC)
# 103/tcp   open  S7 (Safety PLC)
# 4840/tcp  open  OPC UA (Primary SCADA)
# 4841/tcp  open  OPC UA (Backup SCADA)
# 10502/tcp open  Modbus TCP (Turbine PLC)
# 10503/tcp open  Modbus TCP (Safety PLC)
# 10504/tcp open  Modbus TCP (Reactor PLC)
# 44818/tcp open  EtherNet/IP (Turbine PLC)
```

Eight ports, four protocols, multiple PLCs. Each port represented an attack surface. Each protocol had its own characteristics and vulnerabilities.

### Protocol fingerprinting

Simply knowing ports were open wasn't sufficient. Confirming what protocols were actually running required protocol-specific probing:

S7 Protocol (Ports 102, 103):
```bash
# Using nmap's s7-info script
nmap -p 102 --script s7-info 127.0.0.1

# Or using testing scripts
sudo python scripts/vulns/testing-turbine-control-plcs.py
```

Result: Confirmed S7comm protocol, PLC model S7-400, no authentication required.

Modbus TCP (Ports 10502-10504):
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

EtherNet/IP (Port 44818):
```bash
# Using testing script
python scripts/vulns/ab_logix_tag_inventory.py
```

Result: Confirmed CIP protocol, tag enumeration available, 18 tags exposed.

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
- Turbine PLC: Modbus TCP (10502) + EtherNet/IP (44818)
- Reactor PLC: S7 (102) + Modbus TCP (10504)

This wasn't redundancy for security. This was integration necessity. Different systems needed different protocols, so devices supported multiple protocols simultaneously. Each protocol was another attack surface.

### Non-standard ports (sometimes)

The Modbus implementations used non-standard ports (10502+ instead of the standard 502). This provided two benefits:
1. Avoided requiring root privileges for port binding
2. Made the services slightly less obvious to casual port scanning

However, "slightly less obvious" was not a security control. Any attacker running a full port scan would discover them immediately.

The S7 protocol still used the standard port 102, which required elevated privileges to bind. This was unavoidable for S7 compatibility.

### Everything on localhost

The simulator ran everything on 127.0.0.1, which meant:
- No actual network segmentation
- No firewall rules between services
- Complete connectivity between all components

This represented the worst case: an attacker who had gained access to a system on the OT network could reach everything. In a properly segmented network, the turbine PLC network would be separate from the reactor PLC network, which would be separate from the SCADA server network.

But "properly segmented" networks were rarer than network diagrams suggested.

## What the network layout reveals

The reconnaissance scripts (in `scripts/recon/` and `scripts/vulns/`) demonstrated what an attacker could learn:

### Device inventory
- 3 PLCs (turbine, reactor, safety)
- 2 SCADA servers (primary, backup)
- 4 protocols (S7, Modbus, OPC UA, EtherNet/IP)

### Protocol capabilities
- S7: Complete memory access, programme download
- Modbus: Full register/coil access
- OPC UA: Anonymous browsing (primary), authenticated (backup)
- EtherNet/IP: Tag enumeration and access

### Attack surface
Every open port was a potential entry point. Every protocol that lacked authentication was exploitable. The reconnaissance revealed:
- 6 ports with no authentication (S7, Modbus, OPC UA primary, EtherNet/IP)
- 2 ports with authentication (OPC UA backup, technically)
- Complete visibility into all protocols

## Network reconnaissance scripts

The simulator supports several reconnaissance approaches:

[Raw TCP probing](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/recon/raw-tcp-probing.py):
Basic connectivity testing to confirm ports are open and responsive.

[Modbus identity probe](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/recon/modbus_identity_probe.py):
Extracts device identity information via Modbus Function Code 43.

[Turbine reconnaissance](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/recon/turbine_recon.py):
Comprehensive Modbus reconnaissance of turbine PLCs.

[OPC UA connection test](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/recon/connect-remote-substation.py):
Tests OPC UA connectivity and security configuration.

All scripts are read-only reconnaissance, demonstrating what information is available without making any changes.

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

Further Reading:
- [Reconnaissance Scripts](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/recon/README.md) - Network discovery and enumeration
- [Vulnerability Scripts](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/vulns/README.md) - Protocol-specific testing
- [Protocol Integration](https://github.com/ninabarzh/power-and-light-sim/tree/main/docs/protocol_integration.md) - How protocols are implemented

The reconnaissance scripts demonstrate what an attacker can discover about an industrial network through non-invasive scanning and protocol enumeration.
