# Industrial protocol abuse

The industrial protocols that carry commands to PLCs and field devices were designed for reliability in isolated networks. Authentication is absent from most of them; the assumption was that if you can send a Modbus frame, you are authorised to do so because you are on the right network. Living off these protocols means using them as designed, in ways that are operationally valid but operationally wrong.

## Modbus

Modbus is the most widely deployed industrial protocol, running over TCP (port 502) or serial connections. It has no authentication, no encryption, and no concept of sessions. Any host that can reach a Modbus device on port 502 can read any register and write any register that the device permits.

Modbus organises device data into four tables: coils (discrete outputs), discrete inputs, holding registers, and input registers. Coils are individually addressable single-bit values used for relay control; holding registers are 16-bit values used for process parameters such as setpoints, speeds, and positions.

```python
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('<plc-ip>')
client.connect()

# Read holding registers (e.g., current setpoint values)
result = client.read_holding_registers(address=0, count=10, slave=1)
print(result.registers)  # Current values

# Write a holding register (e.g., modify a setpoint)
client.write_register(address=0, value=100, slave=1)
```

Reading before writing establishes the current values and allows restoration after testing. Writing an unexpected value to a setpoint register changes process behaviour without any indication to the SCADA system that the change was unauthorised, because the protocol carries no attribution.

## DNP3

Distributed Network Protocol 3 is used primarily in utilities: power distribution, water treatment, and oil and gas. It carries more sophistication than Modbus, including event buffering and data integrity checks, but the standard version carries no authentication. DNP3 Secure Authentication (SA) was added as an extension but adoption is uneven.

DNP3 uses a master/outstation model. The SCADA master polls outstations (RTUs and field devices) for data and sends control commands. An attacker with a network path to an outstation can send control commands using the same DNP3 function codes the legitimate master uses.

## OPC UA

OPC Unified Architecture is a platform-independent protocol that replaced the earlier OPC standards and is widely used for IT/OT integration. Unlike Modbus and DNP3, OPC UA includes built-in security: message encryption, signing, and certificate-based authentication. However, in practice many OPC UA deployments use `None` security mode (no encryption, no authentication) or `SignAndEncrypt` with self-signed certificates that clients are configured to accept unconditionally.

An OPC UA server in `None` security mode accepts connections from any client and permits browsing and reading the entire node space. This exposes the full tag database of the connected SCADA or historian system, including all process variable values and their addresses.

## BACnet

BACnet is the dominant protocol for building automation: HVAC, lighting, access control, and fire suppression. It runs over IP (port 47808) or MS/TP serial. Like Modbus, it carries no authentication in its base specification. BACnet/SC (Secure Connect) adds TLS and certificate authentication but is not yet widely deployed.

Building automation systems are frequently connected to both the building's network infrastructure and the corporate IT network, and they are rarely treated as security-sensitive infrastructure. A BACnet device controlling HVAC in a data centre can affect physical conditions for the servers it cools.

## EtherNet/IP and Common Industrial Protocol (CIP)

EtherNet/IP carries the Common Industrial Protocol over standard Ethernet and TCP/IP. It is widely used in Allen-Bradley/Rockwell PLCs. Port 44818 (TCP) is used for explicit messaging; port 2222 (UDP) for implicit I/O.

CIP allows reading and writing tags by name (symbolic addressing), which is more expressive than Modbus register addresses. An attacker with access to a Studio 5000 project file (typically found on the engineering workstation) knows the tag names and their meanings, enabling targeted manipulation of specific process values.
