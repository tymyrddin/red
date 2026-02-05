# Protocol reference

## Modbus TCP (easiest)

What it is: Simple protocol for reading/writing values.

Where: Turbines (ports 10501-10504), Safety PLC (port 10501)

Key concepts:
- Holding registers: Values you can read and write
- Input registers: Read-only values
- Coils: Binary on/off values
- Function codes: What operation to perform (read, write, etc.)

Available scripts:
```bash
# Device identity
python scripts/recon/modbus_identity_probe.py --host 127.0.0.1 --port 10502

# Read all registers
python scripts/vulns/modbus_coil_register_snapshot.py --host 127.0.0.1 --port 10502

# Turbine-specific reconnaissance
python scripts/recon/turbine_recon.py
```

Learn more:
- Read Modbus protocol specification
- Write your own Modbus client
- Understand function codes (1, 2, 3, 4, 5, 6, 15, 16)
- Use Wireshark to capture and analyse traffic

## S7comm (medium difficulty)

What it is: Siemens PLC protocol, more complex than Modbus.

Where: Reactor PLC (port 102), Safety PLC (port 103)

Key concepts:
- Rack and slot: Physical PLC location (usually rack 0, slot 2 or 3)
- Memory areas: Different data storage types (M, DB, I, Q)
- Programme blocks: Contains control logic (OB, FB, FC)
- Data blocks (DB): Structured data

Available scripts:
```bash
# PLC status
python scripts/vulns/s7_plc_status_dump.py --host 127.0.0.1 --port 102 --rack 0 --slot 2

# Extract programme blocks
python scripts/vulns/s7_readonly_block_dump.py --host 127.0.0.1 --port 102 --rack 0 --slot 2

# Read memory
python scripts/vulns/s7_read_memory.py --host 127.0.0.1 --port 102 --rack 0 --slot 2
```

Learn more:
- Understand S7 memory addressing
- Learn about STEP 7 programming
- Analyse extracted programme blocks
- Try modifying PLC logic (carefully!)

## OPC UA (modern but misconfigured)

What it is: Modern industrial protocol with security features (disabled here).

Where: Primary SCADA (port 4840), Backup SCADA (port 4841)

Key concepts:
- Endpoints: Connection URLs (opc.tcp://...)
- Nodes: Objects in the server's address space
- Tags: Variables holding current values
- Security policies: Can be None, Basic256Sha256, etc. (here: None)

Available scripts:
```bash
# Browse server
python scripts/vulns/opcua_readonly_probe.py --endpoint opc.tcp://127.0.0.1:4840

# Backup SCADA
python scripts/vulns/opcua_readonly_probe.py --endpoint opc.tcp://127.0.0.1:4841
```

Learn more:
- Understand OPC UA information model
- Learn about security modes (when enabled)
- Browse complete node hierarchy
- Try writing to nodes

## EtherNet/IP (Allen-Bradley)

What it is: Rockwell Automation protocol, common in manufacturing.

Where: Turbines (ports 44818-44820)

Key concepts:
- Tags: Named variables
- CIP (Common Industrial Protocol): Underlying protocol
- Controllers: Allen-Bradley PLCs

Available scripts:
```bash
# Tag inventory
python scripts/vulns/ab_logix_tag_inventory.py --host 127.0.0.1 --port 44818
```

Learn more:
- Understand CIP protocol structure
- Learn about Allen-Bradley addressing
- Compare to other industrial protocols
