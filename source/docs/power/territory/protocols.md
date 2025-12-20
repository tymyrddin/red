# Common OT protocols


Industrial control systems speak their own languages. These protocols were developed decades ago, when security meant 
"put the computer in a locked room", and nobody imagined they'd ever be accessible from outside that room (let alone 
from the internet).

Understanding these protocols is essential for OT security testing. You need to know what's being said on the network, 
what commands are legitimate, and what packets would make a PLC do something regrettable.

The good news is that OT protocols are generally simpler than modern IT protocols. They were designed for efficiency 
and reliability, not flexibility.

The bad news is that they were designed without security at all. No encryption, minimal authentication, and often no 
authorisation beyond "if you can reach this port, you must be authorised to use it".

It's the network security equivalent of having a door with a lock, but the lock is purely decorative and the door 
opens if you push it firmly whilst saying "I'm supposed to be here".

## Modbus, the grandpa of them all

[Modbus](https://modbuskit.com/en/blog?category=protocol) was developed in 1979 by Modicon (now Schneider Electric) 
for PLCs. It's been extended and adapted, but the core protocol remains essentially unchanged. This means it is 
older than many of the security testers testing it.

There are three flavours:

Modbus RTU (serial): Used over RS-232 or RS-485 serial connections. You're unlikely to encounter this during 
network pentesting unless someone has helpfully converted it to TCP/IP using a serial-to-Ethernet converter 
(which happens more than you'd think).

Modbus ASCII (also serial): Like Modbus RTU but using ASCII encoding instead of binary. Slightly less common. 
Still serial. Still not your problem unless someone bridged it to the network.

Modbus TCP (what you'll actually test): Modbus encapsulated in TCP/IP, typically on port 502. This is everywhere 
in OT environments. Pumps, valves, motor drives, sensors, PLCs. If it was made in the last 30 years and needs 
network connectivity, there's a reasonable chance it speaks Modbus TCP.

### How Modbus TCP works

Modbus uses a master-slave architecture (the protocol predates modern terminology debates). One device asks questions, 
other devices answer. The questions are called "function codes", and they fall into a few categories:

- Read coils (discrete outputs): Function code 01
- Read discrete inputs: Function code 02  
- Read holding registers (analog outputs/variables): Function code 03
- Read input registers (analog inputs): Function code 04
- Write single coil: Function code 05
- Write single register: Function code 06
- Write multiple coils: Function code 15
- Write multiple registers: Function code 16

At UU P&L, the Library's environmental system uses Modbus TCP extensively. The temperature sensors are input 
registers (function code `04`). The setpoints are holding registers (function code `03`). The heating and cooling 
actuators are coils (function code 01 to read their status, function code 05 to turn them on/off).

### Security characteristics of Modbus (or lack thereof)

Modbus has no authentication. None. If you can send a TCP packet to port 502, you can read values or write commands. 
The protocol doesn't even have a field for "who's asking".

Modbus has no encryption. Everything is plaintext. Sniff the network and you can see setpoints, sensor readings, 
and commands in clear view.

Modbus has no integrity checking beyond a simple CRC. You can't verify that commands come from legitimate sources.

Modbus has no logging built into the protocol. The device might log locally (if the manufacturer thought of it), 
but the protocol itself doesn't track who did what.

For security testing, this means:
- You can query any Modbus device you can reach on the network
- You can read sensor values and configurations
- You can send write commands (function codes 05, 06, 15, 16) if you're testing in a safe environment
- You can sniff traffic and reconstruct the entire conversation
- You need to use tools like [Wireshark with Modbus dissectors](https://www.wireshark.org/), [pyModbus](https://github.com/pymodbus-dev/pymodbus), or custom Python scripts

### Testing Modbus at UU P&L

During reconnaissance of the Library's environmental system, you discover Modbus TCP traffic on port 502. Using 
Wireshark, you can see:

- Regular reads of input registers (temperature sensors) every 10 seconds
- Occasional writes to holding registers (adjusting setpoints)
- Status queries of coils (checking heating/cooling state)

You can use pyModbus (3.11.4) to query one of the temperature controllers:

```python
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient("192.168.10.15")
client.connect()

result = client.read_holding_registers(address=0, count=1)

if not result.isError():
    print(f"Current setpoint: {result.registers[0] / 10}°C")
else:
    print(result)

client.close()
```

The response shows the current temperature setpoint is 18.5°C, which matches what the Librarian insists is the only 
acceptable temperature for preserving ancient grimoires.

In a real pentest, you'd document that you could read these values. You'd note that you could also theoretically 
write new setpoints (function code 06 or 16). You'd test this on a simulator or isolated test device, not on the 
live Library controls, because explaining to the Librarian that you made their books spontaneously combust "for 
security testing purposes" is not a conversation you want to have.

## DNP3, the protocol for the power grid

[DNP3](https://www.dnp.org/About/Overview-of-DNP3-Protocol) (Distributed Network Protocol 3) was developed in the 
1990s specifically for SCADA systems in the electric power industry. It has since spread to water/wastewater, oil 
and gas, and other utilities.

DNP3 is more sophisticated than Modbus. It was designed for unreliable communications over serial lines that might 
drop packets or lose connection. It has error checking, time synchronization, event buffering, and can operate 
over various physical layers.

### DNP3 architecture

DNP3 uses master-station and outstation terminology. The master polls outstations for data. Outstations can also 
send unsolicited responses when significant events occur.

DNP3 organises data into points:
- Binary inputs (two-state sensors: on/off, open/closed)
- Binary outputs (two-state controls)
- Analog inputs (continuous measurements)
- Analog outputs (continuous controls)  
- Counters (for totalisers, energy meters, etc.)

At UU P&L, DNP3 appears in the city-wide distribution SCADA. The system monitors and controls substations across 
Ankh-Morpork:

- Circuit breaker status (binary inputs/outputs)
- Transformer load levels (analog inputs)
- Voltage setpoints (analog outputs)
- Energy consumption meters (counters)

### Security in DNP3

DNP3 is slightly better than Modbus, which is like saying a paper castle is slightly better than no castle at all.

Original DNP3 (IEEE 1815-2010) has optional authentication, but it's rarely enabled. When it is enabled, it uses 
challenge-response authentication with shared symmetric keys. This requires key management, which many deployments 
find too complex to implement properly.

DNP3 Secure Authentication (SAv5, added in IEEE 1815-2012) provides stronger cryptographic authentication. It's better 
than nothing, but still relies on pre-shared keys and doesn't provide encryption of the data itself.

Most DNP3 implementations you'll encounter in pentests are running without authentication. The protocol runs over 
TCP port 20000 or UDP port 20000, and anyone who can reach that port can send commands.

### Testing DNP3

The distribution SCADA master communicates with substations using DNP3 over TCP. During network reconnaissance, 
you identify DNP3 traffic on port 20000.

Most DNP3 security probing is done by:

- Passive-first: PCAP‑driven probing (most common, safest). DNP3 is stateful. Random active probes stand out immediately. 
- Replay‑based probing (low risk, very effective). Once we had *known‑good traffic*, we could safely poke. This avoids protocol guesswork entirely.
- Wireshark‑assisted fuzzing: probing the implementation. This is how many vendor DNP3 bugs have actually been found.
- More tools and tools, open source and commercial.

### PCAP‑driven probing

1. Capture traffic between master ↔ outstation: 

```bash
tcpdump -i eth0 port 20000 -w dnp3.pcap
```

2. Extract:

* Object groups in use
* Function codes
* Timing
* Confirm behaviour
* Secure Auth presence

3. Using [Wireshark](https://www.wireshark.org/) with DNP3 dissectors enabled, discover:

* Whether unsolicited responses are enabled
* Which class polls are used
* Vendor quirks
* Whether SAv5 is enforced

### Replay‑based probing

1. Capture a legitimate `DNP3 READ`

2. Replay it

```bash
tcpreplay --intf1=eth0 dnp3.pcap
```

Then mutate:

* Sequence numbers
* Object group numbers
* Qualifiers

3. Observe response differences

## Wireshark‑assisted fuzzing 

1. Right‑click a DNP3 packet
   * “Copy → Bytes → Hex Stream”
   * Modify:

     * Object headers
     * Function codes
     * Qualifiers
   * Reinject with a raw socket

### Use purpose-built OT security tools

Open-source / free:

* Wireshark (mandatory)
* tcpdump
* tcpreplay
* nmap (service detection only)
* Metasploit (limited DNP3 support)

Commercial:

* Nozomi
* Claroty
* Dragos
* Tenable.ot

They do exactly the above, just faster and prettier.

### What not to do

Never:

* Flood DNP3
* Send control function codes
* Write to Group 12 objects
* Spam sequence numbers
* Ignore confirms on live systems

DNP3 can and does trigger *physical actions* if mishandled.

You can document that you could theoretically send control commands to operate breakers, but we do not test this on 
the live system because plunging parts of Ankh-Morpork into darkness would:

1. Violate your rules of engagement
2. Alert everyone to your presence  
3. Probably result in the Patrician taking an unwelcome interest in your activities

Instead, we documented the lack of authentication and recommended implementing DNP3 SAv5, network segmentation to 
prevent unauthorised access to DNP3 ports, and intrusion detection specifically tuned for DNP3 protocol anomalies.

## Siemens S7comm, speaking German to PLCs

S7comm (and its encrypted cousin S7comm-plus) is Siemens' proprietary protocol for communicating with their S7-300, 
S7-400, S7-1200, and S7-1500 PLC series. Given Siemens' market share in industrial automation, you'll encounter 
this frequently.

### S7comm (legacy, but everywhere)

The original S7comm protocol runs over TCP port 102. It provides functions for:
- Reading/writing memory areas (flags, data blocks, timers, counters)
- Starting/stopping the CPU
- Uploading/downloading programs
- Reading diagnostic information

S7comm has no authentication in older PLCs (S7-300/400). If you can reach port 102, you can send commands. This has led to some spectacular security failures over the years.

### S7comm-plus (newer, somewhat better)

Siemens introduced S7comm-plus with the S7-1200/1500 series. It adds:
- Encrypted communication (though implementation varies)
- Authentication (though often disabled for "convenience")
- Better access controls (in theory)

In practice, many S7-1200/1500 installations disable security features because they complicate integration with SCADA systems, or because engineers find the additional steps annoying.

### Testing S7 systems at UU P&L

The alchemical reactor controls use Siemens S7-400 PLCs (installed in 2003, which makes them practically modern by UU standards). These speak S7comm on port 102.

Using [Snap7](http://snap7.sourceforge.net/), a free open-source library for S7 communication, you can query the PLC:

```python
import snap7

plc = snap7.client.Client()
plc.connect('192.168.30.25', 0, 1)  # IP, rack, slot

# Read CPU status
cpu_status = plc.get_cpu_state()
print(f"PLC CPU Status: {cpu_status}")

# Read data block 1, starting at byte 0, length 100
data = plc.db_read(1, 0, 100)
print(f"Data Block 1: {data}")

plc.disconnect()
```

The connection succeeds with no authentication required. You can read memory areas, examine data blocks containing process variables and setpoints, and potentially download the entire PLC program.

You document that you could theoretically:
- Upload the PLC program to analysing the reactor control logic
- Modify setpoints in data blocks
- Start or stop the PLC CPU
- Download malicious logic

You don't actually do any of these things to the live reactor controls, because the Bursar's definition of "upset" when their reactor misbehaves includes terms like "catastrophic containment failure" and "turning the campus into a glowing crater".

Instead, you obtain a spare S7-400 PLC (borrowed from the old brewery, which upgraded to newer equipment), recreate a test environment, and demonstrate the attacks there. The video evidence of uploading and modifying PLC logic on the test system is sufficient to communicate the risk.

## EtherNet/IP and CIP, Rockwell's contribution

EtherNet/IP is an industrial Ethernet protocol developed by Rockwell Automation (Allen-Bradley). It encapsulates the Common Industrial Protocol (CIP) over standard Ethernet and TCP/IP.

Despite the name, EtherNet/IP has nothing to do with Internet Protocol. The "IP" stands for "Industrial Protocol", which is confusing branding of the highest order.

EtherNet/IP uses two different transport mechanisms:
- TCP port 44818 for explicit messaging (configuration, diagnostics)
- UDP port 2222 for implicit messaging (real-time I/O data)

### CIP, the Common Industrial Protocol

CIP is the application layer protocol that multiple networks use:
- EtherNet/IP (over Ethernet)
- ControlNet (over a deterministic network)
- DeviceNet (over CAN bus)

CIP organises devices as collections of objects. You interact with these objects using services (read, write, create, delete, etc.). It's object-oriented networking, which sounds modern until you remember it was designed in the 1990s and has no security model.

### Security characteristics

Traditional EtherNet/IP has no authentication or encryption. If you can send packets to port 44818 or 2222, you can interact with the device.

Newer devices may support CIP Security, which adds TLS encryption and certificate-based authentication. However, implementation is optional, and many installations don't enable it because it complicates configuration and requires managing certificates (which OT environments are notoriously bad at).

### Testing EtherNet/IP at UU P&L

The Hex Steam Turbine system uses Allen-Bradley ControlLogix PLCs, which speak EtherNet/IP. During reconnaissance, you identify traffic on ports 44818 and 2222.

Using [cpppo](https://github.com/pjkundert/cpppo), an open-source EtherNet/IP library, you can enumerate the device:

```python
# The warnings "Parameter 'data' unfilled" and "Parameter 'path' unfilled" are caused by parse_operations()
# deliberately leaving fields unset until execution, and cpppo’s own type hints/validators complain even though
# the runtime fills them in later. Ignore.

from cpppo.server.enip import client

host = '192.168.40.10'

with client.connector(host=host) as conn:
    # Get_Attribute_All for Identity Object (Class 0x01, Instance 1)
    ops = client.parse_operations(
        "get-attribute-all@1/1"
    )

    for index, descr, op in ops:
        conn.write(op)
        reply = conn.read()
        print("Identity object:", reply)
```

The response revealed:

- Vendor: Rockwell Automation
- Product: 1756-L73 ControlLogix
- Firmware version: 28.012
- Serial number: \[redacted because that would be telling]

We could read tags (variables), examine configurations, and potentially write values. We documented the lack of 
authentication, noting that an attacker with network access could:

- Read process variables and setpoints
- Modify control logic
- Stop the PLC
- Cause physical damage by sending inappropriate control commands

Testing is done on isolated equipment or simulators because the turbines in question provide power to much of 
Ankh-Morpork, and "I was just pentesting" is not a valid excuse when the Patrician's dinner goes cold.

## OPC UA, the modern alternative that nobody's quite adopted yet

OPC UA (Open Platform Communications Unified Architecture) is the newest major protocol in industrial automation. 
It was designed in the 2000s with security actually considered (revolutionary!).

OPC UA provides:
- Multiple transport protocols (TCP, HTTPS, WebSockets)
- Built-in security (encryption, authentication, authorization)
- Complex data structures (not just simple read/write)
- Platform independence
- Service-oriented architecture

It's genuinely better from a security perspective. The problem is that it's complex, requires certificate management, 
and many OT organisations aren't ready for that level of sophistication.

### Security in OPC UA

OPC UA supports multiple security modes:
- None (no security, like old protocols)
- Sign (messages are authenticated but not encrypted)
- SignAndEncrypt (full security)

It also supports multiple security policies (cryptographic algorithms):
- None (no cryptography)
- Basic128Rsa15 (deprecated, weak)
- Basic256 (minimum recommended)
- Basic256Sha256 (better)
- Aes128Sha256RsaOaep (current recommended)
- Aes256Sha256RsaPss (strongest)

Authentication can be:
- Anonymous (anyone can connect)
- Username/password  
- Certificate-based (mutual TLS)

The catch is that all these options mean many deployments choose the easiest settings: SecurityMode None, Anonymous authentication. This makes OPC UA exactly as insecure as Modbus, just with more complexity.

### Testing OPC UA at UU P&L

The newer sections of the distribution SCADA use OPC UA to communicate between the SCADA server and remote substations. Port 4840 (default OPC UA port) shows activity during reconnaissance.

Using [opcua-asyncio](https://github.com/FreeOpcUa/opcua-asyncio), you attempt to connect:

```python
import asyncio
from asyncua import Client


async def test_opcua():
    client = Client("opc.tcp://192.168.50.20:4840")
    async with client:
        # Get root node
        root = client.get_root_node()
        print(f"Root: {root}")

        # Browse available objects
        objects = await root.get_children()
        for obj in objects:
            print(f"Object: {await obj.read_browse_name()}")


asyncio.run(test_opcua())
```

The connection succeeds with no authentication (`SecurityMode: None, Anonymous access`). We can browse the entire 
information model, read all variables, and subscribe to data changes.

We can discover:
- Circuit breaker states for all substations
- Load levels and voltage readings
- Alarm states
- Historical data queries

We documented that whilst OPC UA is being used, it is configured insecurely. The recommendations included:

- Enable SignAndEncrypt security mode
- Require certificate-based authentication
- Restrict anonymous access
- Implement proper certificate management
- Use security policy Basic256Sha256 or better

The university's response is that implementing proper OPC UA security "requires training and budget", both of which 
are scheduled for "sometime next year", which in university timescales means "when the heat death of the universe 
makes it moot".

## Profinet, BACnet, and the long tail of protocols

There are dozens more protocols in OT environments. The specific ones you encounter depend on the industry and 
vendors involved.

Profinet (Process Field Network) is Siemens' Ethernet-based protocol for factory automation. It operates at layer 2 
(raw Ethernet frames) for real-time performance, making it particularly interesting from a security perspective 
because standard firewalls don't see it.

BACnet (Building Automation and Control Network) is ubiquitous in building management systems (HVAC, lighting, 
access control). It runs on UDP port 47808. Like other OT protocols, security was an afterthought. BACnet/SC 
(Secure Connect) adds encryption and authentication, but adoption is slow.

CAN bus (Controller Area Network) is used in vehicles and some industrial equipment. It has no security model 
whatsoever. If you can inject CAN messages, you can control the system. This is why automotive security is its own 
special nightmare.

At UU P&L, the building management system uses BACnet to control HVAC throughout the campus. During testing, you 
discover you can read temperature setpoints, occupancy sensors, and equipment status. You can also write new 
setpoints, though you resist the temptation to set the Archchancellor's office to 35°C just to see what happens.

## Why none of them thought about security

These protocols were developed in an era when:

- Industrial networks were physically isolated
- Only trained engineers had access
- "Security through obscurity" seemed reasonable  
- Proprietary hardware meant attackers would need expensive equipment
- The thought of connecting factories to the internet seemed absurd

These assumptions are now all false:

- Networks are connected (deliberately or accidentally)
- Remote access is common (vendors, contractors, engineers working from home)
- Protocol specifications are published  
- Attacks can be launched with open-source software and cheap hardware
- Everything is connected to everything else

The protocols remain because replacing them is nearly impossible. You can't just upgrade a protocol when it's 
embedded in millions of devices with 20-year lifespans. You can't retrofit security into protocols that have no 
fields for authentication or encryption.

The solution isn't to fix the protocols (though newer versions try). The solution is to:

- Understand what the protocols can do
- Monitor for unusual protocol behavior  
- Segment networks to limit who can reach protocol endpoints
- Use compensating controls (firewalls, authentication at network level, encryption via VPN or TLS tunnels)
- Accept that the protocols themselves are insecure and build security around them

This is what makes OT security testing different from IT security testing. You're not finding buffer overflows 
in services that can be patched. You're documenting protocol-level weaknesses that are inherent and permanent, 
then recommending architectural changes to mitigate them.

And you're doing this whilst making sure you don't accidentally shut down the turbines, melt the reactor, or 
upset the Librarian.

Because in OT security, the protocols might be insecure, but the consequences of testing them incorrectly are 
very, very real.
