# Discovery into nowhere

The [passive map was complete](passive.md). It showed where the conversations were, but not what was being said. 
The next phase required a question. Only one. For discovery.

The rule was absolute: one device, one query. The target was the busiest listener from the passive capture, the 
device on port 10502. It was already deep in conversation; one more voice in the room might go unnoticed.

The tool had to be specific. Not a scanner, but a speaker of the suspected language. I used mbpoll.

The logic was simple: ask for a single, common thing. Holding register `40001`. A place where one might find a pressure 
reading or a temperature. A normal question.  The goal was to read one register as a floating-point number. 

```bash
$ mbpoll -a 1 -r 40001 127.0.0.1 10502
mbpoll 1.0-0 - FieldTalk(tm) Modbus(R) Master Simulator
Copyright © 2015-2019 Pascal JEAN, https://github.com/epsilonrt/mbpoll
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions; type 'mbpoll -w' for details.

mbpoll: Connection failed: Connection refused.
```

The connection is refused. This is a significant result.

The passive capture [showed clear TCP traffic on port 10502](passive.md). The packets were acknowledged. The 
conversations were bidirectional. Yet, a direct connection from my terminal was rejected.

This indicates one of two scenarios:

- The service is bound specifically to the an address, but only accepts connections from the specific ephemeral ports used by the simulator's own internal SCADA client. A form of implicit, process-based segmentation?
- The service has a rudimentary filtering logic, perhaps based on the initial packet sequence or source port.

The device is not "listening" in the traditional sense. It is in conversation with a pre-approved partner. My knock, 
though on the right port, is from the wrong door.

This changes the active approach. We cannot simply query the discovered services. We must either:

- Intercept and mimic an existing, legitimate conversation.
- Find a service that does listen openly.

The next logical probe shifts to the other prominent port from our passive map: `10520`. This port showed moderate, 
aggregated traffic characteristic of a SCADA server. Servers are often more permissive. They are designed to accept 
connections.

```bash
$ echo -n | nc -v -w 3 127.0.0.1 10520
Connection to 127.0.0.1 10520 port [tcp/*] succeeded!
```

Success. Port `10520` accepted a connection. The supervisory hub was listening. This was the entry point.

The immediate next action was not to send data, but to observe. What did the service offer upon connection? I performed
a simple banner grab.

```bash
$ timeout 2 nc -v 127.0.0.1 10520
Connection to 127.0.0.1 10520 port [tcp/*] succeeded!
```

The connection sat silent. No banner. No prompt.

I sent a minimal stimulus, a single carriage return, to prompt a response.

```bash
$ printf "\n" | timeout 2 nc -v 127.0.0.1 10520
Connection to 127.0.0.1 10520 port [tcp/*] succeeded!
```

Again, silence. The port accepted the TCP handshake but offered no unsolicited data. This is characteristic of a 
protocol that expects a specific, correctly formatted initial client request. A Modbus server, for instance, would 
wait for a complete Modbus Application Data Unit.

The next step was protocol deduction. The passive map showed this port was a client to others (`10502`, `10503`, etc.), 
but here it was acting as a server. This suggested a secondary function: perhaps a management or data-access interface. 
The traffic volume was moderate, not the high-speed polling of the control loop.

I needed to send a valid first packet for a likely protocol. Given the environment, Modbus was the prime candidate. 
I crafted a [minimal Modbus request frame]() using Python's pymodbus to send a read request identical to the earlier 
failed attempt, but now to the listening port.

If this failed or returned an exception, the process of elimination would continue, perhaps with a S7comm or DNP3 test. 
The active reconnaissance became a targeted, iterative dialogue: propose an identity for the service and observe if 
it answered to that name.

```bash
$ python minimal-modbus-request-frame.py 
ReadHoldingRegistersResponse(dev_id=1, transaction_id=1, address=0, count=0, bits=[], registers=[7462], status=1, retries=0)
```

The script executed. The connection succeeded. The Modbus request was sent.

The response was clear: `ReadHoldingRegistersResponse`. It was not an error. The device on port `10520` was a 
Modbus TCP server. It had a Unit ID of 1. It held data. Register address zero contained the value 7462.

This changed the active reconnaissance entirely. We were no longer probing a black box; we were in conversation with 
a known entity. Port 10520 was confirmed as a Modbus endpoint. The SCADA server's secondary interface, perhaps for 
external data clients or historians.

The next step was systematic, but still gentle. We would map the extent of its memory, one small step at a time. 
The goal was not to brute-force every address, but to understand the layout. We would read a small, contiguous 
block from the starting point we had discovered.

```python
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('127.0.0.1', port=10520)
client.connect()

# Read a small block of ten registers starting from address 0
response = client.read_holding_registers(address=0, count=10, slave=1)

if not response.isError():
    print("Register block 0-9 values:", response.registers)
else:
    print("Modbus exception:", response)

client.close()
```

The error `TypeError: read_holding_registers() got an unexpected keyword argument 'slave'` was the data point. The 
tool itself rejected my command structure.

To discover the correct syntax, I interrogated the tool using Python's own introspection, a safe, local operation.

```python
import pymodbus.client
import inspect

# Inspect the signature of the read_holding_registers method
sig = inspect.signature(pymodbus.client.ModbusTcpClient.read_holding_registers)
print("Method signature:", sig)

# Also check the client constructor
client_sig = inspect.signature(pymodbus.client.ModbusTcpClient)
print("Client constructor signature:", client_sig)
```

Resulting in:

```bash
$ python discover_pymodbus_api.py 
Method signature: (self, address: 'int', *, count: 'int' = 1, device_id: 'int' = 1, no_response_expected: 'bool' = False) -> 'T'
Client constructor signature: (host: 'str', *, framer: 'FramerType' = <FramerType.SOCKET: 'socket'>, port: 'int' = 502, name: 'str' = 'comm', source_address: 'tuple[str, int] | None' = None, reconnect_delay: 'float' = 0.1, reconnect_delay_max: 'float' = 300, timeout: 'float' = 3, retries: 'int' = 3, trace_packet: 'Callable[[bool, bytes], bytes] | None' = None, trace_pdu: 'Callable[[bool, ModbusPDU], ModbusPDU] | None' = None, trace_connect: 'Callable[[bool], None] | None' = None) -> 'None'
```

The introspection script revealed the API. The introspection script printed two signatures. The first was for the 
method `read_holding_registers`. It listed the parameters, including `device_id`. The second was for the 
`ModbusTcpClient` constructor. It showed default values for all parameters.

The port=502 in this signature is merely the library's default value if you do not specify a port. It does not mean 
our target is port `502`. It means that if I wrote `ModbusTcpClient('127.0.0.1')` without a port argument, it would 
connect to `502`.

I corrected the census script accordingly:

```python
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('127.0.0.1', port=10520)
client.connect()

# The method signature shows the parameter is 'device_id'
response = client.read_holding_registers(address=0, count=10, device_id=1)

if not response.isError():
    print("Register block 0-9 values:", response.registers)
else:
    print("Modbus exception:", response)

client.close()
```

Resulting in 

```bash
$ python modbus_memory_census.py 
Register block 0-9 values: [10432, 0, 0, 0, 0, 0, 0, 0, 0, 0]
```

This was significant. A single non-zero value in the first register, followed by nine zeros. This pattern suggests a 
header or identifier block, not a span of live, changing process data. Register `0` likely contained a static value, 
perhaps a device model code, a firmware version, or a status word. The zeros indicate either unused memory or a 
padding structure.

The next step was to test this hypothesis. If this was a static block, reading it again after a short interval 
should yield the same values. If it was live data, the first value might change.

```bash
$ python modbus_memory_census.py 
Register block 0-9 values: [11974, 0, 0, 0, 0, 0, 0, 0, 0, 0]
```

The second query returned a different value. [11974, 0, 0, 0, 0, 0, 0, 0, 0, 0].

This changed the hypothesis. The first register is not static. It is changing. The value altered from 10432 to 11974 between two reads seconds apart. This is live data.

The pattern—one volatile word followed by nine stable zeros—suggests a status or measurement register that is actively updated, followed by reserved or unused space.

The next step is to understand the rate and range of change. We need a time series, but we must not flood the device. We will read this single register at a slow, periodic interval.

I created a new script, poll_register_0.py:

```python
from pymodbus.client import ModbusTcpClient
import time

client = ModbusTcpClient('127.0.0.1', port=10520)  # Constructor: only host and port

for i in range(5):
    client.connect()
    # Method: device_id goes here
    response = client.read_holding_registers(address=0, count=1, device_id=1)
    client.close()

    if not response.isError():
        print(f"Sample {i+1}: {response.registers[0]}")
    else:
        print(f"Sample {i+1}: Error - {response}")

    if i < 4:
        time.sleep(5)
```

The script reads register zero five times, with a five-second pause between each read. This is slow enough to be 
negligible within the existing traffic observed in our passive capture.

Do they show a clear trend—incrementing, decrementing, oscillating? Or are they seemingly random? The pattern reveals 
the nature of the data and dictates the precise next probe. If it increments steadily, it may be a timer. If it 
oscillates, it may be a sensor. If random, it may be a pseudo-random number generator for simulation.

Results:

```bash
$ python poll_register_0.py 
Sample 1: 12590
Sample 2: 12604
Sample 3: 12620
Sample 4: 12634
Sample 5: 12650
```

The data unspools in a clear, steady climb.

It's ticking. A heartbeat. One beat every five seconds. But the rhythm seems not a simple second counter. The increments 
are too large, too variable: `14`, `16`, `14`, `16`.

I looked at the passive map on the wall. The line from port 10520 to 10502. The supervisory server talking to 
the busy listener. The listener that refused our direct connection.

The server on 10520 isn't just a data repository. It's a gateway. A translator. It speaks Modbus TCP to us, but 
to the internal devices it speaks their native, protected tongue. And it's polling them. Regularly. For data.

Register zero is probably not a raw sensor value. It's a derivative. A calculation. A sum. A total.

Think of a water meter. It doesn't output current flow rate every second. It counts the gallons that have passed. 
The total keeps going up. That's what I'm seeing. A totalled value. The irregular increments mean the flow rate 
itself is changing. Sometimes `14` units per five seconds, sometimes `16`. That's the actual process variable.

We're reading the server's copy of this total, cached from its last poll of the actual device. Every time we ask, 
we get the latest cached total. And it's always going up.

This changes everything. The reconnaissance shifts from discovery to interpretation.

We've found a live data point. Now we need context. What is being totalled? Where are the other variables?

If register zero is a totaller, it's likely a 32-bit value. Modbus often uses two adjacent 16-bit registers for large 
numbers. Need to check if the second register (currently reading zero) is actually the high word.

```python
from pymodbus.client import ModbusTcpClient
import struct

client = ModbusTcpClient('127.0.0.1', port=10520)
client.connect()

# Read registers 0 and 1 as a potential 32-bit value
response = client.read_holding_registers(address=0, count=2, device_id=1)
client.close()

if not response.isError():
    reg0, reg1 = response.registers
    print(f"Register 0 (low word): {reg0}")
    print(f"Register 1 (high word): {reg1}")
    
    # Combine into a 32-bit integer (assuming big-endian)
    combined_value = (reg1 << 16) | reg0
    print(f"Combined 32-bit value: {combined_value}")
    
    # Also try interpreting as a 32-bit float (IEEE 754)
    # Pack the two registers as big-endian 16-bit values, then interpret as 32-bit float
    bytes_for_float = reg0.to_bytes(2, byteorder='big') + reg1.to_bytes(2, byteorder='big')
    try:
        float_value = struct.unpack('>f', bytes_for_float)[0]  # '>' for big-endian
        print(f"As 32-bit float: {float_value}")
    except Exception as e:
        print(f"Could not interpret as float: {e}")
else:
    print("Modbus exception:", response)
```

The result will confirm or deny the 32-bit hypothesis. It will tell us if we are looking at a simple integer total or 
a more complex floating-point representation.

**(Ponder's Field Notes)**

**File:** `active_recon_phase2.md`

The results from `decode_register_0_type.py` are clear:

```
Register 0 (low word): 15934
Register 1 (high word): 0
Combined 32-bit value: 15934
As 32-bit float: 0.185546875
```

Right. So Register 1 is just zero. Not a 32-bit integer totaliser then. The float interpretation (0.185546875) is a 
neat fraction (19/1024). That's almost certainly meaningless, just the bytes of the integer 15934 being reinterpreted 
as an IEEE 754 float. A coincidence. It doesn't mean the data is stored as a float.

Conclusion: Register 0 is a 16-bit unsigned integer totaliser. It will wrap at 65535. At its current rate 
(~15 units per 5 seconds), that's about 6 hours.

This isn't a major process total. More like a counter for a secondary loop. A timer. Or a tally of events within 
the simulator's cycle.

But more importantly: the pattern. A single active 16-bit word followed by zeros. That structure appeared in my 
initial block read: `[value, 0, 0, 0, ...]`.

I need to find if there are other such islands of data. A sparse scan makes sense. Check strategic points in the 
address space without being aggressive.

`sparse_modbus_scan.py`:

```python
from pymodbus.client import ModbusTcpClient
import time

client = ModbusTcpClient('127.0.0.1', port=10520)

# Strategic checkpoints in the memory map
scan_points = [
    0,      # Known active
    100,    # Common input area
    300,    # Holding registers
    400,    # Classic 4xxxx area (adjusted to 0-based)
    500,
    1000,   # Extended memory
    2000,
    3000,
    4000,
    5000
]

print("Starting sparse memory scan...")
print("Address : Values (first two registers)")
print("-" * 40)

for address in scan_points:
    try:
        client.connect()
        response = client.read_holding_registers(address=address, count=2, device_id=1)
        client.close()
        
        if not response.isError():
            values = response.registers
            # Only report non-zero findings
            if values[0] != 0 or values[1] != 0:
                print(f"{address:4d}    : {values}")
        else:
            # Errors are data too
            print(f"{address:4d}    : Modbus Error - {response}")
            
        time.sleep(0.5)  # Gentle pacing
        
    except Exception as e:
        print(f"{address:4d}    : Connection error - {e}")
        client.close()

print("Scan complete.")
```

Running this will tell me if there are other active data points. If I find them, I'll need to determine if they're 
static (parameters) or dynamic (variables).

The architecture is becoming visible. Isolated data islands. A control system's memory map, exposed through this 
gateway server.

Results:

```bash
$ python sparse_modbus_scan.py
Starting sparse memory scan...
Address : Values (first two registers)
----------------------------------------
   0    : [17630, 0]
 300    : Modbus Error - ExceptionResponse(dev_id=1, function_code=131, exception_code=2)
 400    : Modbus Error - ExceptionResponse(dev_id=1, function_code=131, exception_code=2)
 500    : Modbus Error - ExceptionResponse(dev_id=1, function_code=131, exception_code=2)
1000    : Modbus Error - ExceptionResponse(dev_id=1, function_code=131, exception_code=2)
2000    : Modbus Error - ExceptionResponse(dev_id=1, function_code=131, exception_code=2)
3000    : Modbus Error - ExceptionResponse(dev_id=1, function_code=131, exception_code=2)
4000    : Modbus Error - ExceptionResponse(dev_id=1, function_code=131, exception_code=2)
5000    : Modbus Error - ExceptionResponse(dev_id=1, function_code=131, exception_code=2)
Scan complete.
```

The server appears to have a very sparse memory map:

- Only address 0 (and possibly address 100, though not shown) are accessible
- Most standard Modbus address ranges (300-5000) are either:

  - Not implemented
  - Protected/restricted
  - Require different function codes or device IDs

Noted for further development of the simulator! [Check out some other discovery scripts here.](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/discovery)
