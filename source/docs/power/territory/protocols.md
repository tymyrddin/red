# On the peculiar languages of machines

The Patrician's request was clear, as his requests tend to be. The consequences of getting it wrong were equally 
clear, and involved words like "catastrophic", "city-wide", and "inexplicably amphibious".

My first task was to listen. Not to the engineers, who spoke of resilience and scheduled maintenance, but to the 
systems themselves. I plugged a carefully vetted laptop into what was poetically termed a "diagnostic port" in the 
turbine hall and was promptly deafened by a digital Babel. This was not the familiar chatter of HTTP or the orderly 
procession of TCP handshakes. This was something older, louder, and blithely unconcerned with concepts like 
"authentication" or "secrecy".

I had stepped from the modern world of informational security into the operational world, where the protocols were 
forged in an age of physical locks and implicit trust. If you could hand a note to the clerk, you were assumed to 
have the right to do so. The notes, however, could now be delivered at the speed of light from anywhere in the world.

## Modbus: the clerk who never asks for ID

The most pervasive tongue was [Modbus](https://modbuskit.com/en/blog?category=protocol), a protocol from 1979 that 
runs the Library's environmental system. It operates on a logic of sublime simplicity. To read a temperature, you 
send function code 04. To turn on a cooling pump, or a "coil" in its parlance, you send function code 05. Port 502 
is its desk. There is no receptionist. There is no request for credentials. If your packet arrives at the right 
address, it is acted upon. It is a system built for a closed room where everyone is a colleague. We have since 
connected that room to the entire university network, and by extension, to a disconcerting number of coffee shops 
in Pseudopolis. Tools like `mbtget` or the Python library `pymodbus` can conduct these conversations with trivial ease.

At UU P&L, the turbine governor loop runs on Modbus TCP. The PLC on port 502 accepts holding register writes to 
adjust the governor setpoint and coil writes for emergency stops, from any host that can reach it, without a 
password or a greeting.

## IEC-104: the substation protocol that believes in trust

[IEC 60870-5-104](https://en.wikipedia.org/wiki/IEC_60870-5) is the European power industry's standard for 
communicating between control centres and field devices over TCP/IP. Where Modbus is a factory protocol that 
wandered into power systems, IEC-104 was designed specifically for substations: it carries breaker states, voltage 
measurements, current values, and frequency readings from the field to whoever is asking.

Port 2404 is its door. There is no lock on it. The protocol has no authentication mechanism. The assumption, as 
with Modbus, was that access to the substation network was itself the security control.

What makes UU P&L's substation RTU additionally interesting is a REST management API on port 8080, added by the 
vendor for commissioning and never restricted afterwards. Writing to a datapoint via the REST API pushes a 
spontaneous IEC-104 update to any connected SCADA master within one cycle. This means the attacker does not even 
need to speak IEC-104. A single `curl` command is sufficient to forge a frequency reading, a voltage measurement, 
or a breaker state that the control centre then acts upon as though it were real.

```bash
# Read current substation datapoints
curl http://10.10.5.14:8080/datapoints

# Inject a false under-frequency reading
curl -X POST http://10.10.5.14:8080/datapoints/4 \
     -H 'Content-Type: application/json' \
     -d '{"value": 47.2}'
```

The [c104](https://pypi.org/project/c104/) Python library handles the protocol itself, if one wishes to test the 
IEC-104 endpoint directly. The REST API, however, is the easier path, and the one that requires no specialist 
knowledge of the protocol at all.

## MQTT: the postman who does not check the address

[MQTT](https://mqtt.org/) was designed for constrained devices on unreliable networks. It is now the lingua franca 
of industrial IoT data aggregation: a publish-subscribe protocol where devices publish telemetry to a broker, and 
any subscriber with access to the broker receives it. Port 1883. No authentication by default.

At UU P&L, the Neuron gateway in the Guild Quarter DMZ publishes live process telemetry to the MQTT broker 
`clacks-relay` at 10.10.5.12. The broker accepts anonymous connections. An attacker who can reach it can subscribe 
to every topic the gateway publishes, receiving live operational data without touching the control zone directly.

```bash
# Subscribe to all topics on the broker
mosquitto_sub -h 10.10.5.12 -t '#' -v
```

The more significant angle is persistence. The Neuron gateway can be configured via its management API with a 
southbound Modbus device pointing into the control zone. Once configured and the session closed, the gateway 
continues polling and publishing indefinitely. An attacker who adds a southbound device to the Neuron configuration 
and then disconnects has established a data channel that outlasts their session, accessible to any MQTT subscriber 
on the DMZ or the city network.

## OPC UA: the modern lock left unlatched

Then there is [OPC UA](https://opcfoundation.org/about/opc-technologies/opc-ua/) on port 4840, the new contender 
designed with actual security in mind. It has encryption, certificates, the full paraphernalia of modern trust. 
One finds it in newer SCADA systems and industrial gateways. And yet, in our implementation, it is almost 
invariably configured with `SecurityMode: None` and `Anonymous` access. All that sophisticated machinery, left in 
"demonstration mode" indefinitely. The 
[opcua-asyncio](https://github.com/FreeOpcUa/opcua-asyncio) library can connect, browse the entire address space, 
and call industrial methods without encountering a single cryptographic hurdle. It is a powerful lock installed 
on a door that is propped permanently open with a copy of last year's budget report.

CVE-2025-27615 removed authentication from the umatiGateway web UI in the Guild Quarter, which reveals the OPC-UA 
endpoint address. Anonymous connection with SecurityMode None then permits method calls on industrial objects. 
The vulnerability chain is two hops; neither requires credentials.

## The supporting cast: Profinet, BACnet, IEC 61850

The chorus does not end there. Profinet, Siemens' real-time factory protocol, operates at the Ethernet frame level, 
making it invisible to ordinary firewalls. BACnet on port 47808 chatters through every building on campus, managing 
HVAC and lighting with similar disregard for authentication. The power industry's IEC 61850 completes the picture, 
with its own quirks and historical security oversights.

## A unified theory of existential dread

The pattern is both obvious and horrifying. These protocols form the linguistic bedrock of our physical reality; 
they govern steam, electricity, and volatile metaphysics. Yet they were codified for a world where the only threat 
was the occasional incompetent apprentice. They possess no grammar for "Who are you?" or "This message is private."

This creates a professional paradox of the most acute kind. The vulnerability is not a bug; it is a *design feature*. 
The same tool that politely asks the turbine for its RPM can, by changing one number in the request, order it to tear 
itself apart. The line between scholar and saboteur is a single digit.

Thus, the standard pentester's playbook of reconnaissance, exploitation, and proof becomes an act of unbearable 
restraint. I could map the entire nervous system of UU P&L, but to demonstrate the most critical flaws was to risk 
becoming the very catastrophe I was hired to prevent. I could write in my report, "The Modbus interface allows 
unauthenticated command of the primary coolant pump," but I could not, *dare not*, send that command to the live 
plant.

The conclusion was inescapable and arrived at with a familiar, sinking feeling. I could not test the *territory*. 
To prove the risk, I needed a perfect, causally correct *map*.

Hence, the simulator. The control zone runs the Modbus devices: the turbine PLC at port 502, the protective relay 
IEDs, the revenue meter. The DMZ contains the OPC-UA gateway and the IEC-104 RTU with its unauthenticated REST 
interface. The MQTT broker sits at the network's published edge, receiving telemetry from the Neuron gateway. Now, 
from the safety of a sandboxed terminal, I can use `pymodbus` to send the exact register write that raises the 
governor setpoint above the overspeed threshold, or inject a false frequency reading into the substation RTU via 
a `curl` command. I can watch the log as the command is accepted, the virtual PLC obeys, the physics model 
responds, and the SCADA dashboard tells an increasingly unconvincing story.

It allows me to move from stating a theoretical weakness to presenting Lord Vetinari with a captured specimen of 
the very packet that could darken a district. It translates an abstract threat into a tangible, discrete *thing* 
that can be shown, explained, and defended against. It is, I believe, the only form of evidence that will bridge 
the gap between my technical anxiety and his need for a stable, illuminated city.