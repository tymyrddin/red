# On the peculiar languages of machines

The Patrician's request was clear, as his requests tend to be. The consequences of getting it wrong were equally clear, 
and involved words like "catastrophic", "city-wide", and "inexplicably amphibious".

My first task was to listen. Not to the engineers, who spoke of resilience and scheduled maintenance, but to the 
systems themselves. I plugged a carefully vetted laptop into what was poetically termed a "diagnostic port" in the 
turbine hall and was promptly deafened by a digital Babel. This was not the familiar chatter of HTTP or the orderly 
procession of TCP handshakes. This was something older, louder, and blithely unconcerned with concepts like 
"authentication" or "secrecy".

I had stepped from the modern world of informational security into the operational world, where the protocols were 
forged in an age of physical locks and implicit trust. If you could hand a note to the clerk, you were assumed to 
have the right to do so. The notes, however, could now be delivered at the speed of light from anywhere in the world.

## Modbus: The Clerk Who Never Asks for ID

The most pervasive tongue was [Modbus](https://modbuskit.com/en/blog?category=protocol), a protocol from 1979 that 
runs the Library's environmental system. It operates on a logic of sublime simplicity. To read a temperature, you 
send function code 04. To turn on a cooling pump, or a "coil" in its parlance, you send function code 05. Port 502 
is its desk. There is no receptionist. There is no request for credentials. If your packet arrives at the right 
address, it is acted upon. It is a system built for a closed room where everyone is a colleague. We have since 
connected that room to the entire university network, and by extension, to a disconcerting number of coffee shops 
in Pseudopolis. Tools like `mbtget` or the Python library `pyModbus` can conduct these conversations with trivial ease.

## DNP3: The Garrulous Sub-Station

For the city-wide grid, the language shifts to 
[DNP3 (Distributed Network Protocol)](https://www.dnp.org/About/Overview-of-DNP3-Protocol) on ports 20000. It is 
more conversational. A master station asks for reports, and remote substations send back streams of data about 
circuit breaker states or voltage levels. It has the *potential* for authentication, like a door that *could* have a 
lock fitted. In practice, at UU P&L, the lock is still in its box on a shelf in a storeroom. To probe it, one must 
not shout. One must learn its rhythms in Wireshark and then, perhaps, use `tcpreplay` to repeat a question back with 
a slight, deliberate stumble to see if it confuses the system. The risk of shouting, of flooding it or asking the 
wrong question forcefully, is that the answer might be the very real opening of a breaker and the subsequent 
dimming of lights in the Shades.

## Siemens S7comm: The Secret Guild Handshake

The alchemical reactor speaks S7comm on port 102, the proprietary language of Siemens PLCs. This is not mere data 
exchange; this is the language of *command*. One can ask for the reactor's internal diary, its logic program, or, 
with the right phrase, tell its brain to simply stop. The version in our S7-400 reactor predates the concept of a 
challenge. To know the handshake is to be a guild member. I discovered I could learn the handshake by listening for 
about thirty seconds. The open-source [Snap7](http://snap7.sourceforge.net/) library makes conducting this conversation 
alarmingly straightforward. One can connect, read memory blocks, even stop the CPU, all without so much as a "by 
your leave".

## EtherNet/IP and CIP: Rockwell's Chatty Network

In the turbine hall, the Allen-Bradley ControlLogix PLCs use EtherNet/IP. Do not be fooled by the "IP"; it stands for 
"Industrial Protocol," not Internet Protocol, a distinction that causes endless confusion. It operates over TCP port 
44818 and UDP port 2222, implementing the Common Industrial Protocol (CIP). It presents devices as collections of 
"objects" that can be browsed and manipulated. Its security was, for the longest time, an optional extra. Newer 
versions support CIP Security, but our turbines, like a stubborn old don, refuse to enable it. A library like `cpppo` 
can browse the object tree of a PLC and reveal its identity, firmware, and every tag, or variable, it manages.

## OPC UA: The Modern Lock Left Unlatched

Then there is OPC UA on port 4840, the new contender designed with actual security in mind. It has encryption, 
certificates, the full paraphernalia of modern trust. One finds it in newer SCADA systems. And yet, in our 
implementation, it is almost invariably configured with `SecurityMode: None` and `Anonymous` access. All that 
sophisticated machinery, left in "demonstration mode" indefinitely. The 
[opcua-asyncio](https://github.com/FreeOpcUa/opcua-asyncio) library can connect, browse the entire address space, 
and subscribe to data changes without encountering a single cryptographic hurdle. It is a powerful lock installed 
on a door that is propped permanently open with a copy of last year's budget report.

## The Supporting Cast: Profinet, BACnet, IEC 61850

The chorus does not end there. Profinet, Siemens' real-time factory protocol, operates at the Ethernet frame level, 
making it invisible to ordinary firewalls. BACnet on port 47808 chatters through every building on campus, managing 
HVAC and lighting with similar disregard for authentication. The power industry's IEC 61850 and IEC 60870-5-104 
complete the symphony, each with its own quirks and historical security oversights.

## A Unified Theory of Existential Dread

The pattern is both obvious and horrifying. These protocols form the linguistic bedrock of our physical reality; 
they govern steam, electricity, and volatile metaphysics. Yet they were codified for a world where the only threat 
was the occasional incompetent apprentice. They possess no grammar for "Who are you?" or "This message is private."

This creates a professional paradox of the most acute kind. The vulnerability is not a bug; it is a *design feature*. 
The same tool that politely asks the turbine for its RPM can, by changing one number in the request, order it to tear 
itself apart. The line between scholar and saboteur is a single digit.

Thus, the standard pentester's playbook, reconnaissance, exploitation, proof, becomes an act of unbearable restraint. 
I could map the entire nervous system of UU P&L, but to demonstrate the most critical flaws was to risk becoming the 
very catastrophe I was hired to prevent. I could write in my report, "The Modbus interface allows unauthenticated 
command of the primary coolant pump," but I could not, *dare not*, send that command to the live reactor.

The conclusion was inescapable and arrived at with a familiar, sinking feeling. I could not test the *territory*. 
To prove the risk, I needed a perfect, causally correct *map*.

Hence, the simulator. Its `/components/protocols/` directory is my lexicon of these ancient, dangerous tongues. 
Its `/components/network/servers/` open the same ports. Now, from the safety of a sandboxed terminal, I can use 
`mbtget` to send the exact "emergency stop" code to the *simulated* turbine, or `python-snap7` to halt the virtual 
reactor's CPU. I can watch the log as the command is accepted, the virtual PLC obeys, the physics model spins down, 
and the security monitor screams in alarm. The entire lethal sequence is contained, observable, and, critically, 
*demonstrable*.

It allows me to move from stating a theoretical weakness to presenting Lord Vetinari with a captured specimen of 
the very packet that could darken a district. It translates an abstract threat into a tangible, discrete *thing* 
that can be shown, explained, and defended against. It is, I believe, the only form of evidence that will bridge 
the gap between my technical anxiety and his need for a stable, illuminated city.

