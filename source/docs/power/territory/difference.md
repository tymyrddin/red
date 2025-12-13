# What makes OT different from IT

You're a pentester. You've [broken into web applications](../../in/app/index.rst), 
[compromised Active Directory forests](../../in/network/notes/run-ins.md), and perhaps even 
[made a database cry](../../in/app/techniques/sqli.md). You know your Burp Suite from your Metasploit, your 
privilege escalation from your lateral movement. You are, in the parlance of the trade, rather good at breaking 
things.

Then someone asks you to test an industrial control system.

"How different can it be?" you think. "It's all just computers and networks, right?"

This is the same sort of thinking that leads people to assume that because they can ride a bicycle, they can probably 
fly a helicopter. Technically both involve going places, but the consequences of getting it wrong are somewhat 
different.

## Physical consequences of digital actions

In IT security, when you crash a server, someone gets upset. The website goes down, people can't check their email, 
there might be stern words from management. The worst that happens is someone has to work late to restore from 
backups.

In OT security, when you crash a controller, *things happen in the physical world*.

Consider our running example: Unseen University Power & Light Co. (UU P&L), the venerable institution responsible 
for keeping the lights on across Ankh-Morpork. Their systems include:

- The Hex Steam Turbine Control System, which generates electricity for half the city
- The Bursar's Automated Alchemical Reactor Controls, where incorrect temperatures lead to reactions that are "exciting" in the way that avalanches are exciting
- The Library Environmental Management System, maintaining the precise conditions necessary to prevent L-space from collapsing (and the Librarian from getting upset)
- The City-Wide Distribution SCADA, managing power to everyone from the Patrician's Palace to Mrs. Cake's boarding house

When you send the wrong packet to a PLC controlling a steam turbine, you're not just causing downtime. You might be 
causing the turbine to spin up when it shouldn't, or slam shut a valve whilst hot steam is flowing through it, or 
disable safety interlocks that prevent the boiler from experiencing what engineers euphemistically call "rapid 
unscheduled disassembly".

That web server you accidentally knocked offline? It just stopped responding. This PLC you're testing? It controls a 
robotic arm that's currently welding things, or a valve that's holding back several tons of pressure, or a motor 
that can quite happily continue spinning even after your fingers are caught in it.

The IT security mindset of "break it and see what happens" becomes "carefully observe and predict what might happen 
if we theoretically broke it, then don't actually break it."

## Real-time requirements and timing sensitivity

Your typical web application doesn't care if a response takes 100 milliseconds or 200 milliseconds. Users barely 
notice. The application certainly doesn't stop working.

A PLC running at a 10ms scan cycle absolutely cares about timing. It's reading sensors, making decisions, and 
outputting control signals in a continuous loop. If you interrupt that loop, or flood the network with traffic 
that causes packet loss, or send malformed packets that the PLC needs to waste CPU cycles parsing, you can affect 
the controlled process.

Imagine you're testing the Library's environmental controls. The system maintains temperature and humidity within 
very specific ranges. Too hot, and ancient grimoires start to spontaneously combust. Too humid, and you get mould 
(the magical kind that achieves sentience and starts filing complaints). The controller checks temperatures every 
second and makes adjustments.

Now imagine you run `nmap -A -T5` against that controller.

The aggressive scan hammers the device with thousands of packets. The PLC's modest CPU, designed in an era when 
the fastest thing in computing was a Bursar running from their own expense reports, tries to process this unexpected 
traffic. It falls behind on its scan cycle. It misses a temperature reading. Then another. By the time it catches 
up, the temperature has drifted outside acceptable ranges.

The Library's environmental system, detecting this anomaly, fails safe. It shuts down. The temperature starts rising. 
Books begin to smoulder. The Librarian notices.

And that's how an innocent port scan leads to you being chased across campus by an angry orangutan who knows 
exactly where you live.

## Legacy systems and patch impossibility

In the IT world, patching is a normal part of life. Microsoft Patch Tuesday comes around, you test the patches, 
you deploy them, everyone grumbles but accepts this is how things work.

In the OT world, patching is somewhere between "difficult" and "impossible", with occasional excursions into 
"you must be joking".

That PLC controlling the Hex Steam Turbines? It was installed in 1978. It has been running, without interruption, 
for forty-seven years. It controls the university's primary power generation. Its programming language is a form 
of ladder logic that only three people in the city understand, two of whom are retired, and one of whom is the 
Librarian (who learned it during a brief period of being transformed into a computer terminal).

The manufacturer no longer exists. They were bought by a larger company in 1985, which was then bought by an 
even larger company in 1993, which was then merged with a competitor in 2001, which then divested that division 
to a private equity firm in 2008, which then sold it to another company in 2015, which then went bankrupt in 2019.

There are no patches. There will never be patches. The concept of patches is a distant dream, like world peace or 
a Bursar who understands their own budget.

But it works. It has always worked. And the university's position is that one does not, under any circumstances, 
interfere with things that work. This is a lesson learned over centuries, usually through incidents that required 
rebuilding entire wings of the university.

This means that vulnerability scanning, in the traditional sense, becomes rather pointless. Yes, the PLC is 
vulnerable to seventeen different CVEs. Yes, an attacker with network access could do terrible things. But you 
cannot patch it. You cannot upgrade it. You cannot even restart it without scheduling a city-wide power outage 
three months in advance.

Your job as a pentester shifts from "find vulnerabilities and recommend patches" to "find vulnerabilities and 
recommend compensating controls that don't involve touching the actual system".

## Safety systems and interlocks

OT environments are full of safety systems. These are the mechanisms that prevent accidents, like boilers exploding 
or reactors melting down or the Librarian's bananas being stored at incorrect temperatures (this last one is 
technically a comfort system, but the Librarian's comfort and everyone else's safety are closely related concepts).

These safety systems are often separate from the control systems. They're designed to fail safe. If power is lost, 
they default to the safest state. If they detect an anomaly, they shut everything down.

This is excellent for safety. It's less excellent when you're trying to test security.

Consider the alchemical reactor controls. The reactor has multiple safety interlocks:

- Temperature sensors that trigger emergency cooling if things get too hot
- Pressure relief valves that open automatically if pressure exceeds safe limits  
- Containment field monitors that shut down the reaction if the magical shielding weakens
- A big red button that the Bursar can press if they panic (which is often)

These systems are deliberately simple. They don't communicate over the network much, because network failures 
shouldn't prevent safety systems from working. They're hardwired where possible. They're redundant.

But they're not entirely separate from the control network. Monitoring data flows back to the SCADA system. The 
engineering workstation can query their status. And in a few unfortunate cases, someone decided it would be 
convenient if you could also acknowledge alarms or bypass interlocks remotely "just in case an engineer needs to do 
maintenance".

The job as a pentester includes:

1. Not triggering safety systems accidentally (annoying, causes downtime)
2. Not disabling safety systems accidentally (dangerous, possibly criminal)
3. Testing whether attackers could trigger safety systems maliciously (denying service by making the plant shut itself down)
4. Testing whether attackers could disable safety systems maliciously (extremely dangerous, definitely criminal if they succeed)

The fourth point is particularly delicate. You need to determine if it's possible to disable safety systems without 
actually doing it. This requires creativity, documentation, and very careful conversations with the people who own 
the systems.

"Could I theoretically send commands to disable this interlock?" is a question you need to answer.

"Let me test that by actually disabling the interlock and seeing what happens" is not a question. It's a resignation 
letter written in packet captures.

## The mythology of air gaps

In OT security, you will frequently hear about "air gaps". The OT network, you'll be told, is completely separate from 
the corporate IT network. There is no connection. It's physically isolated. Therefore, it is secure.

This is the sort of comforting fiction that people tell themselves, like "the Patrician doesn't know what you did" or 
"that's probably just a normal rat, not a Death of Rats".

The reality at UU P&L, as at most organisations with OT, is rather different:

### The "air gap" that has WiFi

The turbine control network is indeed on separate physical cabling from the corporate network. However, a 
contractor installed a wireless access point in the turbine hall "for convenience during maintenance". This 
access point is connected to both networks. The air gap is now more of an air suggestion.

### The "isolated" network with the jump box

The SCADA network has no direct connection to the corporate network. Instead, there's a jump box that connects to 
both networks, allowing operators to access SCADA systems from their corporate workstations. This jump box runs 
Windows Server 2003 (because upgrading might break something), has no antivirus (because it might interfere with 
SCADA), and has the same admin password it's had since installation (because changing it would require updating 
documentation, and nobody wants to do that).

### The "separated" systems that share a historian

The control systems are separate. The corporate IT systems are separate. But both send data to the same historian 
database for long-term storage and reporting. And that historian? It's on the corporate network because the IT 
department said having a database server they couldn't patch or monitor was "against policy".

### The "disconnected" network with vendor remote access

The engineering network has absolutely no connection to the outside world. Except for the VPN concentrator that 
vendors use for remote support. Which has been configured to allow vendor access 24/7 rather than only during 
scheduled maintenance windows. And which several ex-employees still have credentials for. And which routes 
directly to the control network.

### The "air gap" that has USB ports

Even if the network truly is isolated (rare), engineers still need to update programs and transfer files. So they 
use USB drives. These same USB drives get used on corporate workstations, personal laptops, and occasionally their 
home computers where their teenage children are downloading questionable software.

Air gaps are a lovely theory. In practice, they're full of holes, like a philosophical argument constructed by 
the Bursar after too much sherry.

The job as a pentester includes documenting all the ways the "air gap" isn't actually an air gap, ideally before 
someone less friendly than you discovers them.

## Why OT people distrust IT people (and vice versa)

In any organisation with both OT and IT departments, there exists a certain amount of mutual suspicion.

The IT department thinks OT is living in the past, refusing to adopt basic security practices, running ancient 
operating systems, and generally being difficult about perfectly reasonable policies like "all systems must be 
patched within 30 days" and "all systems must run approved antivirus software".

The OT department thinks IT is reckless, doesn't understand the consequences of their actions, wants to patch 
things during production hours, and keeps trying to "improve" systems that have been working perfectly well since 
before the IT department existed.

Both are partly right.

At UU P&L, this tension manifests in various ways:

The IT department once tried to enforce a policy requiring all systems to restart monthly for patching. They pushed 
this to the turbine control system during production hours. The turbines shut down. Half of Ankh-Morpork lost power. 
The Patrician was not amused. The IT director learned the meaning of the phrase "strongly worded letter". The OT 
department has not forgotten.

The OT department runs Windows XP on the engineering workstations because "the SCADA software only works on XP". They 
refuse to let IT install antivirus because "it might interfere with the real-time response". They won't allow IT to 
access the OT network for security monitoring because "you'll break something". When WannaCry ransomware hits the 
corporate network and spreads to OT via that "air-gapped" connection, IT gets blamed for not protecting OT, despite 
having been denied access to protect it.

Understanding this dynamic is crucial for successful OT security testing. A pentester would need to work with both 
departments, convince them you understand their concerns, and build trust. This is often harder than the technical 
testing itself.

The IT department needs to understand that you won't recommend patching production systems without extensive testing 
and planned outage windows.

The OT department needs to understand that you're not going to accidentally shut down the turbines (probably), and 
that identifying vulnerabilities is better than having someone less friendly find them first.

And both need to understand that security isn't about making their lives difficult, it's about preventing situations 
that would make everyone's lives significantly more difficult.

This is what makes OT security testing different from IT security testing. It's not just the technical challenges. 
It's the political, organisational, and cultural challenges. It's the understanding that these systems were built 
when security meant "put a lock on the door", and that retrofitting modern security onto 1970s hardware is like 
trying to install airbags in a horse-drawn carriage.

But it needs doing. Because the alternative is leaving the Hex Steam Turbines, the alchemical reactor, and the 
Library's environmental controls accessible to anyone who can plug into a network jack or guess a password.

And nobody wants to explain to the Librarian why the temperature controls are now being operated by a teenage 
hacker from Pseudopolis who thought it would be funny to make all the thermostats read "Ook".
