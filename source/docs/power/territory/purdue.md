# OT architectures and the Purdue Model

If you ask an OT security consultant how an industrial network should be designed, they'll pull up a diagram called 
the [Purdue Enterprise Reference Architecture](https://www.pera.net/), point to its neat layers, and explain how 
everything should be properly segmented with firewalls between each level.

If you then visit an actual industrial facility, you'll discover that the Purdue Model is to real OT networks what a 
tube map is to actually navigating London. Technically accurate in a theoretical sense, but not particularly useful 
when you're lost somewhere between Rotterdam and a crying fit.

Still, understanding the model helps. It gives you a framework for understanding what you're looking at when you 
start mapping the network, and it gives you a vocabulary for explaining to people why their current setup might 
be considered "suboptimal" (consultant-speak for "a disaster waiting to happen").

## The Purdue Enterprise Reference Architecture explained

The Purdue Model divides an industrial organisation into levels, from 0 to 5. Think of it as a layer cake, where 
each layer should only talk to the layers immediately above and below it, and definitely should not let the 
corporate WiFi talk directly to the turbine emergency shutdown system.

### Level 0: Physical processes

This is the actual stuff. The turbines spinning, the alchemical reactions happening, the heating and cooling occurring. 
It's not computers, it's physics and chemistry and occasionally magic (at UU P&L, the distinction between sufficiently 
advanced technology and low-grade magic is somewhat blurry).

At this level, you have:
- Sensors measuring temperature, pressure, flow, rotation, magical field strength
- Actuators controlling valves, motors, heaters, thaumic dampers
- The actual dangerous things that can hurt people if controlled incorrectly

You don't pentest Level 0 directly. You can't port scan thermodynamics. But you need to understand it because 
everything else exists to monitor and control this level.

### Level 1: Basic control

This is where PLCs, RTUs, and other controllers live. These are the computers that directly read sensors and control 
actuators. They're running tight control loops, often scanning at 10-100ms intervals, making decisions based on 
ladder logic or function blocks programmed by engineers who thought "security" meant "don't let operators change 
the setpoints without a password".

At UU P&L's turbine control system, Level 1 includes:
- The ancient Allen-Bradley PLCs controlling each turbine
- The safety PLC that shuts everything down if parameters exceed safe ranges
- The motor controllers for pumps and fans
- Various remote I/O modules scattered throughout the turbine hall

These devices typically speak protocols like Modbus, S7comm, EtherNet/IP, or proprietary protocols that the vendor 
swears are secure but will not let you audit. They rarely have proper authentication. They assume that being on the 
control network means you're authorised to send commands.

This is like assuming everyone in Ankh-Morpork is friendly because they're in the same city as you. Technically 
they're all locals, but that doesn't mean you should let them hold your wallet.

### Level 2: Supervisory control

This level hosts the SCADA servers, HMIs, and data historians. It's where operators actually interact with the 
system, viewing pretty graphics of the process and occasionally pressing buttons that make things happen at Level 1.

At UU P&L:
- The main SCADA server running software that predates the Patrician's current term in office
- HMI workstations in the control room showing animated diagrams of turbines, reactors, and power distribution
- The historian database storing years of operational data (and occasionally crashing because nobody thought to limit its size)
- Engineering workstations with the software needed to reprogram PLCs

Level 2 is where security starts to look more like IT security. These are often Windows machines running applications 
with web interfaces, databases, and network services. They have the usual Windows vulnerabilities plus 
application-specific vulnerabilities plus configuration mistakes.

The catch is that compromising Level 2 gives you control over Level 1. If you can log into the SCADA server, you 
can send commands to PLCs. You don't need to attack the PLCs directly when you can just use the legitimate control 
interface.

This is rather like not bothering to pick the lock on the castle door when you can just walk in with the guards 
during shift change.

### Level 3: Operations management

This level includes production management systems, batch management, manufacturing execution systems (MES), and 
other systems that manage operations but don't directly control processes.

At UU P&L, Level 3 includes:
- The production scheduling system that decides when to run the turbines at full capacity vs partial load
- The maintenance management system tracking when equipment needs service
- The quality management system ensuring power output meets specifications
- Various reporting systems that managers use to make dashboards nobody reads

Level 3 typically runs on standard IT infrastructure. Windows or Linux servers, databases, web applications. It 
connects to Level 2 to get data and sometimes send production schedules or setpoints.

Security-wise, this level is more IT-like, but compromising it can give attackers useful information about operations
and potentially pathways down to Level 2.

### Level 4: Business logistics

Enterprise Resource Planning (ERP), supply chain management, business intelligence. This is where the business side 
of the organisation lives.

At UU P&L:
- The university's general accounting system
- The system tracking how much power is sold to different parts of the city
- HR systems (though at UU P&L, "HR" consists of the Archchancellor's secretary and a filing cabinet)
- The purchasing system for ordering coal, magic reagents, and bananas

Level 4 is entirely IT. It's on the corporate network. It should have no direct connection to the control systems.

Should.

### Level 5: Enterprise

Wide area networks, connections to other facilities, internet access, email, cloud services. The outside world.

This is where threats come from. Phishing emails, compromised websites, advanced persistent threats, ransomware, 
and bored teenagers who think they're hackers because they installed Kali Linux.

## Where theory meets reality (badly)

The Purdue Model assumes clean separation between levels. In practice, reality has a different opinion.

At UU P&L, like at most industrial facilities, the actual network architecture has evolved organically over decades. 
Different systems were added at different times by different vendors with different ideas about networking. The 
result is less "carefully layered architecture" and more "archaeological dig site revealing sedimentary layers of 
bad decisions".

### The Level 2/3 confusion

The historian database is technically Level 2 (supervisory control), but it needs to be accessed by Level 3 and 4 
systems for reporting. So it sits on a network that's sort of between Level 2 and 3. It has firewall rules allowing 
connections from corporate workstations. Those same workstations can get phishing emails. That same historian 
can query the SCADA server. The SCADA server can send commands to PLCs.

Congratulations, you've just connected the Patrician's email to the turbine controls through only three intermediary 
systems. What could possibly go wrong?

### The vendor backdoor problem

The turbine manufacturer requires remote access for support. This VPN tunnel goes straight from the internet 
(Level 5) to the engineering workstation (Level 2), completely bypassing all the theoretical security layers.

The vendor argues this is necessary because when something breaks, they need immediate access. The OT department 
agrees because the contract says "four-hour response time" and that's impossible if you have to coordinate through 
multiple levels of IT security.

So there's a permanent hole through the entire security architecture, documented in a binder that nobody remembers 
exists, protected by credentials that haven't been rotated since installation.

### The wireless access point that should not exist

There's a wireless access point in the turbine hall. It's not in any network diagram. The IT department didn't 
install it. The OT department claims they didn't install it. Yet there it is, broadcasting `TurbineHall_Temp`, 
connected to both the control network and the corporate network, with the default admin password still set to "admin".

Someone, at some point, needed to access something wirelessly during maintenance. They installed this access point 
as a "temporary solution". That was eight years ago. It's now load-bearing infrastructure that nobody dares remove 
because nobody's entirely sure what is using it.

### The flat network pretending to be segmented

The original design called for separate VLANs for each level. Level 1 devices on VLAN 10, Level 2 on VLAN 20, Level 3 
on VLAN 30.

Someone configured these VLANs on the switches. Someone even documented this in a network diagram that's proudly 
displayed in the control room.

What nobody did was configure any inter-VLAN filtering. All the VLANs route to each other with no firewall rules. The 
segmentation is purely decorative, like the gargoyles on the university buildings. Impressive to look at, but 
providing no actual protection.

### The jump boxes that jump too far

There are "secure" jump boxes that operators use to access control systems from corporate workstations. These jump 
boxes are supposed to be hardened, monitored, and tightly controlled.

In practice, they're Windows 7 machines with RDP enabled, shared passwords written on sticky notes, no antivirus 
(might interfere with SCADA), no patching (might break something), and full administrative rights on both the 
corporate and control networks.

They're not so much "jump boxes" as "helpful bridges for attackers". The only thing they successfully jump is to 
conclusions about their own security.

## Common architectural sins

Having pentested enough OT environments, certain patterns emerge. These are the architectural decisions that make 
security testers develop a nervous twitch. Be prepared to be surprised.

### The everything-can-talk-to-everything network

No segmentation. No firewall rules. Every device can reach every other device on every port. It is less a 
"network architecture" and more a "network anarchy".

The justification is usually that segmentation might break something, or that engineers need to be able to 
troubleshoot from anywhere, or that the switches don't support VLANs (which raises the question of why they 
bought switches from 1995).

At UU P&L, the turbine control network is completely flat. An operator workstation in the control room can directly 
connect to the turbine PLCs. The engineering laptop connected to a switch in the turbine hall can directly 
connect to the SCADA server. The contractor's laptop plugged in for ten minutes to diagnose a sensor can see everything.

This means that if you compromise any device on the network, you've effectively compromised all of them. There's no 
need for lateral movement when lateral is the only direction available.

### The perimeter security fallacy

Some organisations focus all their security on the perimeter. Strong firewall between corporate and OT networks. 
VPN with two-factor authentication. Regular penetration testing of external-facing systems.

Meanwhile, once you're inside the OT network, there's nothing. No monitoring, no segmentation, no access controls. 
It's a hard crunchy shell protecting a soft chewy centre.

This is the security model employed by many medieval castles: strong walls, nothing inside. It works until someone 
gets inside, at which point everyone's equally accessible to pillaging.

At UU P&L, the firewall between corporate IT and OT networks is relatively robust. It has rules, logging, regular 
reviews. But once you're on the OT network (via that wireless access point, or the jump box, or social engineering a 
contractor, or physically walking into the turbine hall), you can reach everything.

### The single point of failure that's also a single point of compromise

Critical systems should be redundant. If the primary SCADA server fails, a backup should take over.

But often, both primary and backup servers sit on the same network, with the same access controls, accessible from 
the same compromised jump box. Redundancy for availability, but not for security.

At UU P&L, there are two SCADA servers: primary and backup. Both have the same admin password (for "consistency"). 
Both are accessible from the same engineering workstation. Both trust the same historian database. Compromising one 
means compromising both, which means you can maintain persistent access even if someone notices unusual activity and 
restarts the primary server.

### The DMZ that isn't

Many sites have a "DMZ" between corporate and OT networks. In theory, this is a separate network segment hosting 
services that need access to both networks, with firewalls on both sides controlling traffic.

In practice, the DMZ often has:
- Full access to corporate network resources
- Full access to OT network resources
- Minimal monitoring
- Systems that haven't been patched in years because nobody's sure which department is responsible

It's less a "demilitarised zone" and more a "we put some servers here and hoped security would emerge spontaneously".

At UU P&L, the DMZ hosts the historian, the business intelligence server, and several other systems that have 
accumulated over time. The firewall rules allow bidirectional access on nearly all ports because "various applications 
need various services". The DMZ is actually more permissive than either network it's supposedly separating.

## Data diodes and other expensive solutions

Eventually, someone in management reads an article about the importance of OT security. They demand that IT and 
OT work together to "properly segment the networks".

Several meetings occur. Consultants are brought in. PowerPoint presentations are delivered. Budgets are allocated.

Then someone mentions data diodes.

### Data diodes in theory

A data diode is a hardware device that allows data to flow in only one direction. Physically, electrically impossible 
to send data backwards. You can send data from OT to IT for monitoring and reporting, but IT cannot send commands 
back to OT.

This sounds perfect. OT can send operational data up to business systems without creating a path for malware or 
attackers to come back down.

### Data diodes in practice

They're expensive. Very expensive. The cost of proper data diodes makes people's eyes water, followed shortly by 
their finance directors' eyes watering.

They require careful configuration. You need to specify exactly what data flows through them, in what format, 
at what frequency. This requires understanding what's actually needed, which requires talking to both IT and OT 
departments, which requires meetings, which requires scheduling, which requires ...

Several months pass.

They break some workflows. People discover they were relying on bidirectional communication for things nobody 
documented. The historian needs to query the SCADA server sometimes, not just receive data. The business 
intelligence system needs to send setpoints occasionally. Engineers need to download logs remotely.

Exceptions are made. Bypass mechanisms are created. The data diode remains, protecting a network segment that's 
now accessible via seventeen different alternative routes.

At UU P&L, there was a proposal to install data diodes between Level 2 and Level 3. The cost was £200,000. The 
project was approved. The equipment was ordered.

Then someone discovered that the production planning system occasionally needed to send new recipes and setpoints 
down to the SCADA system. The data diode would prevent this. Several options were considered:

1. Accept that production planning can only send data via scheduled, manual updates (rejected as operationally unworkable)
2. Install a bidirectional data diode with protocol break and manual approval (defeats the purpose, adds complexity)
3. Create an exception process where critical updates go through an alternative path (creates the hole we're trying to close)
4. Actually document and redesign the data flows to separate monitoring from control (the correct solution, but requires time and money)

The project stalled. The data diodes remain in storage. The network remains exactly as permissive as before, but now 
there's equipment depreciating on the balance sheet.

## Jump hosts and their surprisingly long jumps

The jump host (or jump box, or bastion host) is a common compromise solution. You can't let corporate users directly 
access OT systems (security risk), but you can't make OT completely inaccessible from corporate (operational nightmare).

Solution: a hardened server that sits between networks. Users RDP or SSH to the jump host from corporate, then connect 
from the jump host to OT systems. All access goes through this controlled chokepoint, which is monitored, logged, and 
secured.

In theory.

In practice, jump hosts at many sites are:

### Under-maintained

Nobody's quite sure who's responsible for patching them. IT says they're OT's responsibility. OT says they're IT's 
responsibility. The compromise is that nobody does it.

At UU P&L, the main jump host runs Windows Server 2008 R2. Support ended in 2020. It hasn't been patched since 
2018 because "we need to test patches in dev first" and nobody's quite sure where the dev jump host is or if it exists.

### Over-privileged

The jump host needs access to OT systems. The easiest way to grant this is making it a domain admin (on both 
corporate and OT domains if separate domains exist). Now compromising one Windows server gives you administrative 
access to everything.

### Shared accounts everywhere

Rather than dealing with individual user authentication, there's often a shared "engineer" or "operator" account 
that everyone uses to log into the jump host. The password is known to dozens of people, written in multiple places, 
and never changed because that would require updating all those written copies.

### No monitoring that anyone watches

There's often logging configured on jump hosts. The logs go to a SIEM. The SIEM generates alerts. The alerts go to 
an email inbox that nobody monitors because there are thousands of alerts per day and everyone's trained themselves 
to ignore them.

At UU P&L, the jump host logs to the IT department's SIEM. The SIEM categorises OT access as "medium priority". In 
the four years it's been operating, nobody has ever reviewed these logs except after an incident.

This means you can compromise a corporate workstation, RDP to the jump host with shared credentials, connect to 
SCADA systems, and nobody will notice unless you do something dramatic like shut down the turbines.

And even then, most likely they'll blame a control system malfunction before they check the access logs.
