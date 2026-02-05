# The UU Power & Light training programme

*Or: How Ponder's Experience Became A Teaching Curriculum*

## A day of discovery at UU Power & Light

Deep in Ankh-Morpork, Unseen University Power & Light operates from structures that insist they were never meant to be 
buildings, running systems that predate any sensible notion of cybersecurity. 

- Hex Steam Turbines controlled by hardwired logic designed when "network security" meant locking the door. 
- The  Bursar's Automated Alchemical Reactor with control systems accounting for both chemical reactions and metaphysical effects.
- Library Environmental Management where a failed temperature sensor could destabilise L-space itself. 
- City-Wide SCADA integrating decades of infrastructure that was simply added atop whatever came before, never removed, never properly secured. 
- The Archchancellor approved a modernisation project that added network connectivity. Nobody approved authentication.

You have a full day and a simulator full of these gloriously vulnerable systems. No lectures. No rigid schedule. No 
teacher hovering to tell you you're doing it wrong. Pick a challenge, seize control of turbine speeds, steal reactor 
PLC programmes that nation states would covet, map the complete attack surface, operate in pure stealth mode, or create 
the most spectacular cascading failure you can demonstrate safely. 

Work alone or team up. Master one protocol or speedrun them all. Some students spend hours understanding how Modbus 
actually works. Others crash every turbine before lunch and then write custom exploits. The simulator doesn't judge, 
the facilitators don't lecture, and by the end of the day you'll understand viscerally why industrial security is 
magnificently, terrifyingly different from everything IT security taught you. 

[Welcome to the infrastructure keeping the Patrician's city running](../power/workshops/long-day-masterclass/index.rst). 
The coffee is hot, the alarms are probably ignorable, and absolutely nothing requires a password.

## Fixing what you broke: Security hardening

After you've crashed turbines and stolen reactor secrets, here's the difficult part: securing the systems 
without making them unusable, unaffordable, or impossible to maintain. This self-paced study provides eleven hands-on 
challenges using real security components—authentication systems, encryption frameworks, anomaly detection, and 
network segmentation tools. 

You can discover why "just add a password" turns into certificate lifecycle management nightmares, why dual 
authorisation saves lives but drives operators to creative workarounds, and why perfect network segmentation is an 
expensive fiction that operations will never let you implement. You can configure OPC UA encryption and measure 
the performance impact. Deploy jump hosts and handle the aftermath when they fail during emergencies. Implement 
anomaly detection and drown in false positives until you find the right balance. Each challenge ends the same way: 
testing whether your security controls actually work whilst legitimate operators can still do their jobs.

Available as standalone self-study or paired with the Day of Discovery workshop (break things on Day 1, fix them on 
Day 2). 

Challenges range from beginner-friendly configuration changes to expert-level architectural redesigns 
following IEC 62443 standards. The workshop emphasises trade-offs, operational constraints, and the uncomfortable 
truth that real security work is 20% finding vulnerabilities and 80% convincing people to fix them whilst staying 
within budget, meeting compliance requirements, and not shutting down production. You'll finish understanding 
why security professionals who can drive remediation are worth considerably more than those who merely write 
impressive penetration test reports. Components include role-based access control, certificate management, session 
recording, protocol filtering, and complete zone-based network segmentation.

Everything needed to transform UU Power & Light from "anyone can crash this" to 
"[defended in depth, operationally viable, mostly secure](../power/workshops/remediation/index.rst)."


## UU Power & Light masterclass                                                                                                                                                             
                                                                       
Unseen University Power & Light Co. is less a conventional utility company and more an agreement between physics, 
bureaucracy, and several things that ought not to be awake. From repurposed basements and annexes, it supplies 
electricity to the Patrician's Palace whilst managing the Bursar's Automated Alchemical Reactor and maintaining 
environmental controls for the Library, because even minor fluctuations risk L-space destabilisation, and nobody wants 
that on a Tuesday. 
  
The infrastructure is a magnificent archaeological layer cake of systems added over decades, never removed, never 
properly integrated, where experienced staff distinguish ignorable alarms from actual problems and know when equipment 
has developed opinions. And every single protocol is wide open.

You have ninety minutes to conduct a proper red team assessment: probe the Modbus-controlled turbines, extract secrets 
from S7 PLCs, map the SCADA that somehow coordinates all of this, and develop proof-of-concepts dramatic enough to 
matter. 

Then comes the truly difficult part: sixty minutes convincing UU Power & Light's leadership, and ultimately Lord 
Vetinari himself, that these vulnerabilities actually require fixing. 

Finding that industrial control systems lack authentication is easy. Explaining why "just unplug it" isn't a solution 
and proposing remediations whilst a sharp-eyed Patrician asks pointed questions about cost, operational impact, and 
whether you're quite certain you understand how his city's power supply actually works? 
[That's where security careers are made or ended](../power/workshops/masterclass-red-team/index.rst). 


