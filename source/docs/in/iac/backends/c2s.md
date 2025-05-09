# About C2's

One could view BeEF as a C&C, but ... BeEF is a tool designed to provide effective client-side attack vectors and to 
exploit any potential vulnerabilities in the web browser. Ideal for demonstrating and explaining these attack 
vectors. It is unique among the C&C frameworks because it does not try to tackle the more secure network interface 
aspects of a system. These C&C's can. With enough time later, we can give BYOB or Merlin a whirl.

## Centralised C2

With a centralised command and control model, a malware "client" will phone home to a C2 server and check for 
instructions. The server-side infrastructure can include redirectors, load balancers, and defence measures to detect 
security researchers and law enforcement. Public cloud services and Content Delivery Networks (CDNs) are often used to 
host or mask activity.

The domains and servers can be removed within hours of their first use, and the malware is often coded with a list of 
different C2 servers to try and reach.

## P2P C2

In a P2P C2 model, command and control instructions are delivered to members of a botnet relaying messages between one 
another. Some nodes can function as server, but there is no central or master node. This makes it harder to detect or 
disrupt than a centralised model but can also make it more difficult to issue instructions to the entire botnet. 

P2P networks can be used as a fallback mechanism in case the primary centralised C2 channel is disrupted.

## Out of Band

Twitter, Gmail, IRC chat rooms, and even Pinterest can be used to issue C&C messages to compromised hosts.

## Random

Command and control infrastructure can even be random, and use scanning the Internet to find an infected host. This is 
extremely hard to take down.

## C2 Frameworks

* [BYOB](https://github.com/malwaredllc/byob) <=
* [Cobalt Strike](https://www.cobaltstrike.com/) 
* [Covenant](https://github.com/cobbr/Covenant/)
* [Empire](https://github.com/EmpireProject)
* [Koadic](https://github.com/zerosum0x0/koadic) <=
* [Metasploit](https://www.metasploit.com/)
* [Merlin](https://github.com/Ne0nd0g/merlin) <=
* [Sillenttrinity](https://github.com/byt3bl33d3r/SILENTTRINITY)

## Documentation and support

* [BYOB (Build Your Own Botnet) Wiki](https://github.com/malwaredllc/byob/wiki)
* [BYOB Discord support server](https://discord.gg/8FsSrw7)
* [Merlin documentation](https://merlin-c2.readthedocs.io/en/latest/index.html)

## Articles

* [MITRE | ATT&CK Command and Control](https://attack.mitre.org/tactics/TA0011/)
* [Using Merlin agents to evade detection](https://resources.infosecinstitute.com/topic/using-merlin-agents-to-evade-detection/)
