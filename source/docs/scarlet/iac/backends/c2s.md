# About C2s

A command and control framework manages the implants on compromised hosts: it issues tasks, collects results, and
moves data. Choosing one is a trade-off between detection risk, feature set, licence, and maintenance state.

## Centralised C2

With a centralised model, an implant phones home to a C2 server and checks for instructions. The server-side
infrastructure can include redirectors, load balancers, and defence measures to detect security researchers and
incident responders. Public cloud services and Content Delivery Networks (CDNs) are often used to host or mask
activity.

The domains and servers can be removed within hours of their first use, and the implant is often coded with a list
of different C2 servers to try and reach.

## P2P C2

In a P2P C2 model, command and control instructions are delivered to members of a botnet relaying messages between
one another. Some nodes can function as server, but there is no central or master node. This makes it harder to
detect or disrupt than a centralised model but can also make it more difficult to issue instructions to the entire
botnet.

P2P networks can be used as a fallback mechanism in case the primary centralised C2 channel is disrupted.

## Out of band

Discord, Telegram, GitHub repositories, public cloud storage, and even Pinterest have been used to issue C2
messages to compromised hosts. The signal hides inside the noise of normal traffic to a high-reputation service.

## Random rendezvous

C2 infrastructure can scan the Internet to find an infected host on a known port, rather than the host beaconing
out. This is hard to take down because there is no fixed server to seize, but it is also hard to operate at scale.

## Active open-source frameworks (2026)

* [Sliver](https://github.com/BishopFox/sliver) (Go, multiplayer, replaces Empire and SilentTrinity in most
workflows).
* [Mythic](https://github.com/its-a-feature/Mythic) (modular, multi-agent, web UI).
* [Havoc](https://github.com/HavocFramework/Havoc) (modern open-source successor to Cobalt Strike's UX).
* [Metasploit](https://www.metasploit.com/) (still useful for Linux, heavily signatured on Windows).

## Commercial frameworks

* [Cobalt Strike](https://www.cobaltstrike.com/) (the long-standing commercial flagship).
* [Brute Ratel C4](https://bruteratel.com/) (heavy investment in EDR evasion).
* [Nighthawk](https://www.mdsec.co.uk/nighthawk/) (MDSec, vetting-only).

## Largely abandoned, kept for reference

* [Empire](https://github.com/EmpireProject) and [BC-Security Empire](https://github.com/BC-SECURITY/Empire)
(PowerShell-based; the original team stopped, BC Security maintenance is intermittent).
* [SilentTrinity](https://github.com/byt3bl33d3r/SILENTTRINITY) (.NET DLR; abandoned).
* [Covenant](https://github.com/cobbr/Covenant/) (.NET; maintenance gaps).
* [Koadic](https://github.com/zerosum0x0/koadic) (Windows Script Host; abandoned).
* [Merlin](https://github.com/Ne0nd0g/merlin) (Go HTTP/2; sporadic activity).

## Articles

* [MITRE ATT&CK Command and Control](https://attack.mitre.org/tactics/TA0011/)
* [Sliver documentation](https://sliver.sh/docs)
* [Mythic documentation](https://docs.mythic-c2.net/)
