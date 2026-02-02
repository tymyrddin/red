# What makes OT different from IT

Extract from the field notes of Ponder Stibbons, Lecturer in Applied Inconveniences

I am a pentester. I have [broken into web applications](../../in/app/index.rst), [compromised Active Directory forests](../../in/network/notes/run-ins.md), and on occasion even [made a database cry](../../in/app/techniques/sqli.md). I know my Burp Suite from my Metasploit, my privilege escalation from my lateral movement. One becomes rather good at breaking things.

Then the Patrician asks *me* to test an industrial control system.

"How different can it be?" I thought. "It is all just computers and networks, right?"

This is the same sort of thinking that leads people to assume that because they can ride a bicycle, they can probably fly a helicopter. Technically both involve going places, but the consequences of getting it wrong are somewhat different.

## Physical consequences of digital actions

Observation: In IT security, when you crash a server, someone gets upset. The website goes down. The worst that happens is someone works late to restore from backups.

Observation: In OT security, when you crash a controller, *things happen in the physical world*.

The Unseen University Power & Light Co. (UU P&L) is the institution responsible for keeping the lights on across Ankh-Morpork. I have been asked to assess their systems, which include:

*   The Hex Steam Turbine Control System, which generates electricity for half the city.
*   The Bursar's Automated Alchemical Reactor Controls, where incorrect temperatures lead to reactions described as "exciting".
*   The Library Environmental Management System, which prevents L-space from collapsing.
*   The City-Wide Distribution SCADA, managing power from the Palace to Mrs. Cake's boarding house.

Note to self: A misplaced packet to the turbine PLC is not downtime. It could cause the turbine to overspeed, slam shut a valve under pressure, or disable a safety interlock. Engineers have a euphemism for the latter: "rapid unscheduled disassembly".

That web server I once knocked offline simply stopped. This PLC controls a valve holding back several tons of steam. The IT mindset of "break it and see" must become "predict what would happen if it broke, and do not actually break it".

## Real-time requirements and timing sensitivity

Observation: A web application does not care if a response takes 100 or 200 milliseconds.

Observation: A PLC running a 10ms scan cycle cares deeply. It reads sensors, decides, acts. Interrupt that loop and you affect the physical process.

Consider the Library's environmental controls. The parameters are precise. Too hot, and grimoires combust. Too humid, and one gets sentient mould. The controller checks every second.

Now, imagine running `nmap -A -T5` against it.

The scan hammers the device. The PLC's modest CPU, designed in an era when the Bursar was the fastest computing entity, struggles. It falls behind. It misses a temperature reading. Then another.

The system fails safe. It shuts down. The temperature rises. Books begin to smoulder. The Librarian notices.

Conclusion: An innocent port scan could lead to being chased by an orangutan who knows where I live.

## Legacy systems and patch impossibility

Observation: In IT, patching is routine. Patch Tuesday arrives, patches are deployed.

Observation: In OT, patching exists on a spectrum from "difficult" to "you must be joking".

The Hex Turbine PLC was installed in 1978. It has run without interruption for forty-seven years. Its ladder logic is understood by three people. One is the Librarian, who learned it whilst briefly transformed into a computer terminal.

The manufacturer's corporate lineage is a Russian doll of acquisitions and bankruptcies. There are no patches. There will never be patches.

But it works. The university's position is clear: one does not interfere with things that work.

Implication: Vulnerability scanning becomes an academic exercise. The device is vulnerable, but you cannot patch it, upgrade it, or restart it without scheduling a city-wide blackout months in advance.

The job shifts. It is no longer "find vulns and recommend patches". It is "find vulns and recommend controls that do not involve touching the actual system".

## Safety systems and interlocks

Observation: OT environments are filled with safety systems, designed to fail safe. They are excellent for safety, less excellent for security testing.

The alchemical reactor has interlocks: temperature sensors, pressure valves, containment field monitors, a large red button for the Bursar.

They are deliberately simple, often hardwired. But they are not entirely separate. Data flows back to SCADA. In some cases, remote alarm acknowledgement or bypass is "convenient".

The testing paradox:
1.  Do not trigger them accidentally. (Annoying.)
2.  Do not disable them accidentally. (Dangerous.)
3.  Determine if attackers could trigger them. (Denial of service.)
4.  Determine if attackers could disable them. (Extremely dangerous.)

The fourth point requires extreme care. "Could I theoretically disable this?" is the question. "Let me test by disabling it" is a career-ending move.

## The mythology of air gaps

Axiom: You will be told the OT network is "air gapped". It is completely separate. Therefore, secure.

Observation: This is a comforting fiction, like believing the Patrician does not know what you did.

The reality at UU P&L:

*   The "air gap" with WiFi: A contractor installed an access point in the turbine hall "for convenience". It bridges the networks. The gap is now a suggestion.
*   The "isolated" network with a jump box: A Windows Server 2003 machine connects the SCADA and corporate networks. It has no antivirus and a password unchanged since installation.
*   The "separated" systems sharing a historian: Control and IT data both feed a historian database on the corporate network, because IT policy demanded it.
*   The "disconnected" network with vendor VPN: A VPN concentrator allows 24/7 vendor access. Ex-employees may still have credentials.
*   The "air gap" with USB ports: Engineers use USB drives, which also visit corporate and home PCs.

Air gaps are a lovely theory. In practice, they are full of holes, like a philosophical argument constructed by the Bursar after too much sherry.

## Why OT people distrust IT people (and vice versa)

Observation: Mutual suspicion is a defining feature.

IT thinks OT lives in the past, refuses security basics, and is difficult.
OT thinks IT is reckless, ignorant of consequences, and wants to break working systems.

Both are partly right.

Local Example: IT once forced a monthly reboot patch onto the turbine system during production. The turbines shut down. Half of Ankh-Morpork went dark. The Patrician was not amused. OT has not forgotten.

OT runs Windows XP on engineering workstations because the SCADA software requires it. They refuse IT's antivirus and monitoring access. When ransomware spread from corporate to OT via the "air gap", IT was blamed for not protecting a network they were barred from.

Requirement: A pentester must navigate this. Build trust with both. Assure OT you will not crash the turbines (probably). Assure IT you understand patch cycles are not applicable. The political challenge often outweighs the technical one.

This is the core difference. It is not just technical. It is political, organisational, cultural. It is the understanding that these systems were built when security meant a physical lock, and retrofitting modern security is like adding airbags to a horse-drawn carriage.

But it must be done. The alternative is leaving the city's power, its volatile reactor, and the stability of L-space accessible to anyone with a network cable and a guess.

And nobody wants to explain to the Librarian why the thermostats now read "Ook".

## Field note: The inescapable conclusion

My observations are complete. The picture is clear, and it is untenable.

We have, on one side, a mandate from the Palace to secure the city's vital infrastructure. On the other, we have systems where a misplaced packet can cause a blackout, where a port scan is an act of industrial sabotage, and where the concept of a "patch" is as fantastical as a frugal wizard.

The traditional IT playbook, to scan, probe, exploit and recommend patches, is not merely inadequate here. It is a recipe for catastrophe. One cannot "break it and see what happens" when "it" is the only thing preventing the Library's more volatile contents from redecorating the campus.

This leaves us with a professional paradox. We must prove vulnerabilities exist to justify the cost and disruption of securing them. But we cannot demonstrate those vulnerabilities on the live systems without triggering the very consequences we seek to avoid.

There is only one solution. We must build a court of inquiry that is not subject to the city's physical laws.

We need a simulator.

Not a simple model, but a causally correct, layered twin of the UU P&L infrastructure. A phantom territory where the Hex turbine spins in silicon, where the alchemical reactor's excitements are confined to a logic engine, and where the Library's climate is a set of variables in a state fabric. In this simulator, we can safely orchestrate every disaster, trace every attack path from a rogue packet to a tripped safety relay, and validate every mitigation.

It will be our Proof of Concept engine. It will allow us to walk into the Patrician's office and say, "My Lord, we have not risked a single light bulb in the city. Yet we can show you, conclusively, how an attacker might darken the Isle of Gods, and precisely how to prevent it." We can replace theoretical risk with demonstrated causality.

The work, therefore, divides cleanly. First, we must document this reality, the profound *difference* that dictates all that follows. Then, we must build its perfect, safe reflection. Only then can we begin the real test.
