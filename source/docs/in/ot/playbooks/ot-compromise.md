# Playbook: IT-to-OT compromise chain

This playbook connects the OT runbooks into an operational sequence. The chain runs from corporate IT through the IT/OT boundary to engineering-level access inside the OT network. The objective is demonstrating that a corporate IT compromise translates to the capability to affect industrial processes, without actually modifying production systems.

## Objective

Show that the path from corporate IT network access to OT process control capability exists, is reachable through realistic attack techniques, and is not detected by current monitoring. Quantify the gap between the IT/OT boundary and the process control layer.

## Prerequisites

- Explicit written confirmation of OT scope, specifying which segments and devices may be interacted with and at what level (passive observation, protocol read, or controlled write to designated test systems only).
- A named client representative with authority to stop the exercise immediately if any unintended process effect is observed.
- Confirmation that safety systems and safety-classified PLCs are out of scope for all active operations.
- A detailed understanding of the process being controlled, obtained during scoping, sufficient to recognise if any action could cause process disruption.

## Phase 1: IT foothold and boundary identification

Begin with a foothold in the corporate IT network using the techniques documented in the network or endpoint domains. From that foothold, map toward the OT boundary: identify OT-indicative hostnames, historian servers, and any firewall rules or route advertisements that indicate OT segment reachability.

The IT/OT boundary is typically visible in the routing table of an IT host as a static route to a 10.x.x.x or 172.16.x.x range that is not part of the normal corporate IP allocation. DNS hostnames in those ranges usually contain `hist`, `hmi`, `scada`, or `eng`.

## Phase 2: DMZ and historian compromise

The historian is the most accessible OT-layer target from IT. It is designed to be reachable from IT for reporting purposes, and it has direct data connections to Level 2 SCADA systems. Attempt access using default credentials, harvested credentials from the IT network, or pass-the-hash against the RDP or WinRM service.

Confirm that the historian has live data connections to Level 2 SCADA servers. Read current process data from the historian to establish that it reflects live process state. This is the first demonstration that the IT compromise has reached OT data.

## Phase 3: IT/OT lateral movement

From the historian or DMZ, identify direct routes into the Level 2 SCADA and HMI network. Test whether the firewall permits direct TCP access to OT protocol ports (502, 44818, 102, 4840) on Level 2 hosts. In most environments, some degree of direct connectivity exists because the historian's data collection requires it and the firewall rules were written to permit exactly what was needed at deployment time, then never reviewed.

Identify the engineering workstation. It may be in the DMZ, in the Level 2 network, or bridging both. Access it using the same credential techniques as the historian.

## Phase 4: Engineering access and capability demonstration

From the engineering workstation, confirm:

The project files are accessible and readable. The tag database reveals which register addresses correspond to which physical process parameters. The engineering software can connect in online mode to at least one PLC in the Level 2 network. The software reports the PLC's current program state (confirming read access to production logic).

This demonstration establishes that an attacker in the position of this engagement could deploy modified logic to the named PLCs. Do not proceed to any actual logic modification on production systems.

For protocol-level demonstration on approved test devices, use the protocol abuse runbook to read process values and, if within scope, demonstrate a single write to an agreed safe parameter with immediate restoration.

## Phase 5: Detection gap measurement

Throughout the exercise, note what was detected. Key questions:

Did the IT security team detect the lateral movement toward OT? Did the OT monitoring system (Dragos, Claroty, Nozomi) detect the enumeration of OT-segment hosts? Did any alert fire when the engineering workstation was accessed remotely? Did any alert fire when the engineering software connected to the PLC in online mode?

In most engagements, the answer to most of these questions is no. The gap between "attacker reached the OT network" and "any detection occurred" is the primary finding.

## Evidence collection

Document the full path from initial IT foothold to engineering workstation access, with timestamps at each step. Capture: the historian's live data connections as evidence of OT data access, the project file confirming tag-to-register mapping, the engineering software in online mode with a PLC, and the protocol-level read from any devices accessed directly. Present the evidence as a narrative chain that communicates the physical consequence of the access, not just the technical steps.

## Runbooks

- [OT reconnaissance](../runbooks/ot-recon.md)
- [IT to OT pivot](../runbooks/it-ot-pivot.md)
- [Protocol abuse](../runbooks/protocol-abuse.md)
- [Engineering workstation](../runbooks/engineering-workstation.md)
