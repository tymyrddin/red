# Safety systems as targets

Safety Instrumented Systems (SIS) are the last line of defence in industrial processes. When a process variable exceeds a safe operating limit, the SIS detects the condition and executes a protective action: shutting down a pump, closing a valve, venting pressure, or triggering an emergency stop. The SIS is architecturally separate from the Basic Process Control System (BPCS) to ensure that a failure in the control system cannot simultaneously disable the safety system.

This architectural separation is increasingly violated. The pressures of cost reduction, remote monitoring requirements, and the desire for integrated engineering tools have pushed many organisations toward SIS implementations that share networks, engineering workstations, and sometimes even communication infrastructure with the BPCS. When a safety system that was designed to be independent can be reached over the same network as the process control system, the safety isolation fails.

## The TRITON/TRISIS incident

The TRITON malware, discovered in 2017, was the first publicly documented attack specifically targeting a Safety Instrumented System. It targeted Schneider Electric Triconex Safety Instrumented System controllers at a petrochemical facility in Saudi Arabia. The attacker modified the TriStation protocol firmware in memory to enable programming mode, then attempted to modify the safety logic. A programming error caused the safety controllers to enter a fail-safe shutdown state, which actually revealed the attack.

The significance of TRITON is not the specific implementation but the intent: disabling or manipulating safety systems allows a subsequent attack on the BPCS to cause physical harm without the safety system intervening. The attack on safety is preparatory.

## Modern SIS exposure

Safety PLC vendors have progressively added remote connectivity features that create the same exposure as BPCS systems. Ethernet-connected SIS controllers with remote monitoring interfaces are common in new installations. Engineering software for SIS (Triconex TriStation, Honeywell Safety Manager, ABB Ability Safety) shares engineering workstations with BPCS software in many organisations.

Network segmentation between the SIS and BPCS is the primary control, but it is not universally implemented. Where a common engineering workstation can connect to both the BPCS and the SIS network segments, a compromised workstation provides access to both.

## Impact asymmetry

Attacking a BPCS causes process disruption: downtime, product loss, equipment damage. Attacking a SIS, or attacking both simultaneously, removes the safeguard that prevents a process excursion from becoming a physical event: explosion, fire, toxic release, structural failure. This impact asymmetry means that SIS attacks represent a qualitatively different threat category, not just a more severe version of BPCS attacks.

For red team engagements, this asymmetry requires explicit scoping. Demonstrating that a SIS can be reached from the IT network, or that an engineering workstation can connect to the SIS, is a meaningful finding. Demonstrating that SIS logic can be read or that programming mode can be enabled is a further step. Actually modifying safety logic should not occur outside of isolated lab environments; the consequences of doing so on a live system are beyond the scope of any red team engagement.

## What red teams actually test

The relevant OT safety finding for most engagements is architectural: can the SIS be reached from a position the attacker can achieve, and is the SIS engineering workstation shared with BPCS tools? The demonstration is the network path, not the manipulation of safety logic. Confirming reachability is sufficient to establish the risk; the physical consequences of demonstrating it further are not worth the evidence.
