# Indicators that control-plane attacks are possible

Nov 14th, 2025

Or, The Catalogue of Open Doors.

We do not wait for evidence of an attack (by someone else). We *enumerate the invitation*. Every protocol that blindly 
trusts a familiar seal, every system that converges on consensus without verifying the speaker, every ledger that can 
be edited by just one clerk. These are not flaws. They are *formal invitations*. This catalogue is our map of every 
silent door into the city's logic. It answers not *"Was there a breach?"* but *"Where, precisely, would you like to walk 
in?"*

| Invitation Type               | The Silent Door                                                                                                                                                                                    | The Underlying Assumption (The Flaw in the Map)                                                                                | Scarlet Semaphore Query                                                                                                                |
|:------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------|
| The Unquestioned Herald       | A routing system that accepts and propagates a new path announcement because it comes from a "trusted" or previously known peer, without validating if the announcement is *true* or *authorized*. | Trust is transitive and static. A familiar seal guarantees the message, not just the messenger.                                | "What if we *became* a trusted peer? What path would we like the city's messages to take tomorrow?"                                    |
| The Silent Consensus          | A database or ledger where any change, once accepted by a single primary node or clerk, is automatically and irreversibly replicated to all others as the new truth.                               | Authority is centralized; consensus is automated. The system prioritizes consistency over the validity of the initial command. | "Which clerk's stamp do we need to forge, just once, to rewrite history for everyone?"                                                 |
| The Invisible Handshake       | A management or configuration protocol (like SNMP, SSH for management, or an admin API) that uses weak, default, or poorly guarded credentials to govern critical infrastructure.                  | The backstage door is part of the furniture, not a security boundary. The control channel is forgotten because it works.       | "Where is the forgotten key under the mat? The one that doesn't lock the front gate, but opens the panel that controls all the gates?" |
| The Map That Draws Itself     | A system that automatically discovers and trusts new devices or services on the network based on protocol (like LLDP, CDP) or simple declaration, adding them to its operational view.             | The network is benign and self-correcting. New entities are presumed friendly until proven otherwise.                          | "What if we simply announced ourselves as the new central clock? Would the city set its watch by us?"                                  |
| The Single Point of Narrative | A logging, monitoring, or governance system where all data flows to one central authority for analysis, and that authority's view is accepted as the definitive state of reality.                  | The observer is incorruptible. He who controls the narrative controls the perception of the system.                            | "If we feed the watch captain's ledger false truths, what decisions would he make on our behalf?"                                      |

This catalogue shifts the perspective from defense to opportunity. Each "Indicator" is not a warning siren for the 
blue team, but a blueprint and a hypothesis for the red team. The final column, *"Scarlet Semaphore Query,"* is the 
crucial step: translating the abstract vulnerability into a direct, actionable attack scenario that fits the guild's 
philosophy of elegant, logical interference.

