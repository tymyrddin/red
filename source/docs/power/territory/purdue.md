# OT architectures and the Purdue model

*Extracts from the notebooks of Ponder Stibbons, regarding the architectonic dissonance of industrial control systems*

One must begin, as with any enquiry into thaumaturgical infrastructure, with a frame of reference. In the field of 
industrial control, this frame is commonly known as the 
[Purdue Enterprise Reference Architecture](https://www.pera.net/). When a consultant speaks of "proper network 
segmentation", this is the neat, layered diagram they present: a Platonic ideal of order, where firewalls stand 
like sober watchmen between distinct levels of function.

I have observed, however, that the relationship between this model and the operational reality of, for instance, the Unseen University Power & Light Co. is rather akin to the relationship between a formal treatise on civic planning and the actual, organic, pungent sprawl of Ankh-Morpork. The former describes a pleasing theory; the latter is where people live, work, and occasionally have to run from unexpected squid.

Nevertheless, the model is useful. It provides a common nomenclature, a way to categorise the delightful chaos one 
encounters. It allows one to point at a rogue wireless access point and say, with academic precision, "This device 
constitutes a bridging violation between Level 2 and Level 5, subverting the intended segregation," which is a far 
more persuasive statement than, "This is a very bad idea".

## The Theoretical Stratigraphy: The Purdue Levels**

The architecture proposes six strata, from the fundament of physics to the ether of enterprise.

*   **Level 0: The Physical Process.** This is the raw territory: the steam, the spinning metal, the alchemical effervescence. It is measured and manipulated, but it is not, in itself, computable. One cannot send a packet to a valve; one can only instruct a device to move it.
*   **Level 1: Basic Control.** Here reside the devices that perform the measuring and manipulating: the Programmable Logic Controllers, the Remote Terminal Units. At UU P&L, the ancient Allen-Bradley guardians of the Hex turbines operate here, executing their ladder-logic with the single-minded focus of a clerk adding up columns of figures. Their security paradigm is often one of implicit trust, a belief that anyone on the local network must be friendly—an assumption with a historical casualty rate in this city that should give any device pause.
*   **Level 2: Supervisory Control.** This is the operator's domain. The SCADA servers, the Human-Machine Interface screens with their reassuring (and occasionally fictional) animations, the historians quietly amassing years of operational data. To compromise this level is to gain legitimate command of the layers below. It is the difference between picking a lock and being handed the master key by a confused but helpful apprentice.
*   **Level 3: Operations Management.** Scheduling, maintenance logs, quality assurance. Systems that manage the *business* of operation rather than the operation itself. They converse with Level 2 for data and Level 4 for instruction, forming a critical bridge.
*   **Level 4: Business Logistics.** Finance, procurement, human resources. The realm of spreadsheets, invoices for coal and bananas, and the Bursar's more comprehensible ledgers. Firmly in the domain of corporate information technology.
*   **Level 5: The Enterprise.** The wider network, the internet, email. The source of most exogenous threats, from targeted phishing to disorganised mischief.

## The Ankh-Morporkian actual: A study in pragmatic contradictions

Theory assumes clean separation. Practice, as I have documented in the steam-damp corridors of the P&L basements, demonstrates a fascinating principle of infrastructural entropy: systems will intermingle over time in the service of immediate convenience, regardless of grand design.

*   **The Historian's Dilemma.** The data historian, a Level 2 asset, must be queried by business intelligence tools on Level 4. The solution, implemented a decade ago by a technician who has since retired to a smallholding near Sto Lat, was to place it on a network segment with portholes to both worlds. Thus, a vulnerability in a reporting portal can become a stepping stone to the very controls of the turbine. The path is not a flaw, but a documented feature, buried in Appendix C of a system manual no one has read since its publication.
*   **The Permanent Guest: Vendor Remote Access.** The turbine manufacturer's support contract stipulates "unimpeded diagnostic access". This has been interpreted as a permanent VPN tunnel from their offices (somewhere in the agatean Empire) directly to an engineering workstation on the Level 2 network. It bypasses every theoretical control layer like a secret passage under the city walls. Its credentials are known to half a dozen former employees and are changed with a frequency that suggests geological timescales.
*   **The Apparition of Connectivity.** My survey noted a wireless access point in the main turbine hall, broadcasting the SSID `TURBINE_TEMP`. It is not in any network diagram. Neither the IT nor OT departments claim responsibility for its installation. It was, according to workshop legend, installed eight years ago by a contractor needing to check a wiring schematic on his tablet. It has since become critical, if unofficial, infrastructure. Its security configuration is, one might say, optimistic.
*   **The Illusion of Segmentation.** Official documentation proudly displays a network diagram with distinct VLANs for each Purdue Level. What the diagram does not convey is that the firewall rules to enforce separation between these VLANs were drafted but never implemented, for fear of "breaking something". The segmentation is thus cartographic, not actual. It provides the comfort of a plan without the inconvenience of a barrier.

## Common architectural compromises, logically considered**

From these observations, patterns of systemic risk emerge.

1.  **The Hard Shell, Soft Centre.** Considerable resource is expended on the perimeter firewall between the corporate and OT realms. Yet, once inside the OT network—achievable via the spectral access point, a compromised jump box, or simply plugging into a spare socket in the turbine hall—one encounters no further internal resistance. It is a keep with a formidable gate but no doors on the inner rooms.
2.  **Redundancy as a Singularity.** There are two SCADA servers for resilience. Both share the same administrative credentials, "to simplify failover procedures". Both are accessible from the same, lightly monitored engineering terminal. They provide redundancy for *availability*, but collectively constitute a single point of *security* failure.
3.  **The Permeable DMZ.** The Demilitarised Zone, intended as a neutral ground for data exchange, has accrued so many "temporary" exceptions for various business applications that it has become the most permissive and complex part of the network. It is less a buffer zone and more a bustling, unregulated bazaar where data from all levels mingles freely.

## On the procurement of elegant, impractical solutions

When these frailties are finally acknowledged, management may seek a definitive solution. This often leads to the proposal of a **Data Diode**—a hardware device that permits data to flow in only one direction, physically.

In theory, it is elegant. In practice, at UU P&L, it proved otherwise. A project was approved, and €200,000 of such equipment was procured. The crisis emerged during testing: the production scheduling system (Level 3) required the ability to send new setpoints *down* to the SCADA (Level 2). The pristine, one-way data flow was operationally untenable. The diodes now reside in a storage cupboard near the old alchemy labs, a silent testament to the clash between idealised security and operational necessity.

Similarly, the **Jump Host**—a hardened server meant to be the sole, audited gateway between zones—often deteriorates into a shared convenience. It becomes under-patched (its ownership disputed between departments), accessed via a common generic account, and its copious logs are sent to an archive that no one consults. It is intended as a fortified gatehouse but functions as a busy, unguarded side door.

## Synthesis and proposed methodology

This, then, is the core challenge. We have, on one hand, a logical model of how a control system *should* be 
structured. On the other, we have the historical, pragmatic, and financially constrained reality of how it *has* 
grown. To test the latter with the techniques suited to the former is to invite calamity.

My conclusion, therefore, is that we cannot safely experiment upon the living organism. We must construct a detailed 
simulacrum.

Our simulator project does not replicate the messy, ad-hoc network of the real UU P&L. Rather, it instantiates the 
*Purdue Model itself* as a perfect, causal framework. Within this controlled environment, where `/components/physics/` 
embodies Level 0, `/components/devices/` constitute Level 1, and `/components/network/servers/` provide the Level 2 
interface, we can safely introduce the compromises we have observed. We can add the phantom wireless bridge, flatten 
the virtual VLANs, and share the simulated credentials.

We can then demonstrate, without risk to the city's power supply, how a threat propagates through a poorly segmented 
architecture, and, crucially, how proper controls would contain it. It transforms a theoretical model into a 
practical, demonstrable truth—the only kind of evidence with persuasive weight in the halls of power.
