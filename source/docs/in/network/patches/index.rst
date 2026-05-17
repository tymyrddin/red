Patches of mycelium (@Home and @Org)
=========================================

The same artefact type as Rootways, different scope. Where Rootways models interdomain trust collapse at internet
scale, these trees model what happens when local routing protocols are treated as attack surfaces: RIP, EIGRP, OSPF,
IS-IS, BGP in an intranet context, static routing, first-hop redundancy protocols. Each carries its own failure modes
and its own assumptions about trust. Operational procedures for executing against these surfaces are in Tradecraft.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Ghosts don’t fear heights, they own the view.

   rip.md
   eigrp.md
   ospf.md
   is-is.md
   bgp.md
   static.md
   fhrp.md
