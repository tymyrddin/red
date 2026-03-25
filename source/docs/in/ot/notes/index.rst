Field notes from the process layer
=====================================================

OT security sits at the intersection of two threat models that were developed in isolation from each other. The IT
security model assumes that availability can be briefly sacrificed for integrity; the OT model assumes that
availability is non-negotiable and that the commands arriving over the wire are legitimate because the network is
physically separate. Neither assumption holds anymore.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Where commands meet consequences:

   recon.md
   architecture.md
   protocols.md
   engineering.md
   safety.md
   evasion.md
