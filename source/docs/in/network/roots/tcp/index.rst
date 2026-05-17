Transmission Control Protocol (TCP)
=========================================

TCP is a primary attack surface here, not a means to an end for BGP. These trees model connection hijacking,
session exhaustion, stateful device bypass, and transport-layer service disruption in their own right. Cross-protocol
consequences in routing appear in section 3 of the canonical tree as derived outcomes, not the organising principle.

Three files take a specific TCP-transport view of BGP-related mechanics:
:doc:`Router TCP stack exploitation <tcp-stack-on-bgp-router>`,
:doc:`BGP session manipulation <bgp-session-manipulation>`, and
:doc:`Man-in-the-middle BGP sessions <mitm-bgp-sessions>`.
Each is a scoped derivative of the canonical BGP attack surface at :doc:`Rootways: BGP <../bgp/index>`.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: TCP as an attack surface, with cross-protocol routing consequences at depth.

   tree.md
   tcp-stack-on-bgp-router.md
   bgp-session-manipulation.md
   mitm-bgp-sessions.md
   protocol-level-tcp-attacks.md
   off-path-side-channel-attacks.md
   cloud-middlebox-attacks.md
   session-integrity-attacks.md
   network-infra-attacks.md
   advanced-persistence-mechanisms.md
   supply-chain-compromise.md
