Poking physics with network packets
======================================================

.. image:: /_static/images/ot.png
   :alt: An industrial control panel with glowing screens, pipes and valves in the background, a single Ethernet cable snaking from a corporate laptop into the OT network. Subtle dials reading slightly off normal.

Operational technology security is where a misconfigured register ceases to be a finding and becomes a bang, a spill,
or a process that drifts quietly out of spec for six weeks before anyone notices. The protocols are decades old and
were designed for reliability, not security: they trust commands that look normal, they do not authenticate the
engineer behind them, and they assume that anyone who can send a valid Modbus frame belongs there.

The attack pattern that actually works here is not Stuxnet's bespoke precision engineering. It is a corporate laptop
with VPN access and a route to the historian server. Air gaps are mostly mythology; the real topology is a flat
network with a firewall that nobody has reviewed since the last integrator visit. From there, the engineering
workstation holds the logic definitions, the credentials, and the deployment tools that make "authorised maintenance"
look exactly like an attack when the wrong person does it.

.. toctree::
   :glob:
   :maxdepth: 2
   :includehidden:
   :caption: Where network packets meet physical consequences:

   notes/index
   runbooks/index
   playbooks/index

.. toctree::
   :glob:
   :maxdepth: 2
   :includehidden:
   :caption: Controls and detection:

   defence/index
