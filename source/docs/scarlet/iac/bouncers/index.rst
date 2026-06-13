Bounce servers’ hidden rings
==========================================

Bounce servers are the cybersecurity equivalent of that one friend's couch you crash on when things get too hot:
temporary, deniable, and completely disposable. They're an operational base of... well, not exactly operations,
more like that shady storage unit where all the tools live not to be traced back to the actual address.

Burn them down regularly, because nothing ruins a good opsec posture like a cloud provider's
forensic team finding Terraform state files next to those "funny" log entries.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Ancient, layered, and forgotten until you need to vanish.

   payments.md
   providers.md
   wireguard-mesh.md
   tor-hidden.md
   reflector-nets.md
