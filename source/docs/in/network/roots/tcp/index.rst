Transmission Control Protocol (TCP)
=========================================

The Border Gateway Protocol (BGP), which governs global internet routing, fundamentally relies on the Transmission
Control Protocol (TCP) for establishing and maintaining sessions between peers. This inherent dependency creates a
critical attack surface where vulnerabilities within the TCP stack, session management, and cryptographic
protections can be weaponized to compromise the integrity, availability, and confidentiality of the entire global
routing system. This attack tree systematically deconstructs the methods through which an adversary can exploit
TCP to manipulate BGP, ranging from low-level kernel exploits and session hijacking to sophisticated cryptographic
attacks and AI-enhanced offensive operations.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Exploiting TCP's inherent trust to compromise, manipulate, and disrupt global BGP routing.

   tcp-tree.md

