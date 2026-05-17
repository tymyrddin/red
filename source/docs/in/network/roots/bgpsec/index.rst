Border Gateway Protocol Security (BGPsec)
===========================================

BGPsec extends BGP with cryptographic path validation: each autonomous system in the path signs its announcement,
making route forgery detectable by receivers. The surface it introduces is proportional to the complexity it adds.
Key management, deployment heterogeneity, and the gap between partial and full adoption each create conditions where
the security gain is asymmetric, reversible, or absent in practice.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Cryptographic path integrity introduces its own attack surface.

   tree.md
