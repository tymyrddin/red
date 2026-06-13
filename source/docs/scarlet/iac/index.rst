A foothold in the top of the world tree
=========================================================

.. image:: /_static/images/tree-iac.png
  :alt: World tree

Infrastructure as Code allows a deployment to operate like a ghost town that dissolves at a moment's notice. If an
operation is compromised, the entire footprint vanishes instantly, leaving only cloud billing alerts.

To avoid detection, the architecture relies on layers. Redirectors act as proxy fronts, tunneling target traffic back
to hidden control servers.

Adding distinct bounce servers makes the environment entirely ephemeral; a flagged component can be destroyed and
replaced in minutes. Automating this pipeline ensures rapid rotation while serving as a practical study in modern
DevOps and immutable infrastructure.

.. toctree::
   :glob:
   :maxdepth: 2

   redirectors/index
   bouncers/index
   frontend/index
   backends/index
   automation/index
   attack/index

