Getting a foothold in the top of the world tree
=========================================================

Building cloud attack infrastructure is like being a digital property developer - except instead of luxury condos,
you're constructing shady back-alley operations that can disappear overnight. Redirectors are your shell company
fronts, bounce servers are your offshore accounts, and frontends are those suspiciously clean storefronts that
never seem to actually sell anything. The beauty of Infrastructure as Code is that when the authorities come
knocking, your entire operation can vanish faster than a teenager's browser history when parents walk in, leaving
nothing but a smoking crater of AWS billing alerts.

----

.. image:: /_static/images/attack-infra.png
  :alt: Overview

----

We have to pretend to be adversaries that do not wish to be detected no matter what. Redirectors can be used to proxy
requests coming from the target back to our attack infrastructure.

A solution with bounce servers is much more elegant and replacing infrastructure components can be done in minutes.
And automating the server set up process like this also helps in exploring current DevOps methodologies to better
understand the underlying technologies.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: The cloud: Where attackers thrive and budgets die.

   redirectors/index
   bouncers/index
   frontend/index
   backends/index
   automation/index
   attack/index

