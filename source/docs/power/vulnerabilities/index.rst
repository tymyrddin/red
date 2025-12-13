Vulnerability assessment
======================================================

.. image:: /_static/images/ot-vulns.png
   :alt: A bustling factory control room with exposed mechanical brains integrated into walls, glowing red circuits thrumming with energy. Panels display 'default login' prompts and blinking warning lights.

A useful assessment focuses on realistic attack paths and operational impact. Can an attacker reach an HMI from the
IT network? Can they upload logic, alter setpoints, or tamper with historian data without detection? What can be
tested safely, what must be observed only, and what should never be touched outside a simulator.

In Ankh‑Morpork terms, this is the difference between checking whether a door is locked and kicking it in to see
what happens. The former tells you something useful. The latter tells you who will be looking for you afterwards.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Checking:

   hmi-security-testing.md


