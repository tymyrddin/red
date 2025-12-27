Border Gateway Protocol Security (BGPsec)
===========================================

BGPsec represents a critical evolution in internet routing security, designed to cryptographically verify the
authenticity and path integrity of BGP announcements. However, its complex cryptographic foundations, intricate
key management requirements, and challenging global deployment create a new frontier of vulnerabilities.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Ghosts don’t fear heights, they own the view.

   tree.md

Disclaimer
-----------------------------------------
An attack tree is structural, not operational. It exists in the comfortable world of pure logic, where things
either work or they don't, gates either open or stay closed, and time is merely a dimension I/you/we draw an arrow along.

It's comprehensive. It has branches for sub-prefix hijacking, exact-prefix hijacking, squatting attacks, path
manipulation, and several dozen other variations. Each node connects logically to its children. The structure is clean.

Until someone takes a tree seriously enough to ask `but what would this actually *look* like? <https://purple.tymyrddin.dev/docs/lantern/red-lanterns/playbooks/>`_
