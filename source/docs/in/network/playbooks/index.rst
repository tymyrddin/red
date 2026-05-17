Playbooks
=============================================

Where Tradecraft covers individual procedures, playbooks compose them into adversarial campaign logic. The sequence
is the point: entry, escalation, objective. Each playbook traces a chain from foothold to outcome, drawing on the
moves in Tradecraft and the attack surfaces in Rootways and Patches. :doc:`Earthworks <../../../earthworks/index>` is where campaign logic meets fictional-organisation ground truth.

Each playbook opens with a scenario context and states the operator objective. It then chains the constituent
runbooks from Tradecraft in the order they are applied, with decision points where the path forks based on what the
environment allows. Exit criteria mark when the objective is met. Execution detail stays in Tradecraft; the playbook
is the logic that connects steps into a campaign.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Playbooks:

   network-entry.md
