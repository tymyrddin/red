Turning the model against itself
=======================================================================

.. image:: /_static/images/adversarial-ai.png
  :alt: An overview of Adversarial Machine Learning attempts categorized into four major attack vectors: Evasion, Poisoning, Extraction, and Inference.

A learned model is a soft interior and nobody drew its decision
boundary by hand, nobody can fully see it, and the system around it tends to trust whatever label it
returns. That trust is the opening. Five ways an attacker can work a model from the
outside: crafting an input it gets wrong, shaping the data it learns from, cloning it through its own
answers, reading its training data back out, and talking its way past its instructions.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: The model is just another fence, and this one was never locked:

   evasion
   poisoning
   extraction
   inference
   prompt-injection
