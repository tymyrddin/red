Erasing the trail: Evading logging and monitoring
==================================================

Security teams rely on logs and monitors to reconstruct an intruder’s steps—but only if there are steps to follow.
Like a raccoon brushing away its pawprints in the mud, this section focuses on evading, disabling, or outright
manipulating logging and monitoring systems. You’ll study real-time mechanisms like ETW, use PowerShell to dodge
detection, and sabotage the very log pipelines defenders depend on.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: The raccoon not only sneaks in—it ensures no one knows it was ever there.

   etw.md
   ps-reflection.md
   patching.md
   takeover.md
   pipeline.md
   challenge.md

----

.. image:: /_static/images/thm-etw.png
   :alt: THM Room: Evading Logging and Monitoring
   :target: https://tryhackme.com/room/monitoringevasion