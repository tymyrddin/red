Field notes from the bin-raider's handbook
===========================================

Modern cryptanalysis has shifted from "break the cipher" to "break the system around the
cipher, and use AI while doing it". The maths is still there, but it has been joined by
engineering reality and a rather opportunistic streak.

Strong algorithms (AES-256, properly implemented modern ECC) are still standing. What is
falling is everything around them: bad implementations, protocol misuse, weak randomness,
hardware leakage, and the humans who glue it all together.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Attack tradecraft: where cryptographic systems actually break.

   bruteforce.md
   side-channels.md
   protocol-attacks.md
   rng-attacks.md
   ai-cryptanalysis.md
   automated-tools.md
   attack-chain.md

