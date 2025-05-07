# Use an ephemeral OS

For red teaming, use an ephemeral operating system that flushes everything away on every reboot. Store this OS on a USB
stick, and whenever a nice spot is found, plug it into the computer and boot from it.

[Tails](https://tails.boum.org/) is an excellent Linux distribution for this purpose. It automatically rotates the MAC 
address, forces all connections to go through Tor, and avoids storing data on the laptop’s hard disk.
If you do wish to keep some data, make sure to encrypt that data and store it on portable storage.