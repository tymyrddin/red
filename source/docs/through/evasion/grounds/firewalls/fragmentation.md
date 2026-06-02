# Evasion via forcing fragmentation, MTU, and data length

Control the packet size will allow for:

* Fragmenting packets, optionally with given MTU. If the firewall, or the IDS/IPS, does not reassemble the packet, it will most likely let it pass. Consequently, the target system will reassemble and process it.
* Sending packets with specific data lengths.

Fragment packets with 8 bytes of data:

    nmap -sS -Pn -f -F MACHINE_IP

Fragment packets with 16 bytes of data:

    map -sS -Pn -ff -F MACHINE_IP

Fragment packets according to a set MTU:

    nmap -sS -Pn --mtu 8 -F MACHINE_IP

Generate packets with specific length:

    nmap -sS -Pn --data-length 64 -F MACHINE_IP

## Counter moves

Fragmenting traffic and tuning MTU splits a signature across packets the firewall may reassemble differently. Full reassembly at the inspection point and anomaly detection on odd fragmentation close it. The defender's view is in the blue notes on [plausibility as cover](https://blue.tymyrddin.dev/docs/counter/evasion/).
