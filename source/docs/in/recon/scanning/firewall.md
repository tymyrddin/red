# Firewall evasion

Fragment packets:

    # nmap -f <IP>

Most firewalls and IDS detect fragmented packets.

The `nmap --mtu` command allows for specifying offset size (has to be a multiple of 8). This is similar to the packet 
fragmentation technique. During the scan, nmap creates packets of that size, causing confusion to the firewall.

    # nmap --mtu [MTU] <IP>

Decoy:

    # nmap -D RND:[number] <IP>

Idle zombie scan:

    # nmap -sI [zombie] <IP>

Manually specify a source port:

    # nmap --source-port [port] <IP>

Append random data:

    # nmap --data-length [size] <IP>

Randomize target scan order:

    # nmap --randomize-hosts <IP>

Spoof MAC address:

    # nmap --spoof-mac [MAC|0|vendor] <IP>

Send bad checksums:

    # nmap --badsum <IP>

The `badsum` command deploys an invalid TCP/UDP/SCTP checksum for packets transmitted to the target. Practically every 
host IP stack will correctly drop the packets, so each response accepted is possibly originating from a firewall or 
Intrusion Detection System that was not concerned with confirming the checksum. 