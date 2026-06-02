# Advanced persistence mechanisms

Long-term presence in routing infrastructure reduces the overhead of repeated initial access. Stealthy route manipulation and hardware-level compromise both limit the surface area that monitoring systems can observe.

## Attack tree

```text
1. Advanced persistence mechanisms [OR]

    1.1 Stealthy route manipulation [OR]

        1.1.1 Time-based hijacking
            1.1.1.1 Micro-duration route announcements lasting seconds to minutes
            1.1.1.2 Rapid announce-withdraw cycles to avoid detection
            1.1.1.3 Attacks scheduled during low-monitoring periods
            1.1.1.4 Transient route manipulation targeting specific transactions

        1.1.2 Geographic-specific route manipulation
            1.1.2.1 Regional prefix hijacking targeting specific locations
            1.1.2.2 AS-path prepending for traffic engineering evasion
            1.1.2.3 Selective advertisement based on geolocation
            1.1.2.4 Localised routing table poisoning

        1.1.3 Mimicking legitimate AS-path patterns
            1.1.3.1 Copying valid AS-path structures and sequences
            1.1.3.2 Modelling legitimate routing behaviour patterns
            1.1.3.3 Replicating common transit provider patterns
            1.1.3.4 Emulating peer relationship characteristics

    1.2 Persistence through infrastructure compromise [OR]

        1.2.1 Long-term router residency
            1.2.1.1 Firmware-level implants in network devices
            1.2.1.2 Persistent malware in routing engine memory
            1.2.1.3 Configuration backdoors and hidden access methods
            1.2.1.4 Compromised software updates and maintenance channels

        1.2.2 Supply chain persistence
            1.2.2.1 Hardware implants in networking equipment
            1.2.2.2 Compromised firmware distribution mechanisms
            1.2.2.3 Malicious code in vendor software updates
            1.2.2.4 Backdoored management tools and utilities

        1.2.3 Operational compromise
            1.2.3.1 Credential theft and reuse across systems
            1.2.3.2 Compromise of network management systems
            1.2.3.3 Exploitation of remote access infrastructure
            1.2.3.4 Social engineering of network operations staff
```

## Why it works

Detection systems have blind spots for short-lived or low-volume anomalies. Hardware-level compromise, once in place, persists across software updates and is difficult to detect without physical inspection. Firmware implants may survive factory resets depending on the storage location. The global routing table's scale makes comprehensive automated monitoring difficult, and the baseline of legitimate route changes is noisy enough to hide targeted manipulation.

## Operational implications

- Short-duration route manipulation can achieve selective traffic interception for specific transactions without sustained presence in the routing table.
- Firmware-level implants provide persistent access that survives BGP session teardowns and router reboots.
- Mimicking legitimate AS-path patterns reduces the anomaly score of malicious announcements against baseline behaviour.

## Detection pressures

- Micro-duration route changes may appear as noise in route monitoring data, but high-frequency announce-withdraw cycles for the same prefix create a detectable pattern.
- Firmware-level modifications may be detectable through cryptographic verification of boot images, if that capability is enabled and monitored.
- Credentials used to access network management systems from unexpected sources leave authentication log entries.

## Related

- [Rootways: BGP attack tree](../bgp/tree.md)
- [Supply chain compromise](supply-chain-compromise.md)

## Counter moves

Advanced persistence mechanisms is what this page works through. Stateful filtering and anomaly detection on the handshake are the answer. The defender's view is in the blue notes on [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
