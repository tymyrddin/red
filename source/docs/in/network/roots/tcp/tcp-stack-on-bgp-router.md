# Router TCP stack exploitation

*Router OS attack surface. Routing consequences are covered in: [Rootways: BGP](../bgp/tree.md).*

A router running BGP is also a TCP/IP host. Vulnerabilities in the OS TCP implementation, from memory corruption to connection-state exhaustion, offer a path to code execution or service disruption that does not require BGP protocol-layer access.

## Attack tree

```text
1. Router TCP stack exploitation [OR]

    1.1 Remote code execution via TCP/IP flaws [OR]

        1.1.1 OS TCP stack memory corruption
            1.1.1.1 SACK-based memory corruption (e.g., CVE-2019-11477)
            1.1.1.2 Heap overflow via crafted TCP options
            1.1.1.3 TCP segment offloading memory management flaws

        1.1.2 Vendor-specific implementation bugs
            1.1.2.1 JunOS TCP parsing vulnerabilities
            1.1.2.2 IOS XR TCP stack weaknesses
            1.1.2.3 TCP hardware offload engine exploitation

    1.2 Denial of service via connection state exhaustion [OR]

        1.2.1 SACK resource exhaustion
            1.2.1.1 Craft packets with excessive SACK blocks to force disproportionate kernel memory allocation
            1.2.1.2 Trigger kernel panic through memory exhaustion

        1.2.2 SYN flood against port 179
            1.2.2.1 Spoof SYN packets to exhaust the half-open connection table
            1.2.2.2 Starve resources needed for legitimate BGP session establishment

        1.2.3 Crafted packet kernel crashes
            1.2.3.1 Malformed TCP options triggering parser errors
            1.2.3.2 Timestamp processing bugs causing system restart

    1.3 Resource exhaustion via TCP amplification [OR]

        1.3.1 Persist timer exploitation
            1.3.1.1 Force zero-window conditions on BGP sessions
            1.3.1.2 Exhaust CPU cycles through timer management overhead

        1.3.2 Retransmission storm
            1.3.2.1 Induce excessive retransmissions via selective packet loss
            1.3.2.2 Exhaust CPU with retransmission processing on constrained hardware
```

## Why it works

Router operating systems carry full TCP/IP stack implementations, often derived from legacy BSD or proprietary code with long-standing known vulnerabilities. Performance optimisations such as hardware TCP offload and SACK handling add complexity and create vendor-specific failure modes. Dedicated routing hardware tends to have tighter memory and CPU budgets than general-purpose servers, making resource exhaustion attacks more effective.

## Operational implications

- A successful RCE against the TCP stack may allow arbitrary routing table modification without BGP protocol-layer access.
- DoS against port 179 forces session teardown and triggers reconvergence across all peered neighbours.
- Persist timer or retransmission attacks degrade session stability without producing a clean session teardown event.

## Detection pressures

- Port 179 SYN floods appear in flow telemetry as anomalous connection-rate spikes to that port.
- Memory or CPU exhaustion on the router surfaces in SNMP or streaming telemetry before a session drops.
- CVE-specific packet patterns may be detectable via IDS signatures if traffic on the management plane is inspected.

## Related

- [Rootways: BGP attack tree](../bgp/tree.md)
- [BGP session manipulation](bgp-session-manipulation.md)
- [Man-in-the-middle BGP sessions](mitm-bgp-sessions.md)

## Counter moves

Router TCP stack exploitation is what this page works through. Stateful filtering and anomaly detection on the handshake are the answer. Seen from the other side, this sits in the blue notes on [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
