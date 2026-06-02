# BGP session manipulation

*TCP transport perspective. Canonical BGP attack surface: [Rootways: BGP](../bgp/tree.md).*

BGP sessions run over TCP port 179. Disrupting that connection costs less than compromising the BGP speaker: RST injection, sequence number prediction, and timer manipulation all operate at the transport layer, below any BGP-level security control.

## Attack tree

```text
1. BGP session disruption via TCP [OR]

    1.1 Sequence number exploitation [OR]

        1.1.1 Off-path RST injection
            1.1.1.1 Predict sequence numbers via timestamp leaks or poor ISN randomisation
            1.1.1.2 Send spoofed RST to tear down active session

        1.1.2 In-stream injection
            1.1.2.1 Use predicted sequence number to inject malicious BGP UPDATE
            1.1.2.2 Race session establishment before sequence state settles

    1.2 TCP authentication bypass [OR]

        1.2.1 MD5 weakness
            1.2.1.1 Brute-force or exploit known MD5 implementation flaws
            1.2.1.2 Race session establishment before authentication completes

        1.2.2 TCP-AO gap
            1.2.2.1 Target sessions without TCP-AO configured
            1.2.2.2 Extract authentication keys from compromised device memory

    1.3 Finite state machine exploitation [OR]

        1.3.1 Race conditions in state transitions
            1.3.1.1 Send crafted messages during OPENSENT or OPENCONFIRM states
            1.3.1.2 Force invalid state transitions that crash or reset the FSM

        1.3.2 Keepalive and hold timer abuse
            1.3.2.1 Delay TCP ACKs to expire the BGP hold timer
            1.3.2.2 Manipulate window size to stall keepalive exchange
```

## Why it works

BGP session continuity depends entirely on the underlying TCP connection. Tearing it down forces route withdrawal and reconvergence, achievable without touching BGP itself. Sequence number randomisation is inconsistent across implementations, and MD5 session authentication, where deployed, has well-documented weaknesses. TCP-AO is more robust but deployment is uneven.

## Operational implications

- Session teardown produces immediate route withdrawal, creating observable disruption across peered ASes.
- Short-duration attacks blend with ordinary link instability and may not prompt investigation.
- Sequence number injection allows UPDATE messages to be inserted without router compromise.

## Detection pressures

- Anomalous RST packets to port 179 from unexpected source addresses leave a trace in flow data.
- BGP session flapping without a corresponding interface event may surface in NOC tooling.
- Keepalive failures on otherwise stable physical links create a signal that flow-based monitoring may catch.

## Related

- [Rootways: BGP attack tree](../bgp/tree.md)
- [Man-in-the-middle BGP sessions](mitm-bgp-sessions.md)
- [Router TCP stack exploitation](tcp-stack-on-bgp-router.md)

## Counter moves

BGP session manipulation is the case here. Stateful filtering and anomaly detection on the handshake are the answer. Seen from the other side, this sits in the blue notes on [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
