# Enhanced Interior Gateway Routing Protocol (EIGRP)

## Attack tree for EIGRP

```text
1. Compromise EIGRP Routing Tables (OR)

    1.1. Spoof EIGRP Messages (OR)

        1.1.1. Forge Fake Hello Packets (Disrupt Neighbor Adjacency)

        1.1.2. Inject Malicious Update/Query/Reply Packets

        1.1.3. Replay Old EIGRP Messages (If Sequence Numbers Are Predictable)

    1.2. Exploit Weak or Misconfigured Authentication (OR)

        1.2.1. Crack MD5 Authentication (If Weak Key Used)

        1.2.2. Bypass Authentication (If None Configured)

    1.3. Manipulate EIGRP Metrics (OR)

        1.3.1. Advertise False Bandwidth/Delay Values (Traffic Hijacking)

        1.3.2. Trigger Route Flapping (Constant Route Recalculations)

    1.4. Exploit EIGRP Protocol Mechanics (OR)

        1.4.1. Abuse DUAL Finite State Machine (Stuck-in-Active Attacks)

        1.4.2. Exhaust Router Resources with Excessive Queries

    1.5. Man-in-the-Middle (MITM) Attacks (AND)

        1.5.1. Intercept EIGRP Traffic (Required)

        1.5.2. Modify or Inject Fake Routes (Required)

2. Denial-of-Service (DoS) Against EIGRP (OR)

    2.1. Flood EIGRP with Malicious Packets

        2.1.1. Send Excessive Hello/Update Packets (Overwhelm CPU)

        2.1.2. Generate Fake Queries/Replies (Trigger DUAL Loops)

    2.2. Exploit EIGRP’s DUAL Algorithm (OR)

        2.2.1. Force Stuck-in-Active (SIA) Condition

        2.2.2. Cause Route Oscillations (Unstable Network)

    2.3. Resource Exhaustion (OR)

        2.3.1. Fill Topology Table with Bogus Routes

        2.3.2. Overload Router Memory/CPU with EIGRP Processing

3. Information Leakage (OR)

    3.1. Passive Eavesdropping on EIGRP Traffic

        3.1.1. Capture Unencrypted EIGRP Updates

    3.2. Network Topology Discovery

        3.2.1. analyse EIGRP Topology Tables (If Leaked)
```

## Notes

* EIGRP’s reliance on MD5 authentication (no SHA support) makes it vulnerable to brute force if weak keys are used.
* Stuck-in-Active (SIA) attacks are unique to EIGRP due to its DUAL algorithm.
* Unlike RIP, EIGRP is more complex, so attacks often target protocol logic rather than just spoofing.

