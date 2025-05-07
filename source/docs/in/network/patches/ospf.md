# Open Shortest Path First (OSPF)

## Attack tree for OSPF

```text
1. Compromise OSPF Routing Tables (OR)

    1.1. Spoof OSPF Messages (OR)

        1.1.1. Forge Fake Hello Packets (Disrupt Adjacency Formation)

        1.1.2. Inject Malicious Link-State Advertisements (LSAs)

        1.1.3. Replay Old OSPF Messages (If Sequence Numbers Are Predictable)

    1.2. Exploit Weak or Misconfigured Authentication (OR)

        1.2.1. Crack MD5 Authentication (If Weak Key Used)

        1.2.2. Bypass Authentication (If Null/Plaintext Auth Enabled)

    1.3. Manipulate OSPF LSAs (OR)

        1.3.1. Advertise Fake Links (Traffic Redirection)

        1.3.2. Trigger Frequent SPF Recalculations (CPU Exhaustion)

    1.4. Exploit OSPF Protocol Mechanics (OR)

        1.4.1. Abuse Designated Router (DR) Election Process

        1.4.2. Send Max-Age LSAs (Force Premature LSA Flushing)

    1.5. Man-in-the-Middle (MITM) Attacks (AND)

        1.5.1. Intercept OSPF Traffic (Required)

        1.5.2. Modify or Inject Fake LSAs (Required)

2. Denial-of-Service (DoS) Against OSPF (OR)

    2.1. Flood OSPF with Malicious Packets

        2.1.1. Send Excessive Hello Packets (Prevent Adjacency Formation)

        2.1.2. Generate Fake LSAs (Overwhelm SPF Calculations)

    2.2. Exploit OSPF’s Link-State Database (LSDB) (OR)

        2.2.1. Fill LSDB with Bogus LSAs (Memory Exhaustion)

        2.2.2. Trigger Constant LSA Flooding (Network Congestion)

    2.3. Resource Exhaustion (OR)

        2.3.1. Overload Router CPU with SPF Recalculations

        2.3.2. Exhaust Bandwidth with LSA Storms

3. Information Leakage (OR)

    3.1. Passive Eavesdropping on OSPF Traffic

        3.1.1. Capture Unencrypted OSPF LSAs (Topology Mapping)

    3.2. Exploit OSPF’s Hierarchical Design

        3.2.1. Abuse Area Border Router (ABR) Role to Leak Routes
```

## Notes

* OSPF’s MD5 authentication is vulnerable to brute force if weak keys are used.
* LSA manipulation is a critical attack vector (fake links can reroute traffic).
* DR election attacks can disrupt local network stability.

