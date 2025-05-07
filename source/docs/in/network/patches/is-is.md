# Intermediate System to Intermediate System (IS-IS)

## Attack tree for Is-Is

```text
1. Compromise IS-IS Routing Tables (OR)

    1.1. Spoof IS-IS Protocol Data Units (PDUs) (OR)

        1.1.1. Forge Fake Hello (IIH) PDUs (Disrupt Adjacency Formation)

        1.1.2. Inject Malicious Link-State PDUs (LSPs)

        1.1.3. Replay Old PDUs (If Sequence Numbers Are Predictable)

    1.2. Exploit Weak or Misconfigured Authentication (OR)

        1.2.1. Crack MD5/HMAC Authentication (If Weak Keys Used)

        1.2.2. Bypass Authentication (If Null/Plaintext Auth Enabled)

    1.3. Manipulate IS-IS LSPs (OR)

        1.3.1. Advertise Fake Links or Prefixes (Traffic Hijacking)

        1.3.2. Trigger Frequent SPF Recalculations (CPU Exhaustion)

    1.4. Exploit IS-IS Protocol Mechanics (OR)

        1.4.1. Abuse Designated Intermediate System (DIS) Election

        1.4.2. Send Malicious Sequence Number PDUs (LSP Corruption)

    1.5. Man-in-the-Middle (MITM) Attacks (AND)

        1.5.1. Intercept IS-IS Traffic (Required)

        1.5.2. Modify or Inject Fake LSPs (Required)

2. Denial-of-Service (DoS) Against IS-IS (OR)

    2.1. Flood IS-IS with Malicious PDUs

        2.1.1. Send Excessive IIH PDUs (Prevent Adjacency Formation)

        2.1.2. Generate Fake LSPs (Overwhelm SPF Calculations)

    2.2. Exploit IS-IS Link-State Database (LSDB) (OR)

        2.2.1. Fill LSDB with Bogus LSPs (Memory Exhaustion)

        2.2.2. Trigger Constant LSP Flooding (Network Congestion)

    2.3. Resource Exhaustion (OR)

        2.3.1. Overload Router CPU with SPF Recalculations

        2.3.2. Exhaust Bandwidth with LSP Storms

3. Information Leakage (OR)

    3.1. Passive Eavesdropping on IS-IS Traffic

        3.1.1. Capture Unencrypted LSPs (Topology Mapping)

    3.2. Exploit IS-IS Hierarchical Design

        3.2.1. Abuse Level 1/Level 2 Routing to Leak Routes
```

## Notes

* IS-IS lacks native encryption, relying on MD5/HMAC for authentication.
* LSP manipulation is a primary attack vector (e.g., fake links reroute traffic).
* DIS election attacks can disrupt broadcast network stability.

