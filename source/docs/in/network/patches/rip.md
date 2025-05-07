# Routing Information Protocol (RIP)

## Attack tree for RIP

```text
1. Compromise RIP Network Routing

    1.1. Spoof RIP Messages (OR)

        1.1.1. Forge Route Advertisements

        1.1.2. Modify Legitimate RIP Packets in Transit

        1.1.3. Replay Old RIP Updates

    1.2. Exploit RIP Authentication Weaknesses (OR)

        1.2.1. Crack Weak/Plaintext Passwords (if using RIPv2 simple auth)

        1.2.2. Bypass MD5 Authentication (if using RIPv2 MD5)

    1.3. Abuse RIP’s Lack of Route Validation (OR)

        1.3.1. Advertise False Routes (Blackhole, Loop, or Hijack Traffic)

        1.3.2. Overwhelm Network with Excessive Route Updates (DoS)

    1.4. Exploit RIP Protocol Vulnerabilities (OR)

        1.4.1. Trigger Count-to-Infinity Problem (Poison Routes)

        1.4.2. Exploit Missing Sequence Numbers (Replay Attacks)

    1.5. Man-in-the-Middle (MITM) Attacks (AND)

        1.5.1. Intercept RIP Traffic (Required)

        1.5.2. Modify or Inject Fake Routes (Required)

2. Denial-of-Service (DoS) Against RIP (OR)

    2.1. Flood RIP with Malicious Updates

        2.1.1. Send Excessive Route Advertisements

        2.1.2. Advertise Fake High-Cost Routes

    2.2. Exploit RIP’s Slow Convergence (OR)

        2.2.1. Introduce Routing Loops

        2.2.2. Force Continuous Route Recalculations

    2.3. Resource Exhaustion (OR)

        2.3.1. Overload Router CPU with RIP Processing

        2.3.2. Fill Routing Tables with Bogus Routes

3. Information Leakage (OR)

    3.1. Sniff RIP Traffic (Passive Recon)

        3.1.1. Capture Unencrypted RIP Updates

    3.2. Infer Network Topology

        3.2.1. Analyze RIP Route Advertisements
```

## Notes

* RIP’s lack of encryption (in RIPv1) and weak authentication (in RIPv2) makes it vulnerable.
* Many attacks rely on trust assumptions in RIP’s distance-vector nature.

