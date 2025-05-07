# Border Gateway Protocol (BGP)

## Attack tree for BGP in Local Networks

```text
1. Hijack BGP Routes (OR)

    1.1. Spoof BGP Announcements (OR)

        1.1.1. Advertise Fake Prefixes (Prefix Hijacking)

        1.1.2. Announce More Specific Routes (Traffic Interception)

        1.1.3. Modify AS_PATH Attributes (Path Shortening/Elongation)

    1.2. Exploit Weak or Missing Authentication (OR)

        1.2.1. Bypass TCP MD5 Authentication (Session Spoofing)

        1.2.2. Exploit Misconfigured Route Filters (Route Leak)

    1.3. Manipulate BGP Attributes (OR)

        1.3.1. Alter LOCAL_PREF (Influence Outbound Traffic)

        1.3.2. Modify COMMUNITY Values (Bypass Policy Controls)

    1.4. Exploit BGP Session Establishment (OR)

        1.4.1. Fake BGP Peer (Session Takeover)

        1.4.2. Abuse BGP Graceful Restart (DoS + Route Poisoning)

    1.5. Man-in-the-Middle (MITM) Attacks (AND)

        1.5.1. Intercept BGP Sessions (TCP Hijacking)

        1.5.2. Inject Malicious Updates (Route Manipulation)

2. Denial-of-Service (DoS) Against BGP (OR)

    2.1. Flood BGP with Malicious Updates

        2.1.1. Send Excessive UPDATE Messages (CPU Overload)

        2.1.2. Advertise Flapping Routes (Route Instability)

    2.2. Exploit BGP Convergence (OR)

        2.2.1. Trigger Constant Route Withdrawals/Announcements

        2.2.2. Exhaust Router Memory with Large Routing Tables

    2.3. Resource Exhaustion (OR)

        2.3.1. Overload BGP Process with Malicious Keepalives

        2.3.2. Exploit BGP Finite State Machine (Session Resets)

3. Information Leakage & Reconnaissance (OR)

    3.1. Passive Eavesdropping on BGP Sessions

        3.1.1. Capture Unencrypted BGP Updates (Topology Discovery)

    3.2. Exploit BGP Communities & Attributes

        3.2.1. Infer Internal Policies via Leaked COMMUNITY Values
```

## Notes

* Local networks often lack RPKI/ROV, making prefix hijacking easier.
* TCP MD5 is weak against offline brute-force attacks.
* Route leaks are common due to misconfigured filters.

