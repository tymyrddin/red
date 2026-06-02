# First-Hop Redundancy Protocols (HSRP/VRRP)

## Attack tree for HSRP

```text
1. Compromise HSRP Group (OR)

    1.1. Spoof HSRP Messages (OR)

        1.1.1. Forge Hello Packets (Take Over Active Router Role)

        1.1.2. Modify Priority/Preemption Values

    1.2. Exploit Weak Authentication (OR)

        1.2.1. Crack Plaintext/MD5 Authentication

        1.2.2. Bypass Authentication (If None Configured)

    1.3. Cause Failover Disruption (OR)

        1.3.1. Trigger Unnecessary Active-Standby Switches (DoS)

        1.3.2. Send Fake Resign Messages (Force Role Changes)

2. Man-in-the-Middle (MITM) Attacks (AND)

    2.1. Redirect Traffic via HSRP Takeover (AND)

        2.1.1. Become Active Router (Required)

        2.1.2. Intercept/Modify Traffic (Required)

3. Denial-of-Service (DoS) (OR)

    3.1. Flood HSRP Groups (OR)

        3.1.1. Send Excessive Hellos (Disrupt Election)

        3.1.2. Advertise Invalid Virtual IPs (Confusion Attack)
```

## Attack tree for VRRP

```text
1. Compromise VRRP Group (OR)

    1.1. Spoof VRRP Advertisements (OR)

        1.1.1. Forge Master Router Advertisements

        1.1.2. Manipulate Priority Values

    1.2. Exploit Authentication Weaknesses (OR)

        1.2.1. Crack Simple Text/MD5 Authentication

        1.2.2. Exploit No Authentication (Default in VRRPv2)

    1.3. Disrupt Failover (OR)

        1.3.1. Force Unnecessary Master-Backup Transitions

        1.3.2. Send Fake Shutdown Events

2. Traffic Interception (AND)

    2.1. MITM via VRRP Takeover (AND)

        2.1.1. Become Master Router (Required)

        2.1.2. Redirect Traffic to Attacker Node (Required)

3. Denial-of-Service (OR)

    3.1. Flood VRRP Groups (OR)

        3.1.1. Overwhelm with Advertisements (Prevent Election)

        3.1.2. Advertise Conflicting Virtual IPs
```

## Key differences

HSRP (Cisco proprietary) uses UDP 224.0.0.2 (TTL=1). Default authentication is plaintext.

VRRP (IEEE standard) uses 224.0.0.18 (IP protocol 112). VRRPv3 supports IPv6 and stronger authentication.

## Notes

* Priority spoofing: setting a higher priority value is the common path to becoming the active or master router.
* Authentication bypass: weak or absent authentication allows injection of malicious packets without credential recovery.
* Failover abuse: forcing unnecessary role transitions causes instability and may mask other activity on the segment.

## Counter moves

First-Hop Redundancy Protocols (HSRP/VRRP) is what this page works through. Patching the exposed service and segmenting it are the levers. Defenders' notes on this are under [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
