# Static routing

## Attack tree for Static Routing

```text
1. Compromise Static Route Configuration (OR)

    1.1. Gain Unauthorized Access to Router (OR)

        1.1.1. Exploit Default/Weak Credentials (SSH/Telnet/Web GUI)

        1.1.2. Use Privilege Escalation (Vendor Backdoors, CVEs)

        1.1.3. Physical Access to Console Port

    1.2. Modify Static Routes (OR)

        1.2.1. Add Malicious Static Route (Traffic Redirection)

        1.2.2. Delete Critical Static Route (Denial of Service)

        1.2.3. Alter Next-Hop IP (Man-in-the-Middle)

    1.3. Exploit Weak Configuration Management (OR)

        1.3.1. Abuse TFTP/Unencrypted Config Backups

        1.3.2. Exploit Weak SNMP RW Community Strings

2. Denial-of-Service (DoS) via Static Routing (OR)

    2.1. Blackhole Traffic (OR)

        2.1.1. Route Legitimate Traffic to Null0/Drop Interface

        2.1.2. Redirect Traffic to Non-Existent Next-Hop

    2.2. Cause Routing Loops (OR)

        2.2.1. Configure Circular Static Routes (Packet Looping)

        2.2.2. Overlap Routes with Incorrect AD Values

3. Traffic Interception (OR)

    3.1. Redirect Traffic to Malicious Host (OR)

        3.1.1. Point Next-Hop to Attacker-Controlled Router

        3.1.2. Spoof ARP/NDP for Next-Hop IP

    3.2. Bypass Security Controls (OR)

        3.2.1. Create Static Route Around Firewall

        3.2.2. Override Dynamic Routes with Malicious Static Route

4. Persistence & Evasion (AND)

    4.1. Maintain Access (AND)

        4.1.1. Disable Logging for Route Changes

        4.1.2. Create Backdoor Admin Account

    4.2. Prevent Detection (OR)

        4.2.1. Mimic Legitimate Route Patterns

        4.2.2. Use Non-Standard AD Values to Avoid Notice
```

## Notes

* Static routes lack dynamic verification, making them vulnerable to unauthorized changes.
* No protocol-level authentication exists (unlike dynamic routing protocols).
* Attacks often require prior access (physical/remote) to the router.

