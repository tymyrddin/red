# SNMP enumeration

Default SNMP passwords allow attackers to view or modify the SNMP configuration settings. Attackers can enumerate SNMP on remote network devices for:

* Information about network resources such as routers, shares, devices, etc.
* ARP and routing tables
* Device specific information
* Traffic statistics
* And more.

## Tools

* [SNMP enumeration tools](https://testlab.tymyrddin.dev/docs/enum/snmp)

## Remediation

* Minimize the attack surface by removing the SNMP agents where not needed.
* Change default public community strings.
* Upgrade to SNMPv3, which encrypts the community strings and messages.
* Implement group policy for additional restriction on anonymous connections.
* Implement firewalls to restrict unnecessary connections.
* Implement IPSec filtering.
* Block access to TCP/UDP ports 161.
* Encrypt and authenticate using IPSEC.

