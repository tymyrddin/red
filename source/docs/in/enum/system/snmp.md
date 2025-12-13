# SNMP enumeration

Default SNMP passwords allow attackers to view or modify the SNMP configuration settings. Attackers can enumerate SNMP on remote network devices for:

* Information about network resources such as routers, shares, devices, etc.
* ARP and routing tables
* Device specific information
* Traffic statistics
* And more.

## Tools

* [OpUtils](https://www.manageengine.com/products/oputils/) is IP address and switch port management software geared towards helping engineers monitor, diagnose, and troubleshoot IT resources. OpUtils complements existing management tools by providing troubleshooting and real-time monitoring capabilities.
* [SNScan](https://www.softpedia.com/get/Network-Tools/Network-IP-Scanner/SNScan.shtml) is a Windows network tool whose purpose is to scan and detect SNMP-enabled devices on a network. It is able to indicate devices that are potentially vulnerable to SNMP-related security threats.
* [NS Auditor](https://www.nsauditor.com/) includes more than 45 network tools and utilities for network security auditing, scanning, network connections monitoring and more.

## Remediation

* Minimise the attack surface by removing the SNMP agents where not needed.
* Change default public community strings.
* Upgrade to SNMPv3, which encrypts the community strings and messages.
* Implement group policy for additional restriction on anonymous connections.
* Implement firewalls to restrict unnecessary connections.
* Implement IPSec filtering.
* Block access to TCP/UDP ports 161.
* Encrypt and authenticate using IPSEC.

