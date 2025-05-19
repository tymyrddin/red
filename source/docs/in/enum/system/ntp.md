# NTP enumeration

An attacker can enumerate the following information by querying an NTP server.

* List of hosts connected to the NTP server
* Internal client IP addresses, hostnames and operating system used

## Tools

* [ntptrace](https://manpages.org/ntptrace) is a python script that uses the ntpq utility program to follow the chain of NTP servers from a given host back to the primary time source.
* [ntpdc](https://manpages.org/ntpdc) queries the NTP daemon about its current state and to request changes in the state.
* [ntpq](https://manpages.org/ntpq) monitors NTP daemon NTPD operations and determines performance.

## Remediation

* Restrict the usage of NTP and enable the use of NTPSec, where possible.
* Filter the traffic with IPTables.
* Enable logging for the messages and events.
