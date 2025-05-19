# NetBios enumeration

NetBIOS is outdated but still lives on in some older systems, sometimes for backward compatability. It is the equivalent of broadcasting names to look for each other but is not routable. It is local network only. If no one on the other network can use it for your network, then no one there can access your NetBIOS shared folders and printers, unless one has gained access to your local network. You can also access NetBIOS machines with a WINS server. That is the NetBIOS equivalent of a DNS server.

NetBIOS software runs on port 139 on the Windows operating system. File and printer services need to be enabled to enumerate NetBIOS over Windows. An attacker can perform the following on the remote machine:

* Choosing to read or write to a remote machine, depending on the availability of shares.
* Launching a Denial of Service (DoS) attack on the remote machine.
* Enumerating password policies on the remote machine.

## Tools

* [Nbtstat](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/nbtstat) displays NetBIOS over TCP/IP (NetBT) protocol statistics, NetBIOS name tables for both the local computer and remote computers (Windows Server 2022, Windows Server 2019, Windows Server 2016, Windows Server 2012 R2, Windows Server 2012), and the NetBIOS name cache. This command also allows a refresh of the NetBIOS name cache and the names registered with Windows Internet Name Service (WINS).
* [Hyena](https://www.systemtools.com/hyena/) is designed to both simplify and centralise nearly all day-to-day Windows network or Active Directory management tasks, while providing new capabilities for system administration. 
* [Winfingerprint](https://packetstormsecurity.com/files/38356/winfingerprint-0.6.2.zip.html) is a Win32 Host/Network Enumeration Scanner. Winfingerprint is capable of performing SMB, TCP, UDP, ICMP, RPC, and SNMP scans. Using SMB, winfingerprint can enumerate OS, users, groups, SIDs, password policies, services, service packs and hotfixes, NetBIOS shares, transports, sessions, disks, security event log, and time of day in either an NT Domain or Active Directory environment. Winfingerprint-cli is a command line version of winfingerprint and it is currently bundled with each release.

## Remediation

* Minimise the attack surface by minimising the unnecessary service like Server Message Block (SMB).
* Remove file and printer sharing in Windows OS.
