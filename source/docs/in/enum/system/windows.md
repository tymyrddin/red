# Windows enumeration

Get information:

* Usernames
* Default configurations
* Default passwords
* Domain names
* Computer names
* Shares
* Windows information
* Network information like [DNS](dns.md), [SMTP](smtp.md), [SNMP](snmp.md) information
* Application details
* Banners
* Routing tables

## Tools

Windows operating systems can be enumerated with multiple tools from [Sysinternals](https://learn.microsoft.com/en-gb/sysinternals/). Some of the most important:

* PsExec - Execute processes on remote machines.
* PsFile - Displays list of files opened remotely.
* PsGetSid - Translate SID to display name and vice versa.
* PsKill - Kill processes on local or remote machines.
* PsInfo - Displays installation, install date, kernel build, physical memory, processors type and number and so on.
* PsList - Displays process, CPU, memory, thread statistics and more.
* PsLoggedOn - Displays local and remote logged users.
* PsLogList - View event logs.

---

* [net command](https://www.computerhope.com/nethlp.htm) can be used to glean almost any aspect of a local network and its settings including network shares, network printers and print jobs, network users, policies!, etc. It is available from within the Command Prompt in all Windows operating systems including Windows 10, Windows 8, Windows 7, Windows Vista, Windows XP, and further back. The availability of certain net command switches and other net command syntax may differ from operating system to operating system.
* [SMBMap](https://github.com/ShawnDEvans/smbmap) allows users to enumerate samba share drives across an entire domain. List share drives, drive permissions, share contents, upload/download functionality, file name auto-download pattern matching, and even execute remote commands. This tool was designed with pen testing in mind, and is intended to simplify searching for potentially sensitive data across large networks.

## Remediation

* Minimise the attack surface by removing any unnecessary or unused service.
* Ensure IPTables is configured to restrict the access.

