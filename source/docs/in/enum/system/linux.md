# Linux enumeration

Get information from:

* Settings: Users and usernames
* Applications: some run on defaults, or there may be null or blank passwords
* Permissions on key directories and files
* Shares if linux shares resources over the network
* Samba, the linux equivalent to smb, may give information about the windows network and its shares
* NFS information can give information on permissions and the network services
* Network services such as [DNS](dns.md), [LDAP](ldap.md), [SMTP](smtp.md), etc.
* Various built-in commands and utilities

## Tools

* [LinEnum](https://github.com/rebootuser/LinEnum) is a basic shell script that performs over 65 checks, getting anything from kernel information to locating possible escalation points such as potentially useful SUID/GUID files and Sudo/rhost mis-configurations and more.
* [enum4linux](https://labs.portcullis.co.uk/tools/enum4linux/) is a wrapper around the Samba tools smbclient, rpclient, net and nmblookup.
* [netcat](https://github.com/andrew-d/static-binaries/blob/master/binaries/windows/x86/ncat.exe) is network debugging and investigation tool that can assist with port scanning, transferring files, and port listening, and it can also be used as a backdoor. Many descendants.

## Remediation

* Minimize the attack surface by removing any unnecessary or unused service.
* Ensure IPTables is configured to restrict the access.

