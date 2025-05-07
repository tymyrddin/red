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

* [Linux enumeration tools](https://testlab.tymyrddin.dev/docs/enum/linux)

## Remediation

* Minimize the attack surface by removing any unnecessary or unused service.
* Ensure IPTables is configured to restrict the access.

