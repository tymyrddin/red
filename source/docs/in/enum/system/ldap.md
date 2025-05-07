# LDAP enumeration

LDAP supports anonymous remote queries on the server. The query will disclose sensitive information such as usernames, address, contact details, etc.

## Tools

* [LDAP enumeration tools](https://testlab.tymyrddin.dev/docs/enum/ldap)

## Remediation

* Use SSL to encrypt LDAP communication
* Use Kerberos to restrict the access to known users
* Enable account lockout to restrict brute-forcing
* Create a few Active Directory Decoy accounts
* Enable auditing on those accounts
* Run Bloodhound’s Sharphound tool
* Perform LDAP Reconnaissance activities within the active directory environment
* Detect the activities in Windows event logs.
