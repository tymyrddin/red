# LDAP enumeration

LDAP supports anonymous remote queries on the server. The query will disclose sensitive information such as usernames, address, contact details, etc.

## Tools

Bloodhound uses the collector which is called as SharpHound to collect various kinds of data by running a ton of 
LDAP queries to collect information within Active Directory. BloodHoundAD/SharpHound is designed targeting .Net 4.6.2. 
SharpHound must be run from the context of a domain user, either directly through a logon or through another method 
such as `RUNAS`.

## Remediation

* Use SSL to encrypt LDAP communication
* Use Kerberos to restrict the access to known users
* Enable account lockout to restrict brute-forcing
* Create a few Active Directory Decoy accounts
* Enable auditing on those accounts
* Run Bloodhound’s Sharphound tool
* Perform LDAP Reconnaissance activities within the active directory environment
* Detect the activities in Windows event logs.
