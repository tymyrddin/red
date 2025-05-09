# Harvesting passwords

Escalate using found credentials in

1. Unattended Windows installations
2. Powershell history
3. Saved Windows credentials
4. IIS configuration
5. Retrieve credentials from software, for example PuTTY

## Examples

### Unattended Windows installations

When installing Windows on a large number of hosts, administrators often use Windows Deployment Services, which allows for a single operating system image to be deployed to several hosts through the network. 
These unattended installations do not require user interaction. They do require the use of an administrator account for the initial setup, which might end up being stored in the machine in the following locations:

    C:\Unattend.xml
    C:\Windows\Panther\Unattend.xml
    C:\Windows\Panther\Unattend\Unattend.xml
    C:\Windows\system32\sysprep.inf
    C:\Windows\system32\sysprep\sysprep.xml

### Powershell history

Whenever a user runs a command using Powershell, it gets stored into a file that keeps a memory of past commands. 
If a user runs a command that includes a password directly as part of the Powershell command line, it can later be retrieved.

In the `cmd.exe` prompt:

    type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

In the Powershell prompt:

    type $Env:userprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

### Saved Windows credentials

Windows allows for the use of other users' credentials. To list saved credentials:

    cmdkey /list

Passwords are not given, but a possibly interesting credential can be used with the `runas` command and the `/savecred` option:

    runas /savecred /user:admin cmd.exe

### IIS configuration

Internet Information Services (IIS) is the default web server on Windows installations. 
The configuration of websites on IIS is stored in the `web.config` file and can store passwords for databases or configured authentication mechanisms. Depending on the version of IIS, it can be found in:

    C:\inetpub\wwwroot\web.config
    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config

To find database connection strings on the file:

    type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString

### Retrieve credentials from PuTTY

To retrieve the stored proxy credentials, search under the following registry key for ProxyPassword with:

    reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s

Simon Tatham is the creator of PuTTY (and his name is part of the path), and is not the username. Keep command as is.

## Notes

The example for retrieving credentials from software here is PuTTY. but any software that stores passwords, including browsers, email clients, FTP clients, SSH clients, VNC software and others, will have methods to recover any passwords the user has saved. 
